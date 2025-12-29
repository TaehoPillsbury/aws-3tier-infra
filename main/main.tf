############################
# 실행하기 전 메모장에서 ctrl+h 눌러서 
# ap-northeast-2 > 본인이 사용할 main region 
# ap-northeast-1 > 본인이 사용할 dr region 
# 이렇게 바꿔줘야 합니다 
############################

terraform {
  required_version = ">= 1.5.0"

  backend "s3" {
    # [설정] 서울 리전용 백엔드 버킷 정보 (사용 환경에 맞게 수정 필요)
    bucket         = "pldr-tfstate-ap-northeast-2"
    key            = "dev/main/ap-northeast-2/terraform.tfstate"
    region         = "ap-northeast-2"
    dynamodb_table = "pldr-terraform-lock-ap-northeast-2"
    encrypt        = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

############################
# Provider (Main Region: Seoul)
############################
provider "aws" {
  region = "ap-northeast-2"
}

############################
# Compute Toggle (Main Region is Always Active)
############################
variable "enable_compute" {
  description = "EC2 인스턴스 생성 여부 (메인 리전이므로 기본값 true)"
  type        = bool
  default     = true
}

############################
# Common
############################
locals {
  project = "pldr"
  env     = "dev"

  tags = {
    Project = local.project
    Env     = local.env
    Role    = "main"
    Region  = "ap-northeast-2"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

############################
# [추가] Random String for Unique Names
############################
resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

############################
# VPC
############################
resource "aws_vpc" "this" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = merge(local.tags, { Name = "pldr-main-vpc" })
}

############################
# Subnets (2 AZ)
############################
resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet("10.20.0.0/16", 4, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  tags = merge(local.tags, { Name = "pldr-main-public-${count.index}" })
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet("10.20.0.0/16", 4, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags = merge(local.tags, { Name = "pldr-main-private-${count.index}" })
}

############################
# IGW / NAT
############################
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.this.id
  tags   = local.tags
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = local.tags
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  depends_on    = [aws_internet_gateway.igw]
  tags          = local.tags
}

############################
# Route Tables
############################
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = local.tags
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
  tags = local.tags
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

############################
# VPC Gateway Endpoints
############################
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.ap-northeast-2.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  tags              = local.tags
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.ap-northeast-2.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  tags              = local.tags
}

############################
# [수정] DynamoDB Global Table (Random Name 적용)
############################
resource "aws_dynamodb_table" "global_table" {
  # 난수를 붙여 유니크한 이름 생성
  name             = "pldr-global-table-${random_string.suffix.result}"
  billing_mode     = "PAY_PER_REQUEST"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  hash_key  = "PK"
  range_key = "SK"

  attribute {
    name = "PK"
    type = "S"
  }

  attribute {
    name = "SK"
    type = "S"
  }

  # 복제본: 도쿄 중부 (Tokyo Central)
  replica {
    region_name = "ap-northeast-1"
  }

  tags = local.tags
}

############################
# Security Groups
############################
resource "aws_security_group" "alb" {
  name   = "pldr-main-alb-sg"
  vpc_id = aws_vpc.this.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = local.tags
}

resource "aws_security_group" "web" {
  name   = "pldr-main-web-sg"
  vpc_id = aws_vpc.this.id

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = local.tags
}

resource "aws_security_group" "app" {
  name   = "pldr-main-app-sg"
  vpc_id = aws_vpc.this.id

  ingress {
    from_port       = 3001
    to_port         = 3001
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }

  # NLB Health Check
  ingress {
    description = "Allow NLB health checks from VPC"
    from_port   = 3001
    to_port     = 3001
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.this.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = local.tags
}

############################
# SSM Endpoints & Security Group
############################
resource "aws_security_group" "ssm_endpoint" {
  name   = "pldr-main-ssm-endpoint-sg"
  vpc_id = aws_vpc.this.id

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id, aws_security_group.app.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = local.tags
}

resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.ap-northeast-2.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.ssm_endpoint.id]
  private_dns_enabled = true
  tags                = local.tags
}

resource "aws_vpc_endpoint" "ssmmessages" {
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.ap-northeast-2.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.ssm_endpoint.id]
  private_dns_enabled = true
  tags                = local.tags
}

resource "aws_vpc_endpoint" "ec2messages" {
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.ap-northeast-2.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.ssm_endpoint.id]
  private_dns_enabled = true
  tags                = local.tags
}

############################
# IAM Roles & Policies
############################
resource "aws_iam_role" "ec2" {
  name = "pldr-main-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# [수정] 동적 테이블 이름을 참조하도록 정책 변경
resource "aws_iam_role_policy" "dynamodb_access" {
  name = "pldr-main-dynamodb-policy"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.global_table.arn,
          "${aws_dynamodb_table.global_table.arn}/*",
          # 하드코딩 대신 변수 사용
          "arn:aws:dynamodb:*:*:table/${aws_dynamodb_table.global_table.name}" 
        ]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2" {
  role = aws_iam_role.ec2.name
}

############################
# AMI
############################
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-minimal-2023*-x86_64"]
  }
}

############################
# Launch Template & ASG (WEB Tier)
############################
resource "aws_launch_template" "web" {
  name_prefix   = "pldr-web-lt-"
  image_id      = data.aws_ami.al2023.id
  instance_type = "t3.micro"

  block_device_mappings {
    device_name = "/dev/xvda" 
    ebs {
      volume_size = 8
      volume_type = "gp3"
    }
  }

  vpc_security_group_ids = [aws_security_group.web.id]
  
  iam_instance_profile {
    name = aws_iam_instance_profile.ec2.name
  }

  metadata_options {
    http_tokens = "required"
  }

  # [수정] SSM Agent 설치 로직 추가
  user_data = base64encode(<<-EOF
              #!/bin/bash
              set -e

              # 1. SSM Agent 설치 및 실행 (NAT를 통해 설치)
              dnf install -y amazon-ssm-agent
              systemctl enable amazon-ssm-agent
              systemctl start amazon-ssm-agent

              # 2. Nginx 설치 및 설정
              dnf install -y nginx
              setsebool -P httpd_can_network_connect 1

              cat > /etc/nginx/conf.d/app_proxy.conf <<NGINX
              server {
                  listen 80;
                  server_name _;

                  location / {
                      root   /usr/share/nginx/html;
                      index  index.html;
                  }

                  location /api/ {
                      proxy_pass http://app.internal.pldr:3001/;
                      proxy_set_header Host \$host;
                      proxy_set_header X-Real-IP \$remote_addr;
                      proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
                      proxy_set_header X-Forwarded-Proto \$scheme;
                  }
              }
              NGINX

              rm -f /etc/nginx/conf.d/default.conf || true
              systemctl enable nginx
              systemctl restart nginx

              cat > /usr/share/nginx/html/index.html <<'HTML'
              <!DOCTYPE html>
              <html lang="ko">
                <head><title>Pilot Light Service (Main)</title></head>
                <body>
                  <h1>Main Site - Seoul (ASG)</h1>
                  <form id="data-form">
                    <input type="text" name="name" placeholder="Name" required><br>
                    <textarea name="message" placeholder="Message" required></textarea><br>
                    <button type="submit">Submit</button>
                  </form>
                  <div id="result"></div>
                  <script>
                    document.getElementById('data-form').addEventListener('submit', function(e) {
                      e.preventDefault();
                      const data = { 
                        name: e.target.name.value, 
                        message: e.target.message.value 
                      };
                      fetch('/api/submit', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(data)
                      }).then(r => r.json())
                        .then(d => {
                           alert('Success: ' + JSON.stringify(d));
                           document.getElementById('data-form').reset();
                        })
                        .catch(e => alert('Error: ' + e));
                    });
                  </script>
                </body>
              </html>
              HTML
              EOF
  )

  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.tags, { Name = "pldr-main-web-asg" })
  }
}

resource "aws_autoscaling_group" "web" {
  name                = "pldr-main-web-asg"
  vpc_zone_identifier = aws_subnet.private[*].id
  target_group_arns   = [aws_lb_target_group.web.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300

  desired_capacity    = var.enable_compute ? 2 : 0
  min_size            = var.enable_compute ? 2 : 0
  max_size            = var.enable_compute ? 4 : 0

  launch_template {
    id      = aws_launch_template.web.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "pldr-main-web-asg"
    propagate_at_launch = true
  }

  dynamic "tag" {
    for_each = local.tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }
}

############################
# Launch Template & ASG (APP Tier)
############################
resource "aws_launch_template" "app" {
  name_prefix   = "pldr-app-lt-"
  image_id      = data.aws_ami.al2023.id
  instance_type = "t3.micro"

  block_device_mappings {
    device_name = "/dev/xvda" 
    ebs {
      volume_size = 8
      volume_type = "gp3"
    }
  }

  vpc_security_group_ids = [aws_security_group.app.id]

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2.name
  }

  metadata_options {
    http_tokens = "required"
  }

  # [수정] SSM Agent 설치 로직 추가
  user_data = base64encode(<<-EOF
            #!/bin/bash
            set -e

            # 1. SSM Agent 설치 및 실행 (NAT를 통해 설치)
            dnf install -y amazon-ssm-agent
            systemctl enable amazon-ssm-agent
            systemctl start amazon-ssm-agent

            # 2. Python/Flask 환경 구성
            dnf install -y python3-pip
            pip3 install flask gunicorn boto3

            # Flask App Code
            cat > /app.py <<'APP'
            from flask import Flask, jsonify, request
            import boto3
            import uuid
            import os
            from datetime import datetime

            app = Flask(__name__)

            # 서울 리전 설정
            REGION = 'ap-northeast-2'
            
            # [수정] Terraform 변수로 생성된 실제 테이블 이름을 주입
            TABLE_NAME = '${aws_dynamodb_table.global_table.name}'

            dynamodb = boto3.resource('dynamodb', region_name=REGION)
            table = dynamodb.Table(TABLE_NAME)

            @app.route("/")
            def health():
                return "OK (Main)"

            @app.route("/submit", methods=["POST"])
            def submit_data():
                try:
                    data = request.json
                    name = data.get("name")
                    message = data.get("message")
                    
                    if not name or not message:
                        return jsonify({"error": "Missing data"}), 400

                    unique_id = str(uuid.uuid4())
                    timestamp = datetime.utcnow().isoformat() + 'Z'

                    item = {
                        'PK': unique_id,
                        'SK': 'SUBMISSION',
                        'name': name,
                        'message': message,
                        'timestamp': timestamp,
                        'source_region': REGION
                    }
                    
                    table.put_item(Item=item)
                    
                    return jsonify({
                        "success": True, 
                        "message": "Saved to Global Table (Seoul)", 
                        "submitted_name": name
                    }), 200

                except Exception as e:
                    print(f"Error: {e}")
                    return jsonify({"error": str(e)}), 500

            if __name__ == "__main__":
                app.run(host="0.0.0.0", port=3001)
            APP

            # Systemd Service 등록
            cat > /etc/systemd/system/pldr-app.service <<SERVICE
            [Unit]
            Description=Gunicorn instance to serve pldr-app
            After=network.target

            [Service]
            User=root
            Group=root
            WorkingDirectory=/
            Environment="PATH=/usr/local/bin:/usr/bin:/bin"
            ExecStart=/usr/local/bin/gunicorn --workers 3 --bind 0.0.0.0:3001 app:app
            Restart=always

            [Install]
            WantedBy=multi-user.target
            SERVICE

            systemctl daemon-reload
            systemctl start pldr-app
            systemctl enable pldr-app
            EOF
  )

  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.tags, { Name = "pldr-main-app-asg" })
  }
}

resource "aws_autoscaling_group" "app" {
  name                = "pldr-main-app-asg"
  vpc_zone_identifier = aws_subnet.private[*].id
  target_group_arns   = [aws_lb_target_group.app.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300

  desired_capacity    = var.enable_compute ? 2 : 0
  min_size            = var.enable_compute ? 2 : 0
  max_size            = var.enable_compute ? 4 : 0

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "pldr-main-app-asg"
    propagate_at_launch = true
  }

  dynamic "tag" {
    for_each = local.tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }
}

############################
# ALB (External)
############################
resource "aws_lb" "alb" {
  name               = "pldr-main-alb"
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id
  tags               = local.tags
}

resource "aws_lb_target_group" "web" {
  name     = "pldr-main-web-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.this.id

  health_check {
    path    = "/"
    matcher = "200-399"
  }
  tags = local.tags
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}

############################
# Internal NLB (APP Tier)
############################
resource "aws_lb" "app_nlb" {
  name               = "pldr-main-app-nlb"
  load_balancer_type = "network"
  internal           = true
  subnets            = aws_subnet.private[*].id
  enable_cross_zone_load_balancing = true
  tags = local.tags
}

resource "aws_lb_target_group" "app" {
  name        = "pldr-main-app-tg"
  port        = 3001
  protocol    = "TCP"
  vpc_id      = aws_vpc.this.id
  target_type = "instance"

  health_check {
    protocol            = "HTTP"
    path                = "/"
    port                = "3001"
    matcher             = "200-399"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 10
    timeout             = 6
  }
  tags = local.tags
}

resource "aws_lb_listener" "app_tcp_3001" {
  load_balancer_arn = aws_lb.app_nlb.arn
  port              = 3001
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

############################
# [추가] Route 53 Private Hosted Zone (Main Region)
############################
resource "aws_route53_zone" "private" {
  name = "internal.pldr"
  vpc {
    vpc_id = aws_vpc.this.id
  }
  tags = local.tags
}

resource "aws_route53_record" "app_nlb" {
  zone_id = aws_route53_zone.private.zone_id
  name    = "app.internal.pldr"
  type    = "A"

  alias {
    name                   = aws_lb.app_nlb.dns_name
    zone_id                = aws_lb.app_nlb.zone_id
    evaluate_target_health = true
  }
}

############################
# Outputs
############################
output "main_alb_dns_name" {
  value = aws_lb.alb.dns_name
}

output "main_vpc_id" {
  value = aws_vpc.this.id
}

output "main_app_nlb_dns_name" {
  value = aws_lb.app_nlb.dns_name
}

output "dynamodb_table_name" {
  description = "생성된 DynamoDB Global Table 이름"
  value       = aws_dynamodb_table.global_table.name
}