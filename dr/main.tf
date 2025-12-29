############################
# DR Region: tokyo (ap-northeast-1)
# 전략: Pilot Light (ASG Capacity 0)
# 특징: No NAT, No S3 Endpoint, No NLB (Lambda 생성 예정)
############################

terraform {
  required_version = ">= 1.5.0"

  backend "s3" {
    bucket         = "pldr-tfstate-ap-northeast-1"  
    key            = "dev/dr/terraform.tfstate"   
    region         = "ap-northeast-1"             
    dynamodb_table = "pldr-terraform-lock-ap-northeast-1" 
    encrypt        = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-northeast-1"
}

############################
# Remote State (서울 리전 정보 가져오기)
############################
data "terraform_remote_state" "main" {
  backend = "s3"
  config = {
    bucket = "pldr-tfstate-ap-northeast-2"
    key    = "dev/main/ap-northeast-2/terraform.tfstate"
    region = "ap-northeast-2"
  }
}

locals {
  project = "pldr"
  env     = "dr"
  tags = {
    Project = local.project
    Env     = local.env
    Role    = "dr"
    Region  = "ap-northeast-1"
  }
  
  global_table_name = data.terraform_remote_state.main.outputs.dynamodb_table_name
}

data "aws_availability_zones" "available" {
  state = "available"
}

############################
# VPC (No NAT Gateway)
############################
resource "aws_vpc" "this" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = merge(local.tags, { Name = "pldr-dr-vpc" })
}

# Public Subnet (ALB용)
resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet("10.20.0.0/16", 4, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  tags = merge(local.tags, { Name = "pldr-dr-public-${count.index}" })
}

# Private Subnet (Web/App용 - 완전 폐쇄망)
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet("10.20.0.0/16", 4, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags = merge(local.tags, { Name = "pldr-dr-private-${count.index}" })
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.this.id
  tags   = local.tags
}

# [삭제됨] NAT Gateway & S3 Endpoint (사용자 요청에 따라 제거)

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
  # Route 없음 (완전 폐쇄망)
  tags = local.tags
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

############################
# VPC Endpoints (No NAT 필수 요소)
############################

# 1. DynamoDB Gateway Endpoint (앱이 DB 접속하려면 필수)
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.ap-northeast-1.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  tags              = local.tags
}

# 2. SSM Interface Endpoints (Agent가 설치돼 있어도 통신하려면 필수)
resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.ap-northeast-1.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.ssm_endpoint.id]
  private_dns_enabled = true
  tags                = local.tags
}
resource "aws_vpc_endpoint" "ssmmessages" {
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.ap-northeast-1.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.ssm_endpoint.id]
  private_dns_enabled = true
  tags                = local.tags
}
resource "aws_vpc_endpoint" "ec2messages" {
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.ap-northeast-1.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.ssm_endpoint.id]
  private_dns_enabled = true
  tags                = local.tags
}

############################
# Security Groups
############################
resource "aws_security_group" "alb" {
  name   = "pldr-dr-alb-sg"
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
  name   = "pldr-dr-web-sg"
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
  name   = "pldr-dr-app-sg"
  vpc_id = aws_vpc.this.id
  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }
  # NLB Health Check (나중에 생성될 NLB를 위해 열어둠)
  ingress {
    from_port   = 8080
    to_port     = 8080
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

resource "aws_security_group" "ssm_endpoint" {
  name   = "pldr-dr-ssm-endpoint-sg"
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

############################
# IAM
############################
resource "aws_iam_role" "ec2" {
  name = "pldr-dr-ec2-role"
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

resource "aws_iam_role_policy" "dynamodb_access" {
  name = "pldr-dr-dynamodb-policy"
  role = aws_iam_role.ec2.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:UpdateItem",
          "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"
        ]
        Resource = [
          "arn:aws:dynamodb:*:*:table/${local.global_table_name}",
          "arn:aws:dynamodb:*:*:table/${local.global_table_name}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2" {
  role = aws_iam_role.ec2.name
}

############################
# Load Balancers (Web ALB Only)
# [참고] App NLB는 제거됨 (Lambda가 생성)
############################
resource "aws_lb" "alb" {
  name               = "pldr-dr-alb"
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id
  tags               = local.tags
}

resource "aws_lb_target_group" "web" {
  name     = "pldr-dr-web-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.this.id
  health_check { path = "/" }
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

# [중요] NLB 리소스는 삭제되었으나, Target Group은 미리 생성해 둠
# 복구 시 Lambda가 새 NLB를 만들고 이 Target Group을 연결하면 됨
resource "aws_lb_target_group" "app" {
  name        = "pldr-dr-app-tg"
  port        = 8080
  protocol    = "TCP"
  vpc_id      = aws_vpc.this.id
  target_type = "instance"
  health_check {
    protocol = "HTTP"
    path     = "/"
    port     = "8080"
  }
  tags = local.tags
}

############################
# Route 53 Private Hosted Zone
############################
resource "aws_route53_zone" "private" {
  name = "internal.pldr"
  vpc {
    vpc_id = aws_vpc.this.id
  }
  tags = local.tags
}

# [주의] NLB 리소스가 없으므로 'aws_route53_record'는 여기서 생성 불가
# 복구 시 Lambda가 NLB를 생성한 후, 아래와 같은 레코드도 같이 생성해야 함
#
# resource "aws_route53_record" "app_nlb" {
#   zone_id = aws_route53_zone.private.zone_id
#   name    = "app.internal.pldr"
#   type    = "A"
#   alias { ... NLB DNS Name ... }
# }

############################
# AMI & Launch Templates
############################
# Placeholder (Lambda가 AWS Backup AMI ID로 교체 예정)
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-minimal-2023*-x86_64"]
  }
}

# [WEB] Launch Template (DR)
resource "aws_launch_template" "web" {
  name_prefix   = "pldr-dr-web-lt-"
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
  iam_instance_profile { name = aws_iam_instance_profile.ec2.name }
  metadata_options { http_tokens = "required" }

  # [가정] Main AMI에 Nginx 설치됨. 실행만 보장.
  user_data = base64encode(<<-EOF
              #!/bin/bash
              systemctl enable nginx
              systemctl restart nginx
              EOF
  )
  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.tags, { Name = "pldr-dr-web-asg" })
  }
}

# [APP] Launch Template (DR)
resource "aws_launch_template" "app" {
  name_prefix   = "pldr-dr-app-lt-"
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
  iam_instance_profile { name = aws_iam_instance_profile.ec2.name }
  metadata_options { http_tokens = "required" }

  # [가정] Main AMI에 패키지 설치됨. 파일 교체만 수행 (No Network)
  user_data = base64encode(<<-EOF
            #!/bin/bash
            set -e
            
            # SSM Agent 실행 (AMI 내장 가정)
            systemctl start amazon-ssm-agent
            
            # app.py 덮어쓰기 (Main 리전 정보를 DR 리전 정보로 교체 - 로컬작업)
            cat > /app.py <<'APP'
            from flask import Flask, jsonify, request
            import boto3
            import uuid
            import os
            from datetime import datetime

            app = Flask(__name__)

            # DR Region 설정
            REGION = 'ap-northeast-1'
            
            # Table 이름은 Remote State 값 사용
            TABLE_NAME = '${local.global_table_name}'

            dynamodb = boto3.resource('dynamodb', region_name=REGION)
            table = dynamodb.Table(TABLE_NAME)

            @app.route("/")
            def health():
                return "OK (DR tokyo)"

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
                    return jsonify({"success": True, "message": "Saved to Global Table (DR)", "submitted_name": name}), 200
                except Exception as e:
                    return jsonify({"error": str(e)}), 500

            if __name__ == "__main__":
                app.run(host="0.0.0.0", port=8080)
            APP

            # 서비스 재시작
            systemctl daemon-reload
            systemctl restart pldr-app
            EOF
  )
  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.tags, { Name = "pldr-dr-app-asg" })
  }
}

############################
# Auto Scaling Groups (Capacity = 0)
############################
resource "aws_autoscaling_group" "web" {
  name                = "pldr-dr-web-asg"
  vpc_zone_identifier = aws_subnet.private[*].id
  target_group_arns   = [aws_lb_target_group.web.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300
  
  desired_capacity    = 0
  min_size            = 0
  max_size            = 4

  launch_template {
    id      = aws_launch_template.web.id
    version = "$Latest"
  }
  tag {
    key                 = "Name"
    value               = "pldr-dr-web-asg"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group" "app" {
  name                = "pldr-dr-app-asg"
  vpc_zone_identifier = aws_subnet.private[*].id
  target_group_arns   = [aws_lb_target_group.app.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300

  desired_capacity    = 0
  min_size            = 0
  max_size            = 4

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }
  tag {
    key                 = "Name"
    value               = "pldr-dr-app-asg"
    propagate_at_launch = true
  }
}

############################
# Outputs
############################
output "dr_alb_dns_name" {
  value = aws_lb.alb.dns_name
}
output "dr_launch_template_web_id" {
  value = aws_launch_template.web.id
}
output "dr_launch_template_app_id" {
  value = aws_launch_template.app.id
}
output "dr_web_asg_name" {
  value = aws_autoscaling_group.web.name
}
output "dr_app_asg_name" {
  value = aws_autoscaling_group.app.name
}
# [추가] Lambda가 사용할 Target Group ARN
output "dr_app_target_group_arn" {
  value = aws_lb_target_group.app.arn
}
# [추가] Lambda가 레코드 생성 시 사용할 Zone ID
output "dr_route53_zone_id" {
  value = aws_route53_zone.private.zone_id
}