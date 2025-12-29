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
# [수정] Locals: 기존 Remote State 제거 및 4개 테이블 명시
############################
locals {
  project = "pldr"
  env     = "dr"
  tags = {
    Project = local.project
    Env     = local.env
    Role    = "dr"
    Region  = "ap-northeast-1"
  }
  
  # 이미지에서 확인된 4개의 테이블 리스트
  dynamodb_tables = [
    "KDT-Msp4-PLDR-venues",
    "KDT-Msp4-PLDR-schedules",
    "KDT-Msp4-PLDR-performances",
    "KDT-Msp4-PLDR-reservations"
  ]
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

################################################################################
# Security Groups (MegaTicket-DR)
################################################################################
resource "aws_security_group" "alb_sg" {
  name        = "MegaTicket-DR-ALB-SG"
  description = "ALB Security Group"
  vpc_id      = aws_vpc.this.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "MegaTicket-DR-ALB-SG" }
}

resource "aws_security_group" "web_sg" {
  name        = "MegaTicket-DR-Web-SG"
  description = "Web Instance Security Group"
  vpc_id      = aws_vpc.this.id

  ingress {
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "MegaTicket-DR-Web-SG" }
}

resource "aws_security_group" "app_sg" {
  name        = "MegaTicket-DR-App-SG"
  description = "App Instance Security Group"
  vpc_id      = aws_vpc.this.id

  ingress {
    from_port       = 3001
    to_port         = 3001
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id, aws_security_group.web_sg.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "MegaTicket-DR-App-SG" }
}

############################
# VPC Endpoints (No NAT 필수 요소)
############################

# 1. DynamoDB Gateway Endpoint (재설정)
# 이 Endpoint는 VPC 내에서 DynamoDB 서비스로 가는 경로를 열어줍니다.
# 특정 테이블만 허용하려면 Policy를 추가해야 하지만, 기본적으로 Full Access로 설정합니다.
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.ap-northeast-1.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id] # Private 서브넷 라우팅 테이블에 연결
  tags              = local.tags
}

# 2. SSM Interface Endpoints
resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.ap-northeast-1.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.alb_sg.id]
  private_dns_enabled = true
  tags                = local.tags
}

resource "aws_vpc_endpoint" "ssmmessages" {
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.ap-northeast-1.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.alb_sg.id]
  private_dns_enabled = true
  tags                = local.tags
}

resource "aws_vpc_endpoint" "ec2messages" {
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.ap-northeast-1.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.alb_sg.id]
  private_dns_enabled = true
  tags                = local.tags
}

############################
# IAM (4개 테이블 권한 추가)
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

# [수정] 4개 테이블에 대한 모든 권한 부여
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
        # KDT-Msp4-PLDR- 로 시작하는 모든 테이블 허용 (4개 포함)
        Resource = [
          "arn:aws:dynamodb:*:*:table/KDT-Msp4-PLDR-venues",
          "arn:aws:dynamodb:*:*:table/KDT-Msp4-PLDR-schedules",
          "arn:aws:dynamodb:*:*:table/KDT-Msp4-PLDR-performances",
          "arn:aws:dynamodb:*:*:table/KDT-Msp4-PLDR-reservations",
          "arn:aws:dynamodb:*:*:table/KDT-Msp4-PLDR-*" 
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
############################
resource "aws_lb" "alb" {
  name               = "pldr-dr-alb"
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = aws_subnet.public[*].id
  tags               = local.tags
}

resource "aws_lb_target_group" "web" {
  name     = "pldr-dr-web-tg"
  port     = 3000
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

resource "aws_lb_target_group" "app" {
  name        = "pldr-dr-app-tg"
  port        = 3001
  protocol    = "TCP"
  vpc_id      = aws_vpc.this.id
  target_type = "instance"
  health_check {
    protocol = "HTTP"
    path     = "/"
    port     = "3001"
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

############################
# AMI & Launch Templates
############################
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

  vpc_security_group_ids = [aws_security_group.web_sg.id]
  iam_instance_profile { name = aws_iam_instance_profile.ec2.name }
  metadata_options { http_tokens = "required" }

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

# [APP] Launch Template (DR) - 수정됨
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

  vpc_security_group_ids = [aws_security_group.app_sg.id]
  iam_instance_profile { name = aws_iam_instance_profile.ec2.name }
  metadata_options { http_tokens = "required" }

  user_data = base64encode(<<-EOF
            #!/bin/bash
            set -e
            
            # SSM Agent 실행
            systemctl start amazon-ssm-agent
            
            # app.py 덮어쓰기 (Test with Reservations Table)
            cat > /app.py <<'APP'
            from flask import Flask, jsonify, request
            import boto3
            import uuid
            import os
            from datetime import datetime

            app = Flask(__name__)
            REGION = 'ap-northeast-1'
            
            # [수정] 4개 테이블 중 테스트할 테이블 지정 (예: Reservations)
            TABLE_NAME = 'KDT-Msp4-PLDR-reservations'

            dynamodb = boto3.resource('dynamodb', region_name=REGION)
            table = dynamodb.Table(TABLE_NAME)

            @app.route("/")
            def health():
                return "OK (DR tokyo - Tables Connected)"

            @app.route("/submit", methods=["POST"])
            def submit_data():
                try:
                    data = request.json
                    # Reservations 테이블 스키마에 맞춘 예시 (PK, SK)
                    name = data.get("name")
                    message = data.get("message")

                    if not name or not message:
                        return jsonify({"error": "Missing data"}), 400

                    unique_id = str(uuid.uuid4())
                    timestamp = datetime.utcnow().isoformat() + 'Z'

                    item = {
                        'PK': 'RES#' + unique_id,
                        'SK': 'INFO',
                        'name': name,
                        'message': message,
                        'timestamp': timestamp,
                        'source_region': REGION
                    }
                    table.put_item(Item=item)
                    return jsonify({
                        "success": True, 
                        "message": "Saved to Reservations Table (DR)",
                        "id": unique_id
                    }), 200

                except Exception as e:
                    return jsonify({"error": str(e)}), 500

            if __name__ == "__main__":
                app.run(host="0.0.0.0", port=3001)
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
# Outputs
############################
output "dr_alb_dns_name" {
  value = aws_lb.alb.dns_name
}

output "dr_app_target_group_arn" {
  value = aws_lb_target_group.app.arn
}

output "dr_route53_zone_id" {
  value = aws_route53_zone.private.zone_id
}

output "dynamodb_tables_info" {
  description = "Connected DynamoDB Tables"
  value       = local.dynamodb_tables
}