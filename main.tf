#########################
# main.tf
#########################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # 🔐 나중에 S3 backend 쓰고 싶으면 여기에 backend "s3" {} 추가
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "3tier/network.tfstate"
  #   region         = "ap-northeast-2"
  #   encrypt        = true
  #   dynamodb_table = "terraform-lock"
  # }
}

provider "aws" {
  region = var.aws_region
}

#########################
# VPC
#########################

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "3tier-vpc"
  }
}

#########################
# Internet Gateway
#########################

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "3tier-igw"
  }
}

#########################
# Subnets
#########################

# index 헬퍼
locals {
  az_count = length(var.azs)
}

# Public Subnets (ALB, NAT GW 등)
resource "aws_subnet" "public" {
  for_each = {
    for idx, cidr in var.public_subnet_cidrs :
    idx => {
      cidr = cidr
      az   = var.azs[idx]
    }
  }

  vpc_id                  = aws_vpc.this.id
  cidr_block              = each.value.cidr
  availability_zone       = each.value.az
  map_public_ip_on_launch = true

  tags = {
    Name = "3tier-public-${each.value.az}"
    Tier = "public"
  }
}

# Private App Subnets (ECS/EC2 App 서버)
resource "aws_subnet" "private_app" {
  for_each = {
    for idx, cidr in var.private_app_subnet_cidrs :
    idx => {
      cidr = cidr
      az   = var.azs[idx]
    }
  }

  vpc_id            = aws_vpc.this.id
  cidr_block        = each.value.cidr
  availability_zone = each.value.az

  tags = {
    Name = "3tier-private-app-${each.value.az}"
    Tier = "app"
  }
}

# Private DB Subnets (RDS용)
resource "aws_subnet" "private_db" {
  for_each = {
    for idx, cidr in var.private_db_subnet_cidrs :
    idx => {
      cidr = cidr
      az   = var.azs[idx]
    }
  }

  vpc_id            = aws_vpc.this.id
  cidr_block        = each.value.cidr
  availability_zone = each.value.az

  tags = {
    Name = "3tier-private-db-${each.value.az}"
    Tier = "db"
  }
}

#########################
# NAT Gateway (1개, 첫 번째 Public Subnet에)
#########################

# NAT용 EIP
resource "aws_eip" "nat" {
  vpc = true

  tags = {
    Name = "3tier-nat-eip"
  }
}

resource "aws_nat_gateway" "this" {
  allocation_id = aws_eip.nat.id

  # 첫 번째 public subnet에 NAT GW 생성
  subnet_id = aws_subnet.public["0"].id

  tags = {
    Name = "3tier-nat-gw"
  }

  depends_on = [aws_internet_gateway.this]
}

#########################
# Route Tables
#########################

# Public Route Table (0.0.0.0/0 -> IGW)
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = {
    Name = "3tier-public-rt"
  }
}

# Public Route Table Association
resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

# Private App Route Table (0.0.0.0/0 -> NAT GW)
resource "aws_route_table" "private_app" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.this.id
  }

  tags = {
    Name = "3tier-private-app-rt"
  }
}

resource "aws_route_table_association" "private_app" {
  for_each       = aws_subnet.private_app
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private_app.id
}

# Private DB Route Table
# - 일반적으로 DB도 패치/백업 등을 위해 NAT을 타고 나가게 함
# - 완전 고립시키고 싶으면 0.0.0.0/0 route 제거하면 됨
resource "aws_route_table" "private_db" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.this.id
  }

  tags = {
    Name = "3tier-private-db-rt"
  }
}

resource "aws_route_table_association" "private_db" {
  for_each       = aws_subnet.private_db
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private_db.id
}

#########################
# Security Groups (Skeleton)
#########################

# ALB용 SG: 80/443 외부에서 허용
resource "aws_security_group" "alb" {
  name        = "3tier-alb-sg"
  description = "Security group for ALB"
  vpc_id      = aws_vpc.this.id

  # HTTP
  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTPS
  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "3tier-alb-sg"
  }
}

# App 서버(ECS/EC2)용 SG: ALB에서만 접근 허용
resource "aws_security_group" "app" {
  name        = "3tier-app-sg"
  description = "Security group for App tier (ECS/EC2)"
  vpc_id      = aws_vpc.this.id

  # ALB에서 들어오는 HTTP만 허용 (포트는 나중에 변경 가능)
  ingress {
    description     = "HTTP from ALB"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "3tier-app-sg"
  }
}

# DB용 SG: App SG에서만 DB 포트 접근 허용
resource "aws_security_group" "db" {
  name        = "3tier-db-sg"
  description = "Security group for DB tier (RDS)"
  vpc_id      = aws_vpc.this.id

  ingress {
    description     = "DB access from App SG"
    from_port       = 3306 # MySQL 기준, PostgreSQL이면 5432로 변경
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "3tier-db-sg"
  }
}
