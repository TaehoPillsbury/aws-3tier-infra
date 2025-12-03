#########################
# variables.tf
#########################

# 사용할 AWS 리전
variable "aws_region" {
  description = "AWS region to deploy 3-tier VPC"
  type        = string
  default     = "ap-northeast-2"
}

# VPC CIDR
variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

# 사용할 AZ 목록 (2개 AZ 기준)
variable "azs" {
  description = "List of availability zones to use"
  type        = list(string)
  default     = ["ap-northeast-2a", "ap-northeast-2c"]
}

# 퍼블릭 서브넷 CIDR (ALB, NAT GW 등)
variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets (one per AZ)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

# 프라이빗 App 서브넷 CIDR (ECS/EC2 App 서버용)
variable "private_app_subnet_cidrs" {
  description = "CIDR blocks for private app subnets (one per AZ)"
  type        = list(string)
  default     = ["10.0.11.0/24", "10.0.12.0/24"]
}

# 프라이빗 DB 서브넷 CIDR (RDS용)
variable "private_db_subnet_cidrs" {
  description = "CIDR blocks for private db subnets (one per AZ)"
  type        = list(string)
  default     = ["10.0.21.0/24", "10.0.22.0/24"]
}
