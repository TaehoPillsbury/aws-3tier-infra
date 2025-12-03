#########################
# outputs.tf
#########################

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.this.id
}

output "public_subnet_ids" {
  description = "IDs of public subnets"
  value       = [for s in aws_subnet.public : s.id]
}

output "private_app_subnet_ids" {
  description = "IDs of private app subnets"
  value       = [for s in aws_subnet.private_app : s.id]
}

output "private_db_subnet_ids" {
  description = "IDs of private db subnets"
  value       = [for s in aws_subnet.private_db : s.id]
}

output "alb_sg_id" {
  description = "Security group ID for ALB"
  value       = aws_security_group.alb.id
}

output "app_sg_id" {
  description = "Security group ID for App tier"
  value       = aws_security_group.app.id
}

output "db_sg_id" {
  description = "Security group ID for DB tier"
  value       = aws_security_group.db.id
}
