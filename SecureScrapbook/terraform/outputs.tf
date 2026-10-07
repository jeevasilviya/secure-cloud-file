output "vpc_id" {
  description = "VPC identifier"
  value       = aws_vpc.main.id
}

output "backend_public_ip" {
  description = "Public IP address of the EC2 API Elastic IP (Whitelisted for Vercel on 443)"
  value       = aws_eip.backend_eip.public_ip
}

output "backend_public_dns" {
  description = "Public DNS hostname of the EC2 instance"
  value       = aws_instance.backend_api.public_dns
}

output "backend_api_url" {
  description = "HTTPS endpoint URL for Vercel environment configuration"
  value       = "https://${aws_eip.backend_eip.public_ip}"
}

output "rds_postgres_endpoint" {
  description = "PostgreSQL RDS database connection endpoint"
  value       = aws_db_instance.postgres.endpoint
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group for security audit events"
  value       = aws_cloudwatch_log_group.securescrapbook_audit_logs.name
}

output "sns_alert_topic_arn" {
  description = "SNS topic ARN for security alarms"
  value       = aws_sns_topic.security_alerts.arn
}
