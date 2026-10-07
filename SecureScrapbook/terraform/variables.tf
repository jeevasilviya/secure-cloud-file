variable "aws_region" {
  description = "AWS deployment region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "instance_type" {
  description = "EC2 instance size for Ubuntu Node.js API (AWS Free Tier eligible: t3.micro)"
  type        = string
  default     = "t3.micro"
}

variable "db_username" {
  description = "Master username for PostgreSQL database"
  type        = string
  default     = "securescrapbook_admin"
}

variable "db_password" {
  description = "Master password for PostgreSQL database"
  type        = string
  default     = "SecureScrapbook2026!PGBase"
  sensitive   = true
}

variable "vercel_ip_ranges" {
  description = "Vercel edge IP ranges permitted for inbound port 443 HTTPS traffic"
  type        = list(string)
  default = [
    "76.76.21.0/24",
    "76.76.22.0/24",
    "216.198.79.0/24"
  ]
}

variable "security_admin_email" {
  description = "Email address to receive high-priority CloudWatch security violation alarms"
  type        = string
  default     = "security-ops@securescrapbook.internal"
}
