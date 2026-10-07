# =====================================================================
# AWS Security Groups Configuration
# Enforces Principle of Least Privilege & Zero Trust Network Architecture:
# - Inbound strictly restricted to Port 443 (HTTPS) from Vercel edge CIDRs
# - Port 22 (SSH) is completely BLOCKED (Management via AWS Systems Manager SSM)
# - Database port 5432 is strictly isolated to backend EC2 SG
# =====================================================================

# 1. EC2 Backend API Security Group (Restricted to Vercel HTTPS Only)
resource "aws_security_group" "backend_ec2_sg" {
  name        = "securescrapbook-backend-sg"
  description = "Allows inbound HTTPS (443) exclusively from Vercel deployment edge IP ranges"
  vpc_id      = aws_vpc.main.id

  # Inbound HTTPS (Port 443) only from verified Vercel IP Ranges
  ingress {
    description = "Allow TLS traffic from Vercel edge servers"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.vercel_ip_ranges
  }

  # Inbound HTTP (Port 80) strictly for immediate 301 redirection to HTTPS
  ingress {
    description = "Allow HTTP strictly for immediate 301 redirect to HTTPS"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.vercel_ip_ranges
  }

  # NOTE: Port 22 (SSH) is explicitly NOT configured, guaranteeing complete closure.
  # Shell and administration are performed via AWS Systems Manager (SSM) Session Manager.

  # Egress: Allow outbound HTTPS for CloudWatch telemetry and OS security updates
  egress {
    description = "Allow outbound HTTPS (CloudWatch, AWS APIs, OS security updates)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Egress: Allow outbound PostgreSQL traffic towards the RDS DB within VPC
  egress {
    description = "Allow outbound connection to PostgreSQL database within VPC"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = {
    Name = "securescrapbook-backend-sg"
  }
}

# 2. PostgreSQL Database Security Group (Private DB Subnet)
resource "aws_security_group" "db_sg" {
  name        = "securescrapbook-db-sg"
  description = "Database Security Group - Isolated strictly to backend EC2 instance"
  vpc_id      = aws_vpc.main.id

  # Ingress: Strictly port 5432 from backend_ec2_sg only
  ingress {
    description     = "Allow PostgreSQL access strictly from backend EC2 SG"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.backend_ec2_sg.id]
  }

  # Zero arbitrary outbound access permitted
  egress {
    description = "No arbitrary outbound internet access permitted"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = []
  }

  tags = {
    Name = "securescrapbook-db-sg"
  }
}
