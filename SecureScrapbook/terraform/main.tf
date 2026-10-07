terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Application = "SecureScrapbook"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Security    = "High-Compliance"
    }
  }
}

# =====================================================================
# AWS VPC NETWORK TOPOLOGY
# =====================================================================
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "securescrapbook-vpc"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "securescrapbook-igw"
  }
}

# Public Subnets (For EC2 Backend with Elastic IP)
resource "aws_subnet" "public_1" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, 0)
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false

  tags = {
    Name = "securescrapbook-public-1a"
  }
}

resource "aws_subnet" "public_2" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, 1)
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = false

  tags = {
    Name = "securescrapbook-public-1b"
  }
}

# Private Database Subnets (For RDS PostgreSQL - Isolated from Internet)
resource "aws_subnet" "private_db_1" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, 4)
  availability_zone = "${var.aws_region}a"

  tags = {
    Name = "securescrapbook-private-db-1a"
  }
}

resource "aws_subnet" "private_db_2" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, 5)
  availability_zone = "${var.aws_region}b"

  tags = {
    Name = "securescrapbook-private-db-1b"
  }
}

# Routing tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "securescrapbook-public-rt"
  }
}

resource "aws_route_table_association" "pub_1" {
  subnet_id      = aws_subnet.public_1.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "pub_2" {
  subnet_id      = aws_subnet.public_2.id
  route_table_id = aws_route_table.public.id
}

# =====================================================================
# IAM ROLE & INSTANCE PROFILE (Zero SSH, SSM Only)
# =====================================================================
resource "aws_iam_role" "ec2_backend_role" {
  name = "securescrapbook-ec2-backend-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
      }
    ]
  })
}

# Attach AWS Systems Manager (SSM) Policy - Allows secure terminal access without port 22
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ec2_backend_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# CloudWatch Logs & Metrics Permissions
resource "aws_iam_policy" "cloudwatch_logging" {
  name        = "securescrapbook-cloudwatch-logging"
  description = "Allows SecureScrapbook API to write structured audit logs to CloudWatch"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:*:*:log-group:/aws/securescrapbook/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cw_logging_attach" {
  role       = aws_iam_role.ec2_backend_role.name
  policy_arn = aws_iam_policy.cloudwatch_logging.arn
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "securescrapbook-ec2-profile"
  role = aws_iam_role.ec2_backend_role.name
}

# =====================================================================
# UBUNTU EC2 INSTANCE (API HOST)
# =====================================================================
data "aws_ami" "ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  owners = ["099720109477"] # Canonical
}

resource "aws_instance" "backend_api" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = var.instance_type
  subnet_id            = aws_subnet.public_1.id
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  vpc_security_group_ids = [
    aws_security_group.backend_ec2_sg.id
  ]

  root_block_device {
    volume_size           = 20 # 20 GB gp3 (AWS Free Tier provides up to 30 GB EBS)
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 strictly enforced (Mitigates SSRF credential theft)
    http_put_response_hop_limit = 1
  }

  user_data = <<-EOF
              #!/bin/bash
              set -e
              apt-get update -y
              apt-get install -y nodejs npm postgresql-client amazon-cloudwatch-agent
              mkdir -p /opt/securescrapbook
              # Ready for application code pull
              EOF

  tags = {
    Name = "securescrapbook-api-vm"
  }
}

# Elastic IP for public HTTPS endpoint
resource "aws_eip" "backend_eip" {
  instance = aws_instance.backend_api.id
  domain   = "vpc"

  tags = {
    Name = "securescrapbook-backend-eip"
  }
}

# =====================================================================
# MANAGED POSTGRESQL (AWS RDS) - AWS Free Tier (db.t3.micro, 20GB)
# =====================================================================
resource "aws_db_subnet_group" "db_subnets" {
  name       = "securescrapbook-db-subnets"
  subnet_ids = [aws_subnet.private_db_1.id, aws_subnet.private_db_2.id]

  tags = {
    Name = "securescrapbook-db-subnets"
  }
}

resource "aws_db_instance" "postgres" {
  identifier             = "securescrapbook-db"
  engine                 = "postgres"
  engine_version         = "16.3"
  instance_class         = "db.t3.micro" # AWS Free Tier eligible
  allocated_storage      = 20            # AWS Free Tier provides 20 GB storage
  max_allocated_storage  = 20            # Prevent scaling beyond Free Tier limit
  storage_type           = "gp3"
  storage_encrypted      = true

  db_name  = "securescrapbook"
  username = var.db_username
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.db_subnets.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]

  publicly_accessible = false
  skip_final_snapshot = true
  deletion_protection = false

  tags = {
    Name = "securescrapbook-postgres"
  }
}
