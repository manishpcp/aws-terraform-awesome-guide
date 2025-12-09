# \#\#\# **Chapter 5: Core AWS Services with Terraform**

- Networking: VPC, subnets, route tables, internet gateways, NAT gateways
- Compute: EC2 instances, Auto Scaling Groups, Launch Templates
- Storage: S3 buckets, EBS volumes, EFS file systems
- Database: RDS, DynamoDB, ElastiCache
- Security: Security Groups, NACLs, IAM roles and policies
- Global services: CloudFront, Route 53, IAM (region exclusions)

I'll create a comprehensive Chapter 5 on Core AWS Services with Terraform. This will be production-ready with extensive code examples covering networking, compute, storage, databases, security, and global services.

***

# Chapter 5: Core AWS Services with Terraform

## Introduction

Mastering core AWS services through Terraform transforms you from someone who can describe infrastructure to someone who can build production-grade cloud architectures with code. While understanding individual AWS services is valuable, knowing how to orchestrate VPCs, compute instances, databases, and security controls through declarative configuration creates repeatable, version-controlled infrastructure that scales from startup prototypes to enterprise production systems. This chapter bridges the gap between Terraform fundamentals and real-world AWS deployments.

You'll learn to build complete network architectures with proper subnet segmentation, routing configurations, and internet connectivity patterns that follow AWS best practices. Beyond basic resource creation, you'll understand the relationships between services—how security groups control EC2 traffic, how route tables direct network flows, how IAM roles grant least-privilege permissions, and how Auto Scaling Groups maintain application availability. These aren't isolated concepts but interconnected components that work together to create robust infrastructure.

By the end of this chapter, you'll have production-ready code for multi-tier VPC architectures with public and private subnets, Auto Scaling Groups with Launch Templates for compute elasticity, RDS databases with proper backup configurations, S3 buckets with encryption and versioning, and comprehensive security controls. You'll understand when to use managed services versus self-managed solutions, how to implement high availability patterns, and how to structure Terraform configurations for maintainability. This knowledge enables you to architect complete AWS environments that are secure, scalable, and cost-effective from day one.

## AWS Networking with Terraform

### Building a Production VPC

A well-designed VPC is the foundation of AWS infrastructure, providing network isolation, security boundaries, and connectivity patterns.

**Complete VPC Architecture:**

```hcl
# networking/versions.tf
terraform {
  required_version = ">= 1.15.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# networking/variables.tf
variable "aws_region" {
  description = "AWS region for VPC deployment"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
  
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "Must be valid IPv4 CIDR block."
  }
}

variable "availability_zones" {
  description = "Availability zones for subnet distribution"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.11.0/24", "10.0.12.0/24", "10.0.13.0/24"]
}

variable "database_subnet_cidrs" {
  description = "CIDR blocks for database subnets"
  type        = list(string)
  default     = ["10.0.21.0/24", "10.0.22.0/24", "10.0.23.0/24"]
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
  
  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be development, staging, or production."
  }
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for private subnet internet access"
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Use single NAT Gateway (cost savings for non-prod)"
  type        = bool
  default     = false
}

variable "enable_vpn_gateway" {
  description = "Enable VPN Gateway for hybrid connectivity"
  type        = bool
  default     = false
}

variable "enable_dns_hostnames" {
  description = "Enable DNS hostnames in VPC"
  type        = bool
  default     = true
}

variable "enable_dns_support" {
  description = "Enable DNS support in VPC"
  type        = bool
  default     = true
}

# networking/locals.tf
locals {
  common_tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
    Project     = "CoreInfrastructure"
    CostCenter  = "Engineering"
  }
  
  # Calculate number of availability zones
  az_count = length(var.availability_zones)
  
  # Validate subnet counts match AZs
  subnet_count_valid = (
    length(var.public_subnet_cidrs) == local.az_count &&
    length(var.private_subnet_cidrs) == local.az_count &&
    length(var.database_subnet_cidrs) == local.az_count
  )
}

# networking/main.tf
# VPC Resource
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = var.enable_dns_hostnames
  enable_dns_support   = var.enable_dns_support
  
  # Enable VPC Flow Logs for network monitoring
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-vpc"
      Type = "NetworkFoundation"
    }
  )
}

# Internet Gateway for public subnet internet access
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-igw"
    }
  )
}

# Public Subnets - Resources with direct internet access
resource "aws_subnet" "public" {
  count = local.az_count
  
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true  # Auto-assign public IPs
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-public-subnet-${var.availability_zones[count.index]}"
      Type = "Public"
      Tier = "Web"
    }
  )
}

# Private Subnets - Resources without direct internet access
resource "aws_subnet" "private" {
  count = local.az_count
  
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.private_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-private-subnet-${var.availability_zones[count.index]}"
      Type = "Private"
      Tier = "Application"
    }
  )
}

# Database Subnets - Isolated database tier
resource "aws_subnet" "database" {
  count = local.az_count
  
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.database_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-database-subnet-${var.availability_zones[count.index]}"
      Type = "Private"
      Tier = "Database"
    }
  )
}

# Elastic IPs for NAT Gateways
resource "aws_eip" "nat" {
  count = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : local.az_count) : 0
  
  domain = "vpc"
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-nat-eip-${count.index + 1}"
    }
  )
  
  depends_on = [aws_internet_gateway.main]
}

# NAT Gateways for private subnet internet access
resource "aws_nat_gateway" "main" {
  count = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : local.az_count) : 0
  
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-nat-gateway-${count.index + 1}"
    }
  )
  
  depends_on = [aws_internet_gateway.main]
}

# Public Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-public-rt"
      Type = "Public"
    }
  )
}

# Public Route to Internet Gateway
resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

# Associate Public Subnets with Public Route Table
resource "aws_route_table_association" "public" {
  count = local.az_count
  
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Private Route Tables (one per AZ for high availability)
resource "aws_route_table" "private" {
  count = local.az_count
  
  vpc_id = aws_vpc.main.id
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-private-rt-${var.availability_zones[count.index]}"
      Type = "Private"
    }
  )
}

# Private Routes to NAT Gateway
resource "aws_route" "private_nat" {
  count = var.enable_nat_gateway ? local.az_count : 0
  
  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = var.single_nat_gateway ? aws_nat_gateway.main[^0].id : aws_nat_gateway.main[count.index].id
}

# Associate Private Subnets with Private Route Tables
resource "aws_route_table_association" "private" {
  count = local.az_count
  
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Database Route Table (no internet access)
resource "aws_route_table" "database" {
  vpc_id = aws_vpc.main.id
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-database-rt"
      Type = "Database"
    }
  )
}

# Associate Database Subnets with Database Route Table
resource "aws_route_table_association" "database" {
  count = local.az_count
  
  subnet_id      = aws_subnet.database[count.index].id
  route_table_id = aws_route_table.database.id
}

# VPC Flow Logs for network monitoring
resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-vpc-flow-logs"
    }
  )
}

# CloudWatch Log Group for Flow Logs
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/${var.environment}-flow-logs"
  retention_in_days = 30
  
  tags = local.common_tags
}

# IAM Role for Flow Logs
resource "aws_iam_role" "flow_logs" {
  name = "${var.environment}-vpc-flow-logs-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
  
  tags = local.common_tags
}

# IAM Policy for Flow Logs
resource "aws_iam_role_policy" "flow_logs" {
  name = "${var.environment}-vpc-flow-logs-policy"
  role = aws_iam_role.flow_logs.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "*"
    }]
  })
}

# VPN Gateway (optional for hybrid connectivity)
resource "aws_vpn_gateway" "main" {
  count = var.enable_vpn_gateway ? 1 : 0
  
  vpc_id = aws_vpc.main.id
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-vpn-gateway"
    }
  )
}

# networking/outputs.tf
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "IDs of public subnets"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs of private subnets"
  value       = aws_subnet.private[*].id
}

output "database_subnet_ids" {
  description = "IDs of database subnets"
  value       = aws_subnet.database[*].id
}

output "nat_gateway_ids" {
  description = "IDs of NAT Gateways"
  value       = aws_nat_gateway.main[*].id
}

output "internet_gateway_id" {
  description = "ID of Internet Gateway"
  value       = aws_internet_gateway.main.id
}

output "availability_zones" {
  description = "Availability zones used"
  value       = var.availability_zones
}
```

**VPC Architecture Patterns:**


| Pattern | Use Case | NAT Strategy | Cost | HA Level |
| :-- | :-- | :-- | :-- | :-- |
| **Single NAT** | Dev/Test | 1 NAT Gateway | Low | Medium |
| **Multi-AZ NAT** | Production | NAT per AZ | High | High |
| **No NAT** | Isolated workloads | No internet | Lowest | N/A |
| **Transit Gateway** | Multi-VPC | Centralized | Medium | High |

### Network Security with NACLs

Network ACLs provide stateless subnet-level security:

```hcl
# network-acls.tf

# Public Subnet NACL
resource "aws_network_acl" "public" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.public[*].id
  
  # Inbound Rules
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 80
    to_port    = 80
  }
  
  ingress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }
  
  ingress {
    protocol   = "tcp"
    rule_no    = 120
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535  # Ephemeral ports for return traffic
  }
  
  # Outbound Rules
  egress {
    protocol   = "-1"  # All protocols
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-public-nacl"
    }
  )
}

# Private Subnet NACL
resource "aws_network_acl" "private" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.private[*].id
  
  # Allow traffic from public subnets
  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.vpc_cidr  # Internal VPC traffic
    from_port  = 0
    to_port    = 0
  }
  
  # Allow return traffic from internet
  ingress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }
  
  # Allow all outbound
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-private-nacl"
    }
  )
}

# Database Subnet NACL (most restrictive)
resource "aws_network_acl" "database" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.database[*].id
  
  # Only allow traffic from application tier
  dynamic "ingress" {
    for_each = var.private_subnet_cidrs
    content {
      protocol   = "tcp"
      rule_no    = 100 + ingress.key
      action     = "allow"
      cidr_block = ingress.value
      from_port  = 3306  # MySQL/MariaDB
      to_port    = 3306
    }
  }
  
  dynamic "ingress" {
    for_each = var.private_subnet_cidrs
    content {
      protocol   = "tcp"
      rule_no    = 110 + ingress.key
      action     = "allow"
      cidr_block = ingress.value
      from_port  = 5432  # PostgreSQL
      to_port    = 5432
    }
  }
  
  # Deny all other inbound
  ingress {
    protocol   = "-1"
    rule_no    = 200
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  
  # Allow responses back to application tier
  dynamic "egress" {
    for_each = var.private_subnet_cidrs
    content {
      protocol   = "tcp"
      rule_no    = 100 + egress.key
      action     = "allow"
      cidr_block = egress.value
      from_port  = 1024
      to_port    = 65535
    }
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-database-nacl"
    }
  )
}
```


## EC2 Compute with Auto Scaling

### Launch Templates and Auto Scaling Groups

Modern compute deployments use Launch Templates with Auto Scaling Groups for elasticity:

```hcl
# compute/variables.tf
variable "ami_id" {
  description = "AMI ID for EC2 instances"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "min_size" {
  description = "Minimum number of instances"
  type        = number
  default     = 2
}

variable "max_size" {
  description = "Maximum number of instances"
  type        = number
  default     = 10
}

variable "desired_capacity" {
  description = "Desired number of instances"
  type        = number
  default     = 3
}

variable "health_check_grace_period" {
  description = "Time before health checks start (seconds)"
  type        = number
  default     = 300
}

# compute/data.tf
# Get latest Amazon Linux 2023 AMI
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]
  
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
  
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Get VPC data from networking module
data "terraform_remote_state" "networking" {
  backend = "s3"
  
  config = {
    bucket = "mycompany-terraform-state"
    key    = "production/networking/terraform.tfstate"
    region = var.aws_region
  }
}

# compute/main.tf
# IAM Role for EC2 Instances
resource "aws_iam_role" "ec2_instance" {
  name = "${var.environment}-ec2-instance-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
  
  tags = local.common_tags
}

# Attach SSM policy for Systems Manager access
resource "aws_iam_role_policy_attachment" "ssm_managed_instance" {
  role       = aws_iam_role.ec2_instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Attach CloudWatch agent policy
resource "aws_iam_role_policy_attachment" "cloudwatch_agent" {
  role       = aws_iam_role.ec2_instance.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Instance Profile
resource "aws_iam_instance_profile" "ec2_instance" {
  name = "${var.environment}-ec2-instance-profile"
  role = aws_iam_role.ec2_instance.name
  
  tags = local.common_tags
}

# Security Group for Web Servers
resource "aws_security_group" "web_server" {
  name_prefix = "${var.environment}-web-server-"
  description = "Security group for web servers"
  vpc_id      = data.terraform_remote_state.networking.outputs.vpc_id
  
  # Allow HTTP from ALB
  ingress {
    description     = "HTTP from ALB"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  
  # Allow HTTPS from ALB
  ingress {
    description     = "HTTPS from ALB"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  
  # Allow all outbound
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-web-server-sg"
    }
  )
  
  lifecycle {
    create_before_destroy = true
  }
}

# Launch Template
resource "aws_launch_template" "web_server" {
  name_prefix   = "${var.environment}-web-server-"
  image_id      = var.ami_id != "" ? var.ami_id : data.aws_ami.amazon_linux_2023.id
  instance_type = var.instance_type
  
  # IAM Instance Profile
  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_instance.name
  }
  
  # Network Configuration
  network_interfaces {
    associate_public_ip_address = false  # Private subnet
    security_groups             = [aws_security_group.web_server.id]
    delete_on_termination       = true
  }
  
  # Block Device Mapping
  block_device_mappings {
    device_name = "/dev/xvda"
    
    ebs {
      volume_size           = 20
      volume_type           = "gp3"
      iops                  = 3000
      throughput            = 125
      encrypted             = true
      delete_on_termination = true
    }
  }
  
  # User Data for initialization
  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    environment = var.environment
    region      = var.aws_region
  }))
  
  # Monitoring
  monitoring {
    enabled = true
  }
  
  # Metadata Options (IMDSv2)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # Enforce IMDSv2
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }
  
  # Tag Specifications
  tag_specifications {
    resource_type = "instance"
    
    tags = merge(
      local.common_tags,
      {
        Name = "${var.environment}-web-server"
      }
    )
  }
  
  tag_specifications {
    resource_type = "volume"
    
    tags = merge(
      local.common_tags,
      {
        Name = "${var.environment}-web-server-volume"
      }
    )
  }
  
  lifecycle {
    create_before_destroy = true
  }
  
  tags = local.common_tags
}

# Application Load Balancer
resource "aws_lb" "main" {
  name               = "${var.environment}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = data.terraform_remote_state.networking.outputs.public_subnet_ids
  
  enable_deletion_protection = var.environment == "production" ? true : false
  enable_http2               = true
  enable_cross_zone_load_balancing = true
  
  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    enabled = true
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-alb"
    }
  )
}

# ALB Security Group
resource "aws_security_group" "alb" {
  name_prefix = "${var.environment}-alb-"
  description = "Security group for ALB"
  vpc_id      = data.terraform_remote_state.networking.outputs.vpc_id
  
  # Allow HTTP from internet
  ingress {
    description = "HTTP from internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # Allow HTTPS from internet
  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # Allow all outbound
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-alb-sg"
    }
  )
  
  lifecycle {
    create_before_destroy = true
  }
}

# Target Group
resource "aws_lb_target_group" "main" {
  name_prefix = "web-"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = data.terraform_remote_state.networking.outputs.vpc_id
  
  # Health Check Configuration
  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    path                = "/health"
    matcher             = "200"
  }
  
  # Deregistration delay
  deregistration_delay = 30
  
  # Stickiness
  stickiness {
    type            = "lb_cookie"
    cookie_duration = 86400  # 1 day
    enabled         = true
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-web-tg"
    }
  )
  
  lifecycle {
    create_before_destroy = true
  }
}

# ALB Listener (HTTP)
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"
  
  default_action {
    type = "redirect"
    
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# ALB Listener (HTTPS) - Requires ACM certificate
resource "aws_lb_listener" "https" {
  count = var.enable_https ? 1 : 0
  
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main.arn
  }
}

# Auto Scaling Group
resource "aws_autoscaling_group" "main" {
  name_prefix         = "${var.environment}-asg-"
  vpc_zone_identifier = data.terraform_remote_state.networking.outputs.private_subnet_ids
  target_group_arns   = [aws_lb_target_group.main.arn]
  health_check_type   = "ELB"
  health_check_grace_period = var.health_check_grace_period
  
  # Capacity Configuration
  min_size         = var.min_size
  max_size         = var.max_size
  desired_capacity = var.desired_capacity
  
  # Launch Template
  launch_template {
    id      = aws_launch_template.web_server.id
    version = "$Latest"
  }
  
  # Instance Refresh for rolling updates
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
      instance_warmup        = 300
    }
  }
  
  # Termination Policies
  termination_policies = ["OldestLaunchTemplate", "OldestInstance"]
  
  # Metrics Collection
  enabled_metrics = [
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupMaxSize",
    "GroupMinSize",
    "GroupPendingInstances",
    "GroupStandbyInstances",
    "GroupTerminatingInstances",
    "GroupTotalInstances"
  ]
  
  tag {
    key                 = "Name"
    value               = "${var.environment}-web-server"
    propagate_at_launch = true
  }
  
  dynamic "tag" {
    for_each = local.common_tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }
  
  lifecycle {
    create_before_destroy = true
    ignore_changes        = [desired_capacity]
  }
}

# Target Tracking Scaling Policy - CPU
resource "aws_autoscaling_policy" "cpu_target_tracking" {
  name                   = "${var.environment}-cpu-target-tracking"
  autoscaling_group_name = aws_autoscaling_group.main.name
  policy_type            = "TargetTrackingScaling"
  
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 70.0
  }
}

# Target Tracking Scaling Policy - ALB Request Count
resource "aws_autoscaling_policy" "alb_request_count_target_tracking" {
  name                   = "${var.environment}-alb-request-count-target-tracking"
  autoscaling_group_name = aws_autoscaling_group.main.name
  policy_type            = "TargetTrackingScaling"
  
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ALBRequestCountPerTarget"
      resource_label         = "${aws_lb.main.arn_suffix}/${aws_lb_target_group.main.arn_suffix}"
    }
    target_value = 1000.0
  }
}

# S3 Bucket for ALB Logs
resource "aws_s3_bucket" "alb_logs" {
  bucket = "${var.environment}-alb-logs-${data.aws_caller_identity.current.account_id}"
  
  tags = local.common_tags
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  
  rule {
    id     = "delete-old-logs"
    status = "Enabled"
    
    expiration {
      days = 90
    }
  }
}

# compute/user_data.sh
#!/bin/bash
set -e

# Update system
dnf update -y

# Install CloudWatch agent
dnf install -y amazon-cloudwatch-agent

# Install web server
dnf install -y httpd

# Configure web server
cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Production Web Server</title>
</head>
<body>
    <h1>Environment: ${environment}</h1>
    <p>Region: ${region}</p>
    <p>Instance ID: <span id="instance-id"></span></p>
    <script>
        fetch('http://169.254.169.254/latest/meta-data/instance-id')
            .then(response => response.text())
            .then(data => document.getElementById('instance-id').textContent = data);
    </script>
</body>
</html>
EOF

# Health check endpoint
cat > /var/www/html/health << 'EOF'
OK
EOF

# Start services
systemctl start httpd
systemctl enable httpd

# Signal completion
/opt/aws/bin/cfn-signal -e $? --stack ${environment} --resource AutoScalingGroup --region ${region}
```

**Auto Scaling Strategies:**


| Strategy | Metric | Target | Use Case |
| :-- | :-- | :-- | :-- |
| **CPU-based** | Average CPU | 70% | General workloads |
| **Request Count** | Requests/target | 1000 | Web applications |
| **Network** | Network In/Out | Custom | Network-intensive |
| **Custom Metric** | CloudWatch | Variable | Application-specific |
| **Scheduled** | Time-based | Predictable | Known traffic patterns |

## AWS Storage Services

### S3 Buckets with Best Practices

```hcl
# storage/s3.tf

# Data Storage Bucket
resource "aws_s3_bucket" "data" {
  bucket = "${var.environment}-data-${data.aws_caller_identity.current.account_id}"
  
  tags = merge(
    local.common_tags,
    {
      Name        = "${var.environment}-data-bucket"
      Purpose     = "Application Data Storage"
      Compliance  = "GDPR"
    }
  )
}

# Block All Public Access (CRITICAL)
resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable Versioning
resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

# Server-Side Encryption with KMS
resource "aws_kms_key" "s3" {
  description             = "KMS key for S3 bucket encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-s3-encryption-key"
    }
  )
}

resource "aws_kms_alias" "s3" {
  name          = "alias/${var.environment}-s3-encryption"
  target_key_id = aws_kms_key.s3.key_id
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true  # Reduces KMS costs
  }
}

# Lifecycle Policy for Cost Optimization
resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  
  rule {
    id     = "transition-to-ia"
    status = "Enabled"
    
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    
    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }
    
    transition {
      days          = 180
      storage_class = "DEEP_ARCHIVE"
    }
    
    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
  
  rule {
    id     = "delete-incomplete-uploads"
    status = "Enabled"
    
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
  
  rule {
    id     = "expire-old-delete-markers"
    status = "Enabled"
    
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket Policy
resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnforceSSLOnly"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.data.arn,
          "${aws_s3_bucket.data.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "DenyUnencryptedObjectUploads"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.data.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid    = "AllowApplicationAccess"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.ec2_instance.arn
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.data.arn}/*"
      },
      {
        Sid    = "AllowListBucket"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.ec2_instance.arn
        }
        Action = "s3:ListBucket"
        Resource = aws_s3_bucket.data.arn
      }
    ]
  })
}

# S3 Access Logging
resource "aws_s3_bucket" "logs" {
  bucket = "${var.environment}-logs-${data.aws_caller_identity.current.account_id}"
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-logs-bucket"
    }
  )
}

resource "aws_s3_bucket_logging" "data" {
  bucket = aws_s3_bucket.data.id
  
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access-logs/"
}

# S3 Replication (for disaster recovery)
resource "aws_s3_bucket" "replica" {
  provider = aws.replica_region
  
  bucket = "${var.environment}-data-replica-${data.aws_caller_identity.current.account_id}"
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-data-replica"
    }
  )
}

resource "aws_s3_bucket_versioning" "replica" {
  provider = aws.replica_region
  
  bucket = aws_s3_bucket.replica.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

# IAM Role for Replication
resource "aws_iam_role" "replication" {
  name = "${var.environment}-s3-replication-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "s3.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
  
  tags = local.common_tags
}

resource "aws_iam_role_policy" "replication" {
  name = "${var.environment}-s3-replication-policy"
  role = aws_iam_role.replication.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.data.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging"
        ]
        Resource = "${aws_s3_bucket.data.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags"
        ]
        Resource = "${aws_s3_bucket.replica.arn}/*"
      }
    ]
  })
}

# Replication Configuration
resource "aws_s3_bucket_replication_configuration" "data" {
  depends_on = [
    aws_s3_bucket_versioning.data,
    aws_s3_bucket_versioning.replica
  ]
  
  bucket = aws_s3_bucket.data.id
  role   = aws_iam_role.replication.arn
  
  rule {
    id     = "replicate-all"
    status = "Enabled"
    
    filter {}
    
    destination {
      bucket        = aws_s3_bucket.replica.arn
      storage_class = "STANDARD_IA"
      
      replication_time {
        status = "Enabled"
        time {
          minutes = 15
        }
      }
      
      metrics {
        status = "Enabled"
        event_threshold {
          minutes = 15
        }
      }
    }
    
    delete_marker_replication {
      status = "Enabled"
    }
  }
}

# S3 Event Notifications
resource "aws_s3_bucket_notification" "data" {
  bucket = aws_s3_bucket.data.id
  
  lambda_function {
    lambda_function_arn = aws_lambda_function.s3_processor.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "uploads/"
    filter_suffix       = ".jpg"
  }
  
  topic {
    topic_arn = aws_sns_topic.s3_events.arn
    events    = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
  }
  
  depends_on = [
    aws_lambda_permission.allow_s3,
    aws_sns_topic_policy.s3_events
  ]
}

# S3 Intelligent-Tiering
resource "aws_s3_bucket_intelligent_tiering_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  name   = "EntireBucket"
  
  tiering {
    access_tier = "ARCHIVE_ACCESS"
    days        = 90
  }
  
  tiering {
    access_tier = "DEEP_ARCHIVE_ACCESS"
    days        = 180
  }
}
```


### EBS Volumes and Snapshots

```hcl
# storage/ebs.tf

# Additional EBS Volume for Data
resource "aws_ebs_volume" "data" {
  count = var.enable_data_volume ? 1 : 0
  
  availability_zone = var.availability_zones[0]
  size              = var.data_volume_size
  type              = "gp3"
  iops              = 3000
  throughput        = 125
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs.arn
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-data-volume"
    }
  )
}

# KMS Key for EBS Encryption
resource "aws_kms_key" "ebs" {
  description             = "KMS key for EBS volume encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-ebs-encryption-key"
    }
  )
}

resource "aws_kms_alias" "ebs" {
  name          = "alias/${var.environment}-ebs-encryption"
  target_key_id = aws_kms_key.ebs.key_id
}

# Automated EBS Snapshot Lifecycle
resource "aws_dlm_lifecycle_policy" "ebs_snapshots" {
  description        = "EBS snapshot lifecycle policy"
  execution_role_arn = aws_iam_role.dlm_lifecycle.arn
  state              = "ENABLED"
  
  policy_details {
    resource_types = ["VOLUME"]
    
    schedule {
      name = "Daily snapshots"
      
      create_rule {
        interval      = 24
        interval_unit = "HOURS"
        times         = ["03:00"]
      }
      
      retain_rule {
        count = 7  # Keep 7 daily snapshots
      }
      
      tags_to_add = merge(
        local.common_tags,
        {
          SnapshotType = "DLMAutomatic"
        }
      )
      
      copy_tags = true
    }
    
    target_tags = {
      Backup = "true"
    }
  }
  
  tags = local.common_tags
}

# IAM Role for DLM
resource "aws_iam_role" "dlm_lifecycle" {
  name = "${var.environment}-dlm-lifecycle-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "dlm.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
  
  tags = local.common_tags
}

resource "aws_iam_role_policy" "dlm_lifecycle" {
  name = "${var.environment}-dlm-lifecycle-policy"
  role = aws_iam_role.dlm_lifecycle.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateSnapshot",
          "ec2:CreateSnapshots",
          "ec2:DeleteSnapshot",
          "ec2:DescribeInstances",
          "ec2:DescribeVolumes",
          "ec2:DescribeSnapshots"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateTags"
        ]
        Resource = "arn:aws:ec2:*::snapshot/*"
      }
    ]
  })
}
```


### EFS File Systems

```hcl
# storage/efs.tf

# EFS File System
resource "aws_efs_file_system" "main" {
  creation_token = "${var.environment}-efs"
  encrypted      = true
  kms_key_id     = aws_kms_key.efs.arn
  
  # Performance Mode
  performance_mode = "generalPurpose"  # or "maxIO" for high throughput
  
  # Throughput Mode
  throughput_mode                 = "bursting"  # or "provisioned"
  # provisioned_throughput_in_mibps = 100  # Only if provisioned mode
  
  # Lifecycle Policy
  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }
  
  lifecycle_policy {
    transition_to_primary_storage_class = "AFTER_1_ACCESS"
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-efs"
    }
  )
}

# KMS Key for EFS Encryption
resource "aws_kms_key" "efs" {
  description             = "KMS key for EFS encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-efs-encryption-key"
    }
  )
}

# EFS Mount Targets (one per AZ)
resource "aws_efs_mount_target" "main" {
  count = length(data.terraform_remote_state.networking.outputs.private_subnet_ids)
  
  file_system_id  = aws_efs_file_system.main.id
  subnet_id       = data.terraform_remote_state.networking.outputs.private_subnet_ids[count.index]
  security_groups = [aws_security_group.efs.id]
}

# EFS Security Group
resource "aws_security_group" "efs" {
  name_prefix = "${var.environment}-efs-"
  description = "Security group for EFS mount targets"
  vpc_id      = data.terraform_remote_state.networking.outputs.vpc_id
  
  # Allow NFS from application servers
  ingress {
    description     = "NFS from application servers"
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.web_server.id]
  }
  
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-efs-sg"
    }
  )
  
  lifecycle {
    create_before_destroy = true
  }
}

# EFS Backup Policy
resource "aws_efs_backup_policy" "main" {
  file_system_id = aws_efs_file_system.main.id
  
  backup_policy {
    status = "ENABLED"
  }
}

# EFS Access Point (for application isolation)
resource "aws_efs_access_point" "app" {
  file_system_id = aws_efs_file_system.main.id
  
  posix_user {
    gid = 1000
    uid = 1000
  }
  
  root_directory {
    path = "/app-data"
    
    creation_info {
      owner_gid   = 1000
      owner_uid   = 1000
      permissions = "0755"
    }
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-app-access-point"
    }
  )
}
```


## Database Services

### RDS PostgreSQL with High Availability

```hcl
# database/rds.tf

# DB Subnet Group
resource "aws_db_subnet_group" "main" {
  name_prefix = "${var.environment}-db-subnet-group-"
  subnet_ids  = data.terraform_remote_state.networking.outputs.database_subnet_ids
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-db-subnet-group"
    }
  )
  
  lifecycle {
    create_before_destroy = true
  }
}

# DB Parameter Group
resource "aws_db_parameter_group" "postgres" {
  name_prefix = "${var.environment}-postgres-"
  family      = "postgres15"
  
  parameter {
    name  = "log_connections"
    value = "1"
  }
  
  parameter {
    name  = "log_disconnections"
    value = "1"
  }
  
  parameter {
    name  = "log_statement"
    value = "all"
  }
  
  parameter {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements"
  }
  
  tags = local.common_tags
  
  lifecycle {
    create_before_destroy = true
  }
}

# DB Security Group
resource "aws_security_group" "rds" {
  name_prefix = "${var.environment}-rds-"
  description = "Security group for RDS instances"
  vpc_id      = data.terraform_remote_state.networking.outputs.vpc_id
  
  # Allow PostgreSQL from application tier
  ingress {
    description     = "PostgreSQL from application"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.web_server.id]
  }
  
  # No outbound rules needed for RDS
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-rds-sg"
    }
  )
  
  lifecycle {
    create_before_destroy = true
  }
}

# KMS Key for RDS Encryption
resource "aws_kms_key" "rds" {
  description             = "KMS key for RDS encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-rds-encryption-key"
    }
  )
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${var.environment}-rds-encryption"
  target_key_id = aws_kms_key.rds.key_id
}

# Random Password for DB
resource "random_password" "db_master" {
  length  = 32
  special = true
}

# Store Password in Secrets Manager
resource "aws_secretsmanager_secret" "db_master_password" {
  name_prefix             = "${var.environment}-db-master-password-"
  description             = "Master password for RDS database"
  recovery_window_in_days = 7
  
  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "db_master_password" {
  secret_id = aws_secretsmanager_secret.db_master_password.id
  secret_string = jsonencode({
    username = "dbadmin"
    password = random_password.db_master.result
    engine   = "postgres"
    host     = aws_db_instance.main.endpoint
    port     = 5432
    dbname   = aws_db_instance.main.db_name
  })
}

# RDS Instance
resource "aws_db_instance" "main" {
  identifier     = "${var.environment}-postgres"
  engine         = "postgres"
  engine_version = "15.4"
  
  # Instance Configuration
  instance_class        = var.db_instance_class
  allocated_storage     = var.db_allocated_storage
  storage_type          = "gp3"
  iops                  = 3000
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.rds.arn
  
  # Database Configuration
  db_name  = var.db_name
  username = "dbadmin"
  password = random_password.db_master.result
  port     = 5432
  
  # Network Configuration
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false
  
  # High Availability
  multi_az = var.environment == "production" ? true : false
  
  # Backup Configuration
  backup_retention_period = var.environment == "production" ? 30 : 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "mon:04:00-mon:05:00"
  
  # Enhanced Monitoring
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  monitoring_interval             = 60
  monitoring_role_arn             = aws_iam_role.rds_monitoring.arn
  
  # Performance Insights
  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.rds.arn
  performance_insights_retention_period = 7
  
  # Parameter and Option Groups
  parameter_group_name = aws_db_parameter_group.postgres.name
  
  # Deletion Protection
  deletion_protection = var.environment == "production" ? true : false
  skip_final_snapshot = var.environment == "production" ? false : true
  final_snapshot_identifier = var.environment == "production" ? "${var.environment}-postgres-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}" : null
  
  # Auto Minor Version Upgrade
  auto_minor_version_upgrade = true
  
  # Copy tags to snapshots
  copy_tags_to_snapshot = true
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-postgres"
    }
  )
  
  lifecycle {
    ignore_changes = [
      password,  # Managed by Secrets Manager rotation
      final_snapshot_identifier
    ]
  }
}

# IAM Role for Enhanced Monitoring
resource "aws_iam_role" "rds_monitoring" {
  name_prefix = "${var.environment}-rds-monitoring-"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "monitoring.rds.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
  
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# RDS Read Replica (for read scaling)
resource "aws_db_instance" "replica" {
  count = var.create_read_replica ? 1 : 0
  
  identifier           = "${var.environment}-postgres-replica"
  replicate_source_db  = aws_db_instance.main.identifier
  instance_class       = var.db_replica_instance_class
  
  # Read replicas inherit most settings from source
  publicly_accessible = false
  skip_final_snapshot = true
  
  # Enhanced Monitoring
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-postgres-replica"
      Role = "ReadReplica"
    }
  )
}

# CloudWatch Alarms for RDS
resource "aws_cloudwatch_metric_alarm" "database_cpu" {
  alarm_name          = "${var.environment}-rds-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "RDS CPU utilization is too high"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.id
  }
  
  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "database_storage" {
  alarm_name          = "${var.environment}-rds-low-storage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 10000000000  # 10GB in bytes
  alarm_description   = "RDS free storage space is low"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.id
  }
  
  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "database_connections" {
  alarm_name          = "${var.environment}-rds-high-connections"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "RDS connection count is high"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.id
  }
  
  tags = local.common_tags
}
```


### DynamoDB Tables

```hcl
# database/dynamodb.tf

# DynamoDB Table with Global Secondary Index
resource "aws_dynamodb_table" "main" {
  name           = "${var.environment}-application-data"
  billing_mode   = var.environment == "production" ? "PROVISIONED" : "PAY_PER_REQUEST"
  read_capacity  = var.environment == "production" ? 5 : null
  write_capacity = var.environment == "production" ? 5 : null
  hash_key       = "UserId"
  range_key      = "Timestamp"
  
  # Attributes
  attribute {
    name = "UserId"
    type = "S"
  }
  
  attribute {
    name = "Timestamp"
    type = "N"
  }
  
  attribute {
    name = "Status"
    type = "S"
  }
  
  attribute {
    name = "Category"
    type = "S"
  }
  
  # Global Secondary Index
  global_secondary_index {
    name            = "StatusIndex"
    hash_key        = "Status"
    range_key       = "Timestamp"
    projection_type = "ALL"
    read_capacity   = var.environment == "production" ? 5 : null
    write_capacity  = var.environment == "production" ? 5 : null
  }
  
  global_secondary_index {
    name            = "CategoryIndex"
    hash_key        = "Category"
    range_key       = "Timestamp"
    projection_type = "INCLUDE"
    non_key_attributes = ["UserId", "Status"]
    read_capacity   = var.environment == "production" ? 5 : null
    write_capacity  = var.environment == "production" ? 5 : null
  }
  
  # TTL Configuration
  ttl {
    attribute_name = "ExpirationTime"
    enabled        = true
  }
  
  # Encryption at Rest
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.dynamodb.arn
  }
  
  # Point-in-Time Recovery
  point_in_time_recovery {
    enabled = var.environment == "production" ? true : false
  }
  
  # Stream Configuration (for Lambda triggers)
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  
  # Auto Scaling (for provisioned mode)
  dynamic "replica" {
    for_each = var.enable_global_table ? var.replica_regions : []
    content {
      region_name = replica.value
    }
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-application-data"
    }
  )
}

# KMS Key for DynamoDB Encryption
resource "aws_kms_key" "dynamodb" {
  description             = "KMS key for DynamoDB encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-dynamodb-encryption-key"
    }
  )
}

resource "aws_kms_alias" "dynamodb" {
  name          = "alias/${var.environment}-dynamodb-encryption"
  target_key_id = aws_kms_key.dynamodb.key_id
}

# Auto Scaling for DynamoDB (Provisioned Mode)
resource "aws_appautoscaling_target" "dynamodb_table_read" {
  count = var.environment == "production" ? 1 : 0
  
  max_capacity       = 100
  min_capacity       = 5
  resource_id        = "table/${aws_dynamodb_table.main.name}"
  scalable_dimension = "dynamodb:table:ReadCapacityUnits"
  service_namespace  = "dynamodb"
}

resource "aws_appautoscaling_policy" "dynamodb_table_read" {
  count = var.environment == "production" ? 1 : 0
  
  name               = "${var.environment}-dynamodb-read-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.dynamodb_table_read[0].resource_id
  scalable_dimension = aws_appautoscaling_target.dynamodb_table_read[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.dynamodb_table_read[0].service_namespace
  
  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "DynamoDBReadCapacityUtilization"
    }
    target_value = 70.0
  }
}

resource "aws_appautoscaling_target" "dynamodb_table_write" {
  count = var.environment == "production" ? 1 : 0
  
  max_capacity       = 100
  min_capacity       = 5
  resource_id        = "table/${aws_dynamodb_table.main.name}"
  scalable_dimension = "dynamodb:table:WriteCapacityUnits"
  service_namespace  = "dynamodb"
}

resource "aws_appautoscaling_policy" "dynamodb_table_write" {
  count = var.environment == "production" ? 1 : 0
  
  name               = "${var.environment}-dynamodb-write-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.dynamodb_table_write[0].resource_id
  scalable_dimension = aws_appautoscaling_target.dynamodb_table_write[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.dynamodb_table_write[0].service_namespace
  
  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "DynamoDBWriteCapacityUtilization"
    }
    target_value = 70.0
  }
}

# DynamoDB Backup Plan
resource "aws_backup_plan" "dynamodb" {
  name = "${var.environment}-dynamodb-backup-plan"
  
  rule {
    rule_name         = "daily_backup"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 3 * * ? *)"  # 3 AM daily
    
    lifecycle {
      delete_after = 30
    }
    
    recovery_point_tags = local.common_tags
  }
  
  tags = local.common_tags
}

resource "aws_backup_vault" "main" {
  name        = "${var.environment}-backup-vault"
  kms_key_arn = aws_kms_key.backup.arn
  
  tags = local.common_tags
}

resource "aws_kms_key" "backup" {
  description             = "KMS key for backup vault encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-backup-encryption-key"
    }
  )
}

resource "aws_backup_selection" "dynamodb" {
  name         = "${var.environment}-dynamodb-backup-selection"
  plan_id      = aws_backup_plan.dynamodb.id
  iam_role_arn = aws_iam_role.backup.arn
  
  resources = [
    aws_dynamodb_table.main.arn
  ]
}

resource "aws_iam_role" "backup" {
  name_prefix = "${var.environment}-backup-"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "backup.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
  
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}
```


### ElastiCache Redis

```hcl
# database/elasticache.tf

# ElastiCache Subnet Group
resource "aws_elasticache_subnet_group" "main" {
  name       = "${var.environment}-elasticache-subnet-group"
  subnet_ids = data.terraform_remote_state.networking.outputs.database_subnet_ids
  
  tags = local.common_tags
}

# ElastiCache Parameter Group
resource "aws_elasticache_parameter_group" "redis" {
  name   = "${var.environment}-redis-params"
  family = "redis7"
  
  parameter {
    name  = "maxmemory-policy"
    value = "allkeys-lru"
  }
  
  parameter {
    name  = "timeout"
    value = "300"
  }
  
  tags = local.common_tags
}

# Security Group for ElastiCache
resource "aws_security_group" "elasticache" {
  name_prefix = "${var.environment}-elasticache-"
  description = "Security group for ElastiCache cluster"
  vpc_id      = data.terraform_remote_state.networking.outputs.vpc_id
  
  # Allow Redis from application tier
  ingress {
    description     = "Redis from application"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.web_server.id]
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-elasticache-sg"
    }
  )
  
  lifecycle {
    create_before_destroy = true
  }
}

# ElastiCache Replication Group (Redis Cluster)
resource "aws_elasticache_replication_group" "main" {
  replication_group_id       = "${var.environment}-redis"
  replication_group_description = "Redis cluster for ${var.environment}"
  engine                     = "redis"
  engine_version             = "7.0"
  node_type                  = var.redis_node_type
  number_cache_clusters      = var.redis_num_cache_nodes
  port                       = 6379
  
  # Subnet and Security Groups
  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.elasticache.id]
  
  # Parameter Group
  parameter_group_name = aws_elasticache_parameter_group.redis.name
  
  # Encryption
  at_rest_encryption_enabled = true
  kms_key_id                 = aws_kms_key.elasticache.arn
  transit_encryption_enabled = true
  auth_token_enabled         = true
  auth_token                 = random_password.redis_auth.result
  
  # Multi-AZ
  automatic_failover_enabled = var.redis_num_cache_nodes > 1
  multi_az_enabled           = var.redis_num_cache_nodes > 1
  
  # Backup Configuration
  snapshot_retention_limit = var.environment == "production" ? 7 : 1
  snapshot_window         = "03:00-05:00"
  maintenance_window      = "mon:05:00-mon:07:00"
  
  # Auto Minor Version Upgrade
  auto_minor_version_upgrade = true
  
  # Notification
  notification_topic_arn = aws_sns_topic.alerts.arn
  
  # Log Delivery
  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.elasticache.name
    destination_type = "cloudwatch-logs"
    log_format       = "json"
    log_type         = "slow-log"
  }
  
  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.elasticache.name
    destination_type = "cloudwatch-logs"
    log_format       = "json"
    log_type         = "engine-log"
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-redis"
    }
  )
  
  lifecycle {
    ignore_changes = [auth_token]
  }
}

# Random Auth Token for Redis
resource "random_password" "redis_auth" {
  length  = 32
  special = false  # Redis auth token doesn't support special characters
}

# Store Auth Token in Secrets Manager
resource "aws_secretsmanager_secret" "redis_auth" {
  name_prefix             = "${var.environment}-redis-auth-"
  description             = "Auth token for Redis cluster"
  recovery_window_in_days = 7
  
  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "redis_auth" {
  secret_id = aws_secretsmanager_secret.redis_auth.id
  secret_string = jsonencode({
    auth_token = random_password.redis_auth.result
    endpoint   = aws_elasticache_replication_group.main.primary_endpoint_address
    port       = 6379
  })
}

# KMS Key for ElastiCache Encryption
resource "aws_kms_key" "elasticache" {
  description             = "KMS key for ElastiCache encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-elasticache-encryption-key"
    }
  )
}

# CloudWatch Log Group for ElastiCache
resource "aws_cloudwatch_log_group" "elasticache" {
  name              = "/aws/elasticache/${var.environment}"
  retention_in_days = 30
  
  tags = local.common_tags
}

# CloudWatch Alarms for ElastiCache
resource "aws_cloudwatch_metric_alarm" "redis_cpu" {
  alarm_name          = "${var.environment}-redis-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ElastiCache"
  period              = 300
  statistic           = "Average"
  threshold           = 75
  alarm_description   = "Redis CPU utilization is too high"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  
  dimensions = {
    CacheClusterId = "${aws_elasticache_replication_group.main.id}-001"
  }
  
  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "redis_memory" {
  alarm_name          = "${var.environment}-redis-high-memory"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DatabaseMemoryUsagePercentage"
  namespace           = "AWS/ElastiCache"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Redis memory utilization is too high"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  
  dimensions = {
    CacheClusterId = "${aws_elasticache_replication_group.main.id}-001"
  }
  
  tags = local.common_tags
}

## Security Services

### IAM Roles and Policies

```hcl
# security/iam.tf

# Application IAM Role with Least Privilege
resource "aws_iam_role" "application" {
  name_prefix = "${var.environment}-application-"
  description = "IAM role for application instances"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
  
  # Permission boundary for additional security
  permissions_boundary = var.enable_permission_boundary ? aws_iam_policy.permission_boundary[0].arn : null
  
  tags = local.common_tags
}

# Custom IAM Policy for S3 Access
resource "aws_iam_policy" "s3_access" {
  name_prefix = "${var.environment}-s3-access-"
  description = "Allows access to application S3 buckets"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ListBuckets"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = [
          aws_s3_bucket.data.arn,
          aws_s3_bucket.uploads.arn
        ]
      },
      {
        Sid    = "ObjectAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = [
          "${aws_s3_bucket.data.arn}/*",
          "${aws_s3_bucket.uploads.arn}/*"
        ]
        Condition = {
          StringEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid    = "KMSAccess"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = [
          aws_kms_key.s3.arn
        ]
      }
    ]
  })
  
  tags = local.common_tags
}

# Custom IAM Policy for RDS Access
resource "aws_iam_policy" "rds_access" {
  name_prefix = "${var.environment}-rds-access-"
  description = "Allows access to RDS authentication"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RDSConnect"
        Effect = "Allow"
        Action = [
          "rds-db:connect"
        ]
        Resource = "arn:aws:rds-db:${var.aws_region}:${data.aws_caller_identity.current.account_id}:dbuser:${aws_db_instance.main.resource_id}/*"
      }
    ]
  })
  
  tags = local.common_tags
}

# Custom IAM Policy for Secrets Manager
resource "aws_iam_policy" "secrets_access" {
  name_prefix = "${var.environment}-secrets-access-"
  description = "Allows access to Secrets Manager secrets"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GetSecrets"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          aws_secretsmanager_secret.db_master_password.arn,
          aws_secretsmanager_secret.redis_auth.arn,
          "${aws_secretsmanager_secret.api_keys.arn}*"
        ]
      },
      {
        Sid    = "DecryptSecrets"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = [
          aws_kms_key.secrets.arn
        ]
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${var.aws_region}.amazonaws.com"
          }
        }
      }
    ]
  })
  
  tags = local.common_tags
}

# Custom IAM Policy for DynamoDB Access
resource "aws_iam_policy" "dynamodb_access" {
  name_prefix = "${var.environment}-dynamodb-access-"
  description = "Allows access to DynamoDB tables"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBTableAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:BatchGetItem",
          "dynamodb:BatchWriteItem",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem"
        ]
        Resource = [
          aws_dynamodb_table.main.arn,
          "${aws_dynamodb_table.main.arn}/index/*"
        ]
      },
      {
        Sid    = "DynamoDBStreamAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:DescribeStream",
          "dynamodb:GetRecords",
          "dynamodb:GetShardIterator",
          "dynamodb:ListStreams"
        ]
        Resource = "${aws_dynamodb_table.main.arn}/stream/*"
      }
    ]
  })
  
  tags = local.common_tags
}

# Attach Policies to Application Role
resource "aws_iam_role_policy_attachment" "application_s3" {
  role       = aws_iam_role.application.name
  policy_arn = aws_iam_policy.s3_access.arn
}

resource "aws_iam_role_policy_attachment" "application_rds" {
  role       = aws_iam_role.application.name
  policy_arn = aws_iam_policy.rds_access.arn
}

resource "aws_iam_role_policy_attachment" "application_secrets" {
  role       = aws_iam_role.application.name
  policy_arn = aws_iam_policy.secrets_access.arn
}

resource "aws_iam_role_policy_attachment" "application_dynamodb" {
  role       = aws_iam_role.application.name
  policy_arn = aws_iam_policy.dynamodb_access.arn
}

# Attach AWS Managed Policies
resource "aws_iam_role_policy_attachment" "application_ssm" {
  role       = aws_iam_role.application.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "application_cloudwatch" {
  role       = aws_iam_role.application.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Permission Boundary (Optional)
resource "aws_iam_policy" "permission_boundary" {
  count = var.enable_permission_boundary ? 1 : 0
  
  name_prefix = "${var.environment}-permission-boundary-"
  description = "Permission boundary for application roles"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowedServices"
        Effect = "Allow"
        Action = [
          "s3:*",
          "dynamodb:*",
          "rds:*",
          "secretsmanager:*",
          "kms:*",
          "logs:*",
          "cloudwatch:*",
          "ssm:*"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyDangerousActions"
        Effect = "Deny"
        Action = [
          "iam:*",
          "organizations:*",
          "account:*"
        ]
        Resource = "*"
      }
    ]
  })
  
  tags = local.common_tags
}

# Cross-Account Access Role
resource "aws_iam_role" "cross_account_access" {
  count = var.enable_cross_account_access ? 1 : 0
  
  name_prefix = "${var.environment}-cross-account-"
  description = "Role for cross-account access"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = var.trusted_account_arns
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "sts:ExternalId" = var.external_id
        }
        IpAddress = {
          "aws:SourceIp" = var.allowed_source_ips
        }
      }
    }]
  })
  
  tags = local.common_tags
}

# Service Control Policy (SCP) - For AWS Organizations
resource "aws_organizations_policy" "security_baseline" {
  count = var.create_scp ? 1 : 0
  
  name        = "${var.environment}-security-baseline"
  description = "Security baseline SCP"
  type        = "SERVICE_CONTROL_POLICY"
  
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyLeavingOrganization"
        Effect = "Deny"
        Action = [
          "organizations:LeaveOrganization"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyRootAccount"
        Effect = "Deny"
        Action = "*"
        Resource = "*"
        Condition = {
          StringLike = {
            "aws:PrincipalArn" = "arn:aws:iam::*:root"
          }
        }
      },
      {
        Sid    = "RequireMFAForCriticalActions"
        Effect = "Deny"
        Action = [
          "ec2:TerminateInstances",
          "rds:DeleteDBInstance",
          "s3:DeleteBucket"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      },
      {
        Sid    = "DenyUnencryptedStorage"
        Effect = "Deny"
        Action = [
          "s3:PutObject",
          "ec2:CreateVolume",
          "rds:CreateDBInstance"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = ["AES256", "aws:kms"],
            "ec2:Encrypted"                   = "true",
            "rds:StorageEncrypted"            = "true"
          }
        }
      }
    ]
  })
  
  tags = local.common_tags
}

# IAM Access Analyzer
resource "aws_accessanalyzer_analyzer" "main" {
  analyzer_name = "${var.environment}-access-analyzer"
  type          = "ACCOUNT"
  
  tags = local.common_tags
}

# IAM Password Policy
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  hard_expiry                    = false
}
```


### Security Groups with Layered Defense

```hcl
# security/security-groups.tf

# Base Security Group (attached to all instances)
resource "aws_security_group" "base" {
  name_prefix = "${var.environment}-base-"
  description = "Base security group for all instances"
  vpc_id      = data.terraform_remote_state.networking.outputs.vpc_id
  
  # No ingress rules - instances must explicitly allow traffic
  
  # Allow all outbound traffic (can be restricted per environment)
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-base-sg"
      Type = "Base"
    }
  )
  
  lifecycle {
    create_before_destroy = true
  }
}

# Web Tier Security Group
resource "aws_security_group" "web" {
  name_prefix = "${var.environment}-web-"
  description = "Security group for web tier"
  vpc_id      = data.terraform_remote_state.networking.outputs.vpc_id
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-web-sg"
      Tier = "Web"
    }
  )
  
  lifecycle {
    create_before_destroy = true
  }
}

# Web Tier - Allow HTTP/HTTPS from ALB
resource "aws_security_group_rule" "web_http_from_alb" {
  type                     = "ingress"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb.id
  security_group_id        = aws_security_group.web.id
  description              = "Allow HTTP from ALB"
}

resource "aws_security_group_rule" "web_https_from_alb" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb.id
  security_group_id        = aws_security_group.web.id
  description              = "Allow HTTPS from ALB"
}

# Application Tier Security Group
resource "aws_security_group" "app" {
  name_prefix = "${var.environment}-app-"
  description = "Security group for application tier"
  vpc_id      = data.terraform_remote_state.networking.outputs.vpc_id
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-app-sg"
      Tier = "Application"
    }
  )
  
  lifecycle {
    create_before_destroy = true
  }
}

# App Tier - Allow traffic from Web Tier
resource "aws_security_group_rule" "app_from_web" {
  type                     = "ingress"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.web.id
  security_group_id        = aws_security_group.app.id
  description              = "Allow application traffic from web tier"
}

# Database Tier Security Group
resource "aws_security_group" "database" {
  name_prefix = "${var.environment}-database-"
  description = "Security group for database tier"
  vpc_id      = data.terraform_remote_state.networking.outputs.vpc_id
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-database-sg"
      Tier = "Database"
    }
  )
  
  lifecycle {
    create_before_destroy = true
  }
}

# Database - Allow PostgreSQL from App Tier
resource "aws_security_group_rule" "db_postgres_from_app" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.app.id
  security_group_id        = aws_security_group.database.id
  description              = "Allow PostgreSQL from application tier"
}

# Database - Allow MySQL from App Tier
resource "aws_security_group_rule" "db_mysql_from_app" {
  type                     = "ingress"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.app.id
  security_group_id        = aws_security_group.database.id
  description              = "Allow MySQL from application tier"
}

# Management Security Group (for bastion/jump hosts)
resource "aws_security_group" "management" {
  name_prefix = "${var.environment}-management-"
  description = "Security group for management instances"
  vpc_id      = data.terraform_remote_state.networking.outputs.vpc_id
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-management-sg"
      Type = "Management"
    }
  )
  
  lifecycle {
    create_before_destroy = true
  }
}

# Management - Allow SSH from specific IPs
resource "aws_security_group_rule" "management_ssh" {
  count = length(var.allowed_ssh_cidrs) > 0 ? 1 : 0
  
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = var.allowed_ssh_cidrs
  security_group_id = aws_security_group.management.id
  description       = "Allow SSH from trusted networks"
}

# VPC Endpoint Security Group
resource "aws_security_group" "vpc_endpoints" {
  name_prefix = "${var.environment}-vpc-endpoints-"
  description = "Security group for VPC endpoints"
  vpc_id      = data.terraform_remote_state.networking.outputs.vpc_id
  
  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [data.terraform_remote_state.networking.outputs.vpc_cidr]
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-vpc-endpoints-sg"
    }
  )
  
  lifecycle {
    create_before_destroy = true
  }
}

# Security Group for Lambda Functions
resource "aws_security_group" "lambda" {
  name_prefix = "${var.environment}-lambda-"
  description = "Security group for Lambda functions"
  vpc_id      = data.terraform_remote_state.networking.outputs.vpc_id
  
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-lambda-sg"
    }
  )
  
  lifecycle {
    create_before_destroy = true
  }
}

# Allow Lambda to access RDS
resource "aws_security_group_rule" "db_from_lambda" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.lambda.id
  security_group_id        = aws_security_group.database.id
  description              = "Allow PostgreSQL from Lambda functions"
}
```


### AWS WAF for Application Protection

```hcl
# security/waf.tf

# WAF Web ACL
resource "aws_wafv2_web_acl" "main" {
  name        = "${var.environment}-web-acl"
  description = "WAF rules for ${var.environment}"
  scope       = "REGIONAL"
  
  default_action {
    allow {}
  }
  
  # AWS Managed Rule - Common Rule Set
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1
    
    override_action {
      none {}
    }
    
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
        
        # Exclude specific rules if needed
        rule_action_override {
          action_to_use {
            count {}
          }
          name = "SizeRestrictions_BODY"
        }
      }
    }
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }
  
  # AWS Managed Rule - Known Bad Inputs
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2
    
    override_action {
      none {}
    }
    
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesKnownBadInputsRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }
  
  # AWS Managed Rule - SQL Injection
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 3
    
    override_action {
      none {}
    }
    
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesSQLiRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }
  
  # Rate Limiting Rule
  rule {
    name     = "RateLimitRule"
    priority = 4
    
    action {
      block {}
    }
    
    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitRuleMetric"
      sampled_requests_enabled   = true
    }
  }
  
  # Geo Blocking Rule (optional)
  dynamic "rule" {
    for_each = length(var.blocked_countries) > 0 ? [1] : []
    content {
      name     = "GeoBlockingRule"
      priority = 5
      
      action {
        block {}
      }
      
      statement {
        geo_match_statement {
          country_codes = var.blocked_countries
        }
      }
      
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "GeoBlockingRuleMetric"
        sampled_requests_enabled   = true
      }
    }
  }
  
  # IP Reputation List
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 6
    
    override_action {
      none {}
    }
    
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesAmazonIpReputationListMetric"
      sampled_requests_enabled   = true
    }
  }
  
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.environment}-web-acl"
    sampled_requests_enabled   = true
  }
  
  tags = local.common_tags
}

# Associate WAF with ALB
resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.main.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

# WAF Logging Configuration
resource "aws_wafv2_web_acl_logging_configuration" "main" {
  resource_arn            = aws_wafv2_web_acl.main.arn
  log_destination_configs = [aws_kinesis_firehose_delivery_stream.waf_logs.arn]
  
  redacted_fields {
    single_header {
      name = "authorization"
    }
  }
  
  redacted_fields {
    single_header {
      name = "cookie"
    }
  }
}

# Kinesis Firehose for WAF Logs
resource "aws_kinesis_firehose_delivery_stream" "waf_logs" {
  name        = "aws-waf-logs-${var.environment}"
  destination = "extended_s3"
  
  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose_waf.arn
    bucket_arn = aws_s3_bucket.waf_logs.arn
    prefix     = "waf-logs/"
    
    compression_format = "GZIP"
    
    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose_waf.name
      log_stream_name = "S3Delivery"
    }
  }
  
  tags = local.common_tags
}

# S3 Bucket for WAF Logs
resource "aws_s3_bucket" "waf_logs" {
  bucket = "${var.environment}-waf-logs-${data.aws_caller_identity.current.account_id}"
  
  tags = local.common_tags
}

resource "aws_s3_bucket_lifecycle_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id
  
  rule {
    id     = "delete-old-logs"
    status = "Enabled"
    
    expiration {
      days = 90
    }
  }
}

# IAM Role for Firehose
resource "aws_iam_role" "firehose_waf" {
  name_prefix = "${var.environment}-firehose-waf-"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "firehose.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
  
  tags = local.common_tags
}

resource "aws_iam_role_policy" "firehose_waf" {
  name = "${var.environment}-firehose-waf-policy"
  role = aws_iam_role.firehose_waf.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.waf_logs.arn,
          "${aws_s3_bucket.waf_logs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.firehose_waf.arn}:*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "firehose_waf" {
  name              = "/aws/kinesisfirehose/${var.environment}-waf"
  retention_in_days = 30
  
  tags = local.common_tags
}
```


## Global Services

### CloudFront Distribution

```hcl
# global/cloudfront.tf

# CloudFront Origin Access Control (OAC) - Replaces OAI
resource "aws_cloudfront_origin_access_control" "s3" {
  name                              = "${var.environment}-s3-oac"
  description                       = "OAC for S3 bucket access"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# CloudFront Distribution
resource "aws_cloudfront_distribution" "main" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "${var.environment} CDN distribution"
  default_root_object = "index.html"
  price_class         = var.cloudfront_price_class
  aliases             = var.domain_aliases
  web_acl_id          = aws_wafv2_web_acl.cloudfront.arn
  
  # S3 Origin
  origin {
    domain_name              = aws_s3_bucket.cdn_content.bucket_regional_domain_name
    origin_id                = "S3-${aws_s3_bucket.cdn_content.id}"
    origin_access_control_id = aws_cloudfront_origin_access_control.s3.id
    
    origin_shield {
      enabled              = var.environment == "production"
      origin_shield_region = var.aws_region
    }
  }
  
  # ALB Origin (for dynamic content)
  origin {
    domain_name = aws_lb.main.dns_name
    origin_id   = "ALB-${aws_lb.main.name}"
    
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
    
    custom_header {
      name  = "X-Custom-Header"
      value = random_password.origin_header.result
    }
  }
  
  # Default Cache Behavior (S3)
  default_cache_behavior {
    target_origin_id       = "S3-${aws_s3_bucket.cdn_content.id}"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true
    
    allowed_methods = ["GET", "HEAD", "OPTIONS"]
    cached_methods  = ["GET", "HEAD"]
    
    cache_policy_id          = aws_cloudfront_cache_policy.optimized.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.managed_cors_s3.id
    
    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.url_rewrite.arn
    }
  }
  
  # Ordered Cache Behavior for API
  ordered_cache_behavior {
    path_pattern           = "/api/*"
    target_origin_id       = "ALB-${aws_lb.main.name}"
    viewer_protocol_policy = "https-only"
    compress               = true
    
    allowed_methods = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods  = ["GET", "HEAD"]
    
    cache_policy_id          = data.aws_cloudfront_cache_policy.managed_caching_disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.managed_all_viewer.id
    
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id
  }
  
  # Custom Error Responses
  custom_error_response {
    error_code            = 404
    response_code         = 404
    response_page_path    = "/error/404.html"
    error_caching_min_ttl = 300
  }
  
  custom_error_response {
    error_code            = 403
    response_code         = 403
    response_page_path    = "/error/403.html"
    error_caching_min_ttl = 300
  }
  
  custom_error_response {
    error_code            = 500
    response_code         = 500
    response_page_path    = "/error/500.html"
    error_caching_min_ttl = 60
  }
  
  # Geographic Restrictions
  restrictions {
    geo_restriction {
      restriction_type = var.geo_restriction_type
      locations        = var.geo_restriction_locations
    }
  }
  
  # SSL Certificate
  viewer_certificate {
    acm_certificate_arn      = var.acm_certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
  
  # Logging
  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.cloudfront_logs.bucket_domain_name
    prefix          = "cloudfront-logs/"
  }
  
  tags = local.common_tags
  
  depends_on = [
    aws_s3_bucket_policy.cdn_content
  ]
}

# CloudFront Cache Policy
resource "aws_cloudfront_cache_policy" "optimized" {
  name        = "${var.environment}-optimized-cache"
  comment     = "Optimized cache policy"
  default_ttl = 86400    # 1 day
  max_ttl     = 31536000 # 1 year
  min_ttl     = 0
  
  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"
    }
    
    headers_config {
      header_behavior = "none"
    }
    
    query_strings_config {
      query_string_behavior = "none"
    }
    
    enable_accept_encoding_brotli = true
    enable_accept_encoding_gzip   = true
  }
}

# CloudFront Response Headers Policy
resource "aws_cloudfront_response_headers_policy" "security_headers" {
  name    = "${var.environment}-security-headers"
  comment = "Security headers policy"
  
  security_headers_config {
    content_type_options {
      override = true
    }
    
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
    
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }
    
    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }
    
    content_security_policy {
      content_security_policy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https:;"
      override                = true
    }
  }
  
  custom_headers_config {
    items {
      header   = "X-Custom-Header"
      value    = "CustomValue"
      override = true
    }
  }
}

# CloudFront Function for URL Rewrite
resource "aws_cloudfront_function" "url_rewrite" {
  name    = "${var.environment}-url-rewrite"
  runtime = "cloudfront-js-1.0"
  comment = "URL rewrite function"
  publish = true
  
  code = <<-EOT
    function handler(event) {
      var request = event.request;
      var uri = request.uri;
      
      // Add index.html to requests that don't have file extension
      if (!uri.includes('.')) {
        request.uri = uri + '/index.html';
      }
      
      return request;
    }
  EOT
}

# Random password for origin header verification
resource "random_password" "origin_header" {
  length  = 32
  special = false
}

# Store origin header in Secrets Manager
resource "aws_secretsmanager_secret" "origin_header" {
  name_prefix             = "${var.environment}-cf-origin-header-"
  recovery_window_in_days = 7
  
  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "origin_header" {
  secret_id     = aws_secretsmanager_secret.origin_header.id
  secret_string = random_password.origin_header.result
}

# S3 Bucket for CloudFront Content
resource "aws_s3_bucket" "cdn_content" {
  bucket = "${var.environment}-cdn-content-${data.aws_caller_identity.current.account_id}"
  
  tags = local.common_tags
}

resource "aws_s3_bucket_public_access_block" "cdn_content" {
  bucket = aws_s3_bucket.cdn_content.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 Bucket Policy for CloudFront OAC
resource "aws_s3_bucket_policy" "cdn_content" {
  bucket = aws_s3_bucket.cdn_content.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontServicePrincipal"
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.cdn_content.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.main.arn
          }
        }
      }
    ]
  })
}

# S3 Bucket for CloudFront Logs
resource "aws_s3_bucket" "cloudfront_logs" {
  bucket = "${var.environment}-cf-logs-${data.aws_caller_identity.current.account_id}"
  
  tags = local.common_tags
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudfront_logs" {
  bucket = aws_s3_bucket.cloudfront_logs.id
  
  rule {
    id     = "delete-old-logs"
    status = "Enabled"
    
    expiration {
      days = 90
    }
  }
}

# Data sources for AWS managed policies
data "aws_cloudfront_cache_policy" "managed_caching_disabled" {
  name = "Managed-CachingDisabled"
}

data "aws_cloudfront_origin_request_policy" "managed_all_viewer" {
  name = "Managed-AllViewer"
}

data "aws_cloudfront_origin_request_policy" "managed_cors_s3" {
  name = "Managed-CORS-S3Origin"
}

# WAF for CloudFront (must be in us-east-1)
resource "aws_wafv2_web_acl" "cloudfront" {
  provider = aws.us_east_1
  
  name        = "${var.environment}-cloudfront-waf"
  description = "WAF for CloudFront distribution"
  scope       = "CLOUDFRONT"
  
  default_action {
    allow {}
  }
  
  rule {
    name     = "RateLimitRule"
    priority = 1
    
    action {
      block {}
    }
    
    statement {
      rate_based_statement {
        limit              = 10000
        aggregate_key_type = "IP"
      }
    }
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CloudFrontRateLimitRule"
      sampled_requests_enabled   = true
    }
  }
  
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.environment}-cloudfront-waf"
    sampled_requests_enabled   = true
  }
  
  tags = local.common_tags
}

### Route 53 DNS Management

```hcl
# global/route53.tf

# Hosted Zone
resource "aws_route53_zone" "main" {
  name    = var.domain_name
  comment = "Managed by Terraform for ${var.environment}"
  
  tags = local.common_tags
}

# Primary A Record for ALB
resource "aws_route53_record" "alb" {
  zone_id = aws_route53_zone.main.zone_id
  name    = var.environment == "production" ? var.domain_name : "${var.environment}.${var.domain_name}"
  type    = "A"
  
  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}

# CloudFront Distribution Record
resource "aws_route53_record" "cdn" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "cdn.${var.domain_name}"
  type    = "A"
  
  alias {
    name                   = aws_cloudfront_distribution.main.domain_name
    zone_id                = aws_cloudfront_distribution.main.hosted_zone_id
    evaluate_target_health = false
  }
}

# API Subdomain
resource "aws_route53_record" "api" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "api.${var.domain_name}"
  type    = "A"
  
  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}

# WWW Record
resource "aws_route53_record" "www" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "www.${var.domain_name}"
  type    = "CNAME"
  ttl     = 300
  records = [var.domain_name]
}

# MX Records for Email
resource "aws_route53_record" "mx" {
  count = length(var.mx_records) > 0 ? 1 : 0
  
  zone_id = aws_route53_zone.main.zone_id
  name    = var.domain_name
  type    = "MX"
  ttl     = 3600
  records = var.mx_records
}

# TXT Record for Domain Verification
resource "aws_route53_record" "txt_verification" {
  zone_id = aws_route53_zone.main.zone_id
  name    = var.domain_name
  type    = "TXT"
  ttl     = 300
  records = var.txt_records
}

# SPF Record
resource "aws_route53_record" "spf" {
  count = var.enable_email_security ? 1 : 0
  
  zone_id = aws_route53_zone.main.zone_id
  name    = var.domain_name
  type    = "TXT"
  ttl     = 3600
  records = ["v=spf1 include:_spf.google.com ~all"]
}

# DMARC Record
resource "aws_route53_record" "dmarc" {
  count = var.enable_email_security ? 1 : 0
  
  zone_id = aws_route53_zone.main.zone_id
  name    = "_dmarc.${var.domain_name}"
  type    = "TXT"
  ttl     = 3600
  records = ["v=DMARC1; p=quarantine; rua=mailto:dmarc@${var.domain_name}"]
}

# Health Check for Primary Region
resource "aws_route53_health_check" "primary" {
  fqdn              = aws_lb.main.dns_name
  port              = 443
  type              = "HTTPS"
  resource_path     = "/health"
  failure_threshold = 3
  request_interval  = 30
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-primary-health-check"
    }
  )
}

# CloudWatch Alarm for Health Check
resource "aws_cloudwatch_metric_alarm" "route53_health_check" {
  alarm_name          = "${var.environment}-route53-health-check-failed"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HealthCheckStatus"
  namespace           = "AWS/Route53"
  period              = 60
  statistic           = "Minimum"
  threshold           = 1
  alarm_description   = "Route53 health check failed"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  
  dimensions = {
    HealthCheckId = aws_route53_health_check.primary.id
  }
  
  tags = local.common_tags
}

# Failover Configuration (Primary-Secondary)
resource "aws_route53_record" "failover_primary" {
  count = var.enable_failover ? 1 : 0
  
  zone_id = aws_route53_zone.main.zone_id
  name    = "app.${var.domain_name}"
  type    = "A"
  
  set_identifier = "primary"
  
  failover_routing_policy {
    type = "PRIMARY"
  }
  
  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
  
  health_check_id = aws_route53_health_check.primary.id
}

resource "aws_route53_record" "failover_secondary" {
  count = var.enable_failover ? 1 : 0
  
  zone_id = aws_route53_zone.main.zone_id
  name    = "app.${var.domain_name}"
  type    = "A"
  
  set_identifier = "secondary"
  
  failover_routing_policy {
    type = "SECONDARY"
  }
  
  alias {
    name                   = var.secondary_alb_dns_name
    zone_id                = var.secondary_alb_zone_id
    evaluate_target_health = true
  }
}

# Geolocation Routing
resource "aws_route53_record" "geo_us" {
  count = var.enable_geo_routing ? 1 : 0
  
  zone_id = aws_route53_zone.main.zone_id
  name    = "geo.${var.domain_name}"
  type    = "A"
  
  set_identifier = "US"
  
  geolocation_routing_policy {
    country = "US"
  }
  
  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "geo_eu" {
  count = var.enable_geo_routing ? 1 : 0
  
  zone_id = aws_route53_zone.main.zone_id
  name    = "geo.${var.domain_name}"
  type    = "A"
  
  set_identifier = "EU"
  
  geolocation_routing_policy {
    continent = "EU"
  }
  
  alias {
    name                   = var.eu_alb_dns_name
    zone_id                = var.eu_alb_zone_id
    evaluate_target_health = true
  }
}

# Latency-Based Routing
resource "aws_route53_record" "latency_us_east" {
  count = var.enable_latency_routing ? 1 : 0
  
  zone_id = aws_route53_zone.main.zone_id
  name    = "latency.${var.domain_name}"
  type    = "A"
  
  set_identifier = "us-east-1"
  
  latency_routing_policy {
    region = "us-east-1"
  }
  
  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "latency_us_west" {
  count = var.enable_latency_routing ? 1 : 0
  
  zone_id = aws_route53_zone.main.zone_id
  name    = "latency.${var.domain_name}"
  type    = "A"
  
  set_identifier = "us-west-2"
  
  latency_routing_policy {
    region = "us-west-2"
  }
  
  alias {
    name                   = var.us_west_alb_dns_name
    zone_id                = var.us_west_alb_zone_id
    evaluate_target_health = true
  }
}

# Weighted Routing (Blue-Green Deployments)
resource "aws_route53_record" "weighted_blue" {
  count = var.enable_weighted_routing ? 1 : 0
  
  zone_id = aws_route53_zone.main.zone_id
  name    = "bg.${var.domain_name}"
  type    = "A"
  
  set_identifier = "blue"
  
  weighted_routing_policy {
    weight = var.blue_weight
  }
  
  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "weighted_green" {
  count = var.enable_weighted_routing ? 1 : 0
  
  zone_id = aws_route53_zone.main.zone_id
  name    = "bg.${var.domain_name}"
  type    = "A"
  
  set_identifier = "green"
  
  weighted_routing_policy {
    weight = var.green_weight
  }
  
  alias {
    name                   = var.green_alb_dns_name
    zone_id                = var.green_alb_zone_id
    evaluate_target_health = true
  }
}

# Query Logging
resource "aws_route53_query_log" "main" {
  depends_on = [aws_cloudwatch_log_resource_policy.route53_query_logging]
  
  cloudwatch_log_group_arn = aws_cloudwatch_log_group.route53_queries.arn
  zone_id                  = aws_route53_zone.main.zone_id
}

resource "aws_cloudwatch_log_group" "route53_queries" {
  name              = "/aws/route53/${var.domain_name}"
  retention_in_days = 30
  
  tags = local.common_tags
}

resource "aws_cloudwatch_log_resource_policy" "route53_query_logging" {
  policy_name = "${var.environment}-route53-query-logging"
  
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "route53.amazonaws.com"
      }
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.route53_queries.arn}:*"
    }]
  })
}

# DNSSEC Configuration
resource "aws_route53_key_signing_key" "main" {
  count = var.enable_dnssec ? 1 : 0
  
  hosted_zone_id             = aws_route53_zone.main.zone_id
  key_management_service_arn = aws_kms_key.dnssec[0].arn
  name                       = "${var.environment}-dnssec-ksk"
}

resource "aws_kms_key" "dnssec" {
  count = var.enable_dnssec ? 1 : 0
  
  description              = "KMS key for Route53 DNSSEC"
  deletion_window_in_days  = 30
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Route 53 DNSSEC Service"
        Effect = "Allow"
        Principal = {
          Service = "dnssec-route53.amazonaws.com"
        }
        Action = [
          "kms:DescribeKey",
          "kms:GetPublicKey",
          "kms:Sign"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow Route 53 DNSSEC to CreateGrant"
        Effect = "Allow"
        Principal = {
          Service = "dnssec-route53.amazonaws.com"
        }
        Action   = "kms:CreateGrant"
        Resource = "*"
        Condition = {
          Bool = {
            "kms:GrantIsForAWSResource" = "true"
          }
        }
      }
    ]
  })
  
  tags = local.common_tags
}

resource "aws_route53_hosted_zone_dnssec" "main" {
  count = var.enable_dnssec ? 1 : 0
  
  hosted_zone_id = aws_route53_key_signing_key.main[0].hosted_zone_id
  
  depends_on = [aws_route53_key_signing_key.main]
}
```


## ⚠️ Common Pitfalls

### Pitfall 1: Not Using VPC Endpoints

**❌ PROBLEM:**

```hcl
# EC2 instances in private subnet accessing S3/DynamoDB
# Traffic goes through NAT Gateway
# Results in:
# - NAT Gateway data transfer costs ($0.045/GB)
# - Slower performance
# - Unnecessary NAT dependency
```

**✅ SOLUTION:**

```hcl
# VPC Endpoint for S3 (Gateway Endpoint - Free!)
resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.main.id
  service_name = "com.amazonaws.${var.aws_region}.s3"
  
  route_table_ids = concat(
    [aws_route_table.public.id],
    aws_route_table.private[*].id
  )
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-s3-endpoint"
    }
  )
}

# VPC Endpoint for DynamoDB (Gateway Endpoint - Free!)
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id       = aws_vpc.main.id
  service_name = "com.amazonaws.${var.aws_region}.dynamodb"
  
  route_table_ids = aws_route_table.private[*].id
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-dynamodb-endpoint"
    }
  )
}

# Interface Endpoints for other services
resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-ssm-endpoint"
    }
  )
}

# Cost Savings: 1TB/month through NAT = $45
# Cost with VPC Endpoints (S3/DynamoDB): $0
# Annual savings: $540
```


### Pitfall 2: Single NAT Gateway for Production

**❌ PROBLEM:**

```hcl
# Single NAT Gateway for all AZs
resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id  # Only in one AZ!
}

# Problems:
# - Single point of failure
# - Cross-AZ data transfer charges
# - If AZ goes down, ALL private subnets lose internet
```

**✅ SOLUTION:**

```hcl
# NAT Gateway per AZ for high availability
resource "aws_nat_gateway" "main" {
  count = length(var.availability_zones)
  
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-nat-${var.availability_zones[count.index]}"
    }
  )
}

# Each private subnet routes to NAT in same AZ
resource "aws_route" "private_nat" {
  count = length(var.availability_zones)
  
  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main[count.index].id
}

# Cost: ~$32/month per NAT Gateway
# Production: Worth it for HA
# Dev: Use single NAT with var.single_nat_gateway = true
```


### Pitfall 3: Not Enabling RDS Deletion Protection

**❌ PROBLEM:**

```hcl
resource "aws_db_instance" "main" {
  identifier = "production-db"
  # ... other config ...
  
  deletion_protection = false  # DEFAULT!
  skip_final_snapshot = true   # DANGEROUS!
}

# terraform destroy
# Database permanently deleted with no backup!
# Data loss incident!
```

**✅ SOLUTION:**

```hcl
resource "aws_db_instance" "main" {
  identifier = "production-db"
  # ... other config ...
  
  # Prevent accidental deletion
  deletion_protection = var.environment == "production"
  
  # Always take final snapshot
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.environment}-db-final-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"
  
  # Backup configuration
  backup_retention_period = var.environment == "production" ? 30 : 7
  backup_window          = "03:00-04:00"
  
  # Also protect with lifecycle
  lifecycle {
    prevent_destroy = true  # Terraform will refuse to destroy
  }
  
  tags = local.common_tags
}

# Additional safety: S3 bucket lifecycle on snapshots
```


### Pitfall 4: Hardcoding Availability Zones

**❌ PROBLEM:**

```hcl
# Hardcoded AZs
resource "aws_subnet" "public" {
  count             = 3
  availability_zone = ["us-east-1a", "us-east-1b", "us-east-1c"][count.index]
  # Breaks when deployed to different region!
}
```

**✅ SOLUTION:**

```hcl
# Dynamic AZ discovery
data "aws_availability_zones" "available" {
  state = "available"
  
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

locals {
  # Use first 3 available AZs
  availability_zones = slice(data.aws_availability_zones.available.names, 0, 3)
}

resource "aws_subnet" "public" {
  count             = length(local.availability_zones)
  availability_zone = local.availability_zones[count.index]
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  
  tags = {
    Name = "${var.environment}-public-${local.availability_zones[count.index]}"
  }
}

# Works in any region!
```


### Pitfall 5: Not Tagging Resources Properly

**❌ PROBLEM:**

```hcl
resource "aws_instance" "web" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"
  # No tags!
}

# Problems:
# - Can't track costs per environment
# - Can't identify resource ownership
# - Can't automate based on tags
# - Compliance violations
```

**✅ SOLUTION:**

```hcl
# Provider-level default tags
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Environment = var.environment
      ManagedBy   = "Terraform"
      Project     = var.project_name
      Owner       = var.team_email
      CostCenter  = var.cost_center
      Compliance  = "SOC2"
    }
  }
}

# Resource-specific tags
resource "aws_instance" "web" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"
  
  tags = {
    Name        = "${var.environment}-web-server"
    Role        = "WebServer"
    BackupDaily = "true"
  }
  # Inherits all default_tags automatically
}

# Cost allocation tags enabled in AWS Console
# Now can track: Total cost by Environment, CostCenter, Owner
```


### Pitfall 6: Public S3 Buckets

**❌ PROBLEM:**

```hcl
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  # No public access block!
  # Default allows public access if policy permits
}

resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id
  
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"  # PUBLIC ACCESS!
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.data.arn}/*"
    }]
  })
}

# Data breach waiting to happen
```

**✅ SOLUTION:**

```hcl
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}

# ALWAYS block public access
resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# If you need public content, use CloudFront with OAC
resource "aws_cloudfront_distribution" "main" {
  # ... config ...
  
  origin {
    domain_name              = aws_s3_bucket.data.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.s3.id
  }
}

# Only CloudFront can access bucket
```


### Pitfall 7: Not Using IMDSv2

**❌ PROBLEM:**

```hcl
resource "aws_launch_template" "web" {
  image_id      = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"
  
  # Default uses IMDSv1 (vulnerable to SSRF attacks)
}

# IMDSv1 allows: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name
# SSRF vulnerability can steal IAM credentials!
```

**✅ SOLUTION:**

```hcl
resource "aws_launch_template" "web" {
  image_id      = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"
  
  # Enforce IMDSv2
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # IMDSv2 only
    http_put_response_hop_limit = 1           # Prevent forwarding
    instance_metadata_tags      = "enabled"
  }
}

# IMDSv2 requires token:
# TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
# curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```


### Pitfall 8: Not Using Secrets Manager for Passwords

**❌ PROBLEM:**

```hcl
resource "aws_db_instance" "main" {
  identifier = "production-db"
  username   = "admin"
  password   = "SuperSecret123!"  # Hardcoded in code!
  # Password visible in:
  # - Terraform state file
  # - Git history
  # - Plan output
  # - Terraform Cloud runs
}
```

**✅ SOLUTION:**

```hcl
# Generate random password
resource "random_password" "db_master" {
  length  = 32
  special = true
}

# Store in Secrets Manager
resource "aws_secretsmanager_secret" "db_password" {
  name_prefix             = "${var.environment}-db-password-"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id = aws_secretsmanager_secret.db_password.id
  secret_string = jsonencode({
    username = "dbadmin"
    password = random_password.db_master.result
    engine   = "postgres"
    host     = aws_db_instance.main.endpoint
  })
}

# Use in RDS
resource "aws_db_instance" "main" {
  identifier = "production-db"
  username   = "dbadmin"
  password   = random_password.db_master.result
  
  # Application retrieves from Secrets Manager
}

# Mark as sensitive
output "db_secret_arn" {
  value     = aws_secretsmanager_secret.db_password.arn
  sensitive = false  # ARN is safe to expose
}
```


### Pitfall 9: Missing CloudWatch Alarms

**❌ PROBLEM:**

```hcl
# Created RDS, EC2, ALB
# No monitoring
# No alerts
# Problems discovered by customers!
```

**✅ SOLUTION:**

```hcl
# SNS Topic for Alerts
resource "aws_sns_topic" "alerts" {
  name = "${var.environment}-alerts"
  
  tags = local.common_tags
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.ops_email
}

# RDS CPU Alarm
resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "${var.environment}-rds-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_actions       = [aws_sns_topic.alerts.arn]
  
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.id
  }
}

# ALB Target Health Alarm
resource "aws_cloudwatch_metric_alarm" "unhealthy_targets" {
  alarm_name          = "${var.environment}-unhealthy-targets"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Average"
  threshold           = 0
  alarm_actions       = [aws_sns_topic.alerts.arn]
  
  dimensions = {
    TargetGroup  = aws_lb_target_group.main.arn_suffix
    LoadBalancer = aws_lb.main.arn_suffix
  }
}

# Create alarms for ALL critical metrics
```


### Pitfall 10: Not Using Latest AMI

**❌ PROBLEM:**

```hcl
# Hardcoded AMI ID
resource "aws_instance" "web" {
  ami = "ami-0c55b159cbfafe1f0"  # From 2 years ago!
  # Missing security patches
  # Old software versions
}
```

**✅ SOLUTION:**

```hcl
# Always get latest AMI
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]
  
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
  
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  
  filter {
    name   = "state"
    values = ["available"]
  }
}

resource "aws_launch_template" "web" {
  image_id = data.aws_ami.amazon_linux_2023.id
  
  # Use lifecycle to prevent unexpected AMI changes
  lifecycle {
    create_before_destroy = true
  }
}

# Regularly apply to get latest AMI
# Use instance refresh for rolling updates
```


### Pitfall 11: Cross-AZ Data Transfer Costs

**❌ PROBLEM:**

```hcl
# ALB in us-east-1a, 1b, 1c
# EC2 instances only in us-east-1a
# RDS Multi-AZ: Primary in 1a, Standby in 1b

# Cross-AZ traffic:
# - ALB in 1b forwarding to EC2 in 1a
# - EC2 in 1a to RDS standby in 1b (read replica)
# Cost: $0.01/GB for cross-AZ = $10/TB
```

**✅ SOLUTION:**

```hcl
# Distribute instances across all AZs
resource "aws_autoscaling_group" "main" {
  vpc_zone_identifier = aws_subnet.private[*].id  # All AZs
  min_size            = 6  # 2 per AZ
  
  # AZ balancing
  capacity_rebalance = true
}

# Use cross-zone load balancing disabled for cost savings
resource "aws_lb" "main" {
  enable_cross_zone_load_balancing = false
  # ALB routes to instances in same AZ
}

# Or enable and accept the cost for better distribution
```


### Pitfall 12: Not Using Lifecycle Policies

**❌ PROBLEM:**

```hcl
resource "aws_s3_bucket" "logs" {
  bucket = "application-logs"
  # No lifecycle policy
  # Logs accumulate indefinitely
  # Storage costs grow exponentially
  # $0.023/GB/month × 100TB = $2,300/month!
}
```

**✅ SOLUTION:**

```hcl
resource "aws_s3_bucket" "logs" {
  bucket = "application-logs"
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  
  rule {
    id     = "log-retention"
    status = "Enabled"
    
    transition {
      days          = 30
      storage_class = "STANDARD_IA"  # $0.0125/GB
    }
    
    transition {
      days          = 90
      storage_class = "GLACIER_IR"   # $0.004/GB
    }
    
    expiration {
      days = 365  # Delete after 1 year
    }
  }
}

# Savings: 100TB × 12 months
# Without lifecycle: $27,600/year
# With lifecycle: ~$8,000/year
# Savings: $19,600/year
```


## 💡 Expert Tips from the Field

1. **"Use VPC Flow Logs with Athena for network debugging"** - Flow logs + S3 + Athena = queryable network traffic. Find security incidents, debug connectivity issues, track bandwidth usage.
2. **"Enable S3 Intelligent-Tiering for unknown access patterns"** - Automatically moves objects to cheaper tiers. No lifecycle rules needed. Saves 70% on storage with zero overhead.
3. **"Use AWS Systems Manager Session Manager instead of bastion hosts"** - No SSH keys to manage, full audit trail, no inbound ports. Eliminates bastion host costs (\$15/month/host).
4. **"Set S3 bucket_key_enabled = true for KMS encryption"** - Reduces KMS API calls by 99%, saves on KMS request costs. Essential for high-traffic buckets.
5. **"Use RDS Proxy for Lambda database connections"** - Prevents connection exhaustion, manages pooling. Critical for serverless applications accessing RDS.
6. **"Enable EBS gp3 instead of gp2 volumes"** - Same performance, 20% cheaper. 3000 IOPS and 125 MB/s included vs gp2's variable performance.
7. **"Use CloudFront Origin Shield for multi-region origins"** - Additional caching layer, reduces origin load by 50-60%. Worth \$50/month for high-traffic sites.
8. **"Set Auto Scaling Group capacity_rebalance = true"** - Proactively replaces Spot instances before interruption. Maintains application stability with Spot pricing.
9. **"Use Application Load Balancer path-based routing"** - One ALB for multiple services. Saves \$16/month per eliminated ALB. Route /api to service A, /admin to service B.
10. **"Enable RDS Performance Insights with 7-day retention"** - Free for 7 days, invaluable for query performance analysis. Identifies slow queries instantly.
11. **"Use DynamoDB on-demand for unpredictable workloads"** - Pay per request, no capacity planning. Provisioned mode only when traffic is consistent.
12. **"Set ALB deletion_protection = true for production"** - Prevents accidental deletion via console or API. Terraform can still delete with lifecycle workaround.
13. **"Use Security Group references instead of CIDR blocks"** - `security_groups = [aws_security_group.app.id]` better than `cidr_blocks`. Automatic updates when instances change.
14. **"Enable S3 bucket versioning before first write"** - Can't retroactively version. First write without versioning = unrecoverable if deleted.
15. **"Use Route 53 Alias records for AWS resources"** - Free queries vs CNAME (charged). Supports zone apex (example.com not just www.example.com).
16. **"Set RDS backup_retention_period = 7 minimum"** - Point-in-time recovery requires backups. Free for standard backup window. 7 days covers most recovery scenarios.
17. **"Use CloudWatch Logs Insights for log analysis"** - Built-in query language, no additional tools needed. Parse JSON logs, aggregate metrics, debug issues.
18. **"Enable ELB access logs for troubleshooting"** - Disabled by default. Essential for debugging 4xx/5xx errors. Store in S3 with lifecycle policy.
19. **"Use aws_lb_target_group health_check timeout < interval"** - timeout must be less than interval. Common mistake causes intermittent failures.
20. **"Set EBS volumes encrypted = true by default"** - Use aws_ebs_encryption_by_default. All new volumes encrypted automatically. No performance penalty.

## 🎯 Practical Exercises

### Exercise 1: Three-Tier VPC Architecture

**Difficulty:** Intermediate
**Time:** 45 minutes
**Objective:** Build production VPC with public, private, and database tiers

**Prerequisites:**

- AWS account
- Terraform 1.15+
- Basic understanding of networking

**Steps:**

1. Create VPC with 3 availability zones:
```bash
mkdir three-tier-vpc
cd three-tier-vpc
```

2. Use the networking code from earlier in this chapter
3. Deploy and verify:
```bash
terraform init
terraform plan
terraform apply

# Verify resources
aws ec2 describe-vpcs --filters "Name=tag:Name,Values=production-vpc"
aws ec2 describe-subnets --filters "Name=vpc-id,Values=vpc-xxxxx"
aws ec2 describe-nat-gateways
aws ec2 describe-internet-gateways
```

4. Test connectivity:
```bash
# Launch test instance in public subnet
# SSH and verify internet access

# Launch test instance in private subnet
# Verify internet access through NAT
# Verify no direct public IP
```

**Validation:**

- 3 public subnets with internet gateway route
- 3 private subnets with NAT gateway routes
- 3 database subnets with no internet access
- VPC Flow Logs enabled

**Challenge:** Add VPC peering to another VPC in different region.

### Exercise 2: Auto Scaling Web Application

**Difficulty:** Advanced
**Time:** 60 minutes
**Objective:** Deploy Auto Scaling Group with ALB and health checks

**Steps:**

1. Use compute code from earlier chapter
2. Create simple web application:
```bash
# user_data.sh
#!/bin/bash
yum update -y
yum install -y httpd
systemctl start httpd
systemctl enable httpd

cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<body>
<h1>Instance: $(ec2-metadata --instance-id)</h1>
</body>
</html>
EOF

cat > /var/www/html/health << 'EOF'
OK
EOF
```

3. Deploy:
```bash
terraform apply
```

4. Test scaling:
```bash
# Generate load
ab -n 10000 -c 100 http://your-alb-dns/

# Watch Auto Scaling
aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names production-asg

# Verify new instances launch
```

**Validation:**

- ALB distributes traffic across instances
- Health checks mark unhealthy instances
- Auto Scaling launches new instances under load
- Target tracking maintains 70% CPU

**Challenge:** Implement blue-green deployment using two target groups.

### Exercise 3: RDS with Read Replica

**Difficulty:** Intermediate
**Time:** 40 minutes
**Objective:** Deploy RDS with automated backups and read replica

**Steps:**

1. Use RDS code from database section
2. Deploy primary:
```bash
terraform apply -target=aws_db_instance.main
```

3. Create read replica:
```bash
terraform apply
```

4. Test replication:
```bash
# Connect to primary
psql -h primary-endpoint -U dbadmin -d mydb

# Create test data
CREATE TABLE test (id SERIAL PRIMARY KEY, data TEXT);
INSERT INTO test (data) VALUES ('test1'), ('test2');

# Connect to replica
psql -h replica-endpoint -U dbadmin -d mydb

# Verify data replicated
SELECT * FROM test;
```

**Validation:**

- Primary accepts writes
- Replica replicates data within seconds
- Automated backups enabled
- Performance Insights active

**Challenge:** Add automated failover using Route 53 health checks.

### Exercise 4: S3 with CloudFront CDN

**Difficulty:** Beginner
**Time:** 30 minutes
**Objective:** Deploy S3 bucket with CloudFront distribution

**Steps:**

1. Use CloudFront code from global services section
2. Upload test content:
```bash
# Create test files
echo "<h1>Test Page</h1>" > index.html
aws s3 cp index.html s3://your-cdn-bucket/

# Create different cache-control headers
aws s3 cp logo.png s3://your-cdn-bucket/ \
  --cache-control "max-age=31536000"
```

3. Test CDN:
```bash
# Access via CloudFront
curl https://your-distribution.cloudfront.net/

# Check cache headers
curl -I https://your-distribution.cloudfront.net/logo.png

# Verify edge location
# X-Cache: Hit from cloudfront
```

**Validation:**

- CloudFront serves content
- Cache headers correct
- Origin access control blocks direct S3 access
- HTTPS only (no HTTP)

**Challenge:** Add Lambda@Edge function for A/B testing.

### Exercise 5: Complete Monitoring Stack

**Difficulty:** Advanced
**Time:** 50 minutes
**Objective:** Set up comprehensive monitoring with alarms

**Steps:**

1. Create CloudWatch dashboard:
```hcl
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.environment}-dashboard"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization", {stat = "Average"}],
            ["AWS/RDS", "CPUUtilization", {stat = "Average"}],
            ["AWS/ApplicationELB", "TargetResponseTime", {stat = "Average"}]
          ]
          period = 300
          stat   = "Average"
          region = var.aws_region
          title  = "System Health"
        }
      }
    ]
  })
}
```

2. Create comprehensive alarms (from pitfall \#9)
3. Test alerting:
```bash
# Trigger CPU alarm
stress-ng --cpu 4 --timeout 600s

# Verify SNS email received
# Check alarm state
aws cloudwatch describe-alarms --alarm-names production-ec2-high-cpu
```

**Validation:**

- All critical metrics have alarms
- SNS notifications delivered
- Dashboard shows key metrics
- Alarm history tracked

**Challenge:** Integrate with PagerDuty or Slack for advanced alerting.

## Key Takeaways

- VPC architecture with proper subnet segmentation (public, private, database) provides security through network isolation while enabling controlled internet access via NAT gateways
- Auto Scaling Groups with Launch Templates enable elastic compute capacity that scales based on demand, reducing costs during low traffic and maintaining performance during peaks
- S3 lifecycle policies combined with versioning provide cost-effective storage (\$0.004/GB for Glacier vs \$0.023/GB for Standard) while maintaining data recovery capabilities
- RDS Multi-AZ deployments with automated backups ensure database high availability with automatic failover in under 2 minutes during AZ failures
- Security Groups should reference other security groups rather than CIDR blocks, creating dynamic security relationships that update automatically as infrastructure changes
- CloudFront with Origin Access Control protects S3 content while delivering it globally with 50-90% latency reduction through edge caching
- VPC endpoints (Gateway for S3/DynamoDB, Interface for other services) eliminate NAT gateway costs for AWS service access, saving \$0.045/GB in data transfer fees


## What's Next

With core AWS services mastered, you're ready to package reusable infrastructure components. In **Chapter 6: Terraform Modules**, you'll learn how to design modular architectures, create shareable modules following HashiCorp's standards, publish modules to private registries, implement versioning strategies, and handle module dependencies. You'll explore composition patterns for complex infrastructures, testing methodologies for module reliability, and upgrade strategies for production modules. Modules transform infrastructure code from project-specific configurations into reusable building blocks that accelerate development across teams while ensuring consistency and reducing errors.

## Additional Resources

**Official AWS Documentation:**

- [AWS VPC User Guide](https://docs.aws.amazon.com/vpc/) - Complete VPC networking documentation
- [Amazon EC2 Auto Scaling](https://docs.aws.amazon.com/autoscaling/ec2/) - Auto Scaling best practices
- [Amazon RDS User Guide](https://docs.aws.amazon.com/rds/) - RDS deployment and management
- [Amazon S3 Developer Guide](https://docs.aws.amazon.com/s3/) - S3 features and configuration

**Terraform AWS Provider:**

- [AWS Provider Documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs) - Complete resource reference
- [Terraform AWS Modules](https://github.com/terraform-aws-modules) - Community-maintained modules
- [AWS Provider Changelog](https://github.com/hashicorp/terraform-provider-aws/blob/main/CHANGELOG.md) - Latest updates

**AWS Architecture:**

- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/) - Architecture best practices
- [AWS Architecture Center](https://aws.amazon.com/architecture/) - Reference architectures
- [AWS Prescriptive Guidance](https://aws.amazon.com/prescriptive-guidance/) - Implementation guides

**Security Best Practices:**

- [AWS Security Best Practices](https://aws.amazon.com/security/best-practices/) - Security guidelines
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services) - Security hardening
- [AWS Security Hub](https://aws.amazon.com/security-hub/) - Security posture management

**Cost Optimization:**

- [AWS Cost Optimization](https://aws.amazon.com/pricing/cost-optimization/) - Cost-saving strategies
- [AWS Pricing Calculator](https://calculator.aws/) - Cost estimation
- [Infracost](https://www.infracost.io/) - Terraform cost estimation

**Monitoring and Observability:**

- [Amazon CloudWatch](https://docs.aws.amazon.com/cloudwatch/) - Monitoring documentation
- [AWS X-Ray](https://aws.amazon.com/xray/) - Distributed tracing
- [AWS Systems Manager](https://docs.aws.amazon.com/systems-manager/) - Operations management

***

**Remember:** Core AWS services are the building blocks of cloud infrastructure. Master VPC networking for security isolation, Auto Scaling for elasticity, RDS for managed databases, and S3 for scalable storage. Always enable encryption at rest and in transit, implement proper IAM least-privilege policies, use VPC endpoints to reduce costs, and create comprehensive CloudWatch alarms for production visibility. Security, reliability, and cost optimization must be built in from day one—retrofitting is expensive and risky!



