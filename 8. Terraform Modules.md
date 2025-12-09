# Chapter 8: Terraform Modules

## Introduction

Terraform modules are the fundamental building blocks that transform infrastructure code from one-off scripts into reusable, testable, and maintainable components. Without modules, every team writes their own VPC configuration, security groups, and load balancer definitions—each subtly different, each with unique bugs, each requiring separate updates when vulnerabilities emerge. With modules, you write infrastructure once, test it thoroughly, version it semantically, and deploy it consistently across dozens of environments and teams. The difference between managing 50 resources and managing 5,000 resources isn't writing more code—it's writing better abstractions.

Modules solve the composability problem at the heart of infrastructure as code. A well-designed module encapsulates complexity behind a clean interface: input variables define configuration, output values expose dependencies, and internal resources implement best practices automatically. Users don't need to know that your VPC module creates flow logs, enables DNS hostnames, and configures DHCP options—they simply pass a CIDR block and receive a production-ready network. This abstraction enables teams to move fast while maintaining security and compliance standards that would be impossible to enforce in raw resource definitions.

This chapter covers the complete module lifecycle from creation to deprecation. You'll learn module design patterns that maximize reusability, composition strategies for building complex architectures from simple components, versioning practices that enable safe updates across hundreds of deployments, and testing methodologies using Terratest that catch breaking changes before they reach production. Whether you're extracting your first module from duplicated code or managing a private registry with 50+ modules serving multiple teams, these patterns will help you build infrastructure components that scale with your organization.

## Creating Reusable Modules

### Module Design Principles

A well-designed module follows the single responsibility principle—it does one thing and does it completely.

**Good Module Scope:**

- VPC with subnets, route tables, internet gateway, NAT gateways
- RDS instance with subnet group, parameter group, security group
- Application Load Balancer with target groups and listeners
- ECS cluster with service, task definition, and auto-scaling

**Poor Module Scope (Too Broad):**

- "Complete application" module that creates VPC, ALB, ECS, RDS, S3, CloudFront
- Overly coupled components that can't be used independently
- Modules that try to support every possible configuration option

**Poor Module Scope (Too Narrow):**

- Single security group rule as a module
- Individual subnet as a module
- Resources that provide no abstraction value


### Standard Module Structure

Every module should follow HashiCorp's standard structure:

```
terraform-aws-vpc/
├── README.md              # Module documentation
├── main.tf                # Primary resource definitions
├── variables.tf           # Input variable declarations
├── outputs.tf             # Output value declarations
├── versions.tf            # Terraform and provider version constraints
├── locals.tf              # Local value definitions (optional)
├── data.tf                # Data source definitions (optional)
│
├── examples/              # Example usage
│   ├── complete/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   └── simple/
│       └── main.tf
│
├── modules/               # Nested sub-modules (optional)
│   ├── private-subnets/
│   └── public-subnets/
│
└── tests/                 # Automated tests
    ├── integration_test.go
    └── unit_test.go
```


### Example: VPC Module

```hcl
# terraform-aws-vpc/versions.tf
terraform {
  required_version = ">= 1.11.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# terraform-aws-vpc/variables.tf
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "Must be valid IPv4 CIDR."
  }
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, production)"
  type        = string
}

variable "availability_zones" {
  description = "List of availability zones for subnets"
  type        = list(string)
  
  validation {
    condition     = length(var.availability_zones) >= 2
    error_message = "At least 2 availability zones required for high availability."
  }
}

variable "enable_nat_gateway" {
  description = "Enable NAT gateway for private subnets"
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Use single NAT gateway (cost savings for non-prod)"
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

variable "enable_flow_logs" {
  description = "Enable VPC flow logs"
  type        = bool
  default     = true
}

variable "flow_logs_retention_days" {
  description = "Retention period for VPC flow logs"
  type        = number
  default     = 30
}

variable "tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}

# terraform-aws-vpc/locals.tf
locals {
  # Calculate subnet CIDRs
  public_subnet_cidrs  = [for i in range(length(var.availability_zones)) : cidrsubnet(var.vpc_cidr, 8, i)]
  private_subnet_cidrs = [for i in range(length(var.availability_zones)) : cidrsubnet(var.vpc_cidr, 8, i + 10)]
  database_subnet_cidrs = [for i in range(length(var.availability_zones)) : cidrsubnet(var.vpc_cidr, 8, i + 20)]
  
  # NAT gateway count
  nat_gateway_count = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : length(var.availability_zones)) : 0
  
  # Common tags
  common_tags = merge(
    var.tags,
    {
      Environment = var.environment
      ManagedBy   = "Terraform"
      Module      = "terraform-aws-vpc"
    }
  )
}

# terraform-aws-vpc/main.tf
# VPC
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = var.enable_dns_hostnames
  enable_dns_support   = var.enable_dns_support
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-vpc"
    }
  )
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-igw"
    }
  )
}

# Public Subnets
resource "aws_subnet" "public" {
  count = length(var.availability_zones)
  
  vpc_id                  = aws_vpc.main.id
  cidr_block              = local.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-public-${var.availability_zones[count.index]}"
      Type = "public"
    }
  )
}

# Private Subnets
resource "aws_subnet" "private" {
  count = length(var.availability_zones)
  
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.private_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-private-${var.availability_zones[count.index]}"
      Type = "private"
    }
  )
}

# Database Subnets
resource "aws_subnet" "database" {
  count = length(var.availability_zones)
  
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.database_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-database-${var.availability_zones[count.index]}"
      Type = "database"
    }
  )
}

# Elastic IPs for NAT Gateways
resource "aws_eip" "nat" {
  count  = local.nat_gateway_count
  domain = "vpc"
  
  depends_on = [aws_internet_gateway.main]
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-nat-eip-${count.index + 1}"
    }
  )
}

# NAT Gateways
resource "aws_nat_gateway" "main" {
  count = local.nat_gateway_count
  
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[var.single_nat_gateway ? 0 : count.index].id
  
  depends_on = [aws_internet_gateway.main]
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-nat-${count.index + 1}"
    }
  )
}

# Public Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-public-rt"
    }
  )
}

# Public Route Table Associations
resource "aws_route_table_association" "public" {
  count = length(var.availability_zones)
  
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Private Route Tables
resource "aws_route_table" "private" {
  count = local.nat_gateway_count
  
  vpc_id = aws_vpc.main.id
  
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[var.single_nat_gateway ? 0 : count.index].id
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-private-rt-${count.index + 1}"
    }
  )
}

# Private Route Table Associations
resource "aws_route_table_association" "private" {
  count = length(var.availability_zones)
  
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[var.single_nat_gateway ? 0 : count.index].id
}

# Database Route Table
resource "aws_route_table" "database" {
  vpc_id = aws_vpc.main.id
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-database-rt"
    }
  )
}

# Database Route Table Associations
resource "aws_route_table_association" "database" {
  count = length(var.availability_zones)
  
  subnet_id      = aws_subnet.database[count.index].id
  route_table_id = aws_route_table.database.id
}

# VPC Flow Logs
resource "aws_flow_log" "main" {
  count = var.enable_flow_logs ? 1 : 0
  
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs[^0].arn
  log_destination = aws_cloudwatch_log_group.flow_logs[^0].arn
  
  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0
  
  name              = "/aws/vpc/${var.environment}-flow-logs"
  retention_in_days = var.flow_logs_retention_days
  
  tags = local.common_tags
}

resource "aws_iam_role" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0
  
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

resource "aws_iam_role_policy" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0
  
  name = "${var.environment}-vpc-flow-logs-policy"
  role = aws_iam_role.flow_logs[^0].id
  
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

# terraform-aws-vpc/outputs.tf
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "internet_gateway_id" {
  description = "ID of the Internet Gateway"
  value       = aws_internet_gateway.main.id
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

output "public_route_table_id" {
  description = "ID of public route table"
  value       = aws_route_table.public.id
}

output "private_route_table_ids" {
  description = "IDs of private route tables"
  value       = aws_route_table.private[*].id
}

output "database_route_table_id" {
  description = "ID of database route table"
  value       = aws_route_table.database.id
}

# terraform-aws-vpc/README.md
# AWS VPC Terraform Module

Production-ready VPC module with public, private, and database subnets.

## Features

- Multi-AZ VPC with public, private, and database subnets
- Internet Gateway for public subnet internet access
- NAT Gateways for private subnet internet access (optional)
- VPC Flow Logs to CloudWatch (optional)
- Automatic CIDR calculation for subnets
- High availability with multiple AZs
- Cost optimization with single NAT gateway option

## Usage

```

module "vpc" {
source = "git::https://github.com/myorg/terraform-aws-vpc.git?ref=v2.0.0"

vpc_cidr           = "10.0.0.0/16"
environment        = "production"
availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]

enable_nat_gateway   = true
single_nat_gateway   = false  \# Multi-AZ for production
enable_flow_logs     = true

tags = {
Project = "MyApp"
Owner   = "Platform Team"
}
}

```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| vpc_cidr | CIDR block for VPC | string | n/a | yes |
| environment | Environment name | string | n/a | yes |
| availability_zones | List of AZs | list(string) | n/a | yes |
| enable_nat_gateway | Enable NAT gateway | bool | true | no |
| single_nat_gateway | Use single NAT (cost savings) | bool | false | no |
| enable_flow_logs | Enable VPC flow logs | bool | true | no |
| tags | Additional tags | map(string) | {} | no |

## Outputs

| Name | Description |
|------|-------------|
| vpc_id | VPC ID |
| public_subnet_ids | Public subnet IDs |
| private_subnet_ids | Private subnet IDs |
| database_subnet_ids | Database subnet IDs |

## Examples

See `examples/` directory for complete usage examples.
```


### Module Best Practices

**Input Variables:**

- Provide sensible defaults where possible
- Use validation blocks to catch invalid inputs early
- Document every variable with descriptions
- Use appropriate types (string, number, bool, list, map, object)
- Mark sensitive variables with `sensitive = true`

**Outputs:**

- Only expose outputs that consumers actually need
- Document each output with a description
- Mark sensitive outputs with `sensitive = true`
- Use consistent naming conventions

**Documentation:**

- Maintain comprehensive README.md with examples
- Include input/output tables (use terraform-docs to generate)
- Provide both simple and complete examples
- Document requirements and dependencies


## Module Composition and Nesting

Compose complex infrastructure from smaller, focused modules.

### Nested Module Pattern

```
terraform-aws-app-stack/
├── main.tf
├── variables.tf
├── outputs.tf
├── versions.tf
│
└── modules/
    ├── networking/     # VPC sub-module
    ├── compute/        # ECS sub-module
    ├── database/       # RDS sub-module
    └── monitoring/     # CloudWatch sub-module
```

**Parent Module (terraform-aws-app-stack/main.tf):**

```hcl
# Call networking sub-module
module "networking" {
  source = "./modules/networking"
  
  vpc_cidr           = var.vpc_cidr
  environment        = var.environment
  availability_zones = var.availability_zones
  
  tags = local.common_tags
}

# Call compute sub-module
module "compute" {
  source = "./modules/compute"
  
  environment        = var.environment
  vpc_id             = module.networking.vpc_id
  private_subnet_ids = module.networking.private_subnet_ids
  
  instance_type    = var.instance_type
  desired_capacity = var.desired_capacity
  
  tags = local.common_tags
}

# Call database sub-module
module "database" {
  source = "./modules/database"
  
  environment         = var.environment
  vpc_id              = module.networking.vpc_id
  database_subnet_ids = module.networking.database_subnet_ids
  
  instance_class      = var.db_instance_class
  allocated_storage   = var.db_allocated_storage
  
  allowed_security_groups = [module.compute.security_group_id]
  
  tags = local.common_tags
}

# Call monitoring sub-module
module "monitoring" {
  source = "./modules/monitoring"
  
  environment = var.environment
  
  alarm_sns_topic_arn = var.alarm_sns_topic_arn
  
  # Pass resource IDs for monitoring
  alb_arn         = module.compute.alb_arn
  ecs_cluster_id  = module.compute.ecs_cluster_id
  rds_instance_id = module.database.rds_instance_id
  
  tags = local.common_tags
}
```


### Composition Best Practices

- Keep sub-modules focused on a single service or capability
- Pass dependencies explicitly through outputs/inputs
- Avoid deep nesting (2-3 levels maximum)
- Use `depends_on` sparingly—rely on implicit dependencies through outputs
- Document module dependencies in README


## Using Community Modules from Terraform Registry

The Terraform Registry hosts thousands of community modules.

### Finding Quality Modules

**Evaluation Criteria:**

- ✅ Official/verified badge from HashiCorp
- ✅ Recent updates (within last 6 months)
- ✅ High download count
- ✅ Comprehensive documentation
- ✅ Active GitHub repository
- ✅ Good test coverage
- ✅ Semantic versioning

**Example: Using Official AWS VPC Module:**

```hcl
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
  
  name = "${var.environment}-vpc"
  cidr = "10.0.0.0/16"
  
  azs             = ["us-east-1a", "us-east-1b", "us-east-1c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
  
  enable_nat_gateway = true
  enable_vpn_gateway = false
  
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}
```

**Popular Community Modules:**

- `terraform-aws-modules/vpc/aws` - AWS VPC
- `terraform-aws-modules/security-group/aws` - Security Groups
- `terraform-aws-modules/eks/aws` - EKS Cluster
- `terraform-aws-modules/rds/aws` - RDS Instances
- `terraform-aws-modules/alb/aws` - Application Load Balancer


### Module Sources

```hcl
# Terraform Registry
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
}

# GitHub (HTTPS)
module "vpc" {
  source = "github.com/terraform-aws-modules/terraform-aws-vpc?ref=v5.0.0"
}

# GitHub (SSH)
module "vpc" {
  source = "git@github.com:terraform-aws-modules/terraform-aws-vpc.git?ref=v5.0.0"
}

# Git with specific branch/tag
module "vpc" {
  source = "git::https://github.com/myorg/terraform-modules.git//vpc?ref=main"
}

# Local path (for development)
module "vpc" {
  source = "../../modules/vpc"
}

# S3 bucket
module "vpc" {
  source = "s3::https://s3.amazonaws.com/my-modules/vpc.zip"
}
```


## Module Versioning and Lifecycle Management

Semantic versioning is essential for safe module evolution.

### Semantic Versioning (SemVer)

Format: `MAJOR.MINOR.PATCH` (e.g., `v2.3.1`)

- **MAJOR** (v2.0.0): Breaking changes—requires user action
- **MINOR** (v1.3.0): New features—backward compatible
- **PATCH** (v1.2.4): Bug fixes—backward compatible

**Version Constraints in Terraform:**

```hcl
# Exact version (not recommended for flexibility)
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"
}

# Pessimistic constraint (recommended)
# Allows 5.1.x and 5.2.x, but not 6.0.0
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.1"
}

# Range
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = ">= 5.0.0, < 6.0.0"
}

# Greater than or equal
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = ">= 5.1.0"
}
```


### Module Release Strategy

**Development Workflow:**

```bash
# 1. Create feature branch
git checkout -b feature/add-ipv6-support

# 2. Make changes and test
terraform init
terraform plan
terraform apply

# 3. Commit and push
git add .
git commit -m "feat: add IPv6 support"
git push origin feature/add-ipv6-support

# 4. Create pull request
# 5. Review and merge to main

# 6. Tag release
git checkout main
git pull
git tag -a v2.1.0 -m "Release v2.1.0: Add IPv6 support"
git push origin v2.1.0
```

**Changelog (CHANGELOG.md):**

```markdown
# Changelog

## [2.1.0] - 2025-12-08

### Added
- IPv6 support with dual-stack configuration
- New variable `enable_ipv6` for IPv6 enablement
- New output `ipv6_cidr_block` for VPC IPv6 CIDR

### Changed
- Updated AWS provider requirement to >= 5.30

### Fixed
- NAT gateway creation timing issue

## [2.0.0] - 2025-11-15

### Breaking Changes
- Removed deprecated `create_vpc` variable
- Changed `subnet_tags` variable structure from list to map

### Migration Guide
See MIGRATION.md for upgrade instructions.
```


## Module Deprecation Strategies

Handle breaking changes gracefully:

### Deprecation Warnings

```hcl
# variables.tf
variable "old_variable_name" {
  description = "DEPRECATED: Use new_variable_name instead. Will be removed in v3.0.0"
  type        = string
  default     = null
}

variable "new_variable_name" {
  description = "New variable with improved naming"
  type        = string
  default     = null
}

# main.tf
locals {
  # Support both old and new variable during transition
  actual_value = coalesce(var.new_variable_name, var.old_variable_name)
}

# Emit warning if old variable used
resource "null_resource" "deprecation_warning" {
  count = var.old_variable_name != null ? 1 : 0
  
  triggers = {
    warning = "WARNING: old_variable_name is deprecated. Use new_variable_name instead."
  }
  
  provisioner "local-exec" {
    command = "echo '${self.triggers.warning}' >&2"
  }
}
```


### Migration Guides

**MIGRATION.md:**

```markdown
# Migration Guide: v1.x to v2.0

## Breaking Changes

### 1. Subnet Tags Structure Changed

**Before (v1.x):**
```

module "vpc" {
source = "..."

subnet_tags = ["tag1", "tag2"]
}

```

**After (v2.0):**
```

module "vpc" {
source = "..."

subnet_tags = {
public  = { Type = "public" }
private = { Type = "private" }
}
}

```

### 2. Removed create_vpc Variable

The `create_vpc` variable has been removed. Use conditional module calls instead:

**Before:**
```

module "vpc" {
source     = "..."
create_vpc = var.should_create
}

```

**After:**
```

module "vpc" {
count  = var.should_create ? 1 : 0
source = "..."
}

```

## Upgrade Steps

1. Update module version in your configuration
2. Run `terraform init -upgrade`
3. Apply changes from this migration guide
4. Run `terraform plan` to review changes
5. Apply with `terraform apply`
```


## Input Variables and Output Values Best Practices

### Advanced Variable Patterns

```hcl
# variables.tf

# Object type for complex configuration
variable "vpc_config" {
  description = "VPC configuration object"
  type = object({
    cidr_block           = string
    enable_dns_hostnames = optional(bool, true)
    enable_dns_support   = optional(bool, true)
    
    public_subnets = list(object({
      cidr_block        = string
      availability_zone = string
    }))
    
    private_subnets = list(object({
      cidr_block        = string
      availability_zone = string
    }))
  })
  
  validation {
    condition     = can(cidrhost(var.vpc_config.cidr_block, 0))
    error_message = "VPC CIDR must be valid IPv4 CIDR."
  }
}

# Map of objects for multiple instances
variable "databases" {
  description = "Map of database configurations"
  type = map(object({
    instance_class    = string
    allocated_storage = number
    engine_version    = string
    multi_az          = bool
  }))
  default = {}
}

# Dynamic default based on environment
variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = null
  
  validation {
    condition = var.instance_type == null || contains([
      "t3.micro", "t3.small", "t3.medium", "t3.large"
    ], var.instance_type)
    error_message = "Instance type must be valid t3 type."
  }
}

locals {
  # Computed default if not provided
  instance_type = coalesce(
    var.instance_type,
    var.environment == "production" ? "t3.large" : "t3.micro"
  )
}

# Sensitive variable
variable "database_password" {
  description = "Database master password"
  type        = string
  sensitive   = true
}
```


### Advanced Output Patterns

```hcl
# outputs.tf

# Simple output
output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

# Conditional output
output "nat_gateway_ips" {
  description = "Elastic IPs of NAT Gateways"
  value       = var.enable_nat_gateway ? aws_eip.nat[*].public_ip : []
}

# Sensitive output
output "database_password" {
  description = "Database master password"
  value       = random_password.db.result
  sensitive   = true
}

# Complex object output
output "vpc_config" {
  description = "Complete VPC configuration"
  value = {
    vpc_id     = aws_vpc.main.id
    vpc_cidr   = aws_vpc.main.cidr_block
    
    public_subnets = {
      ids   = aws_subnet.public[*].id
      cidrs = aws_subnet.public[*].cidr_block
      azs   = aws_subnet.public[*].availability_zone
    }
    
    private_subnets = {
      ids   = aws_subnet.private[*].id
      cidrs = aws_subnet.private[*].cidr_block
      azs   = aws_subnet.private[*].availability_zone
    }
    
    nat_gateways = var.enable_nat_gateway ? {
      ids = aws_nat_gateway.main[*].id
      ips = aws_eip.nat[*].public_ip
    } : null
  }
}

# Output for module chaining
output "security_group_rules" {
  description = "Security group rules for downstream modules"
  value = {
    alb_sg_id = aws_security_group.alb.id
    ecs_sg_id = aws_security_group.ecs.id
    rds_sg_id = aws_security_group.rds.id
  }
}
```


## Module Testing Approaches

Comprehensive testing ensures module reliability.

### Testing Pyramid

1. **Static Analysis** (fastest, cheapest)
    - `terraform fmt -check`
    - `terraform validate`
    - `tflint`
    - `tfsec` / `checkov`
2. **Unit Tests** (fast, isolated)
    - Test individual resources
    - Mock external dependencies
    - Validate variable transformations
3. **Integration Tests** (slower, realistic)
    - Deploy to real AWS account
    - Verify resource creation
    - Test resource interactions
4. **End-to-End Tests** (slowest, most comprehensive)
    - Full deployment
    - Application-level testing
    - Performance and security validation

### Terratest Integration Tests

**Installation:**

```bash
# Install Go
brew install go  # macOS
# or download from golang.org

# Initialize Go module
cd tests/
go mod init github.com/myorg/terraform-aws-vpc/tests
go get github.com/gruntwork-io/terratest/modules/terraform
go get github.com/stretchr/testify/assert
```

**Example Test (tests/vpc_test.go):**

```go
package test

import (
    "testing"
    
    "github.com/gruntwork-io/terratest/modules/aws"
    "github.com/gruntwork-io/terratest/modules/terraform"
    "github.com/stretchr/testify/assert"
)

func TestVPCModule(t *testing.T) {
    t.Parallel()
    
    // Define expected values
    expectedVPCCIDR := "10.0.0.0/16"
    expectedEnvironment := "test"
    expectedRegion := "us-east-1"
    
    // Terraform options
    terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
        // Path to Terraform code
        TerraformDir: "../examples/complete",
        
        // Variables to pass
        Vars: map[string]interface{}{
            "vpc_cidr":           expectedVPCCIDR,
            "environment":        expectedEnvironment,
            "availability_zones": []string{"us-east-1a", "us-east-1b"},
        },
        
        // Environment variables
        EnvVars: map[string]string{
            "AWS_DEFAULT_REGION": expectedRegion,
        },
    })
    
    // Clean up resources at end of test
    defer terraform.Destroy(t, terraformOptions)
    
    // Deploy infrastructure
    terraform.InitAndApply(t, terraformOptions)
    
    // Retrieve outputs
    vpcID := terraform.Output(t, terraformOptions, "vpc_id")
    publicSubnetIDs := terraform.OutputList(t, terraformOptions, "public_subnet_ids")
    privateSubnetIDs := terraform.OutputList(t, terraformOptions, "private_subnet_ids")
    
    // Assertions
    assert.NotEmpty(t, vpcID, "VPC ID should not be empty")
    assert.Len(t, publicSubnetIDs, 2, "Should have 2 public subnets")
    assert.Len(t, privateSubnetIDs, 2, "Should have 2 private subnets")
    
    // Verify VPC exists in AWS
    vpc := aws.GetVpcById(t, vpcID, expectedRegion)
    assert.Equal(t, expectedVPCCIDR, vpc.CidrBlock, "VPC CIDR should match")
    
    // Verify subnets exist
    for _, subnetID := range publicSubnetIDs {
        subnet := aws.GetSubnetById(t, subnetID, expectedRegion)
        assert.Equal(t, vpcID, subnet.VpcId, "Subnet should belong to VPC")
        assert.True(t, subnet.MapPublicIpOnLaunch, "Public subnet should auto-assign public IPs")
    }
    
    // Verify NAT gateways exist
    natGateways := aws.GetNatGatewaysInVpc(t, vpcID, expectedRegion)
    assert.GreaterOrEqual(t, len(natGateways), 1, "Should have at least 1 NAT gateway")
    
    // Verify Internet Gateway exists
    igw := aws.GetInternetGatewayForVpc(t, vpcID, expectedRegion)
    assert.NotNil(t, igw, "Internet Gateway should exist")
}

// Test with single NAT gateway (cost optimization)
func TestVPCModuleSingleNAT(t *testing.T) {
    t.Parallel()
    
    terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
        TerraformDir: "../examples/complete",
        
        Vars: map[string]interface{}{
            "vpc_cidr":           "10.0.0.0/16",
            "environment":        "dev",
            "availability_zones": []string{"us-east-1a", "us-east-1b"},
            "single_nat_gateway": true,
        },
    })
    
    defer terraform.Destroy(t, terraformOptions)
    terraform.InitAndApply(t, terraformOptions)
    
    vpcID := terraform.Output(t, terraformOptions, "vpc_id")
    natGateways := aws.GetNatGatewaysInVpc(t, vpcID, "us-east-1")
    
    // Should have exactly 1 NAT gateway
    assert.Len(t, natGateways, 1, "Should have exactly 1 NAT gateway")
}
```

**Run Tests:**

```bash
cd tests/
go test -v -timeout 30m
```


### CI/CD Integration

**GitHub Actions (.github/workflows/module-test.yml):**

```yaml
name: Module Tests

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  validate:
    name: Validate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.11.0
      
      - name: Terraform Format
        run: terraform fmt -check -recursive
      
      - name: Terraform Init
        run: terraform init
        working-directory: examples/complete
      
      - name: Terraform Validate
        run: terraform validate
        working-directory: examples/complete
  
  security:
    name: Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run tfsec
        uses: aquasecurity/tfsec-action@v1.0.3
      
      - name: Run Checkov
        uses: bridgecrewio/checkov-action@v12
  
  integration:
    name: Integration Tests
    runs-on: ubuntu-latest
    needs: [validate, security]
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'
      
      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.11.0
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_TEST_ROLE_ARN }}
          aws-region: us-east-1
      
      - name: Run Terratest
        run: go test -v -timeout 30m
        working-directory: tests/
        env:
          AWS_DEFAULT_REGION: us-east-1
```


## Key Module Takeaways

- Design modules with single responsibility and clear boundaries—a good module does one thing completely, making it reusable across projects
- Follow semantic versioning religiously with pessimistic version constraints to enable safe updates while preventing breaking changes
- Invest in comprehensive testing using the pyramid approach: static analysis catches syntax errors in seconds, integration tests validate AWS deployment in minutes, preventing production failures that cost hours
- Document exhaustively with README, examples, input/output tables, and migration guides because undocumented modules create confusion, support burden, and adoption barriers
- Leverage community modules from Terraform Registry for common patterns, but evaluate quality through verified badges, recent updates, and active maintenance before production use


