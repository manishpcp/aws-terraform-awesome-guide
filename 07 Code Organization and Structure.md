# Chapter 7: Code Organization and Structure

## Introduction

Terraform code organization transforms from a simple task with a handful of resources into a critical architectural decision as infrastructure scales. A poorly structured Terraform project becomes unmaintainable at 1,000+ resources—changes to development environments accidentally affect production, duplicate code proliferates across teams, state files grow to megabytes causing multi-minute plan times, and the blast radius of a single `terraform destroy` encompasses entire business units. These aren't theoretical concerns but production incidents that happen when structure is an afterthought rather than a foundational decision.

The challenge isn't just technical—it's organizational. Different teams need different access levels, security policies, and deployment schedules. Development environments require rapid iteration with minimal approval, staging needs production-like configurations for testing, and production demands change control, audit trails, and zero-downtime deployments. Your Terraform structure must support these workflows while preventing configuration drift, maintaining DRY principles, and enabling code reuse across environments and accounts.

This chapter provides battle-tested patterns for organizing Terraform projects from startups with single environments to enterprises with hundreds of AWS accounts. You'll learn when to use workspaces versus separate directories, how to structure modules for maximum reusability, how to implement environment-specific configurations without duplication, and how to manage multi-account AWS Organizations with cross-account roles and centralized state management. The right structure makes infrastructure changes confidence-inspiring; the wrong structure makes every deployment a white-knuckle experience. Let's build the former.

## Terraform Project Structure Best Practices

### Small Project Structure (< 50 Resources)

For projects with fewer than 50 resources, simplicity trumps abstraction.

```
project-name/
├── .gitignore
├── .terraform.lock.hcl
├── README.md
├── main.tf                 # Core infrastructure resources
├── variables.tf            # Input variable definitions
├── outputs.tf              # Output value definitions
├── versions.tf             # Terraform and provider versions
├── terraform.tfvars        # Variable values (add to .gitignore if sensitive)
└── backend.tf              # Remote state configuration
```

**Example Implementation:**

```hcl
# versions.tf
terraform {
  required_version = ">= 1.11.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# backend.tf
terraform {
  backend "s3" {
    bucket         = "mycompany-terraform-state"
    key            = "simple-project/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:us-east-1:123456789012:alias/terraform-state"
    dynamodb_table = "terraform-state-locks"
  }
}

# main.tf
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "SimpleApp"
      ManagedBy   = "Terraform"
      Environment = var.environment
    }
  }
}

# VPC
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name = "${var.environment}-vpc"
  }
}

# Subnets
resource "aws_subnet" "public" {
  count = length(var.availability_zones)
  
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true
  
  tags = {
    Name = "${var.environment}-public-${var.availability_zones[count.index]}"
  }
}

# variables.tf
variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "development"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "Availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

# outputs.tf
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "IDs of public subnets"
  value       = aws_subnet.public[*].id
}

# README.md
# Simple App Infrastructure

Terraform configuration for Simple App infrastructure.

## Prerequisites
- Terraform >= 1.11.0
- AWS CLI configured
- S3 bucket for state storage

## Usage
```

terraform init
terraform plan
terraform apply

```

## Variables
See `variables.tf` for configurable parameters.
```


### Medium Project Structure (50-200 Resources)

As projects grow, separate resources into logical files:

```
project-name/
├── .gitignore
├── .terraform.lock.hcl
├── README.md
├── versions.tf
├── backend.tf
├── providers.tf           # Provider configurations
├── variables.tf
├── terraform.tfvars
├── outputs.tf
├── locals.tf              # Local values
│
├── network.tf             # VPC, subnets, route tables
├── compute.tf             # EC2, Auto Scaling
├── database.tf            # RDS, DynamoDB
├── storage.tf             # S3, EBS, EFS
├── security.tf            # Security groups, IAM, KMS
├── monitoring.tf          # CloudWatch, SNS
└── load-balancer.tf       # ALB, NLB
```

**Example locals.tf:**

```hcl
# locals.tf
locals {
  # Common tags applied to all resources
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    Owner       = var.owner_email
    CostCenter  = var.cost_center
  }
  
  # Naming prefix for resources
  name_prefix = "${var.project_name}-${var.environment}"
  
  # Availability zones
  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)
  
  # CIDR calculations
  public_subnet_cidrs  = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 8, i)]
  private_subnet_cidrs = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 8, i + 10)]
  
  # Environment-specific settings
  instance_type = var.environment == "production" ? "t3.large" : "t3.micro"
  min_size      = var.environment == "production" ? 3 : 1
  max_size      = var.environment == "production" ? 10 : 2
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}
```


### Large Project Structure (200+ Resources)

Large projects require modularization and separation by service:

```
project-name/
├── .gitignore
├── README.md
├── Makefile                # Common commands
│
├── modules/                # Reusable modules
│   ├── networking/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   └── README.md
│   ├── compute/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   └── database/
│       ├── main.tf
│       ├── variables.tf
│       └── outputs.tf
│
├── environments/           # Environment-specific configs
│   ├── dev/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── terraform.tfvars
│   │   ├── backend.tf
│   │   └── outputs.tf
│   ├── staging/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── terraform.tfvars
│   │   ├── backend.tf
│   │   └── outputs.tf
│   └── production/
│       ├── main.tf
│       ├── variables.tf
│       ├── terraform.tfvars
│       ├── backend.tf
│       └── outputs.tf
│
├── global/                 # Global resources (IAM, Route53)
│   ├── iam/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   └── dns/
│       ├── main.tf
│       ├── variables.tf
│       └── outputs.tf
│
└── scripts/                # Helper scripts
    ├── init-environment.sh
    ├── plan-all.sh
    └── apply-with-approval.sh
```

**Example environment configuration:**

```hcl
# environments/production/main.tf
terraform {
  required_version = ">= 1.11.0"
  
  backend "s3" {
    bucket         = "mycompany-terraform-state"
    key            = "production/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:us-east-1:123456789012:alias/terraform-state"
    dynamodb_table = "terraform-state-locks"
  }
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  
  assume_role {
    role_arn = "arn:aws:iam::${var.production_account_id}:role/TerraformDeployer"
  }
  
  default_tags {
    tags = {
      Environment = "production"
      ManagedBy   = "Terraform"
      Project     = var.project_name
    }
  }
}

# Networking module
module "networking" {
  source = "../../modules/networking"
  
  environment         = "production"
  vpc_cidr            = "10.0.0.0/16"
  availability_zones  = ["us-east-1a", "us-east-1b", "us-east-1c"]
  enable_nat_gateway  = true
  single_nat_gateway  = false  # HA for production
  enable_vpn_gateway  = true
  
  tags = local.common_tags
}

# Compute module
module "compute" {
  source = "../../modules/compute"
  
  environment         = "production"
  vpc_id              = module.networking.vpc_id
  private_subnet_ids  = module.networking.private_subnet_ids
  instance_type       = "t3.large"
  min_size            = 3
  max_size            = 10
  desired_capacity    = 5
  
  ami_id = data.aws_ami.amazon_linux_2023.id
  
  tags = local.common_tags
}

# Database module
module "database" {
  source = "../../modules/database"
  
  environment         = "production"
  vpc_id              = module.networking.vpc_id
  database_subnet_ids = module.networking.database_subnet_ids
  instance_class      = "db.r6g.large"
  allocated_storage   = 100
  multi_az            = true
  backup_retention    = 30
  
  allowed_security_groups = [module.compute.security_group_id]
  
  tags = local.common_tags
}

# environments/production/variables.tf
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "production_account_id" {
  description = "Production AWS account ID"
  type        = string
}

variable "project_name" {
  description = "Project name"
  type        = string
}

locals {
  common_tags = {
    Project     = var.project_name
    Environment = "production"
    ManagedBy   = "Terraform"
  }
}

# environments/production/terraform.tfvars
aws_region            = "us-east-1"
production_account_id = "123456789012"
project_name          = "MyApp"
```


### Makefile for Common Operations

```makefile
# Makefile
.PHONY: help init validate plan apply destroy fmt lint

ENVIRONMENT ?= dev
ENV_DIR = environments/$(ENVIRONMENT)

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $1, $2}'

init: ## Initialize Terraform
	cd $(ENV_DIR) && terraform init

validate: ## Validate Terraform configuration
	cd $(ENV_DIR) && terraform validate

plan: ## Run Terraform plan
	cd $(ENV_DIR) && terraform plan -out=tfplan

apply: ## Apply Terraform changes
	cd $(ENV_DIR) && terraform apply tfplan

destroy: ## Destroy infrastructure (use with caution!)
	cd $(ENV_DIR) && terraform destroy

fmt: ## Format Terraform files
	terraform fmt -recursive

lint: ## Run tflint
	cd $(ENV_DIR) && tflint --recursive

security-scan: ## Run security scanning
	tfsec .
	checkov -d .

all-plan: ## Plan all environments
	@for env in dev staging production; do \
		echo "Planning $$env..."; \
		cd environments/$$env && terraform plan; \
		cd ../..; \
	done

# Usage examples:
# make init ENVIRONMENT=production
# make plan ENVIRONMENT=staging
# make apply ENVIRONMENT=dev
```


## Organizing Code by Environment

### Strategy 1: Separate Directories (Recommended for Production)

Complete isolation between environments with separate state files:

```
infrastructure/
├── modules/                    # Shared modules
│   └── ...
│
├── environments/
│   ├── dev/
│   │   ├── backend.tf         # Dev state backend
│   │   ├── main.tf            # Dev-specific resources
│   │   ├── variables.tf
│   │   ├── terraform.tfvars   # Dev variable values
│   │   └── outputs.tf
│   │
│   ├── staging/
│   │   ├── backend.tf         # Staging state backend
│   │   ├── main.tf            # Staging-specific resources
│   │   ├── variables.tf
│   │   ├── terraform.tfvars   # Staging variable values
│   │   └── outputs.tf
│   │
│   └── production/
│       ├── backend.tf         # Production state backend
│       ├── main.tf            # Production-specific resources
│       ├── variables.tf
│       ├── terraform.tfvars   # Production variable values
│       └── outputs.tf
│
└── global/                    # Shared across all environments
    ├── iam/
    ├── dns/
    └── s3/
```

**Separate Directory Benefits:**

- ✅ Complete isolation—cannot accidentally affect wrong environment
- ✅ Different backend configurations per environment
- ✅ Different provider configurations (regions, accounts)
- ✅ Easy to apply different access controls
- ✅ Clear CI/CD pipelines per environment
- ✅ Can have different module versions per environment

**Separate Directory Drawbacks:**

- ❌ Code duplication across directories
- ❌ More files to maintain
- ❌ Changes must be applied to each environment separately

**Environment-Specific Backend Configuration:**

```hcl
# environments/dev/backend.tf
terraform {
  backend "s3" {
    bucket         = "mycompany-terraform-state"
    key            = "dev/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:us-east-1:123456789012:alias/terraform-state"
    dynamodb_table = "terraform-state-locks"
    
    # Dev-specific workspace prefix
    workspace_key_prefix = "dev-workspaces"
  }
}

# environments/production/backend.tf
terraform {
  backend "s3" {
    bucket         = "mycompany-terraform-state"
    key            = "production/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:us-east-1:123456789012:alias/terraform-state"
    dynamodb_table = "terraform-state-locks"
    
    # Production-specific workspace prefix
    workspace_key_prefix = "production-workspaces"
  }
}
```

**Environment-Specific tfvars:**

```hcl
# environments/dev/terraform.tfvars
aws_region         = "us-east-1"
environment        = "dev"
instance_type      = "t3.micro"
min_size           = 1
max_size           = 3
desired_capacity   = 1
enable_monitoring  = false
backup_retention   = 7
multi_az           = false

# environments/staging/terraform.tfvars
aws_region         = "us-east-1"
environment        = "staging"
instance_type      = "t3.small"
min_size           = 2
max_size           = 5
desired_capacity   = 2
enable_monitoring  = true
backup_retention   = 14
multi_az           = true

# environments/production/terraform.tfvars
aws_region         = "us-east-1"
environment        = "production"
instance_type      = "t3.large"
min_size           = 3
max_size           = 10
desired_capacity   = 5
enable_monitoring  = true
backup_retention   = 30
multi_az           = true
```


### Strategy 2: Terraform Workspaces (Use with Caution)

Single codebase with workspace-specific state:

```
infrastructure/
├── main.tf
├── variables.tf
├── outputs.tf
├── backend.tf
└── terraform.tfvars
```

**Using Workspaces:**

```bash
# Create workspaces
terraform workspace new dev
terraform workspace new staging
terraform workspace new production

# List workspaces
terraform workspace list
# Output:
#   default
#   dev
#   staging
# * production  (current)

# Switch workspace
terraform workspace select dev

# Show current workspace
terraform workspace show

# Deploy to specific workspace
terraform workspace select production
terraform plan
terraform apply
```

**Workspace-Aware Configuration:**

```hcl
# main.tf
locals {
  # Environment from workspace name
  environment = terraform.workspace
  
  # Environment-specific configurations
  config = {
    dev = {
      instance_type    = "t3.micro"
      min_size         = 1
      max_size         = 2
      multi_az         = false
      backup_retention = 7
    }
    staging = {
      instance_type    = "t3.small"
      min_size         = 2
      max_size         = 4
      multi_az         = true
      backup_retention = 14
    }
    production = {
      instance_type    = "t3.large"
      min_size         = 3
      max_size         = 10
      multi_az         = true
      backup_retention = 30
    }
  }
  
  # Current environment config
  env_config = local.config[local.environment]
  
  # Common tags with workspace
  common_tags = {
    Environment = local.environment
    Workspace   = terraform.workspace
    ManagedBy   = "Terraform"
  }
}

resource "aws_instance" "web" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = local.env_config.instance_type
  
  tags = merge(
    local.common_tags,
    {
      Name = "${local.environment}-web-server"
    }
  )
}

resource "aws_db_instance" "main" {
  identifier            = "${local.environment}-database"
  multi_az              = local.env_config.multi_az
  backup_retention_period = local.env_config.backup_retention
  
  tags = local.common_tags
}
```

**Workspace Backend Configuration:**

```hcl
# backend.tf
terraform {
  backend "s3" {
    bucket         = "mycompany-terraform-state"
    key            = "shared/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:us-east-1:123456789012:alias/terraform-state"
    dynamodb_table = "terraform-state-locks"
    
    # Workspace-specific state files
    workspace_key_prefix = "workspaces"
    # Results in: workspaces/dev/shared/terraform.tfstate
    #             workspaces/staging/shared/terraform.tfstate
    #             workspaces/production/shared/terraform.tfstate
  }
}
```

**Workspace Benefits:**

- ✅ Single codebase—no duplication
- ✅ Easy to switch between environments
- ✅ Good for similar environments

**Workspace Drawbacks:**

- ❌ Easy to apply to wrong workspace accidentally
- ❌ Limited flexibility for very different environments
- ❌ All environments must use same provider/backend config
- ❌ Harder to implement different access controls
- ❌ Not recommended for production environments

**When to Use Workspaces vs Directories:**


| Scenario | Recommendation |
| :-- | :-- |
| **Small project, similar environments** | Workspaces ✅ |
| **Production workloads** | Separate directories ✅ |
| **Different AWS accounts per environment** | Separate directories ✅ |
| **Team with strict access controls** | Separate directories ✅ |
| **Rapid prototyping/experimentation** | Workspaces ✅ |
| **Different backend configs per environment** | Separate directories ✅ |
| **Multi-region deployments** | Separate directories ✅ |

### Strategy 3: Hybrid Approach (Best of Both Worlds)

Combine separate directories with workspaces for maximum flexibility:

```
infrastructure/
├── modules/              # Shared modules
│
├── accounts/            # Account-level resources
│   ├── dev-account/
│   ├── staging-account/
│   └── prod-account/
│
└── applications/        # Application infrastructure
    ├── app-a/
    │   ├── environments/
    │   │   ├── dev/
    │   │   ├── staging/
    │   │   └── production/
    │   └── modules/
    │
    └── app-b/
        ├── environments/
        │   ├── dev/
        │   ├── staging/
        │   └── production/
        └── modules/
```


## Module-Based Architecture Patterns

### Composition Pattern (Recommended)

Break infrastructure into composable modules:

```
terraform-modules/      # Private module repository
├── networking/
│   ├── vpc/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   ├── README.md
│   │   └── examples/
│   │       └── complete/
│   ├── subnets/
│   └── nat-gateway/
│
├── compute/
│   ├── ec2/
│   ├── asg/
│   └── ecs/
│
├── database/
│   ├── rds/
│   ├── dynamodb/
│   └── elasticache/
│
├── security/
│   ├── security-groups/
│   ├── iam-roles/
│   └── kms-keys/
│
└── monitoring/
    ├── cloudwatch/
    └── sns/
```

**Example VPC Module:**

```hcl
# modules/networking/vpc/variables.tf
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "Must be valid IPv4 CIDR."
  }
}

variable "environment" {
  description = "Environment name"
  type        = string
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

variable "tags" {
  description = "Additional tags"
  type        = map(string)
  default     = {}
}

# modules/networking/vpc/main.tf
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = var.enable_dns_hostnames
  enable_dns_support   = var.enable_dns_support
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-vpc"
    }
  )
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-igw"
    }
  )
}

resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  
  tags = var.tags
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/${var.environment}-flow-logs"
  retention_in_days = 30
  
  tags = var.tags
}

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
  
  tags = var.tags
}

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

# modules/networking/vpc/outputs.tf
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

output "flow_log_id" {
  description = "ID of VPC Flow Log"
  value       = aws_flow_log.main.id
}

# modules/networking/vpc/README.md
# VPC Module

Creates an AWS VPC with Internet Gateway and Flow Logs.

## Usage

```

module "vpc" {
source = "git::https://github.com/myorg/terraform-modules.git//networking/vpc?ref=v1.0.0"

vpc_cidr             = "10.0.0.0/16"
environment          = "production"
enable_dns_hostnames = true
enable_dns_support   = true

tags = {
Project = "MyApp"
}
}

```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| vpc_cidr | CIDR block for VPC | string | n/a | yes |
| environment | Environment name | string | n/a | yes |
| enable_dns_hostnames | Enable DNS hostnames | bool | true | no |
| enable_dns_support | Enable DNS support | bool | true | no |
| tags | Additional tags | map(string) | {} | no |

## Outputs

| Name | Description |
|------|-------------|
| vpc_id | ID of the VPC |
| vpc_cidr | CIDR block of the VPC |
| internet_gateway_id | ID of the Internet Gateway |
| flow_log_id | ID of VPC Flow Log |
```

**Using Modules in Environments:**

```hcl
# environments/production/main.tf
module "vpc" {
  source = "git::https://github.com/myorg/terraform-modules.git//networking/vpc?ref=v1.2.0"
  
  vpc_cidr    = "10.0.0.0/16"
  environment = "production"
  
  tags = local.common_tags
}

module "subnets" {
  source = "git::https://github.com/myorg/terraform-modules.git//networking/subnets?ref=v1.2.0"
  
  vpc_id             = module.vpc.vpc_id
  availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]
  
  public_subnet_cidrs  = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  private_subnet_cidrs = ["10.0.11.0/24", "10.0.12.0/24", "10.0.13.0/24"]
  
  tags = local.common_tags
}

module "nat_gateway" {
  source = "git::https://github.com/myorg/terraform-modules.git//networking/nat-gateway?ref=v1.2.0"
  
  vpc_id            = module.vpc.vpc_id
  public_subnet_ids = module.subnets.public_subnet_ids
  single_nat        = false  # Multi-AZ for production
  
  tags = local.common_tags
}

module "compute" {
  source = "git::https://github.com/myorg/terraform-modules.git//compute/asg?ref=v2.0.0"
  
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.subnets.private_subnet_ids
  
  instance_type    = "t3.large"
  min_size         = 3
  max_size         = 10
  desired_capacity = 5
  
  tags = local.common_tags
}
```


## DRY Principle Implementation

### Pattern 1: Shared Configuration with Terragrunt

Terragrunt eliminates duplication across environments:

```hcl
# terragrunt.hcl (root)
locals {
  # Parse environment from path
  environment = basename(get_terragrunt_dir())
  
  # Load region-specific variables
  region_vars = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  region      = local.region_vars.locals.region
  
  # Load account-specific variables
  account_vars = read_terragrunt_config(find_in_parent_folders("account.hcl"))
  account_id   = local.account_vars.locals.account_id
  
  # Common tags
  common_tags = {
    Environment = local.environment
    ManagedBy   = "Terragrunt"
    Region      = local.region
  }
}

# Generate backend configuration
remote_state {
  backend = "s3"
  
  config = {
    bucket         = "mycompany-terraform-state-${local.account_id}"
    key            = "${path_relative_to_include()}/terraform.tfstate"
    region         = local.region
    encrypt        = true
    kms_key_id     = "arn:aws:kms:${local.region}:${local.account_id}:alias/terraform-state"
    dynamodb_table = "terraform-state-locks"
  }
  
  generate = {
    path      = "backend.tf"
    if_exists = "overwrite"
  }
}

# Generate provider configuration
generate "provider" {
  path      = "provider.tf"
  if_exists = "overwrite"
  contents  = <<EOF
provider "aws" {
  region = "${local.region}"
  
  assume_role {
    role_arn = "arn:aws:iam::${local.account_id}:role/TerraformDeployer"
  }
  
  default_tags {
    tags = ${jsonencode(local.common_tags)}
  }
}
EOF
}

# environments/dev/us-east-1/terragrunt.hcl
include "root" {
  path = find_in_parent_folders()
}

inputs = {
  environment      = "dev"
  instance_type    = "t3.micro"
  min_size         = 1
  max_size         = 2
  multi_az         = false
  backup_retention = 7
}

# environments/production/us-east-1/terragrunt.hcl
include "root" {
  path = find_in_parent_folders()
}

inputs = {
  environment      = "production"
  instance_type    = "t3.large"
  min_size         = 3
  max_size         = 10
  multi_az         = true
  backup_retention = 30
}

## Workspace Management Strategies

Terraform workspaces are best for lightweight environment switching when configuration is mostly identical, but they should not be the only isolation mechanism for serious staging/production setups. Use them deliberately and keep the blast radius small.

### Practical Workspace Patterns

```hcl
# locals for workspace-aware configuration
locals {
  env = terraform.workspace

  env_settings = {
    dev = {
      replicas      = 1
      instance_type = "t3.micro"
      monitoring    = false
    }
    staging = {
      replicas      = 2
      instance_type = "t3.small"
      monitoring    = true
    }
    production = {
      replicas      = 4
      instance_type = "t3.large"
      monitoring    = true
    }
  }

  cfg = lookup(local.env_settings, local.env, local.env_settings.dev)
}

resource "aws_autoscaling_group" "app" {
  desired_capacity = local.cfg.replicas
  min_size         = local.cfg.replicas
  max_size         = local.cfg.replicas * 2

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }
}
```

Use workspaces for:

- Developer sandboxes and ephemeral preview environments.
- Same-account, same-region variants that differ only by sizing or toggles.
Avoid workspaces for:
- Different AWS accounts or significantly different architectures, where directories and separate backends are safer.


## Directory Structure Conventions

A common pattern is “layers × environments”: global, networking, and application layers, each with dev/stage/prod folders.

```text
infra/
├── global/              # Org-wide: IAM, SSO, GuardDuty, CT, DNS
├── networking/
│   ├── dev/
│   ├── staging/
│   └── production/
└── apps/
    ├── payments/
    │   ├── dev/
    │   ├── staging/
    │   └── production/
    └── api/
        ├── dev/
        ├── staging/
        └── production/
```

Conventions that help at scale:

- One state file per “unit of blast radius” (e.g., per app per env).
- Predictable names: `providers.tf`, `backend.tf`, `main.tf`, `variables.tf`, `outputs.tf`, `locals.tf`.
- Keep modules pure (no backends/providers inside them); keep providers/backends only in root configurations.


## DRY Principle in Terraform

The main DRY levers in Terraform are modules, locals, and external tooling (Terragrunt, Makefiles, pipelines), not copy–paste.

### DRY Techniques

- **Core modules**: VPC, ALB, ECS/EKS cluster, RDS, S3, IAM role, security-group; publish via a private registry or Git repo.
- **Environment overlays**: root configs per env that only wire modules + inputs, avoiding duplication of resource definitions.
- **Shared locals**: naming conventions, tagging schemes, common CIDR math in `locals.tf` and reused across files.
- **Generated files**: use Terragrunt or small scripts to generate `backend.tf` / `provider.tf` so you don’t repeat backend and assume-role boilerplate.

Example DRY root:

```hcl
module "app_stack" {
  source = "../../modules/app-stack"

  environment = var.environment
  aws_region  = var.aws_region

  vpc_cidr       = var.vpc_cidr
  instance_type  = var.instance_type
  desired_count  = var.desired_count
  enable_canary  = var.enable_canary
}
```


## Managing Multiple AWS Accounts

For multi-account orgs, cross-account roles plus per-account state is the standard baseline.

### Core Patterns

- **One “management”/pipeline account** runs Terraform and assumes roles into workload accounts using `assume_role` in provider blocks.
- **Per-account state buckets**: e.g., `org-terraform-state-<account-id>` with KMS and DynamoDB locking, so no account can read another’s state by default.
- **Account-scoped root configs**: `accounts/dev/`, `accounts/staging/`, `accounts/prod/` each owning their own providers/backend and referencing the same modules.

Example provider block for cross-account:

```hcl
provider "aws" {
  region = var.aws_region

  assume_role {
    role_arn     = "arn:aws:iam::${var.account_id}:role/TerraformDeployer"
    session_name = "tf-${var.environment}"
  }
}
```

For large orgs, AWS Prescriptive Guidance and Account Factory for Terraform (AFT) provide opinionated multi-account scaffolding that plugs into Terraform workflows and centralizes guardrails and baselines.

## Recommended Patterns Summary

- Use **modules** as the main abstraction: thin environment roots calling thick, well-versioned modules.
- Prefer **separate directories and backends per environment** for anything that touches production; reserve workspaces for small, low-risk scenarios.
- Apply DRY through **shared modules + locals + generation tooling**, not by sharing a single, massive state.
- For multiple AWS accounts, standardize on **cross-account roles, per-account state, and org-level guardrails**, ideally aligned with AWS Organizations and Control Tower/AFT guidance.