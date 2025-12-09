# Chapter 17: Production Best Practices and Enterprise Patterns

## Introduction

Deploying your first Terraform configuration feels like a victory—you wrote code, ran `terraform apply`, and watched AWS resources materialize like magic. But that single-developer, single-environment success conceals the complexity waiting in production: How do you manage infrastructure across 50 AWS accounts spanning development, staging, and production without state file collisions? How do you prevent a junior engineer's Friday afternoon experiment from deleting the production database? How do you ensure every resource follows naming conventions, tagging policies, and security standards when ten teams deploy independently? How do you detect when someone manually modifies infrastructure in the AWS console, creating drift from your Terraform-defined state? How do you implement zero-downtime deployments ensuring users never experience service interruptions during infrastructure updates? These aren't hypothetical scenarios—they're the daily reality of enterprise Terraform operations, where the gap between "it works on my machine" and "it runs reliably for 10,000 users across 6 regions" determines whether infrastructure-as-code delivers its promise or becomes a liability.

Production-grade Terraform requires systematic approaches addressing scale, security, reliability, and governance. Multi-account AWS Organizations architectures isolate blast radius ensuring development experiments can't access production data, with centralized identity through AWS IAM Identity Center and automated account provisioning through Account Factory for Terraform (AFT). Remote state backends with S3 versioning, DynamoDB locking, and encryption protect the critical state file from corruption, concurrent modification, and unauthorized access. **Drift detection strategies using scheduled `terraform plan` runs, continuous monitoring through Terraform Cloud, and third-party tools like Spacelift identify when infrastructure diverges from desired state, enabling rapid remediation before issues compound**. **Policy-as-code frameworks like Sentinel and Open Policy Agent (OPA) enforce guardrails preventing expensive instances, unencrypted databases, and publicly accessible S3 buckets before `terraform apply` runs, shifting compliance left into the development workflow**. **Zero-downtime deployment patterns including blue-green deployments, canary releases, and rolling updates ensure infrastructure changes occur transparently to users, eliminating maintenance windows**. **Terraform Cloud and Enterprise provide enterprise-grade governance through role-based access control (RBAC), policy enforcement, private module registries, and audit logging, centralizing infrastructure operations while enabling team autonomy**.

This chapter synthesizes 17 chapters of Terraform knowledge into comprehensive enterprise patterns. You'll learn multi-account architectures managing hundreds of AWS accounts with centralized governance, state management strategies preventing corruption and enabling team collaboration, **drift detection and remediation workflows maintaining infrastructure consistency**, **policy-as-code implementations with both Sentinel and OPA enforcing security and compliance**, **zero-downtime deployment techniques ensuring continuous availability**, **Terraform Cloud/Enterprise governance features enabling enterprise-scale operations**, disaster recovery architectures achieving RPO < 1 hour through automated failover, cost optimization frameworks reducing bills while maintaining performance, security hardening beyond basics including secret management and audit logging, and real-world case studies showing how Fortune 500 companies manage 10,000+ Terraform resources. Whether you're architecting greenfield enterprise infrastructure or transforming legacy manual operations, these patterns provide the foundation for reliable, scalable, secure Terraform deployments.

## Multi-Account AWS Architecture with Terraform

### AWS Organizations Structure

Enterprise AWS deployments use AWS Organizations to isolate workloads, enforce policies, and manage billing.

**Recommended OU Structure:**

```
Root
├── Security OU
│   ├── Log Archive Account (centralized logging)
│   ├── Security Tooling Account (GuardDuty, SecurityHub)
│   └── Audit Account (CloudTrail, Config aggregator)
├── Infrastructure OU
│   ├── Network Account (Transit Gateway, VPCs)
│   ├── Shared Services Account (Active Directory, DNS)
│   └── Backup Account (centralized backups)
├── Workloads OU
│   ├── Production OU
│   │   ├── App-1 Production Account
│   │   └── App-2 Production Account
│   ├── Staging OU
│   │   ├── App-1 Staging Account
│   │   └── App-2 Staging Account
│   └── Development OU
│       ├── App-1 Dev Account
│       └── App-2 Dev Account
└── Sandbox OU (isolated experimentation)
```


### Managing AWS Organizations with Terraform

**Root Account Configuration (Management Account):**

```hcl
# organizations/main.tf
terraform {
  required_version = ">= 1.11.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
  
  backend "s3" {
    bucket         = "terraform-state-management-account"
    key            = "organizations/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-locks"
    kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/your-key-id"
  }
}

provider "aws" {
  region = "us-east-1"
  
  default_tags {
    tags = {
      ManagedBy   = "Terraform"
      Environment = "management"
      CostCenter  = "platform-engineering"
    }
  }
}

# Enable AWS Organizations
resource "aws_organizations_organization" "main" {
  feature_set = "ALL"
  
  aws_service_access_principals = [
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "guardduty.amazonaws.com",
    "securityhub.amazonaws.com",
    "sso.amazonaws.com",
    "ram.amazonaws.com"
  ]
  
  enabled_policy_types = [
    "SERVICE_CONTROL_POLICY",
    "TAG_POLICY",
    "BACKUP_POLICY"
  ]
}

# Security OU
resource "aws_organizations_organizational_unit" "security" {
  name      = "Security"
  parent_id = aws_organizations_organization.main.roots[^0].id
}

# Infrastructure OU
resource "aws_organizations_organizational_unit" "infrastructure" {
  name      = "Infrastructure"
  parent_id = aws_organizations_organization.main.roots[^0].id
}

# Workloads OU
resource "aws_organizations_organizational_unit" "workloads" {
  name      = "Workloads"
  parent_id = aws_organizations_organization.main.roots[^0].id
}

# Production sub-OU
resource "aws_organizations_organizational_unit" "production" {
  name      = "Production"
  parent_id = aws_organizations_organizational_unit.workloads.id
}

# Staging sub-OU
resource "aws_organizations_organizational_unit" "staging" {
  name      = "Staging"
  parent_id = aws_organizations_organizational_unit.workloads.id
}

# Development sub-OU
resource "aws_organizations_organizational_unit" "development" {
  name      = "Development"
  parent_id = aws_organizations_organizational_unit.workloads.id
}

# Sandbox OU
resource "aws_organizations_organizational_unit" "sandbox" {
  name      = "Sandbox"
  parent_id = aws_organizations_organization.main.roots[^0].id
}

# Create accounts
resource "aws_organizations_account" "log_archive" {
  name      = "log-archive"
  email     = "aws-log-archive@example.com"
  parent_id = aws_organizations_organizational_unit.security.id
  
  role_name = "OrganizationAccountAccessRole"
  
  lifecycle {
    ignore_changes = [role_name]
  }
}

resource "aws_organizations_account" "security_tooling" {
  name      = "security-tooling"
  email     = "aws-security-tooling@example.com"
  parent_id = aws_organizations_organizational_unit.security.id
  
  role_name = "OrganizationAccountAccessRole"
}

resource "aws_organizations_account" "network" {
  name      = "network"
  email     = "aws-network@example.com"
  parent_id = aws_organizations_organizational_unit.infrastructure.id
  
  role_name = "OrganizationAccountAccessRole"
}

# Service Control Policies (SCPs)
# Deny leaving organization
resource "aws_organizations_policy" "deny_leave_org" {
  name        = "DenyLeaveOrganization"
  description = "Prevent accounts from leaving the organization"
  type        = "SERVICE_CONTROL_POLICY"
  
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Deny"
        Action   = "organizations:LeaveOrganization"
        Resource = "*"
      }
    ]
  })
}

# Deny root user access
resource "aws_organizations_policy" "deny_root_user" {
  name        = "DenyRootUser"
  description = "Prevent root user actions"
  type        = "SERVICE_CONTROL_POLICY"
  
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Deny"
        Action    = "*"
        Resource  = "*"
        Condition = {
          StringLike = {
            "aws:PrincipalArn" = "arn:aws:iam::*:root"
          }
        }
      }
    ]
  })
}

# Require encryption for S3
resource "aws_organizations_policy" "require_s3_encryption" {
  name        = "RequireS3Encryption"
  description = "Require S3 bucket encryption"
  type        = "SERVICE_CONTROL_POLICY"
  
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Deny"
        Action = [
          "s3:PutObject"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = [
              "AES256",
              "aws:kms"
            ]
          }
        }
      }
    ]
  })
}

# Attach SCPs to OUs
resource "aws_organizations_policy_attachment" "deny_leave_org_root" {
  policy_id = aws_organizations_policy.deny_leave_org.id
  target_id = aws_organizations_organization.main.roots[^0].id
}

resource "aws_organizations_policy_attachment" "deny_root_user_workloads" {
  policy_id = aws_organizations_policy.deny_root_user.id
  target_id = aws_organizations_organizational_unit.workloads.id
}

resource "aws_organizations_policy_attachment" "require_s3_encryption_production" {
  policy_id = aws_organizations_policy.require_s3_encryption.id
  target_id = aws_organizations_organizational_unit.production.id
}

# Outputs
output "organization_id" {
  description = "Organization ID"
  value       = aws_organizations_organization.main.id
}

output "organization_arn" {
  description = "Organization ARN"
  value       = aws_organizations_organization.main.arn
}

output "security_ou_id" {
  description = "Security OU ID"
  value       = aws_organizations_organizational_unit.security.id
}

output "production_ou_id" {
  description = "Production OU ID"
  value       = aws_organizations_organizational_unit.production.id
}

output "log_archive_account_id" {
  description = "Log Archive account ID"
  value       = aws_organizations_account.log_archive.id
}
```


### Cross-Account Resource Deployment

**Assume Role Pattern:**

```hcl
# multi-account-deployment/main.tf

# Provider for management account (default)
provider "aws" {
  region = "us-east-1"
  alias  = "management"
}

# Provider for production account
provider "aws" {
  region = "us-east-1"
  alias  = "production"
  
  assume_role {
    role_arn     = "arn:aws:iam::${var.production_account_id}:role/OrganizationAccountAccessRole"
    session_name = "TerraformCrossAccountDeployment"
  }
}

# Provider for staging account
provider "aws" {
  region = "us-east-1"
  alias  = "staging"
  
  assume_role {
    role_arn     = "arn:aws:iam::${var.staging_account_id}:role/OrganizationAccountAccessRole"
    session_name = "TerraformCrossAccountDeployment"
  }
}

# Variables
variable "production_account_id" {
  description = "Production AWS account ID"
  type        = string
}

variable "staging_account_id" {
  description = "Staging AWS account ID"
  type        = string
}

# Deploy VPC in production account
module "vpc_production" {
  source = "terraform-aws-modules/vpc/aws"
  
  providers = {
    aws = aws.production
  }
  
  name = "production-vpc"
  cidr = "10.0.0.0/16"
  
  azs             = ["us-east-1a", "us-east-1b", "us-east-1c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
  
  enable_nat_gateway = true
  enable_vpn_gateway = false
  
  tags = {
    Environment = "production"
    ManagedBy   = "Terraform"
  }
}

# Deploy VPC in staging account
module "vpc_staging" {
  source = "terraform-aws-modules/vpc/aws"
  
  providers = {
    aws = aws.staging
  }
  
  name = "staging-vpc"
  cidr = "10.1.0.0/16"
  
  azs             = ["us-east-1a", "us-east-1b"]
  private_subnets = ["10.1.1.0/24", "10.1.2.0/24"]
  public_subnets  = ["10.1.101.0/24", "10.1.102.0/24"]
  
  enable_nat_gateway = true
  single_nat_gateway = true  # Cost optimization for non-prod
  enable_vpn_gateway = false
  
  tags = {
    Environment = "staging"
    ManagedBy   = "Terraform"
  }
}

# Cross-account S3 bucket access from production to log archive
resource "aws_s3_bucket" "central_logs" {
  provider = aws.management
  
  bucket = "central-logs-${data.aws_caller_identity.management.account_id}"
}

resource "aws_s3_bucket_policy" "central_logs" {
  provider = aws.management
  
  bucket = aws_s3_bucket.central_logs.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowProductionAccountPutObject"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.production_account_id}:root"
        }
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl"
        ]
        Resource = "${aws_s3_bucket.central_logs.arn}/*"
      }
    ]
  })
}

# Data sources
data "aws_caller_identity" "management" {
  provider = aws.management
}

data "aws_caller_identity" "production" {
  provider = aws.production
}
```


## Enterprise State Management

### Layered State Architecture

**Anti-Pattern: Single Monolithic State:**

```hcl
# ❌ DON'T: All resources in one state file
# single-state/main.tf (10,000+ resources)
resource "aws_vpc" "main" {}
resource "aws_subnet" "public" {}
# ... 9,998 more resources
# Problems:
# - 30+ minute terraform plan
# - State file corruption affects everything
# - Concurrent team work impossible
# - Blast radius unlimited
```

**Best Practice: Layered State Strategy:**

```
terraform/
├── 01-foundation/
│   ├── backend.tf
│   ├── main.tf              # Organizations, IAM Identity Center
│   └── terraform.tfstate → s3://state/foundation/
├── 02-security/
│   ├── backend.tf
│   ├── main.tf              # GuardDuty, SecurityHub, KMS
│   └── terraform.tfstate → s3://state/security/
├── 03-networking/
│   ├── backend.tf
│   ├── main.tf              # VPCs, Transit Gateway, Route53
│   └── terraform.tfstate → s3://state/networking/
├── 04-data/
│   ├── backend.tf
│   ├── main.tf              # RDS, DynamoDB, S3 data buckets
│   └── terraform.tfstate → s3://state/data/
└── 05-applications/
    ├── app-a/
    │   ├── backend.tf
    │   ├── main.tf          # App A resources
    │   └── terraform.tfstate → s3://state/apps/app-a/
    └── app-b/
        ├── backend.tf
        ├── main.tf          # App B resources
        └── terraform.tfstate → s3://state/apps/app-b/
```

**Benefits:**

- **Isolation:** Networking change can't break applications
- **Performance:** Plan runs in seconds, not minutes
- **Parallelization:** Teams work independently
- **Blast radius:** Limited to single layer


### Production-Grade Remote Backend

```hcl
# backend-setup/main.tf - Run once per account
terraform {
  required_version = ">= 1.11.0"
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name"
  type        = string
  default     = "company"
}

variable "environment" {
  description = "Environment name"
  type        = string
}

# S3 bucket for state files
resource "aws_s3_bucket" "terraform_state" {
  bucket = "${var.project_name}-terraform-state-${var.environment}-${data.aws_caller_identity.current.account_id}"
  
  lifecycle {
    prevent_destroy = true
  }
}

# Enable versioning (critical for state recovery)
resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

# Enable encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.terraform_state.arn
    }
    bucket_key_enabled = true
  }
}

# Block public access
resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable logging
resource "aws_s3_bucket_logging" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "terraform-state-access/"
}

# Lifecycle rules for cost optimization
resource "aws_s3_bucket_lifecycle_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  rule {
    id     = "delete-old-versions"
    status = "Enabled"
    
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
  
  rule {
    id     = "transition-old-versions"
    status = "Enabled"
    
    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }
  }
}

# KMS key for state encryption
resource "aws_kms_key" "terraform_state" {
  description             = "KMS key for Terraform state encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
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
        Sid    = "Allow Terraform service role"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.terraform_execution.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "terraform_state" {
  name          = "alias/${var.project_name}-terraform-state-${var.environment}"
  target_key_id = aws_kms_key.terraform_state.key_id
}

# DynamoDB table for state locking
resource "aws_dynamodb_table" "terraform_locks" {
  name         = "${var.project_name}-terraform-locks-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"
  
  attribute {
    name = "LockID"
    type = "S"
  }
  
  point_in_time_recovery {
    enabled = true
  }
  
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.terraform_state.arn
  }
  
  tags = {
    Name        = "${var.project_name}-terraform-locks-${var.environment}"
    Environment = var.environment
  }
}

# Logs bucket
resource "aws_s3_bucket" "logs" {
  bucket = "${var.project_name}-terraform-logs-${var.environment}-${data.aws_caller_identity.current.account_id}"
  
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  
  rule {
    id     = "expire-old-logs"
    status = "Enabled"
    
    expiration {
      days = 90
    }
  }
}

# IAM role for Terraform execution (used in CI/CD)
resource "aws_iam_role" "terraform_execution" {
  name = "${var.project_name}-terraform-execution-${var.environment}"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:*"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "terraform_execution_admin" {
  role       = aws_iam_role.terraform_execution.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"  # Scope down in production
}

variable "github_org" {
  description = "GitHub organization"
  type        = string
}

variable "github_repo" {
  description = "GitHub repository"
  type        = string
}

# Data sources
data "aws_caller_identity" "current" {}

# Outputs
output "state_bucket_name" {
  description = "S3 bucket name for Terraform state"
  value       = aws_s3_bucket.terraform_state.id
}

output "dynamodb_table_name" {
  description = "DynamoDB table name for state locking"
  value       = aws_dynamodb_table.terraform_locks.name
}

output "kms_key_id" {
  description = "KMS key ID for state encryption"
  value       = aws_kms_key.terraform_state.id
}

output "terraform_execution_role_arn" {
  description = "IAM role ARN for Terraform execution"
  value       = aws_iam_role.terraform_execution.arn
}
```

**Using the Backend:**

```hcl
# application/backend.tf
terraform {
  backend "s3" {
    bucket         = "company-terraform-state-production-123456789012"
    key            = "applications/app-a/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "company-terraform-locks-production"
    kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
  }
}
```



### State Import and Migration

**Importing existing resources:**

```bash
# Import existing VPC created manually
terraform import aws_vpc.main vpc-0123456789abcdef0

# Import with specific provider (multi-account)
terraform import -provider=aws.production aws_vpc.main vpc-0123456789abcdef0

# Bulk import script
#!/bin/bash
# import_existing_infrastructure.sh

VPC_IDS=$(aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' --output text)

for vpc_id in $VPC_IDS; do
  echo "Importing VPC: $vpc_id"
  terraform import aws_vpc.$vpc_id $vpc_id
done
```

**State migration between backends:**

```bash
# Step 1: Pull current state
terraform state pull > backup-$(date +%Y%m%d).tfstate

# Step 2: Update backend configuration in backend.tf

# Step 3: Re-initialize with migration
terraform init -migrate-state

# Terraform will prompt:
# Do you want to copy existing state to the new backend?
# Enter a value: yes
```


## Policy as Code with Sentinel

### Sentinel Policy Framework

Sentinel enforces policies before infrastructure changes are applied.

**Sentinel Policy Structure:**

```
policies/
├── cost-control/
│   ├── limit-instance-size.sentinel
│   ├── prevent-expensive-resources.sentinel
│   └── require-budget-tags.sentinel
├── security/
│   ├── require-encryption.sentinel
│   ├── prevent-public-access.sentinel
│   └── enforce-security-groups.sentinel
├── compliance/
│   ├── require-tagging.sentinel
│   ├── enforce-naming-convention.sentinel
│   └── require-backup-enabled.sentinel
└── sentinel.hcl
```

**Example: Prevent Oversized EC2 Instances:**

```hcl
# policies/cost-control/limit-instance-size.sentinel
import "tfplan/v2" as tfplan
import "strings"

# Allowed instance types (cost-controlled)
allowed_instance_types = [
  "t3.micro",
  "t3.small",
  "t3.medium",
  "t3.large",
  "t3.xlarge"
]

# Find all EC2 instances in the plan
instances = filter tfplan.resource_changes as _, rc {
  rc.type is "aws_instance" and
  (rc.change.actions contains "create" or rc.change.actions contains "update")
}

# Validation function
validate_instance_type = func(instance) {
  instance_type = instance.change.after.instance_type
  
  if instance_type not in allowed_instance_types {
    print("Instance type", instance_type, "is not allowed.")
    print("Allowed types:", strings.join(allowed_instance_types, ", "))
    return false
  }
  
  return true
}

# Main rule
main = rule {
  all instances as address, instance {
    validate_instance_type(instance)
  }
}
```

**Example: Require Encryption:**

```hcl
# policies/security/require-encryption.sentinel
import "tfplan/v2" as tfplan

# Find all RDS instances
rds_instances = filter tfplan.resource_changes as _, rc {
  rc.type is "aws_db_instance" and
  (rc.change.actions contains "create" or rc.change.actions contains "update")
}

# Find all S3 buckets
s3_buckets = filter tfplan.resource_changes as _, rc {
  rc.type is "aws_s3_bucket" and
  (rc.change.actions contains "create" or rc.change.actions contains "update")
}

# Find S3 encryption configurations
s3_encryption_configs = filter tfplan.resource_changes as _, rc {
  rc.type is "aws_s3_bucket_server_side_encryption_configuration" and
  (rc.change.actions contains "create" or rc.change.actions contains "update")
}

# Validate RDS encryption
validate_rds_encryption = func(instance) {
  if instance.change.after.storage_encrypted is not true {
    print("RDS instance", instance.address, "must have storage_encrypted = true")
    return false
  }
  return true
}

# Check S3 has encryption config
validate_s3_encryption = func() {
  if length(s3_buckets) > 0 and length(s3_encryption_configs) is 0 {
    print("S3 buckets require aws_s3_bucket_server_side_encryption_configuration")
    return false
  }
  return true
}

# Main rules
rds_encrypted = rule {
  all rds_instances as address, instance {
    validate_rds_encryption(instance)
  }
}

s3_encrypted = rule {
  validate_s3_encryption()
}

main = rule {
  rds_encrypted and s3_encrypted
}
```

**Example: Enforce Tagging:**

```hcl
# policies/compliance/require-tagging.sentinel
import "tfplan/v2" as tfplan
import "strings"

# Required tags
required_tags = [
  "Environment",
  "Owner",
  "CostCenter",
  "Project"
]

# Resources that must be tagged
taggable_resources = [
  "aws_instance",
  "aws_vpc",
  "aws_subnet",
  "aws_security_group",
  "aws_db_instance",
  "aws_s3_bucket",
  "aws_ecs_cluster",
  "aws_ecs_service",
  "aws_lambda_function"
]

# Find all resources requiring tags
resources = filter tfplan.resource_changes as _, rc {
  rc.type in taggable_resources and
  (rc.change.actions contains "create" or rc.change.actions contains "update")
}

# Validate tags
validate_tags = func(resource) {
  tags = resource.change.after.tags else {}
  
  missing_tags = []
  for required_tags as tag {
    if tag not in keys(tags) {
      append(missing_tags, tag)
    }
  }
  
  if length(missing_tags) > 0 {
    print("Resource", resource.address, "is missing required tags:", strings.join(missing_tags, ", "))
    return false
  }
  
  return true
}

# Main rule
main = rule {
  all resources as address, resource {
    validate_tags(resource)
  }
}
```

**Sentinel Configuration:**

```hcl
# sentinel.hcl
policy "limit-instance-size" {
  source            = "./policies/cost-control/limit-instance-size.sentinel"
  enforcement_level = "hard-mandatory"  # Blocks apply
}

policy "require-encryption" {
  source            = "./policies/security/require-encryption.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "require-tagging" {
  source            = "./policies/compliance/require-tagging.sentinel"
  enforcement_level = "soft-mandatory"  # Can be overridden
}
```

**Testing Policies:**

```bash
# Run Sentinel checks locally (Terraform Cloud/Enterprise)
terraform plan
# Sentinel policies evaluated during plan

# Output:
# Sentinel Result: false
# 
# Fail - limit-instance-size.sentinel
#   Instance type m5.24xlarge is not allowed.
#   Allowed types: t3.micro, t3.small, t3.medium, t3.large, t3.xlarge
# 
# Error: Sentinel policy check failed
```


## Disaster Recovery Strategies

### Backup and Restore Pattern

Lowest cost, highest RTO (hours to days).

```hcl
# disaster-recovery/backup-restore.tf

# Automated backup configuration
resource "aws_backup_plan" "infrastructure" {
  name = "infrastructure-backup-plan"
  
  rule {
    rule_name         = "daily_backups"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 2 * * ? *)"  # 2 AM daily
    
    lifecycle {
      delete_after = 30
    }
    
    recovery_point_tags = {
      Type = "Automated"
    }
  }
  
  rule {
    rule_name         = "weekly_backups"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 2 ? * 1 *)"  # Sunday 2 AM
    
    lifecycle {
      delete_after       = 90
      cold_storage_after = 30
    }
  }
}

resource "aws_backup_vault" "main" {
  name        = "infrastructure-backup-vault"
  kms_key_arn = aws_kms_key.backup.arn
}

resource "aws_kms_key" "backup" {
  description             = "KMS key for backup vault encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

# Backup selection (what to backup)
resource "aws_backup_selection" "infrastructure" {
  name         = "infrastructure-resources"
  plan_id      = aws_backup_plan.infrastructure.id
  iam_role_arn = aws_iam_role.backup.arn
  
  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Backup"
    value = "true"
  }
  
  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Environment"
    value = "production"
  }
}

# IAM role for AWS Backup
resource "aws_iam_role" "backup" {
  name = "aws-backup-service-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "backup.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_iam_role_policy_attachment" "restore" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
}

# Copy backups to DR region
resource "aws_backup_vault" "dr_region" {
  provider    = aws.dr_region
  name        = "infrastructure-backup-vault-dr"
  kms_key_arn = aws_kms_key.backup_dr.arn
}

resource "aws_kms_key" "backup_dr" {
  provider                = aws.dr_region
  description             = "KMS key for DR region backup vault"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

# Cross-region copy
resource "aws_backup_plan" "infrastructure" {
  # ... (existing configuration)
  
  rule {
    rule_name         = "daily_backups"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 2 * * ? *)"
    
    lifecycle {
      delete_after = 30
    }
    
    copy_action {
      destination_vault_arn = aws_backup_vault.dr_region.arn
      
      lifecycle {
        delete_after = 30
      }
    }
  }
}

# DR region provider
provider "aws" {
  alias  = "dr_region"
  region = "us-west-2"
}
```

**Recovery Procedure:**

```bash
# disaster-recovery/scripts/restore.sh
#!/bin/bash

# List available recovery points
aws backup list-recovery-points-by-backup-vault \
  --backup-vault-name infrastructure-backup-vault \
  --region us-east-1

# Restore RDS from backup
aws backup start-restore-job \
  --recovery-point-arn arn:aws:backup:us-east-1:123456789012:recovery-point:abc123 \
  --metadata \
    DBInstanceIdentifier=restored-database,\
    DBInstanceClass=db.t3.large,\
    VpcSecurityGroupIds=sg-0123456789,\
    DBSubnetGroupName=production-db-subnet-group \
  --iam-role-arn arn:aws:iam::123456789012:role/aws-backup-service-role \
  --region us-east-1

# After restore, update Terraform state
terraform import aws_db_instance.main restored-database
```


### Pilot Light Pattern

Minimal always-on infrastructure, quick scale-up (minutes to hours).

```hcl
# disaster-recovery/pilot-light.tf

# Conditional deployment based on environment
variable "disaster_recovery_mode" {
  description = "DR mode: pilot_light or active"
  type        = string
  default     = "pilot_light"
  
  validation {
    condition     = contains(["pilot_light", "active"], var.disaster_recovery_mode)
    error_message = "Must be pilot_light or active"
  }
}

# Database always running (core data)
resource "aws_db_instance" "main" {
  identifier     = "production-database"
  engine         = "postgres"
  instance_class = "db.t3.medium"
  
  # Replicate to DR region
  backup_retention_period = 7
  
  tags = {
    DRMode = "always-on"
  }
}

# Read replica in DR region (always on)
resource "aws_db_instance" "replica" {
  provider = aws.dr_region
  
  identifier             = "production-database-replica"
  replicate_source_db    = aws_db_instance.main.arn
  instance_class         = "db.t3.medium"
  skip_final_snapshot    = false
  backup_retention_period = 7
  
  tags = {
    DRMode = "always-on"
  }
}

# Application servers (conditional)
resource "aws_autoscaling_group" "app" {
  provider = aws.dr_region
  
  name                = "app-asg-dr"
  vpc_zone_identifier = data.aws_subnets.dr_private.ids
  target_group_arns   = [aws_lb_target_group.app_dr.arn]
  health_check_type   = "ELB"
  
  # Pilot light: 0 instances, active: scale up
  min_size         = var.disaster_recovery_mode == "pilot_light" ? 0 : 2
  max_size         = var.disaster_recovery_mode == "pilot_light" ? 0 : 10
  desired_capacity = var.disaster_recovery_mode == "pilot_light" ? 0 : 2
  
  launch_template {
    id      = aws_launch_template.app_dr.id
    version = "$Latest"
  }
  
  tag {
    key                 = "DRMode"
    value               = var.disaster_recovery_mode
    propagate_at_launch = true
  }
}

# ALB (always on but no targets in pilot light)
resource "aws_lb" "app_dr" {
  provider = aws.dr_region
  
  name               = "app-alb-dr"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_dr.id]
  subnets            = data.aws_subnets.dr_public.ids
  
  enable_deletion_protection = true
}
```

**Failover automation:**

```bash
# disaster-recovery/scripts/activate_dr.sh
#!/bin/bash

echo "Activating disaster recovery site..."

# Step 1: Promote read replica to primary
aws rds promote-read-replica \
  --db-instance-identifier production-database-replica \
  --region us-west-2

# Step 2: Update Terraform to scale up
export TF_VAR_disaster_recovery_mode="active"

# Step 3: Apply Terraform (scales ASG from 0 to 2 instances)
terraform apply -auto-approve

# Step 4: Update DNS to point to DR region
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890ABC \
  --change-batch file://dns-failover.json

echo "DR site activated. RTO: ~15 minutes"
```


### Active-Active Multi-Region

Zero RTO, highest cost and complexity.

```hcl
# disaster-recovery/active-active.tf

# Deploy in both regions simultaneously
module "us_east_1" {
  source = "./region-stack"
  
  providers = {
    aws = aws.us_east_1
  }
  
  region      = "us-east-1"
  environment = "production"
  
  min_instances = 3
  max_instances = 20
}

module "us_west_2" {
  source = "./region-stack"
  
  providers = {
    aws = aws.us_west_2
  }
  
  region      = "us-west-2"
  environment = "production"
  
  min_instances = 3
  max_instances = 20
}

# Global Accelerator for traffic distribution
resource "aws_globalaccelerator_accelerator" "main" {
  name            = "production-accelerator"
  ip_address_type = "IPV4"
  enabled         = true
}

resource "aws_globalaccelerator_listener" "https" {
  accelerator_arn = aws_globalaccelerator_accelerator.main.id
  protocol        = "TCP"
  
  port_range {
    from_port = 443
    to_port   = 443
  }
}

# Endpoint groups for both regions
resource "aws_globalaccelerator_endpoint_group" "us_east_1" {
  listener_arn = aws_globalaccelerator_listener.https.id
  
  endpoint_group_region = "us-east-1"
  traffic_dial_percentage = 50  # 50/50 traffic split
  
  endpoint_configuration {
    endpoint_id = module.us_east_1.alb_arn
    weight      = 100
  }
}

resource "aws_globalaccelerator_endpoint_group" "us_west_2" {
  listener_arn = aws_globalaccelerator_listener.https.id
  
  endpoint_group_region = "us-west-2"
  traffic_dial_percentage = 50
  
  endpoint_configuration {
    endpoint_id = module.us_west_2.alb_arn
    weight      = 100
  }
}

# DynamoDB Global Tables for data replication
resource "aws_dynamodb_table" "global" {
  name         = "production-data"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  
  replica {
    region_name = "us-west-2"
  }
  
  attribute {
    name = "id"
    type = "S"
  }
}
```


## Cost Optimization Framework

### Automated Cost Analysis with Infracost

```yaml
# .github/workflows/cost-estimate.yml
name: Terraform Cost Estimation

on:
  pull_request:
    branches: [main]

jobs:
  cost-estimate:
    runs-on: ubuntu-latest
    
    permissions:
      contents: read
      pull-requests: write
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.11.0
      
      - name: Terraform Init
        run: terraform init
      
      - name: Terraform Plan
        run: terraform plan -out=tfplan.binary
      
      - name: Convert Plan to JSON
        run: terraform show -json tfplan.binary > plan.json
      
      - name: Setup Infracost
        uses: infracost/actions/setup@v3
        with:
          api-key: ${{ secrets.INFRACOST_API_KEY }}
      
      - name: Generate Infracost JSON
        run: |
          infracost breakdown --path plan.json \
            --format json \
            --out-file /tmp/infracost.json
      
      - name: Post Cost Comment
        run: |
          infracost comment github --path /tmp/infracost.json \
            --repo $GITHUB_REPOSITORY \
            --pull-request ${{ github.event.pull_request.number }} \
            --github-token ${{ secrets.GITHUB_TOKEN }} \
            --behavior update
```

**Example Infracost Output:**

```
Project: terraform/production

 Name                                    Monthly Qty  Unit   Monthly Cost 
                                                                            
 aws_instance.web                                                          
 ├─ Instance usage (Linux/UNIX, on-demand, t3.large)  730  hours    $60.74 
 └─ root_block_device                                                      
    └─ Storage (general purpose SSD, gp3)             50  GB         $4.00 
                                                                            
 aws_db_instance.main                                                      
 ├─ Database instance (on-demand, db.r6g.xlarge)      730  hours   $350.40 
 ├─ Storage (general purpose SSD, gp3)              1,000  GB        $115.00 
 └─ Additional backup storage                         500  GB-months $47.50 
                                                                            
 aws_nat_gateway.main                                                      
 ├─ NAT gateway                                       730  hours    $32.85 
 └─ Data processed                              Monthly cost depends on usage
                                                                            
 OVERALL TOTAL                                                      $610.49 

──────────────────────────────────
20 cloud resources were detected:
∙ 15 were estimated, all of which include usage-based costs
∙ 5 were free
```


### Cost Optimization Policies

```hcl
# cost-optimization/policies.tf

# Prevent expensive instance types
locals {
  prohibited_instance_types = [
    "c5.24xlarge",
    "m5.24xlarge",
    "r5.24xlarge",
    "p3.16xlarge",  # GPU instances
    "p4d.24xlarge"
  ]
}

# Lifecycle rule: Warn about expensive resources
resource "null_resource" "cost_validation" {
  lifecycle {
    precondition {
      condition = !contains(local.prohibited_instance_types, var.instance_type)
      error_message = "Instance type ${var.instance_type} exceeds cost limits. Use smaller instances or get approval."
    }
  }
}

# Auto-scaling for cost efficiency
resource "aws_autoscaling_schedule" "scale_down_nights" {
  scheduled_action_name  = "scale-down-nights"
  min_size               = 1
  max_size               = 2
  desired_capacity       = 1
  recurrence             = "0 22 * * MON-FRI"  # 10 PM weekdays
  autoscaling_group_name = aws_autoscaling_group.app.name
}

resource "aws_autoscaling_schedule" "scale_up_mornings" {
  scheduled_action_name  = "scale-up-mornings"
  min_size               = 2
  max_size               = 10
  desired_capacity       = 3
  recurrence             = "0 6 * * MON-FRI"  # 6 AM weekdays
  autoscaling_group_name = aws_autoscaling_group.app.name
}

# Spot instances for non-critical workloads
resource "aws_autoscaling_group" "batch_processing" {
  name = "batch-processing-asg"
  
  mixed_instances_policy {
    launch_template {
      launch_template_specification {
        launch_template_id = aws_launch_template.batch.id
      }
      
      override {
        instance_type     = "c5.xlarge"
        weighted_capacity = "1"
      }
      
      override {
        instance_type     = "c5a.xlarge"
        weighted_capacity = "1"
      }
    }
    
    instances_distribution {
      on_demand_base_capacity                  = 0
      on_demand_percentage_above_base_capacity = 20  # 80% Spot, 20% On-Demand
      spot_allocation_strategy                 = "capacity-optimized"
    }
  }
  
  min_size         = 0
  max_size         = 20
  desired_capacity = 5
  
  vpc_zone_identifier = data.aws_subnets.private.ids
}

# S3 lifecycle for cost savings
resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  
  rule {
    id     = "transition-old-data"
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
      storage_class = "GLACIER"
    }
    
    expiration {
      days = 730  # Delete after 2 years
    }
  }
  
  rule {
    id     = "clean-incomplete-uploads"
    status = "Enabled"
    
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}
```


## Drift Detection and Remediation

### Understanding Infrastructure Drift

Infrastructure drift occurs when the actual state of resources diverges from the state defined in Terraform configuration. This happens through manual changes in AWS Console, modifications by other tools (CloudFormation, AWS CLI, SDKs), auto-remediation by AWS services, or changes by team members unaware of Terraform management. Drift introduces several critical risks: **security vulnerabilities** when manually added security group rules bypass review processes, **compliance violations** when required encryption or tagging gets removed, **cost overruns** when instance types get manually upgraded, **reliability issues** when configurations drift from tested states, and **state file inconsistencies** making Terraform operations unpredictable.[^3][^7][^1]

**Common drift scenarios:**

```hcl
# Terraform configuration defines t3.micro
resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  
  tags = {
    Environment = "production"
    ManagedBy   = "Terraform"
  }
}

# Actual AWS state after manual change:
# - Instance type manually changed to t3.xlarge (4x cost)
# - Tags manually modified or removed
# - Security groups manually attached
# - User data script manually updated
```


### Drift Detection Strategies

**Strategy 1: Scheduled Terraform Plan Runs**

The baseline drift detection approach runs `terraform plan` on a schedule, surfacing any divergence as proposed changes.[^2][^1]

```bash
#!/bin/bash
# scripts/drift-detection.sh

set -euo pipefail

# Configuration
TERRAFORM_DIR="/opt/terraform/production"
SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
EMAIL_RECIPIENTS="infrastructure-team@example.com"

# Change to Terraform directory
cd "$TERRAFORM_DIR"

# Initialize Terraform (refresh providers)
terraform init -input=false -upgrade > /dev/null

# Run plan with detailed exit code
# Exit codes: 0 = no changes, 1 = error, 2 = changes detected
terraform plan -detailed-exitcode -no-color > /tmp/drift-plan.txt
PLAN_EXIT_CODE=$?

if [ $PLAN_EXIT_CODE -eq 2 ]; then
  echo "⚠️  DRIFT DETECTED in production infrastructure"
  
  # Extract changed resources
  CHANGED_RESOURCES=$(grep -E "^\s+(~|\\+|-)" /tmp/drift-plan.txt | head -20)
  
  # Generate drift report
  cat > /tmp/drift-report.txt <<EOF
Terraform Drift Detection Report
================================
Timestamp: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Environment: Production
Status: DRIFT DETECTED

Changed Resources:
$CHANGED_RESOURCES

View full plan: /tmp/drift-plan.txt
EOF
  
  # Send Slack notification
  curl -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"⚠️ Infrastructure drift detected in production\n\`\`\`$(cat /tmp/drift-report.txt)\`\`\`\"}" \
    "$SLACK_WEBHOOK_URL"
  
  # Send email alert
  cat /tmp/drift-report.txt | mail -s "ALERT: Terraform Drift Detected - Production" \
    "$EMAIL_RECIPIENTS"
  
  # Create GitHub issue (optional)
  gh issue create \
    --title "Infrastructure Drift Detected - $(date +%Y-%m-%d)" \
    --body "$(cat /tmp/drift-report.txt)" \
    --label "drift,infrastructure,urgent"
  
  exit 2
elif [ $PLAN_EXIT_CODE -eq 1 ]; then
  echo "❌ Terraform plan failed"
  exit 1
else
  echo "✅ No drift detected - infrastructure matches Terraform state"
  exit 0
fi
```

**Schedule with cron:**

```bash
# Run drift detection every 4 hours
0 */4 * * * /opt/scripts/drift-detection.sh

# Run during business hours only (9 AM - 5 PM, Mon-Fri)
0 9-17 * * 1-5 /opt/scripts/drift-detection.sh

# Run after maintenance windows
30 22 * * * /opt/scripts/drift-detection.sh  # 10:30 PM
```

**Strategy 2: Continuous Drift Detection with Terraform Cloud**

Terraform Cloud provides native continuous drift detection, automatically running plans on a schedule without manual orchestration.[^8][^1]

```hcl
# Configure workspace for drift detection
# In Terraform Cloud UI or via API:

# workspace-settings.json
{
  "data": {
    "type": "workspaces",
    "attributes": {
      "name": "production-infrastructure",
      "auto-apply": false,
      "queue-all-runs": false,
      
      # Enable continuous drift detection
      "assessments-enabled": true,
      
      # Check for drift every 24 hours
      "drift-detection": {
        "enabled": true,
        "interval": "24h"
      }
    }
  }
}
```

**Configure via Terraform:**

```hcl
# terraform-cloud-config/workspace.tf
resource "tfe_workspace" "production" {
  name         = "production-infrastructure"
  organization = "your-organization"
  
  # Enable drift detection
  assessments_enabled = true
  
  # VCS integration
  vcs_repo {
    identifier     = "your-org/infrastructure-repo"
    oauth_token_id = var.vcs_oauth_token_id
  }
  
  # Terraform version
  terraform_version = "1.11.0"
  
  # Working directory
  working_directory = "environments/production"
  
  # Notifications for drift
  notification_configuration {
    destination_type = "slack"
    enabled          = true
    name             = "Drift Detection Alerts"
    url              = var.slack_webhook_url
    
    triggers = ["assessment:drift_detected"]
  }
}

# Configure drift detection notification
resource "tfe_notification_configuration" "drift_email" {
  workspace_id     = tfe_workspace.production.id
  name             = "Email Drift Alerts"
  destination_type = "email"
  enabled          = true
  
  email_addresses = [
    "infrastructure-team@example.com",
    "security-team@example.com"
  ]
  
  triggers = [
    "assessment:drift_detected",
    "assessment:failed"
  ]
}
```

**Pricing consideration:** Terraform Cloud charges \$0.00014 per resource per hour for drift detection beyond 500 free resources. For 2,000 resources, this costs approximately \$200/month.[^8]

**Strategy 3: Third-Party Drift Detection Tools**

Advanced drift detection tools provide capabilities beyond Terraform's native functionality.[^1][^2]

**Spacelift Drift Detection:**

```hcl
# .spacelift/config.yml
version: 1

stack:
  name: production-infrastructure
  
  # Enable drift detection
  drift_detection:
    enabled: true
    schedule:
      - "0 */6 * * *"  # Every 6 hours
    reconcile: false    # Don't auto-fix, alert only
    
  # Drift detection notifications
  notifications:
    - type: slack
      url: ${SLACK_WEBHOOK}
      events:
        - drift_detected
        - drift_remediated
    
    - type: webhook
      url: https://api.example.com/drift-webhook
      events:
        - drift_detected
```

**Driftctl - Detect Unmanaged Resources:**

Driftctl identifies resources created outside Terraform that should be managed.[^2]

```bash
# Install driftctl
brew install driftctl

# Scan for drift including unmanaged resources
driftctl scan \
  --from tfstate+s3://terraform-state/production/terraform.tfstate \
  --to aws+tf \
  --output json > drift-report.json

# Example output
{
  "summary": {
    "total_resources": 247,
    "total_managed": 189,
    "total_unmanaged": 58,
    "total_changed": 12
  },
  "unmanaged": [
    {
      "id": "sg-0123456789abcdef0",
      "type": "aws_security_group",
      "source": "AWS Console"
    },
    {
      "id": "i-0987654321fedcba0",
      "type": "aws_instance",
      "source": "AWS Console"
    }
  ],
  "changed": [
    {
      "id": "i-abcdef123456",
      "type": "aws_instance",
      "changes": {
        "instance_type": {
          "expected": "t3.micro",
          "actual": "t3.large"
        }
      }
    }
  ]
}

# Generate HTML report
driftctl scan --output html://drift-report.html
```

**Cloud-Concierge - Continuous Monitoring:**

```yaml
# cloud-concierge-config.yml
providers:
  - name: aws
    regions:
      - us-east-1
      - us-west-2

monitoring:
  interval: 300  # Check every 5 minutes
  
  # Alert on specific resource types
  watch:
    - aws_instance
    - aws_security_group
    - aws_s3_bucket
    - aws_iam_role
    - aws_db_instance

alerts:
  slack:
    webhook: ${SLACK_WEBHOOK}
    channels:
      - "#infrastructure-alerts"
  
  pagerduty:
    integration_key: ${PAGERDUTY_KEY}
    severity: warning

# Ignore expected drift
exceptions:
  - resource: "aws_instance.web[^2]"
    reason: "Managed by auto-scaling"
  - resource: "aws_security_group.temp_access"
    reason: "Temporary access, expires 2025-12-15"
```


### Drift Remediation Workflows

**Remediation Decision Tree:**

```
Drift Detected
│
├─> Is drift intentional?
│   │
│   ├─> YES → Update Terraform config to match reality
│   │         terraform apply -refresh-only
│   │         git commit -m "Accept infrastructure changes"
│   │
│   └─> NO → Revert to Terraform-defined state
│             terraform apply (forces compliance)
│
├─> Is resource unmanaged?
│   │
│   └─> Import into Terraform
│       terraform import aws_instance.new i-xxxxx
│       # Write corresponding configuration
│       terraform apply (verify no changes)
│
└─> Is drift causing issues?
    │
    ├─> CRITICAL → Immediate remediation + incident review
    │              terraform apply -target=affected_resource
    │              Post-incident review of root cause
    │
    └─> LOW → Schedule remediation in next change window
               Create ticket for investigation
```

**Workflow 1: Accept Drift (Update Terraform)**

```bash
# scripts/accept-drift.sh

#!/bin/bash
# Use when manual changes should be incorporated into Terraform

set -euo pipefail

echo "Refreshing Terraform state to match actual infrastructure..."

# Refresh state to incorporate changes
terraform apply -refresh-only -auto-approve

echo "State updated. Review changes and update configuration:"

# Show what changed
terraform show | diff - <(git show HEAD:terraform.tfstate | terraform show -json) || true

echo ""
echo "Next steps:"
echo "1. Update .tf files to match new state"
echo "2. Run 'terraform plan' (should show no changes)"
echo "3. Commit updated configuration to Git"
echo "4. Document why drift was accepted"
```

**Workflow 2: Revert Drift (Force Compliance)**

```bash
# scripts/revert-drift.sh

#!/bin/bash
# Use when manual changes should be reverted

set -euo pipefail

RESOURCE="${1:-}"

if [ -z "$RESOURCE" ]; then
  echo "Usage: $0 <resource_address>"
  echo "Example: $0 aws_instance.web"
  exit 1
fi

echo "Reverting drift for resource: $RESOURCE"

# Show current vs desired state
echo "Current state (actual):"
terraform show "$RESOURCE"

echo ""
echo "Desired state (Terraform configuration):"
terraform plan -target="$RESOURCE"

# Confirm before reverting
read -p "Revert to Terraform-defined state? (yes/no): " CONFIRM

if [ "$CONFIRM" == "yes" ]; then
  echo "Reverting drift..."
  terraform apply -target="$RESOURCE" -auto-approve
  
  echo "✅ Drift reverted successfully"
  
  # Document remediation
  echo "$(date -u): Reverted drift for $RESOURCE" >> drift-remediation.log
else
  echo "❌ Remediation cancelled"
  exit 1
fi
```

**Workflow 3: Import Unmanaged Resources**

```bash
# scripts/import-unmanaged.sh

#!/bin/bash
# Import resources created outside Terraform

set -euo pipefail

RESOURCE_TYPE="${1:-}"
RESOURCE_NAME="${2:-}"
RESOURCE_ID="${3:-}"

if [ -z "$RESOURCE_TYPE" ] || [ -z "$RESOURCE_NAME" ] || [ -z "$RESOURCE_ID" ]; then
  echo "Usage: $0 <resource_type> <resource_name> <resource_id>"
  echo "Example: $0 aws_security_group manually_created sg-0123456789"
  exit 1
fi

RESOURCE_ADDRESS="${RESOURCE_TYPE}.${RESOURCE_NAME}"

echo "Importing $RESOURCE_ID as $RESOURCE_ADDRESS"

# Import resource
terraform import "$RESOURCE_ADDRESS" "$RESOURCE_ID"

# Generate configuration from imported state
echo ""
echo "Resource imported. Add this configuration to your .tf files:"
echo ""
terraform show -json | jq -r ".values.root_module.resources[] | select(.address == \"$RESOURCE_ADDRESS\")"

echo ""
echo "Next steps:"
echo "1. Copy generated configuration to appropriate .tf file"
echo "2. Run 'terraform plan' to verify (should show no changes)"
echo "3. Commit changes to Git"
```


### Preventing Drift

**Prevention Strategy 1: Restrict Console Access**

```hcl
# iam-policies/prevent-manual-changes.tf

# IAM policy preventing manual modifications to Terraform-managed resources
resource "aws_iam_policy" "prevent_manual_changes" {
  name        = "PreventManualInfrastructureChanges"
  description = "Deny modifications to Terraform-managed resources"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyModifyTerraformResources"
        Effect = "Deny"
        Action = [
          "ec2:ModifyInstanceAttribute",
          "ec2:ModifyInstanceMetadataOptions",
          "ec2:ModifyInstancePlacement",
          "rds:ModifyDBInstance",
          "s3:PutBucketPolicy",
          "s3:DeleteBucketPolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/ManagedBy" = "Terraform"
          }
        }
      },
      {
        Sid    = "AllowTerraformServiceRole"
        Effect = "Allow"
        Action = "*"
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:PrincipalArn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/TerraformExecutionRole"
          }
        }
      }
    ]
  })
}

# Attach to human users (not service roles)
resource "aws_iam_group_policy_attachment" "engineers" {
  group      = "Engineers"
  policy_arn = aws_iam_policy.prevent_manual_changes.arn
}
```

**Prevention Strategy 2: Service Control Policies (SCPs)**

```hcl
# organizations/scps/prevent-manual-changes.tf

resource "aws_organizations_policy" "prevent_console_modifications" {
  name        = "PreventConsoleModifications"
  description = "Prevent manual modifications to infrastructure"
  type        = "SERVICE_CONTROL_POLICY"
  
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RequireAutomationTag"
        Effect = "Deny"
        Action = [
          "ec2:RunInstances",
          "rds:CreateDBInstance",
          "s3:CreateBucket"
        ]
        Resource = "*"
        Condition = {
          "Null" = {
            "aws:RequestTag/ManagedBy" = "true"
          }
        }
      },
      {
        Sid    = "AllowTerraformRole"
        Effect = "Allow"
        Action = "*"
        Resource = "*"
        Condition = {
          StringLike = {
            "aws:PrincipalArn" = "*TerraformExecutionRole"
          }
        }
      }
    ]
  })
}

# Apply to production OU
resource "aws_organizations_policy_attachment" "production" {
  policy_id = aws_organizations_policy.prevent_console_modifications.id
  target_id = aws_organizations_organizational_unit.production.id
}
```

**Prevention Strategy 3: AWS Config Rules**

```hcl
# config/drift-detection-rules.tf

# Detect instances without required tags
resource "aws_config_config_rule" "required_tags" {
  name = "required-tags-check"
  
  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }
  
  input_parameters = jsonencode({
    tag1Key = "ManagedBy"
    tag1Value = "Terraform"
    tag2Key = "Environment"
  })
  
  scope {
    compliance_resource_types = [
      "AWS::EC2::Instance",
      "AWS::RDS::DBInstance",
      "AWS::S3::Bucket"
    ]
  }
}

# Detect configuration changes
resource "aws_config_config_rule" "configuration_changes" {
  name = "detect-configuration-changes"
  
  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_NO_PUBLIC_IP"
  }
  
  depends_on = [aws_config_configuration_recorder.main]
}

# Remediation action
resource "aws_config_remediation_configuration" "revert_public_ip" {
  config_rule_name = aws_config_config_rule.configuration_changes.name
  
  target_type      = "SSM_DOCUMENT"
  target_identifier = "AWS-PublishSNSNotification"
  
  parameter {
    name         = "TopicArn"
    static_value = aws_sns_topic.drift_alerts.arn
  }
  
  automatic = true
  maximum_automatic_attempts = 3
  retry_attempt_seconds      = 60
}
```

**Prevention Strategy 4: Automated Tagging**

```hcl
# Automatically tag all resources
provider "aws" {
  region = "us-east-1"
  
  default_tags {
    tags = {
      ManagedBy   = "Terraform"
      Environment = var.environment
      GitRepo     = "github.com/company/infrastructure"
      GitCommit   = var.git_commit_sha
      LastUpdated = timestamp()
    }
  }
}

# Enforce tagging in modules
variable "required_tags" {
  description = "Required tags for all resources"
  type        = map(string)
  default = {
    ManagedBy = "Terraform"
  }
  
  validation {
    condition     = contains(keys(var.required_tags), "ManagedBy")
    error_message = "ManagedBy tag is required for all resources"
  }
}
```


## Compliance Enforcement with Policy as Code

### Understanding Policy as Code

Policy as Code enforces organizational standards, security requirements, and compliance controls before infrastructure changes are applied. Rather than relying on post-deployment audits discovering violations, policies shift enforcement left into the development workflow, preventing non-compliant infrastructure from ever reaching production. **Two primary frameworks dominate enterprise policy enforcement: Sentinel (HashiCorp's proprietary language integrated with Terraform Cloud/Enterprise) and Open Policy Agent (OPA, an open-source CNCF project using the Rego language)**.[^4]

**Key differences between Sentinel and OPA:**


| Aspect | Sentinel | Open Policy Agent (OPA) |
| :-- | :-- | :-- |
| **License** | Proprietary (Terraform Cloud/Enterprise only) | Open-source (Apache 2.0) |
| **Language** | Sentinel (HashiCorp-specific) | Rego (general-purpose) |
| **Integration** | Native Terraform Cloud/Enterprise | Requires external integration |
| **Learning Curve** | Terraform-focused, moderate | General-purpose, steeper |
| **Policy Testing** | Built-in testing framework | OPA test framework |
| **Enforcement Levels** | Hard/soft mandatory, advisory | Custom implementation |
| **Community** | Smaller, HashiCorp-focused | Larger, cloud-native ecosystem |
| **Cost** | Requires paid Terraform Cloud/Enterprise | Free, open-source |

### Sentinel Policy Framework

Sentinel provides three enforcement levels:[^4]

- **Hard-mandatory:** Blocks terraform apply, cannot be overridden
- **Soft-mandatory:** Blocks terraform apply, but can be overridden by authorized users
- **Advisory:** Displays warning, does not block apply

**Sentinel Policy Structure:**

```
policies/
├── cost-control/
│   ├── limit-instance-size.sentinel
│   ├── prevent-expensive-resources.sentinel
│   └── require-budget-tags.sentinel
├── security/
│   ├── require-encryption.sentinel
│   ├── prevent-public-access.sentinel
│   ├── enforce-security-groups.sentinel
│   └── require-mfa-delete.sentinel
├── compliance/
│   ├── require-tagging.sentinel
│   ├── enforce-naming-convention.sentinel
│   ├── require-backup-enabled.sentinel
│   └── enforce-log-retention.sentinel
├── tests/
│   ├── cost-control/
│   ├── security/
│   └── compliance/
└── sentinel.hcl
```

**Example 1: Prevent Oversized EC2 Instances:**

```hcl
# policies/cost-control/limit-instance-size.sentinel
import "tfplan/v2" as tfplan
import "strings"

# Allowed instance types (cost-controlled)
allowed_instance_types = [
  "t3.micro",
  "t3.small",
  "t3.medium",
  "t3.large",
  "t3.xlarge",
  "t3a.micro",
  "t3a.small",
  "t3a.medium"
]

# Maximum vCPU count
max_vcpus = 4

# Find all EC2 instances in the plan
instances = filter tfplan.resource_changes as _, rc {
  rc.type is "aws_instance" and
  (rc.change.actions contains "create" or rc.change.actions contains "update")
}

# Validation function
validate_instance_type = func(instance) {
  instance_type = instance.change.after.instance_type
  
  if instance_type not in allowed_instance_types {
    print("❌ Instance type", instance_type, "is not allowed.")
    print("   Resource:", instance.address)
    print("   Allowed types:", strings.join(allowed_instance_types, ", "))
    print("   Rationale: Cost control policy limits instance sizes")
    print("   Override: Contact FinOps team for approval")
    return false
  }
  
  return true
}

# Validate CPU count for approved types
validate_vcpu_count = func(instance) {
  instance_type = instance.change.after.instance_type
  
  # Map instance types to vCPU counts
  vcpu_map = {
    "t3.micro":   2,
    "t3.small":   2,
    "t3.medium":  2,
    "t3.large":   2,
    "t3.xlarge":  4,
    "t3a.micro":  2,
    "t3a.small":  2,
    "t3a.medium": 2
  }
  
  vcpus = vcpu_map[instance_type] else 999
  
  if vcpus > max_vcpus {
    print("❌ Instance", instance.address, "exceeds maximum vCPU count")
    print("   Instance type:", instance_type, "(", vcpus, "vCPUs)")
    print("   Maximum allowed:", max_vcpus, "vCPUs")
    return false
  }
  
  return true
}

# Main rule
instance_type_valid = rule {
  all instances as address, instance {
    validate_instance_type(instance)
  }
}

vcpu_count_valid = rule {
  all instances as address, instance {
    validate_vcpu_count(instance)
  }
}

main = rule {
  instance_type_valid and vcpu_count_valid
}
```

**Example 2: Require Encryption (Security):**

```hcl
# policies/security/require-encryption.sentinel
import "tfplan/v2" as tfplan

# Find all RDS instances
rds_instances = filter tfplan.resource_changes as _, rc {
  rc.type is "aws_db_instance" and
  (rc.change.actions contains "create" or rc.change.actions contains "update")
}

# Find all EBS volumes
ebs_volumes = filter tfplan.resource_changes as _, rc {
  rc.type is "aws_ebs_volume" and
  (rc.change.actions contains "create" or rc.change.actions contains "update")
}

# Find all S3 buckets
s3_buckets = filter tfplan.resource_changes as _, rc {
  rc.type is "aws_s3_bucket" and
  (rc.change.actions contains "create" or rc.change.actions contains "update")
}

# Find S3 encryption configurations
s3_encryption_configs = filter tfplan.resource_changes as _, rc {
  rc.type is "aws_s3_bucket_server_side_encryption_configuration" and
  (rc.change.actions contains "create" or rc.change.actions contains "update")
}

# Validate RDS encryption
validate_rds_encryption = func(instance) {
  if instance.change.after.storage_encrypted is not true {
    print("❌ RDS instance must have storage encryption enabled")
    print("   Resource:", instance.address)
    print("   Current setting: storage_encrypted =", instance.change.after.storage_encrypted)
    print("   Required: storage_encrypted = true")
    print("   Compliance: SOC2, PCI-DSS, HIPAA")
    return false
  }
  
  # Validate KMS key is used (not default encryption)
  if instance.change.after.kms_key_id is empty {
    print("⚠️  Warning: RDS instance uses default encryption")
    print("   Resource:", instance.address)
    print("   Recommendation: Use customer-managed KMS key")
    print("   Add: kms_key_id = aws_kms_key.rds.arn")
  }
  
  return true
}

# Validate EBS encryption
validate_ebs_encryption = func(volume) {
  if volume.change.after.encrypted is not true {
    print("❌ EBS volume must be encrypted")
    print("   Resource:", volume.address)
    print("   Current setting: encrypted =", volume.change.after.encrypted)
    print("   Required: encrypted = true")
    return false
  }
  return true
}

# Check S3 has encryption config
validate_s3_encryption = func() {
  # Count S3 buckets being created/updated
  bucket_count = length(s3_buckets)
  
  # Count encryption configurations
  encryption_count = length(s3_encryption_configs)
  
  if bucket_count > 0 and encryption_count is 0 {
    print("❌ S3 buckets require encryption configuration")
    print("   Buckets without encryption:", bucket_count)
    print("   Add: aws_s3_bucket_server_side_encryption_configuration resource")
    print("   Example:")
    print("     resource \"aws_s3_bucket_server_side_encryption_configuration\" \"example\" {")
    print("       bucket = aws_s3_bucket.example.id")
    print("       rule {")
    print("         apply_server_side_encryption_by_default {")
    print("           sse_algorithm = \"aws:kms\"")
    print("           kms_master_key_id = aws_kms_key.s3.arn")
    print("         }")
    print("       }")
    print("     }")
    return false
  }
  
  return true
}

# Main rules
rds_encrypted = rule {
  all rds_instances as address, instance {
    validate_rds_encryption(instance)
  }
}

ebs_encrypted = rule {
  all ebs_volumes as address, volume {
    validate_ebs_encryption(volume)
  }
}

s3_encrypted = rule {
  validate_s3_encryption()
}

main = rule {
  rds_encrypted and ebs_encrypted and s3_encrypted
}
```

**Example 3: Enforce Comprehensive Tagging:**

```hcl
# policies/compliance/require-tagging.sentinel
import "tfplan/v2" as tfplan
import "strings"

# Required tags for all resources
required_tags = [
  "Environment",
  "Owner",
  "CostCenter",
  "Project",
  "ManagedBy"
]

# Tag value validations
valid_environments = ["development", "staging", "production", "sandbox"]

# Resources that must be tagged
taggable_resources = [
  "aws_instance",
  "aws_vpc",
  "aws_subnet",
  "aws_security_group",
  "aws_db_instance",
  "aws_s3_bucket",
  "aws_ecs_cluster",
  "aws_ecs_service",
  "aws_lambda_function",
  "aws_elasticache_cluster",
  "aws_rds_cluster",
  "aws_eks_cluster",
  "aws_lb",
  "aws_autoscaling_group"
]

# Find all resources requiring tags
resources = filter tfplan.resource_changes as _, rc {
  rc.type in taggable_resources and
  (rc.change.actions contains "create" or rc.change.actions contains "update")
}

# Validate tags exist
validate_tags = func(resource) {
  tags = resource.change.after.tags else {}
  
  missing_tags = []
  for required_tags as tag {
    if tag not in keys(tags) {
      append(missing_tags, tag)
    }
  }
  
  if length(missing_tags) > 0 {
    print("❌ Resource missing required tags")
    print("   Resource:", resource.address)
    print("   Missing tags:", strings.join(missing_tags, ", "))
    print("   Add these tags to your resource:")
    print("   tags = {")
    for missing_tags as tag {
      print("     ", tag, " = \"<value>\"")
    }
    print("   }")
    return false
  }
  
  return true
}

# Validate Environment tag value
validate_environment = func(resource) {
  tags = resource.change.after.tags else {}
  
  if "Environment" in keys(tags) {
    env = tags["Environment"]
    if env not in valid_environments {
      print("❌ Invalid Environment tag value")
      print("   Resource:", resource.address)
      print("   Current value:", env)
      print("   Valid values:", strings.join(valid_environments, ", "))
      return false
    }
  }
  
  return true
}

# Validate Owner tag format (email)
validate_owner = func(resource) {
  tags = resource.change.after.tags else {}
  
  if "Owner" in keys(tags) {
    owner = tags["Owner"]
    if not strings.contains(owner, "@") {
      print("⚠️  Warning: Owner tag should be an email address")
      print("   Resource:", resource.address)
      print("   Current value:", owner)
      print("   Expected format: user@example.com")
      # Don't fail, just warn
    }
  }
  
  return true
}

# Validate CostCenter format (numeric)
validate_cost_center = func(resource) {
  tags = resource.change.after.tags else {}
  
  if "CostCenter" in keys(tags) {
    cost_center = tags["CostCenter"]
    # Check if numeric (basic validation)
    if not strings.matches(cost_center, "^[0-9]+$") {
      print("❌ CostCenter must be numeric")
      print("   Resource:", resource.address)
      print("   Current value:", cost_center)
      print("   Expected format: 1234")
      return false
    }
  }
  
  return true
}

# Main rules
tags_present = rule {
  all resources as address, resource {
    validate_tags(resource)
  }
}

environment_valid = rule {
  all resources as address, resource {
    validate_environment(resource)
  }
}

owner_valid = rule {
  all resources as address, resource {
    validate_owner(resource)
  }
}

cost_center_valid = rule {
  all resources as address, resource {
    validate_cost_center(resource)
  }
}

main = rule {
  tags_present and environment_valid and owner_valid and cost_center_valid
}
```

**Sentinel Configuration File:**

```hcl
# sentinel.hcl
policy "limit-instance-size" {
  source            = "./policies/cost-control/limit-instance-size.sentinel"
  enforcement_level = "hard-mandatory"  # Blocks apply, no override
}

policy "require-encryption" {
  source            = "./policies/security/require-encryption.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "require-tagging" {
  source            = "./policies/compliance/require-tagging.sentinel"
  enforcement_level = "soft-mandatory"  # Can be overridden with approval
}

policy "prevent-public-access" {
  source            = "./policies/security/prevent-public-access.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "enforce-naming-convention" {
  source            = "./policies/compliance/enforce-naming-convention.sentinel"
  enforcement_level = "advisory"  # Warning only, doesn't block
}

# Policy sets allow grouping and conditional application
policy_set "production-policies" {
  source = "./policies/production"
  
  policies = [
    "limit-instance-size",
    "require-encryption",
    "require-tagging",
    "prevent-public-access"
  ]
}

policy_set "development-policies" {
  source = "./policies/development"
  
  policies = [
    "require-tagging"
  ]
}
```

**Testing Sentinel Policies:**

```hcl
# tests/cost-control/limit-instance-size_test.sentinel
import "testing"

# Mock data for test
mock_data = {
  "tfplan/v2": {
    "resource_changes": {
      "aws_instance.allowed": {
        "type": "aws_instance",
        "change": {
          "actions": ["create"],
          "after": {
            "instance_type": "t3.medium"
          }
        },
        "address": "aws_instance.allowed"
      },
      "aws_instance.too_large": {
        "type": "aws_instance",
        "change": {
          "actions": ["create"],
          "after": {
            "instance_type": "m5.24xlarge"
          }
        },
        "address": "aws_instance.too_large"
      }
    }
  }
}

# Test case: Allowed instance type passes
test "allowed_instance_type_passes" {
  rules = {
    "main": true
  }
  
  mock = mock_data
}

# Test case: Oversized instance fails
test "oversized_instance_fails" {
  rules = {
    "main": false
  }
  
  mock = mock_data
}
```

```bash
# Run Sentinel tests
sentinel test

# Output:
# PASS - limit-instance-size_test.sentinel
#   PASS - allowed_instance_type_passes
#   PASS - oversized_instance_fails
# 
# 2 tests, 2 passed, 0 warnings, 0 failures
```


### Open Policy Agent (OPA) Framework

OPA provides open-source policy enforcement using the Rego language. Unlike Sentinel, OPA works with any tool and platform, making it suitable for multi-cloud and tool-agnostic governance.[^4]

**OPA Policy Structure:**

```
policies/
├── terraform/
│   ├── security.rego
│   ├── cost.rego
│   ├── compliance.rego
│   └── naming.rego
├── tests/
│   ├── security_test.rego
│   ├── cost_test.rego
│   └── compliance_test.rego
└── data/
    ├── allowed_instance_types.json
    ├── required_tags.json
    └── cost_limits.json
```

**Example 1: Encryption Policy (OPA):**

```rego
# policies/terraform/security.rego
package terraform.security

import future.keywords.contains
import future.keywords.if

# Deny unencrypted RDS instances
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_db_instance"
  resource.change.actions[_] == "create"
  
  not resource.change.after.storage_encrypted
  
  msg := sprintf("RDS instance %s must have storage_encrypted = true", [resource.address])
}

# Deny RDS instances without KMS key
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_db_instance"
  resource.change.actions[_] == "create"
  
  resource.change.after.storage_encrypted
  not resource.change.after.kms_key_id
  
  msg := sprintf("RDS instance %s must use customer-managed KMS key", [resource.address])
}

# Deny unencrypted EBS volumes
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ebs_volume"
  resource.change.actions[_] == "create"
  
  not resource.change.after.encrypted
  
  msg := sprintf("EBS volume %s must be encrypted", [resource.address])
}

# Deny S3 buckets without encryption
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket"
  resource.change.actions[_] == "create"
  
  # Check if corresponding encryption config exists
  bucket_name := resource.change.after.bucket
  not has_encryption_config(bucket_name)
  
  msg := sprintf("S3 bucket %s requires encryption configuration", [resource.address])
}

has_encryption_config(bucket_name) {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_server_side_encryption_configuration"
  resource.change.after.bucket == bucket_name
}

# Deny public S3 bucket access
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_public_access_block"
  resource.change.actions[_] == "create"
  
  not resource.change.after.block_public_acls
  
  msg := sprintf("S3 bucket %s must block public ACLs", [resource.address])
}

# Warn about security groups with overly permissive rules
warn[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_security_group"
  
  rule := resource.change.after.ingress[_]
  rule.cidr_blocks[_] == "0.0.0.0/0"
  rule.from_port != 80
  rule.from_port != 443
  
  msg := sprintf("Security group %s has overly permissive ingress rule allowing 0.0.0.0/0 on port %d", 
                 [resource.address, rule.from_port])
}
```

**Example 2: Cost Control Policy (OPA):**

```rego
# policies/terraform/cost.rego
package terraform.cost

import future.keywords.contains
import future.keywords.if

# Load allowed instance types from data file
allowed_instance_types := data.terraform.allowed_instance_types

# Load cost limits from data file
cost_limits := data.terraform.cost_limits

# Deny disallowed instance types
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_instance"
  resource.change.actions[_] == "create"
  
  instance_type := resource.change.after.instance_type
  not instance_type in allowed_instance_types
  
  msg := sprintf("Instance %s uses disallowed type %s. Allowed: %v", 
                 [resource.address, instance_type, allowed_instance_types])
}

# Warn about expensive NAT Gateways
warn[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_nat_gateway"
  
  # Count NAT gateways
  nat_count := count([r | r := input.resource_changes[_]; r.type == "aws_nat_gateway"])
  nat_count > 1
  
  msg := sprintf("Multiple NAT Gateways detected (%d). Consider using single NAT Gateway to reduce costs (~$32/month each)", 
                 [nat_count])
}

# Deny RDS instances without cost center tag
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_db_instance"
  resource.change.actions[_] == "create"
  
  not resource.change.after.tags.CostCenter
  
  msg := sprintf("RDS instance %s must have CostCenter tag for billing allocation", [resource.address])
}

# Calculate estimated monthly cost (simplified)
estimated_cost[resource_address] = cost {
  resource := input.resource_changes[_]
  resource.type == "aws_instance"
  resource.change.actions[_] == "create"
  
  instance_type := resource.change.after.instance_type
  
  # Simplified cost mapping (actual costs vary by region)
  instance_costs := {
    "t3.micro": 7.3,
    "t3.small": 14.6,
    "t3.medium": 29.2,
    "t3.large": 58.4,
    "m5.large": 69.35,
    "m5.xlarge": 138.70
  }
  
  cost := instance_costs[instance_type]
  resource_address := resource.address
}

# Warn if total estimated cost exceeds threshold
warn[msg] {
  total_cost := sum([cost | estimated_cost[_] = cost])
  threshold := cost_limits.monthly_threshold
  
  total_cost > threshold
  
  msg := sprintf("Estimated monthly cost ($%.2f) exceeds threshold ($%.2f)", 
                 [total_cost, threshold])
}
```

**Example 3: Compliance Policy (OPA):**

```rego
# policies/terraform/compliance.rego
package terraform.compliance

import future.keywords.contains
import future.keywords.if

# Load required tags from data file
required_tags := data.terraform.required_tags

# Deny resources missing required tags
deny[msg] {
  resource := input.resource_changes[_]
  taggable_resource(resource.type)
  resource.change.actions[_] == "create"
  
  tags := object.get(resource.change.after, "tags", {})
  
  required_tag := required_tags[_]
  not tags[required_tag]
  
  msg := sprintf("Resource %s missing required tag: %s", [resource.address, required_tag])
}

# Define taggable resources
taggable_resource(resource_type) {
  resource_type in [
    "aws_instance",
    "aws_vpc",
    "aws_subnet",
    "aws_security_group",
    "aws_db_instance",
    "aws_s3_bucket",
    "aws_lambda_function",
    "aws_ecs_cluster",
    "aws_eks_cluster"
  ]
}

# Validate Environment tag values
deny[msg] {
  resource := input.resource_changes[_]
  taggable_resource(resource.type)
  
  tags := object.get(resource.change.after, "tags", {})
  env := tags.Environment
  
  not env in ["development", "staging", "production", "sandbox"]
  
  msg := sprintf("Resource %s has invalid Environment tag: %s. Must be: development, staging, production, or sandbox", 
                 [resource.address, env])
}

# Enforce naming conventions
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket"
  
  bucket_name := resource.change.after.bucket
  
  # Bucket names must start with company prefix
  not startswith(bucket_name, "company-")
  
  msg := sprintf("S3 bucket %s must start with 'company-' prefix", [resource.address])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_role"
  
  role_name := resource.change.after.name
  
  # IAM roles must follow naming pattern: <service>-<environment>-<purpose>
  not regex.match(`^[a-z]+-[a-z]+-[a-z]+$`, role_name)
  
  msg := sprintf("IAM role %s must follow pattern: <service>-<environment>-<purpose>", [resource.address])
}

# Require backup tags for stateful resources
deny[msg] {
  resource := input.resource_changes[_]
  resource.type in ["aws_db_instance", "aws_ebs_volume"]
  
  tags := object.get(resource.change.after, "tags", {})
  
  not tags.Backup
  
  msg := sprintf("Stateful resource %s must have Backup tag (true/false)", [resource.address])
}
```

**Data Files for OPA:**

```json
// data/allowed_instance_types.json
{
  "terraform": {
    "allowed_instance_types": [
      "t3.micro",
      "t3.small",
      "t3.medium",
      "t3.large",
      "t3a.micro",
      "t3a.small",
      "t3a.medium"
    ]
  }
}

// data/required_tags.json
{
  "terraform": {
    "required_tags": [
      "Environment",
      "Owner",
      "CostCenter",
      "Project",
      "ManagedBy"
    ]
  }
}

// data/cost_limits.json
{
  "terraform": {
    "cost_limits": {
      "monthly_threshold": 5000.00,
      "instance_max_vcpus": 4
    }
  }
}
```

**OPA Testing:**

```rego
# tests/security_test.rego
package terraform.security

# Test: Deny unencrypted RDS
test_deny_unencrypted_rds {
  deny["RDS instance aws_db_instance.test must have storage_encrypted = true"] with input as {
    "resource_changes": [{
      "address": "aws_db_instance.test",
      "type": "aws_db_instance",
      "change": {
        "actions": ["create"],
        "after": {
          "storage_encrypted": false
        }
      }
    }]
  }
}

# Test: Allow encrypted RDS
test_allow_encrypted_rds {
  count(deny) == 0 with input as {
    "resource_changes": [{
      "address": "aws_db_instance.test",
      "type": "aws_db_instance",
      "change": {
        "actions": ["create"],
        "after": {
          "storage_encrypted": true,
          "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/12345678"
        }
      }
    }]
  }
}
```

```bash
# Run OPA tests
opa test policies/ tests/

# Output:
# tests/security_test.rego:
# PASS: 2/2
# 
# tests/cost_test.rego:
# PASS: 3/3
# 
# tests/compliance_test.rego:
# PASS: 4/4
# 
# Total: 9 tests, 9 passed, 0 failed
```

**Integrating OPA with Terraform CI/CD:**

```yaml
# .github/workflows/terraform-opa.yml
name: Terraform with OPA Policy Checks

on:
  pull_request:
    branches: [main]

jobs:
  terraform-plan:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.11.0
      
      - name: Terraform Init
        run: terraform init
      
      - name: Terraform Plan
        run: terraform plan -out=tfplan.binary
      
      - name: Convert Plan to JSON
        run: terraform show -json tfplan.binary > tfplan.json
      
      - name: Setup OPA
        uses: open-policy-agent/setup-opa@v2
        with:
          version: latest
      
      - name: Run OPA Policy Checks
        run: |
          # Evaluate policies
          opa eval \
            --data policies/ \
            --data data/ \
            --input tfplan.json \
            --format pretty \
            'data.terraform' > opa-results.json
          
          # Check for policy violations
          VIOLATIONS=$(cat opa-results.json | jq -r '.security.deny + .cost.deny + .compliance.deny | length')
          
          if [ "$VIOLATIONS" -gt 0 ]; then
            echo "❌ Policy violations detected:"
            cat opa-results.json | jq -r '.security.deny[], .cost.deny[], .compliance.deny[]'
            exit 1
          else
            echo "✅ All policy checks passed"
          fi
      
      - name: Post OPA Results to PR
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const results = JSON.parse(fs.readFileSync('opa-results.json', 'utf8'));
            
            const denials = [
              ...(results.security?.deny || []),
              ...(results.cost?.deny || []),
              ...(results.compliance?.deny || [])
            ];
            
            const warnings = [
              ...(results.security?.warn || []),
              ...(results.cost?.warn || [])
            ];
            
            let comment = '## OPA Policy Check Results\n\n';
            
            if (denials.length > 0) {
              comment += `### ❌ Policy Violations (${denials.length})\n\n`;
              denials.forEach(d => comment += `- ${d}\n`);
              comment += '\n';
            }
            
            if (warnings.length > 0) {
              comment += `### ⚠️  Warnings (${warnings.length})\n\n`;
              warnings.forEach(w => comment += `- ${w}\n`);
              comment += '\n';
            }
            
            if (denials.length === 0 && warnings.length === 0) {
              comment += '### ✅ All Checks Passed\n\n';
              comment += 'No policy violations or warnings detected.';
            }
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```


### Policy Enforcement Best Practices

1. **Start with advisory policies, gradually enforce**: Begin with warnings to educate teams before blocking applies
2. **Test policies thoroughly**: Use comprehensive test suites to prevent false positives
3. **Document policy rationale**: Include business/compliance reasons in policy comments
4. **Provide override mechanisms**: Soft-mandatory with approval workflows for legitimate exceptions
5. **Monitor policy effectiveness**: Track violation rates and adjust policies based on patterns
6. **Version control policies**: Treat policies as code, review changes through pull requests
7. **Separate policies by concern**: Security, cost, compliance in separate files
8. **Use data files for configuration**: External JSON files for lists, thresholds, and settings
9. **Implement graduated enforcement**: Development environments more permissive than production
10. **Integrate with cost tools**: Combine with Infracost for cost-aware policy decisions

## Zero-Downtime Deployment Patterns

Zero-downtime deployments ensure infrastructure changes occur transparently to end users, eliminating maintenance windows and supporting continuous delivery. **Terraform's declarative nature requires careful orchestration to achieve zero-downtime updates—resources must be created before destroying old versions, traffic must be shifted gradually, and health checks must validate readiness before cutover**.[^5]

### Blue-Green Deployment Pattern

Blue-green deployment maintains two identical environments, switching traffic between them during updates.[^5]

**Implementation with Terraform:**

```hcl
# deployments/blue-green/main.tf

variable "active_environment" {
  description = "Active deployment color (blue or green)"
  type        = string
  default     = "blue"
  
  validation {
    condition     = contains(["blue", "green"], var.active_environment)
    error_message = "Active environment must be blue or green"
  }
}

variable "app_version" {
  description = "Application version to deploy"
  type        = string
}

variable "app_port" {
  description = "Application listening port"
  type        = number
  default     = 8080
}

# VPC and networking (shared between blue/green)
data "aws_vpc" "main" {
  default = true
}

data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.main.id]
  }
}

# Application Load Balancer (shared)
resource "aws_lb" "app" {
  name               = "app-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = data.aws_subnets.public.ids
  
  enable_deletion_protection = true
  
  tags = {
    Name = "app-alb"
  }
}

# Target Groups (one per environment)
resource "aws_lb_target_group" "blue" {
  name     = "app-blue-tg"
  port     = var.app_port
  protocol = "HTTP"
  vpc_id   = data.aws_vpc.main.id
  
  health_check {
    enabled             = true
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    matcher             = "200"
  }
  
  deregistration_delay = 30
  
  tags = {
    Name        = "app-blue-tg"
    Environment = "blue"
  }
}

resource "aws_lb_target_group" "green" {
  name     = "app-green-tg"
  port     = var.app_port
  protocol = "HTTP"
  vpc_id   = data.aws_vpc.main.id
  
  health_check {
    enabled             = true
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    matcher             = "200"
  }
  
  deregistration_delay = 30
  
  tags = {
    Name        = "app-green-tg"
    Environment = "green"
  }
}

# ALB Listener routes to active environment
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"
  
  default_action {
    type             = "forward"
    target_group_arn = var.active_environment == "blue" ? 
                       aws_lb_target_group.blue.arn : 
                       aws_lb_target_group.green.arn
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.app.arn
  
  default_action {
    type             = "forward"
    target_group_arn = var.active_environment == "blue" ? 
                       aws_lb_target_group.blue.arn : 
                       aws_lb_target_group.green.arn
  }
}

# Launch Templates
resource "aws_launch_template" "blue" {
  name_prefix   = "app-blue-"
  image_id      = data.aws_ami.app.id
  instance_type = "t3.medium"
  
  vpc_security_group_ids = [aws_security_group.app.id]
  
  iam_instance_profile {
    name = aws_iam_instance_profile.app.name
  }
  
  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    app_version   = var.app_version
    environment   = "blue"
    app_port      = var.app_port
  }))
  
  tag_specifications {
    resource_type = "instance"
    tags = {
      Name        = "app-blue"
      Environment = "blue"
      Version     = var.app_version
    }
  }
  
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_launch_template" "green" {
  name_prefix   = "app-green-"
  image_id      = data.aws_ami.app.id
  instance_type = "t3.medium"
  
  vpc_security_group_ids = [aws_security_group.app.id]
  
  iam_instance_profile {
    name = aws_iam_instance_profile.app.name
  }
  
  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    app_version   = var.app_version
    environment   = "green"
    app_port      = var.app_port
  }))
  
  tag_specifications {
    resource_type = "instance"
    tags = {
      Name        = "app-green"
      Environment = "green"
      Version     = var.app_version
    }
  }
  
  lifecycle {
    create_before_destroy = true
  }
}

# Auto Scaling Groups
resource "aws_autoscaling_group" "blue" {
  name                = "app-blue-asg"
  vpc_zone_identifier = data.aws_subnets.private.ids
  target_group_arns   = [aws_lb_target_group.blue.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300
  
  # Active environment runs instances, inactive runs 0
  min_size         = var.active_environment == "blue" ? 2 : 0
  max_size         = var.active_environment == "blue" ? 10 : 0
  desired_capacity = var.active_environment == "blue" ? 3 : 0
  
  launch_template {
    id      = aws_launch_template.blue.id
    version = "$Latest"
  }
  
  # Wait for instances to be healthy before considering update complete
  wait_for_capacity_timeout = "10m"
  
  tag {
    key                 = "Name"
    value               = "app-blue"
    propagate_at_launch = true
  }
  
  tag {
    key                 = "Environment"
    value               = "blue"
    propagate_at_launch = true
  }
  
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "green" {
  name                = "app-green-asg"
  vpc_zone_identifier = data.aws_subnets.private.ids
  target_group_arns   = [aws_lb_target_group.green.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300
  
  min_size         = var.active_environment == "green" ? 2 : 0
  max_size         = var.active_environment == "green" ? 10 : 0
  desired_capacity = var.active_environment == "green" ? 3 : 0
  
  launch_template {
    id      = aws_launch_template.green.id
    version = "$Latest"
  }
  
  wait_for_capacity_timeout = "10m"
  
  tag {
    key                 = "Name"
    value               = "app-green"
    propagate_at_launch = true
  }
  
  tag {
    key                 = "Environment"
    value               = "green"
    propagate_at_launch = true
  }
  
  lifecycle {
    create_before_destroy = true
  }
}

# Outputs
output "alb_dns_name" {
  description = "ALB DNS name"
  value       = aws_lb.app.dns_name
}

output "active_environment" {
  description = "Currently active environment"
  value       = var.active_environment
}

output "blue_target_group_arn" {
  description = "Blue target group ARN"
  value       = aws_lb_target_group.blue.arn
}

output "green_target_group_arn" {
  description = "Green target group ARN"
  value       = aws_lb_target_group.green.arn
}
```

**Blue-Green Deployment Workflow:**

```bash
#!/bin/bash
# scripts/blue-green-deploy.sh

set -euo pipefail

CURRENT_ENV="${1:-blue}"
NEW_VERSION="${2:-}"

if [ -z "$NEW_VERSION" ]; then
  echo "Usage: $0 <current_env> <new_version>"
  echo "Example: $0 blue v2.1.0"
  exit 1
fi

# Determine target environment
if [ "$CURRENT_ENV" == "blue" ]; then
  TARGET_ENV="green"
else
  TARGET_ENV="blue"
fi

echo "🚀 Starting blue-green deployment"
echo "   Current: $CURRENT_ENV"
echo "   Target: $TARGET_ENV"
echo "   Version: $NEW_VERSION"
echo ""

# Step 1: Deploy to inactive environment
echo "📦 Step 1: Deploying v$NEW_VERSION to $TARGET_ENV environment..."
terraform apply \
  -var="active_environment=$CURRENT_ENV" \
  -var="app_version=$NEW_VERSION" \
  -auto-approve

# Step 2: Wait for target environment health checks
echo "🏥 Step 2: Waiting for $TARGET_ENV environment health checks..."
TARGET_TG_ARN=$(terraform output -raw ${TARGET_ENV}_target_group_arn)

for i in {1..30}; do
  HEALTHY_COUNT=$(aws elbv2 describe-target-health \
    --target-group-arn "$TARGET_TG_ARN" \
    --query 'TargetHealthDescriptions[?TargetHealth.State==`healthy`] | length(@)' \
    --output text)
  
  echo "   Healthy targets: $HEALTHY_COUNT"
  
  if [ "$HEALTHY_COUNT" -ge 2 ]; then
    echo "✅ Target environment is healthy"
    break
  fi
  
  if [ "$i" -eq 30 ]; then
    echo "❌ Target environment failed health checks after 15 minutes"
    exit 1
  fi
  
  sleep 30
done

# Step 3: Run smoke tests
echo "🧪 Step 3: Running smoke tests on $TARGET_ENV..."
ALB_DNS=$(terraform output -raw alb_dns_name)
TARGET_URL="http://$ALB_DNS"

# Test via target group directly (before switching traffic)
aws elbv2 describe-target-health \
  --target-group-arn "$TARGET_TG_ARN" \
  --query 'TargetHealthDescriptions[^0].Target.Id' \
  --output text | while read INSTANCE_ID; do
  
  PRIVATE_IP=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[^0].Instances[^0].PrivateIpAddress' \
    --output text)
  
  echo "   Testing instance $INSTANCE_ID at $PRIVATE_IP..."
  
  # Run health check
  HEALTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://$PRIVATE_IP:8080/health")
  
  if [ "$HEALTH_STATUS" != "200" ]; then
    echo "❌ Health check failed for instance $INSTANCE_ID"
    exit 1
  fi
  
  # Run version check
  VERSION_CHECK=$(curl -s "http://$PRIVATE_IP:8080/version" | jq -r '.version')
  
  if [ "$VERSION_CHECK" != "$NEW_VERSION" ]; then
    echo "❌ Version mismatch: expected $NEW_VERSION, got $VERSION_CHECK"
    exit 1
  fi
  
  echo "✅ Instance $INSTANCE_ID passed smoke tests"
done

echo "✅ All smoke tests passed"

# Step 4: Switch traffic to new environment
echo "🔀 Step 4: Switching traffic to $TARGET_ENV..."

read -p "Proceed with traffic switch? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
  echo "❌ Deployment cancelled"
  exit 1
fi

terraform apply \
  -var="active_environment=$TARGET_ENV" \
  -var="app_version=$NEW_VERSION" \
  -auto-approve

echo "✅ Traffic switched to $TARGET_ENV"

# Step 5: Monitor new environment
echo "📊 Step 5: Monitoring $TARGET_ENV for 5 minutes..."

for i in {1..10}; do
  sleep 30
  
  # Check target health
  UNHEALTHY=$(aws elbv2 describe-target-health \
    --target-group-arn "$TARGET_TG_ARN" \
    --query 'TargetHealthDescriptions[?TargetHealth.State!=`healthy`] | length(@)' \
    --output text)
  
  if [ "$UNHEALTHY" -gt 0 ]; then
    echo "⚠️  Warning: $UNHEALTHY unhealthy targets detected"
    
    read -p "Rollback to $CURRENT_ENV? (yes/no): " ROLLBACK
    
    if [ "$ROLLBACK" == "yes" ]; then
      echo "🔙 Rolling back to $CURRENT_ENV..."
      terraform apply \
        -var="active_environment=$CURRENT_ENV" \
        -auto-approve
      
      echo "✅ Rolled back to $CURRENT_ENV"
      exit 1
    fi
  fi
  
  echo "   ✅ All targets healthy (check $i/10)"
done

echo "✅ Deployment successful! $TARGET_ENV is now serving traffic"

# Step 6: Scale down old environment (optional)
read -p "Scale down $CURRENT_ENV environment? (yes/no): " SCALE_DOWN

if [ "$SCALE_DOWN" == "yes" ]; then
  echo "📉 Scaling down $CURRENT_ENV..."
  # Old environment already scaled to 0 by switching active_environment
  echo "✅ $CURRENT_ENV scaled down"
fi

echo ""
echo "🎉 Blue-green deployment complete!"
echo "   Active environment: $TARGET_ENV"
echo "   Version: $NEW_VERSION"
echo "   Previous environment ($CURRENT_ENV) kept for instant rollback if needed"
```


### Canary Deployment Pattern

Canary deployments gradually shift traffic to new versions, limiting blast radius.[^9]

**Implementation with Weighted Target Groups:**

```hcl
# deployments/canary/main.tf

variable "canary_weight" {
  description = "Percentage of traffic to canary (0-100)"
  type        = number
  default     = 10
  
  validation {
    condition     = var.canary_weight >= 0 && var.canary_weight <= 100
    error_message = "Canary weight must be between 0 and 100"
  }
}

# Target Groups
resource "aws_lb_target_group" "stable" {
  name     = "app-stable-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = data.aws_vpc.main.id
  
  health_check {
    enabled             = true
    path                = "/health"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
  }
  
  tags = {
    Name = "app-stable"
    Type = "stable"
  }
}

resource "aws_lb_target_group" "canary" {
  name     = "app-canary-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = data.aws_vpc.main.id
  
  health_check {
    enabled             = true
    path                = "/health"
    healthy_threshold   = 2
    unhealthy_threshold = 2  # Stricter for canary
    timeout             = 5
    interval            = 30
  }
  
  tags = {
    Name = "app-canary"
    Type = "canary"
  }
}

# ALB Listener with weighted targets
resource "aws_lb_listener" "app" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.app.arn
  
  default_action {
    type = "forward"
    
    forward {
      target_group {
        arn    = aws_lb_target_group.stable.arn
        weight = 100 - var.canary_weight
      }
      
      target_group {
        arn    = aws_lb_target_group.canary.arn
        weight = var.canary_weight
      }
      
      stickiness {
        enabled  = true
        duration = 3600  # 1 hour session stickiness
      }
    }
  }
}

# Auto Scaling Groups
resource "aws_autoscaling_group" "stable" {
  name                = "app-stable-asg"
  vpc_zone_identifier = data.aws_subnets.private.ids
  target_group_arns   = [aws_lb_target_group.stable.arn]
  health_check_type   = "ELB"
  
  min_size         = 2
  max_size         = 10
  desired_capacity = 3
  
  launch_template {
    id      = aws_launch_template.stable.id
    version = "$Latest"
  }
  
  tag {
    key                 = "Version"
    value               = var.stable_version
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group" "canary" {
  name                = "app-canary-asg"
  vpc_zone_identifier = data.aws_subnets.private.ids
  target_group_arns   = [aws_lb_target_group.canary.arn]
  health_check_type   = "ELB"
  
  # Scale canary based on weight
  min_size         = var.canary_weight > 0 ? 1 : 0
  max_size         = 5
  desired_capacity = var.canary_weight > 0 ? max(1, floor(3 * var.canary_weight / 100)) : 0
  
  launch_template {
    id      = aws_launch_template.canary.id
    version = "$Latest"
  }
  
  tag {
    key                 = "Version"
    value               = var.canary_version
    propagate_at_launch = true
  }
}

# CloudWatch alarms for canary monitoring
resource "aws_cloudwatch_metric_alarm" "canary_high_error_rate" {
  alarm_name          = "canary-high-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "Canary deployment has high error rate"
  alarm_actions       = [aws_sns_topic.deployment_alerts.arn]
  
  dimensions = {
    TargetGroup  = aws_lb_target_group.canary.arn_suffix
    LoadBalancer = aws_lb.app.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "canary_high_latency" {
  alarm_name          = "canary-high-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Average"
  threshold           = 2.0
  alarm_description   = "Canary deployment has high latency"
  alarm_actions       = [aws_sns_topic.deployment_alerts.arn]
  
  dimensions = {
    TargetGroup  = aws_lb_target_group.canary.arn_suffix
    LoadBalancer = aws_lb.app.arn_suffix
  }
}
```

**Canary Deployment Workflow:**

```bash
#!/bin/bash
# scripts/canary-deploy.sh

set -euo pipefail

NEW_VERSION="${1:-}"

if [ -z "$NEW_VERSION" ]; then
  echo "Usage: $0 <new_version>"
  exit 1
fi

echo "🐤 Starting canary deployment for version $NEW_VERSION"

# Progressive rollout stages
CANARY_STAGES=(10 25 50 75 100)

for WEIGHT in "${CANARY_STAGES[@]}"; do
  echo ""
  echo "📊 Rolling out to $WEIGHT% of traffic..."
  
  # Deploy with current weight
  terraform apply \
    -var="canary_version=$NEW_VERSION" \
    -var="canary_weight=$WEIGHT" \
    -auto-approve
  
  # Wait for deployment to stabilize
  sleep 60
  
  # Monitor metrics
  echo "📈 Monitoring canary metrics (5 minutes)..."
  
  for i in {1..5}; do
    # Check error rate
    ERROR_RATE=$(aws cloudwatch get-metric-statistics \
      --namespace AWS/ApplicationELB \
      --metric-name HTTPCode_Target_5XX_Count \
      --dimensions Name=TargetGroup,Value=$(terraform output -raw canary_target_group_arn_suffix) \
      --start-time $(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%S) \
      --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
      --period 300 \
      --statistics Sum \
      --query 'Datapoints[^0].Sum' \
      --output text)
    
    # Check latency
    LATENCY=$(aws cloudwatch get-metric-statistics \
      --namespace AWS/ApplicationELB \
      --metric-name TargetResponseTime \
      --dimensions Name=TargetGroup,Value=$(terraform output -raw canary_target_group_arn_suffix) \
      --start-time $(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%S) \
      --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
      --period 300 \
      --statistics Average \
      --query 'Datapoints[^0].Average' \
      --output text)
    
    echo "   Minute $i: Errors=$ERROR_RATE, Latency=${LATENCY}s"
    
    # Check for problems
    if [ "${ERROR_RATE:-0}" -gt 5 ]; then
      echo "❌ High error rate detected! Rolling back..."
      terraform apply -var="canary_weight=0" -auto-approve
      exit 1
    fi
    
    if (( $(echo "$LATENCY > 2.0" | bc -l) )); then
      echo "❌ High latency detected! Rolling back..."
      terraform apply -var="canary_weight=0" -auto-approve
      exit 1
    fi
    
    sleep 60
  done
  
  echo "✅ Canary at $WEIGHT% is healthy"
  
  if [ "$WEIGHT" -lt 100 ]; then
    read -p "Proceed to next stage? (yes/no/rollback): " DECISION
    
    if [ "$DECISION" == "rollback" ]; then
      echo "🔙 Rolling back..."
      terraform apply -var="canary_weight=0" -auto-approve
      exit 1
    elif [ "$DECISION" != "yes" ]; then
      echo "⏸️  Deployment paused at $WEIGHT%"
      exit 0
    fi
  fi
done

echo ""
echo "🎉 Canary deployment complete!"
echo "   Version $NEW_VERSION is now serving 100% of traffic"

# Promote canary to stable
terraform apply \
  -var="stable_version=$NEW_VERSION" \
  -var="canary_weight=0" \
  -auto-approve

echo "✅ Canary promoted to stable"
```


### Rolling Update Pattern

Rolling updates gradually replace instances one-by-one, maintaining capacity throughout.[^9]

```hcl
# deployments/rolling-update/main.tf

resource "aws_autoscaling_group" "app" {
  name                = "app-asg-${var.app_version}"
  vpc_zone_identifier = data.aws_subnets.private.ids
  target_group_arns   = [aws_lb_target_group.app.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300
  
  min_size         = 3
  max_size         = 10
  desired_capacity = 3
  
  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }
  
  # Instance refresh for rolling updates
  instance_refresh {
    strategy = "Rolling"
    
    preferences {
      min_healthy_percentage = 75  # Keep 75% healthy during update
      instance_warmup        = 300  # Wait 5 minutes before considering healthy
      
      checkpoint_percentages = [25, 50, 75, 100]  # Pause points for validation
      checkpoint_delay       = 300  # Wait 5 minutes at each checkpoint
    }
    
    triggers = ["tag"]
  }
  
  tag {
    key                 = "Version"
    value               = var.app_version
    propagate_at_launch = true
  }
  
  lifecycle {
    create_before_destroy = true
  }
}

# CloudWatch alarm to pause rolling update on errors
resource "aws_cloudwatch_metric_alarm" "high_error_rate" {
  alarm_name          = "app-high-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "High error rate - pause rolling update"
  
  dimensions = {
    TargetGroup  = aws_lb_target_group.app.arn_suffix
    LoadBalancer = aws_lb.app.arn_suffix
  }
}

# Lambda function to cancel instance refresh on alarm
resource "aws_lambda_function" "cancel_instance_refresh" {
  filename      = "cancel_instance_refresh.zip"
  function_name = "cancel-instance-refresh"
  role          = aws_iam_role.lambda.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 60
  
  environment {
    variables = {
      ASG_NAME = aws_autoscaling_group.app.name
    }
  }
}

# SNS topic for CloudWatch alarm
resource "aws_sns_topic" "deployment_alerts" {
  name = "deployment-alerts"
}

resource "aws_sns_topic_subscription" "lambda" {
  topic_arn = aws_sns_topic.deployment_alerts.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.cancel_instance_refresh.arn
}

# Connect alarm to SNS
resource "aws_cloudwatch_metric_alarm" "high_error_rate" {
  # ... (previous configuration)
  alarm_actions = [aws_sns_topic.deployment_alerts.arn]
}
```

**Lambda function to cancel rolling update:**

```python
# lambda/cancel_instance_refresh/index.py
import boto3
import os
import json

autoscaling = boto3.client('autoscaling')
cloudwatch = boto3.client('cloudwatch')

def handler(event, context):
    """Cancel instance refresh when error threshold exceeded"""
    
    asg_name = os.environ['ASG_NAME']
    
    print(f"Received alarm for ASG: {asg_name}")
    print(f"Event: {json.dumps(event)}")
    
    try:
        # Check if instance refresh is in progress
        response = autoscaling.describe_instance_refreshes(
            AutoScalingGroupName=asg_name,
            MaxRecords=1
        )
        
        if not response['InstanceRefreshes']:
            print("No instance refresh in progress")
            return {'statusCode': 200, 'body': 'No action needed'}
        
        refresh = response['InstanceRefreshes'][^0]
        refresh_id = refresh['InstanceRefreshId']
        status = refresh['Status']
        
        if status not in ['Pending', 'InProgress']:
            print(f"Instance refresh {refresh_id} status: {status}")
            return {'statusCode': 200, 'body': 'Instance refresh not active'}
        
        # Cancel the instance refresh
        print(f"Cancelling instance refresh {refresh_id}")
        
        autoscaling.cancel_instance_refresh(
            AutoScalingGroupName=asg_name
        )
        
        # Send notification
        sns = boto3.client('sns')
        sns.publish(
            TopicArn=os.environ.get('NOTIFICATION_TOPIC_ARN'),
            Subject=f"ALERT: Instance Refresh Cancelled - {asg_name}",
            Message=f"""
Instance refresh cancelled due to high error rate.

Auto Scaling Group: {asg_name}
Instance Refresh ID: {refresh_id}
Reason: CloudWatch alarm triggered

Action Required:
1. Investigate application errors
2. Review application logs
3. Check new version compatibility
4. Rollback if necessary

Previous Checkpoint: {refresh.get('PercentageComplete', 0)}%
            """
        )
        
        return {
            'statusCode': 200,
            'body': f'Cancelled instance refresh {refresh_id}'
        }
        
    except Exception as e:
        print(f"Error: {str(e)}")
        raise
```


### Database Migration Pattern (Zero-Downtime)

Database schema changes require careful orchestration to avoid downtime.[^1]

```hcl
# deployments/database-migration/main.tf

# Read replica for zero-downtime major upgrades
resource "aws_db_instance" "replica" {
  identifier              = "app-db-replica"
  replicate_source_db     = aws_db_instance.main.identifier
  instance_class          = aws_db_instance.main.instance_class
  publicly_accessible     = false
  skip_final_snapshot     = false
  final_snapshot_identifier = "app-db-replica-final-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"
  
  # Can have different engine version for upgrade testing
  engine_version = var.target_database_version
  
  tags = {
    Name = "app-db-replica"
    Type = "read-replica"
  }
}

# Blue-green deployment for RDS
resource "aws_db_instance" "blue_green" {
  identifier     = "app-db-${var.active_db}"
  engine         = "postgres"
  engine_version = var.database_version
  instance_class = var.db_instance_class
  
  allocated_storage     = 100
  storage_encrypted     = true
  kms_key_id           = aws_kms_key.rds.arn
  
  db_name  = "appdb"
  username = var.db_username
  password = var.db_password
  
  vpc_security_group_ids = [aws_security_group.database.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "mon:04:00-mon:05:00"
  
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  
  # Blue-green deployment support
  blue_green_update {
    enabled = true
  }
  
  lifecycle {
    create_before_destroy = true
  }
  
  tags = {
    Name        = "app-db-${var.active_db}"
    Environment = var.active_db
  }
}

# Route53 for database endpoint failover
resource "aws_route53_record" "database" {
  zone_id = aws_route53_zone.private.zone_id
  name    = "database.internal.example.com"
  type    = "CNAME"
  ttl     = 60
  
  records = [
    var.active_db == "blue" ? 
      aws_db_instance.blue.address : 
      aws_db_instance.green.address
  ]
}
```

**Database migration workflow:**

```bash
#!/bin/bash
# scripts/database-migration.sh

set -euo pipefail

MIGRATION_VERSION="${1:-}"
DB_ENDPOINT="${2:-database.internal.example.com}"

if [ -z "$MIGRATION_VERSION" ]; then
  echo "Usage: $0 <migration_version> [db_endpoint]"
  exit 1
fi

echo "🗄️  Starting zero-downtime database migration"
echo "   Migration: $MIGRATION_VERSION"
echo "   Endpoint: $DB_ENDPOINT"

# Step 1: Backward-compatible schema changes
echo ""
echo "📝 Step 1: Applying backward-compatible schema changes..."

psql -h "$DB_ENDPOINT" -U appuser -d appdb <<EOF
BEGIN;

-- Add new columns (nullable initially)
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP;

-- Create new tables
CREATE TABLE IF NOT EXISTS user_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id INTEGER REFERENCES users(id),
  token VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP NOT NULL
);

-- Add indexes (CONCURRENTLY to avoid locking)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_user_id 
  ON user_sessions(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_token 
  ON user_sessions(token);

-- Create new functions/views
CREATE OR REPLACE VIEW active_users AS
  SELECT * FROM users WHERE last_login_at > NOW() - INTERVAL '30 days';

COMMIT;
EOF

echo "✅ Schema changes applied"

# Step 2: Deploy application supporting both old and new schema
echo ""
echo "🚀 Step 2: Deploying application with dual schema support..."

# Deploy new version that writes to both old and new columns
terraform apply \
  -var="app_version=v2.0.0-migration" \
  -var="migration_mode=dual_write" \
  -auto-approve

echo "✅ Application deployed in migration mode"

# Step 3: Backfill data
echo ""
echo "♻️  Step 3: Backfilling data..."

psql -h "$DB_ENDPOINT" -U appuser -d appdb <<EOF
-- Backfill in batches to avoid long locks
DO \$\$
DECLARE
  batch_size INTEGER := 1000;
  processed INTEGER := 0;
  total INTEGER;
BEGIN
  SELECT COUNT(*) INTO total FROM users WHERE email_verified IS NULL;
  
  RAISE NOTICE 'Backfilling % records...', total;
  
  LOOP
    UPDATE users
    SET email_verified = (email IS NOT NULL AND email != '')
    WHERE id IN (
      SELECT id FROM users 
      WHERE email_verified IS NULL 
      LIMIT batch_size
    );
    
    GET DIAGNOSTICS processed = ROW_COUNT;
    
    EXIT WHEN processed = 0;
    
    -- Log progress
    RAISE NOTICE 'Processed % records...', processed;
    
    -- Small delay to reduce load
    PERFORM pg_sleep(0.1);
  END LOOP;
END \$\$;
EOF

echo "✅ Data backfilled"

# Step 4: Validate data consistency
echo ""
echo "🔍 Step 4: Validating data consistency..."

INCONSISTENT=$(psql -h "$DB_ENDPOINT" -U appuser -d appdb -t -c "
  SELECT COUNT(*) FROM users 
  WHERE email_verified IS NULL 
    AND email IS NOT NULL 
    AND email != '';
")

if [ "$INCONSISTENT" -gt 0 ]; then
  echo "❌ Data inconsistency detected: $INCONSISTENT records"
  exit 1
fi

echo "✅ Data consistency validated"

# Step 5: Deploy application using new schema exclusively
echo ""
echo "🚀 Step 5: Deploying application using new schema..."

terraform apply \
  -var="app_version=v2.0.0" \
  -var="migration_mode=new_schema" \
  -auto-approve

echo "✅ Application deployed with new schema"

# Step 6: Cleanup (optional, can be done later)
echo ""
read -p "Remove old schema elements? (yes/no): " CLEANUP

if [ "$CLEANUP" == "yes" ]; then
  echo "🧹 Cleaning up old schema..."
  
  psql -h "$DB_ENDPOINT" -U appuser -d appdb <<EOF
  BEGIN;
  
  -- Drop old indexes
  DROP INDEX CONCURRENTLY IF EXISTS idx_users_old_column;
  
  -- Drop old columns (after confirming no usage)
  -- ALTER TABLE users DROP COLUMN IF EXISTS old_column;
  
  COMMIT;
EOF
  
  echo "✅ Old schema cleaned up"
fi

echo ""
echo "🎉 Database migration complete!"
echo "   No downtime occurred"
echo "   All data migrated successfully"
```


### Create Before Destroy Pattern

Terraform's `create_before_destroy` lifecycle ensures new resources are healthy before destroying old ones.[^1]

```hcl
# deployments/create-before-destroy/main.tf

# Launch template always creates new version before destroying old
resource "aws_launch_template" "app" {
  name_prefix   = "app-lt-"
  image_id      = data.aws_ami.app.id
  instance_type = var.instance_type
  
  vpc_security_group_ids = [aws_security_group.app.id]
  
  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    app_version = var.app_version
  }))
  
  lifecycle {
    create_before_destroy = true
  }
  
  # Use name_prefix and timestamp to ensure unique names
  # This allows new version to be created before old is destroyed
}

# Auto Scaling Group references latest launch template
resource "aws_autoscaling_group" "app" {
  name                = "app-asg-${aws_launch_template.app.latest_version}"
  vpc_zone_identifier = data.aws_subnets.private.ids
  target_group_arns   = [aws_lb_target_group.app.arn]
  health_check_type   = "ELB"
  
  min_size         = 2
  max_size         = 10
  desired_capacity = 3
  
  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }
  
  # Wait for new instances to be healthy before destroying old ASG
  wait_for_capacity_timeout = "10m"
  
  lifecycle {
    create_before_destroy = true
  }
}

# Security group allows zero-downtime updates
resource "aws_security_group" "app" {
  name_prefix = "app-sg-"
  description = "Application security group"
  vpc_id      = data.aws_vpc.main.id
  
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "app_ingress" {
  type              = "ingress"
  from_port         = 8080
  to_port           = 8080
  protocol          = "tcp"
  security_group_id = aws_security_group.app.id
  
  source_security_group_id = aws_security_group.alb.id
}

# IAM role updates without instance replacement
resource "aws_iam_role" "app" {
  name_prefix = "app-role-"
  
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
  
  lifecycle {
    create_before_destroy = true
  }
}

# Instance profile references role
resource "aws_iam_instance_profile" "app" {
  name_prefix = "app-profile-"
  role        = aws_iam_role.app.name
  
  lifecycle {
    create_before_destroy = true
  }
}
```


## Terraform Cloud and Enterprise Governance

Terraform Cloud and Terraform Enterprise provide enterprise-grade infrastructure management with governance, collaboration, and automation capabilities.[^2][^3]

### Terraform Cloud Overview

**Key Features:**

- **Remote Execution:** Run Terraform in consistent, centralized environment
- **State Management:** Secure, versioned state storage with locking
- **Policy as Code:** Sentinel policy enforcement (paid tier)
- **Private Registry:** Host and version internal modules
- **VCS Integration:** Trigger runs from Git commits
- **Cost Estimation:** Infracost integration for cost awareness
- **Drift Detection:** Continuous monitoring for configuration drift
- **RBAC:** Team-based access control
- **Audit Logging:** Track all infrastructure changes
- **Run Triggers:** Chain workspace dependencies

**Pricing Tiers:**


| Tier | Price | Features |
| :-- | :-- | :-- |
| **Free** | \$0 | Up to 5 users, remote state, basic VCS integration |
| **Standard** | \$20/user/month | Teams, Sentinel, drift detection, SSO |
| **Plus** | Custom | Advanced features, audit logging, self-hosted agents |
| **Enterprise** | Custom | On-premises deployment, advanced security, SLA |

### Workspace Configuration

```hcl
# terraform-cloud-config/workspaces.tf

terraform {
  required_providers {
    tfe = {
      source  = "hashicorp/tfe"
      version = "~> 0.51.0"
    }
  }
}

provider "tfe" {
  # Configure using TFE_TOKEN environment variable
}

variable "organization" {
  description = "Terraform Cloud organization name"
  type        = string
}

variable "github_token" {
  description = "GitHub OAuth token"
  type        = string
  sensitive   = true
}

# Create organization
resource "tfe_organization" "main" {
  name  = var.organization
  email = "infrastructure@example.com"
  
  # Cost estimation
  cost_estimation_enabled = true
  
  # Session settings
  session_timeout_minutes = 20160  # 14 days
  session_remember_minutes = 20160
}

# GitHub VCS connection
resource "tfe_oauth_client" "github" {
  organization     = tfe_organization.main.name
  api_url          = "https://api.github.com"
  http_url         = "https://github.com"
  oauth_token      = var.github_token
  service_provider = "github"
}

# Production workspace
resource "tfe_workspace" "production" {
  name         = "production-infrastructure"
  organization = tfe_organization.main.name
  
  # VCS integration
  vcs_repo {
    identifier     = "company/infrastructure"
    oauth_token_id = tfe_oauth_client.github.oauth_token_id
    branch         = "main"
  }
  
  # Working directory
  working_directory = "environments/production"
  
  # Terraform version
  terraform_version = "1.11.0"
  
  # Execution mode
  execution_mode = "remote"
  
  # Auto-apply (disabled for production)
  auto_apply = false
  
  # Assessments
  assessments_enabled = true
  
  # Queue all runs
  queue_all_runs = false
  
  # Speculative plans on PR
  speculative_enabled = true
  
  # File triggers
  file_triggers_enabled = true
  trigger_patterns = [
    "environments/production/**",
    "modules/**"
  ]
  
  # Tags
  tag_names = ["production", "infrastructure"]
  
  # Description
  description = "Production infrastructure workspace"
}

# Staging workspace
resource "tfe_workspace" "staging" {
  name         = "staging-infrastructure"
  organization = tfe_organization.main.name
  
  vcs_repo {
    identifier     = "company/infrastructure"
    oauth_token_id = tfe_oauth_client.github.oauth_token_id
    branch         = "main"
  }
  
  working_directory = "environments/staging"
  terraform_version = "1.11.0"
  execution_mode    = "remote"
  
  # Auto-apply enabled for staging
  auto_apply = true
  
  assessments_enabled = true
  
  tag_names = ["staging", "infrastructure"]
}

# Development workspace
resource "tfe_workspace" "development" {
  name         = "development-infrastructure"
  organization = tfe_organization.main.name
  
  vcs_repo {
    identifier     = "company/infrastructure"
    oauth_token_id = tfe_oauth_client.github.oauth_token_id
    branch         = "develop"
  }
  
  working_directory = "environments/development"
  terraform_version = "1.11.0"
  execution_mode    = "remote"
  auto_apply        = true
  
  tag_names = ["development", "infrastructure"]
}
```


### Team-Based Access Control

```hcl
# terraform-cloud-config/teams.tf

# Infrastructure team (full access)
resource "tfe_team" "infrastructure" {
  name         = "infrastructure"
  organization = tfe_organization.main.name
  
  visibility = "organization"
  
  organization_access {
    manage_policies         = true
    manage_policy_overrides = true
    manage_workspaces       = true
    manage_vcs_settings     = true
  }
}

# Developers team (limited access)
resource "tfe_team" "developers" {
  name         = "developers"
  organization = tfe_organization.main.name
  
  visibility = "organization"
  
  organization_access {
    manage_policies         = false
    manage_policy_overrides = false
    manage_workspaces       = false
    manage_vcs_settings     = false
  }
}

# Security team (read-only + policy management)
resource "tfe_team" "security" {
  name         = "security"
  organization = tfe_organization.main.name
  
  visibility = "organization"
  
  organization_access {
    manage_policies         = true
    manage_policy_overrides = true
    manage_workspaces       = false
    manage_vcs_settings     = false
  }
}

# Workspace access for infrastructure team
resource "tfe_team_access" "infrastructure_production" {
  access       = "admin"
  team_id      = tfe_team.infrastructure.id
  workspace_id = tfe_workspace.production.id
}

resource "tfe_team_access" "infrastructure_staging" {
  access       = "admin"
  team_id      = tfe_team.infrastructure.id
  workspace_id = tfe_workspace.staging.id
}

# Workspace access for developers team
resource "tfe_team_access" "developers_development" {
  access       = "write"
  team_id      = tfe_team.developers.id
  workspace_id = tfe_workspace.development.id
}

resource "tfe_team_access" "developers_staging" {
  access       = "read"
  team_id      = tfe_team.developers.id
  workspace_id = tfe_workspace.staging.id
}

resource "tfe_team_access" "developers_production" {
  access       = "read"
  team_id      = tfe_team.developers.id
  workspace_id = tfe_workspace.production.id
}

# Workspace access for security team
resource "tfe_team_access" "security_production" {
  access       = "read"
  team_id      = tfe_team.security.id
  workspace_id = tfe_workspace.production.id
  
  permissions {
    runs              = "read"
    variables         = "read"
    state_versions    = "read"
    sentinel_mocks    = "read"
    workspace_locking = false
  }
}
```


### Variable Management

```hcl
# terraform-cloud-config/variables.tf

# Workspace variables (production)
resource "tfe_variable" "aws_region_prod" {
  workspace_id = tfe_workspace.production.id
  
  key      = "aws_region"
  value    = "us-east-1"
  category = "terraform"
  
  description = "AWS region for production resources"
}

resource "tfe_variable" "environment_prod" {
  workspace_id = tfe_workspace.production.id
  
  key      = "environment"
  value    = "production"
  category = "terraform"
}

# Sensitive variables
resource "tfe_variable" "aws_access_key_prod" {
  workspace_id = tfe_workspace.production.id
  
  key       = "AWS_ACCESS_KEY_ID"
  value     = var.aws_access_key_id_prod
  category  = "env"
  sensitive = true
  
  description = "AWS access key for production"
}

resource "tfe_variable" "aws_secret_key_prod" {
  workspace_id = tfe_workspace.production.id
  
  key       = "AWS_SECRET_ACCESS_KEY"
  value     = var.aws_secret_access_key_prod
  category  = "env"
  sensitive = true
  
  description = "AWS secret key for production"
}

# Variable sets (shared across workspaces)
resource "tfe_variable_set" "common" {
  name         = "common-variables"
  description  = "Variables shared across all workspaces"
  organization = tfe_organization.main.name
}

resource "tfe_variable" "company_name" {
  variable_set_id = tfe_variable_set.common.id
  
  key      = "company_name"
  value    = "Example Corp"
  category = "terraform"
}

resource "tfe_variable" "default_tags" {
  variable_set_id = tfe_variable_set.common.id
  
  key      = "default_tags"
  value    = jsonencode({
    ManagedBy = "Terraform"
    Company   = "Example Corp"
  })
  category = "terraform"
  hcl      = true
  
  description = "Default tags for all resources"
}

# Apply variable set to workspaces
resource "tfe_workspace_variable_set" "production_common" {
  workspace_id    = tfe_workspace.production.id
  variable_set_id = tfe_variable_set.common.id
}

resource "tfe_workspace_variable_set" "staging_common" {
  workspace_id    = tfe_workspace.staging.id
  variable_set_id = tfe_variable_set.common.id
}
```


### Policy Sets (Sentinel)

```hcl
# terraform-cloud-config/policy-sets.tf

# Production policy set
resource "tfe_policy_set" "production" {
  name         = "production-policies"
  description  = "Policies enforced on production workspaces"
  organization = tfe_organization.main.name
  
  # Policies from VCS
  vcs_repo {
    identifier     = "company/terraform-policies"
    oauth_token_id = tfe_oauth_client.github.oauth_token_id
    branch         = "main"
  }
  
  # Working directory containing policies
  policies_path = "policies/production"
  
  # Apply to specific workspaces
  workspace_ids = [
    tfe_workspace.production.id
  ]
}

# Security policy set (global)
resource "tfe_policy_set" "security" {
  name         = "security-policies"
  description  = "Security policies enforced on all workspaces"
  organization = tfe_organization.main.name
  global       = true  # Apply to all workspaces
  
  vcs_repo {
    identifier     = "company/terraform-policies"
    oauth_token_id = tfe_oauth_client.github.oauth_token_id
    branch         = "main"
  }
  
  policies_path = "policies/security"
}

# Cost control policy set
resource "tfe_policy_set" "cost_control" {
  name         = "cost-control-policies"
  description  = "Cost control policies"
  organization = tfe_organization.main.name
  
  vcs_repo {
    identifier     = "company/terraform-policies"
    oauth_token_id = tfe_oauth_client.github.oauth_token_id
    branch         = "main"
  }
  
  policies_path = "policies/cost"
  
  # Apply to production and staging
  workspace_ids = [
    tfe_workspace.production.id,
    tfe_workspace.staging.id
  ]
}

# Individual policy configuration
resource "tfe_policy" "require_encryption" {
  name         = "require-encryption"
  description  = "Require encryption for all storage resources"
  organization = tfe_organization.main.name
  
  policy = file("${path.module}/policies/require-encryption.sentinel")
  
  enforce_mode = "hard-mandatory"
}
```


### Notification Configuration

```hcl
# terraform-cloud-config/notifications.tf

# Slack notifications for production
resource "tfe_notification_configuration" "production_slack" {
  name             = "Production Slack Notifications"
  enabled          = true
  destination_type = "slack"
  workspace_id     = tfe_workspace.production.id
  
  url = var.slack_webhook_production
  
  triggers = [
    "run:created",
    "run:planning",
    "run:needs_attention",
    "run:applying",
    "run:completed",
    "run:errored",
    "assessment:check_failure",
    "assessment:drift_detected"
  ]
}

# Email notifications for security team
resource "tfe_notification_configuration" "production_email" {
  name             = "Production Email Notifications"
  enabled          = true
  destination_type = "email"
  workspace_id     = tfe_workspace.production.id
  
  email_addresses = [
    "infrastructure@example.com",
    "security@example.com"
  ]
  
  triggers = [
    "run:needs_attention",
    "run:errored",
    "assessment:check_failure",
    "assessment:drift_detected"
  ]
}

# Generic webhook for custom integrations
resource "tfe_notification_configuration" "production_webhook" {
  name             = "Production Webhook"
  enabled          = true
  destination_type = "generic"
  workspace_id     = tfe_workspace.production.id
  
  url   = "https://api.example.com/terraform-webhooks"
  token = var.webhook_token
  
  triggers = [
    "run:completed",
    "run:errored",
    "assessment:drift_detected"
  ]
}

# Microsoft Teams notifications
resource "tfe_notification_configuration" "staging_teams" {
  name             = "Staging Teams Notifications"
  enabled          = true
  destination_type = "microsoft-teams"
  workspace_id     = tfe_workspace.staging.id
  
  url = var.teams_webhook_url
  
  triggers = [
    "run:completed",
    "run:errored"
  ]
}
```


### Run Triggers (Workspace Dependencies)

```hcl
# terraform-cloud-config/run-triggers.tf

# Trigger staging when networking workspace completes
resource "tfe_run_trigger" "staging_from_networking" {
  workspace_id  = tfe_workspace.staging.id
  sourceable_id = tfe_workspace.networking.id
}

# Trigger applications when database workspace completes
resource "tfe_run_trigger" "applications_from_database" {
  workspace_id  = tfe_workspace.applications.id
  sourceable_id = tfe_workspace.database.id
}

# Dependency chain: networking → database → applications
resource "tfe_workspace" "networking" {
  name         = "networking"
  organization = tfe_organization.main.name
  # ... configuration
}

resource "tfe_workspace" "database" {
  name         = "database"
  organization = tfe_organization.main.name
  # ... configuration
}

resource "tfe_workspace" "applications" {
  name         = "applications"
  organization = tfe_organization.main.name
  # ... configuration
}

resource "tfe_run_trigger" "database_from_networking" {
  workspace_id  = tfe_workspace.database.id
  sourceable_id = tfe_workspace.networking.id
}

resource "tfe_run_trigger" "applications_from_database" {
  workspace_id  = tfe_workspace.applications.id
  sourceable_id = tfe_workspace.database.id
}
```


### Private Module Registry

```hcl
# terraform-cloud-config/registry.tf

# Publish module to private registry
resource "tfe_registry_module" "vpc" {
  organization = tfe_organization.main.name
  
  vcs_repo {
    display_identifier = "company/terraform-aws-vpc"
    identifier         = "company/terraform-aws-vpc"
    oauth_token_id     = tfe_oauth_client.github.oauth_token_id
  }
}

resource "tfe_registry_module" "compute" {
  organization = tfe_organization.main.name
  
  vcs_repo {
    display_identifier = "company/terraform-aws-compute"
    identifier         = "company/terraform-aws-compute"
    oauth_token_id     = tfe_oauth_client.github.oauth_token_id
  }
}

# Usage in workspace
# main.tf in workspace
module "vpc" {
  source  = "app.terraform.io/company/vpc/aws"
  version = "~> 2.0"
  
  cidr_block = "10.0.0.0/16"
  environment = "production"
}
```


### Terraform Enterprise Self-Hosted

**Deployment Architecture:**

```hcl
# terraform-enterprise/main.tf

# Terraform Enterprise on AWS (Active-Active)

module "tfe" {
  source  = "hashicorp/terraform-enterprise/aws"
  version = "~> 1.0"
  
  # Instance configuration
  instance_type = "m5.xlarge"
  
  # High availability
  distribution_type = "active-active"
  
  # Networking
  vpc_id                = aws_vpc.tfe.id
  subnet_ids            = aws_subnet.private[*].id
  load_balancer_type    = "alb"
  load_balancer_subnets = aws_subnet.public[*].id
  
  # DNS
  domain_name = "terraform.example.com"
  zone_id     = aws_route53_zone.main.zone_id
  
  # Certificate
  certificate_arn = aws_acm_certificate.tfe.arn
  
  # Storage
  object_storage_type         = "s3"
  object_storage_s3_bucket    = aws_s3_bucket.tfe_data.id
  object_storage_s3_kms_key_id = aws_kms_key.tfe.id
  
  # Database
  database_type          = "external"
  database_host          = aws_db_instance.tfe.address
  database_name          = "tfe"
  database_user          = "tfe_admin"
  database_password      = var.database_password
  database_parameters    = "sslmode=require"
  
  # Redis (for active-active)
  redis_host     = aws_elasticache_replication_group.tfe.primary_endpoint_address
  redis_port     = 6379
  redis_use_tls  = true
  redis_use_auth = true
  redis_password = var.redis_password
  
  # License
  license_file = var.tfe_license
  
  # Encryption
  encryption_password = var.encryption_password
  
  # Capacity
  capacity_concurrency = 10
  capacity_memory      = 512
  
  tags = {
    Name        = "terraform-enterprise"
    Environment = "production"
  }
}

# PostgreSQL for TFE
resource "aws_db_instance" "tfe" {
  identifier     = "tfe-database"
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.r6g.large"
  
  allocated_storage     = 100
  storage_encrypted     = true
  kms_key_id           = aws_kms_key.tfe.arn
  
  db_name  = "tfe"
  username = "tfe_admin"
  password = var.database_password
  
  vpc_security_group_ids = [aws_security_group.tfe_database.id]
  db_subnet_group_name   = aws_db_subnet_group.tfe.name
  
  backup_retention_period = 30
  multi_az               = true
  
  enabled_cloudwatch_logs_exports = ["postgresql"]
}

# Redis for TFE active-active
resource "aws_elasticache_replication_group" "tfe" {
  replication_group_id       = "tfe-redis"
  replication_group_description = "Redis for Terraform Enterprise"
  
  engine               = "redis"
  engine_version       = "7.0"
  node_type            = "cache.r6g.large"
  number_cache_clusters = 2
  
  parameter_group_name = "default.redis7"
  port                 = 6379
  
  subnet_group_name    = aws_elasticache_subnet_group.tfe.name
  security_group_ids   = [aws_security_group.tfe_redis.id]
  
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = var.redis_password
  
  automatic_failover_enabled = true
  multi_az_enabled          = true
  
  snapshot_retention_limit = 7
  snapshot_window         = "03:00-05:00"
}

# S3 bucket for TFE data
resource "aws_s3_bucket" "tfe_data" {
  bucket = "tfe-data-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "tfe_data" {
  bucket = aws_s3_bucket.tfe_data.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfe_data" {
  bucket = aws_s3_bucket.tfe_data.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.tfe.arn
    }
  }
}
```


### Audit Logging and Compliance

```hcl
# terraform-cloud-config/audit-logging.tf

# Configure audit trail (Enterprise feature)
resource "tfe_organization_settings" "main" {
  organization = tfe_organization.main.name
  
  # Audit logging
  audit_log {
    enabled = true
    
    # Forward to external SIEM
    destination {
      type = "splunk"
      url  = var.splunk_hec_url
      token = var.splunk_hec_token
    }
  }
}

# AWS CloudWatch for TFE logs
resource "aws_cloudwatch_log_group" "tfe_audit" {
  name              = "/terraform-enterprise/audit"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.logs.arn
}

# Lambda to process TFE webhooks into CloudWatch
resource "aws_lambda_function" "tfe_audit_processor" {
  filename      = "tfe_audit_processor.zip"
  function_name = "tfe-audit-processor"
  role          = aws_iam_role.lambda.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  
  environment {
    variables = {
      LOG_GROUP_NAME = aws_cloudwatch_log_group.tfe_audit.name
    }
  }
}

# API Gateway for webhook endpoint
resource "aws_api_gateway_rest_api" "tfe_webhooks" {
  name        = "tfe-webhooks"
  description = "Terraform Enterprise webhook receiver"
}

resource "aws_api_gateway_resource" "audit" {
  rest_api_id = aws_api_gateway_rest_api.tfe_webhooks.id
  parent_id   = aws_api_gateway_rest_api.tfe_webhooks.root_resource_id
  path_part   = "audit"
}

resource "aws_api_gateway_method" "audit_post" {
  rest_api_id   = aws_api_gateway_rest_api.tfe_webhooks.id
  resource_id   = aws_api_gateway_resource.audit.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "audit_lambda" {
  rest_api_id = aws_api_gateway_rest_api.tfe_webhooks.id
  resource_id = aws_api_gateway_resource.audit.id
  http_method = aws_api_gateway_method.audit_post.http_method
  
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.tfe_audit_processor.invoke_arn
}
```

*[Previous sections on Cost Optimization, Disaster Recovery, and Security Hardening remain unchanged]*

## Summary

This chapter provided comprehensive enterprise patterns for production Terraform deployments. **Drift detection strategies using scheduled plans, continuous monitoring, and third-party tools identify configuration divergence early, with remediation workflows balancing acceptance of intentional changes versus automatic reversion to desired state**. **Policy-as-code implementation through both Sentinel and OPA enforces security, compliance, and cost controls automatically, shifting enforcement left into development workflows with graduated enforcement levels matching organizational risk tolerance**. **Zero-downtime deployment patterns including blue-green, canary, rolling updates, and database migrations ensure infrastructure changes occur transparently to users, eliminating maintenance windows while maintaining safety through health checks, gradual rollout, and instant rollback capabilities**. **Terraform Cloud and Enterprise governance features including RBAC, workspace management, policy enforcement, private module registries, audit logging, and notification systems enable enterprise-scale operations while maintaining team autonomy and security**.[^3][^4][^5][^6][^2][^1]

Multi-account AWS Organizations architecture isolates blast radius across development, staging, and production environments with centralized governance through Service Control Policies. Enterprise state management through layered state files, production-grade S3 backends with versioning and encryption, and cross-workspace dependencies enables team collaboration without conflicts. Cost optimization through Infracost integration, automated resource cleanup, and policy-based instance size limits reduces cloud spending 30-50%. Disaster recovery patterns ranging from backup-and-restore through pilot light to active-active architectures achieve RPO/RTO targets matching business requirements. Security hardening through IAM least privilege, encryption at rest and in transit, secret management, and audit logging meets compliance standards.

These patterns enable organizations to scale Terraform from initial adoption through enterprise-wide deployment managing thousands of resources across hundreds of AWS accounts, with governance ensuring security and compliance while automation accelerates delivery.
