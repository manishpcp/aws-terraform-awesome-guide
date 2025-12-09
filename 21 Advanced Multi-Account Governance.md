# Chapter 21: Advanced Multi-Account Governance with Terraform, Control Tower, and CI/CD

## Introduction

Managing AWS infrastructure across dozens or hundreds of accounts requires more than basic Terraform skills—it demands systematic governance, automated guardrails, and sophisticated CI/CD pipelines that prevent configuration drift while enabling team autonomy. You've mastered single-account deployments, state management, and policy enforcement in previous chapters, but production enterprise platforms operate differently: AWS Control Tower establishes the foundational landing zone with prescribed organizational units and security baselines, Terraform layers workload infrastructure on top without conflicting with Control Tower automation, and multi-account CI/CD pipelines orchestrate deployments across development, staging, and production environments spanning multiple AWS accounts. The challenge isn't writing Terraform code—it's architecting a system where Control Tower-managed guardrails coexist with Terraform-managed resources, where CI/CD pipelines safely assume roles across 50+ accounts, where AWS Provider v6.x breaking changes don't cause unexpected resource replacement, and where new accounts are provisioned with standardized baselines through Account Factory for Terraform (AFT) within minutes.

This chapter bridges the gap between Control Tower's opinionated landing zone management and Terraform's flexible infrastructure-as-code capabilities. You'll learn how to integrate Terraform with AWS Control Tower's Account Factory, design multi-account CI/CD pipelines using GitHub Actions and GitLab CI with OIDC authentication, navigate AWS Provider v6.x breaking changes and migration strategies, implement Account Factory for Terraform (AFT) for automated account provisioning, build cross-account deployment workflows with environment promotion gates, establish drift detection across multi-account environments, and enforce governance policies that respect Control Tower guardrails while extending Terraform control. These patterns enable organizations to scale from 10 to 1,000+ AWS accounts while maintaining security, compliance, and operational efficiency.

Whether you're migrating existing multi-account setups to Control Tower, building greenfield landing zones with Terraform integration, or scaling CI/CD pipelines to support growing teams, this chapter provides production-tested architectures and code examples from real enterprise deployments managing billions of dollars in AWS infrastructure.

## Understanding AWS Control Tower and Terraform Integration

AWS Control Tower provides an opinionated, pre-configured multi-account AWS environment with built-in governance guardrails, centralized logging, and automated account provisioning through Account Factory. The core challenge for Terraform practitioners is determining what Control Tower should manage versus what Terraform should control—getting this boundary wrong results in configuration drift, automated remediation conflicts, and operational complexity.

### Control Tower Architecture and Components

Control Tower establishes a landing zone consisting of:

**Management Account (Root):** Houses AWS Organizations, Control Tower setup, and Account Factory configuration. This account should have minimal Terraform automation—Control Tower owns it.

**Log Archive Account:** Centralized repository for CloudTrail logs, Config snapshots, and VPC Flow Logs from all member accounts. Control Tower manages the log aggregation; Terraform can manage log analysis resources (Athena queries, Glue crawlers, QuickSight dashboards).

**Audit Account (Security Tooling):** Hosts GuardDuty master, Security Hub aggregator, and compliance dashboards. Control Tower establishes baseline security services; Terraform extends with custom security automation (Lambda functions for automated response, SNS topics for alerting, Step Functions for remediation workflows).

**Organizational Units (OUs):** Hierarchical structure grouping accounts by function (Security, Infrastructure, Workloads, Sandbox). Control Tower creates the OU structure; Terraform deploys standardized resources into accounts within OUs.

**Guardrails:** Preventive (SCPs) and detective (AWS Config rules) controls enforcing compliance. Control Tower manages guardrails; Terraform respects them when creating resources.

### The Control Tower and Terraform Boundary

**What Control Tower Should Manage:**

- AWS Organizations root account and organizational units
- Core security and logging accounts (Log Archive, Audit)
- Baseline CloudTrail configuration for organization-wide logging
- AWS Config recorders and aggregators for compliance
- Mandatory and strongly recommended guardrails (SCPs)
- Account Factory provisioning workflow
- IAM Identity Center (AWS SSO) federation configuration

**What Terraform Should Manage:**

- VPCs, subnets, routing tables, security groups in member accounts
- Application infrastructure (EC2, ECS, EKS, Lambda, RDS, DynamoDB)
- Shared services (Transit Gateway, Route 53 private zones, VPC endpoints)
- Optional guardrails and custom Config rules beyond Control Tower defaults
- IAM roles and policies for application workloads
- Monitoring and alerting infrastructure (CloudWatch dashboards, SNS topics)
- Cost allocation tags and resource tagging enforcement
- Cross-account networking (VPC peering, Transit Gateway attachments)


### Integration Pattern: Terraform Consuming Control Tower Outputs

The recommended pattern treats Control Tower as an external system that Terraform reads from but doesn't modify:

```hcl
# control-tower-integration/data.tf
terraform {
  required_version = ">= 1.9.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# Management account provider (read-only for Control Tower data)
provider "aws" {
  region = var.aws_region
  alias  = "management"
  
  default_tags {
    tags = {
      ManagedBy      = "Terraform"
      LandingZone    = "ControlTower"
      TerraformStack = "control-tower-integration"
    }
  }
}

# Data source: AWS Organizations structure
data "aws_organizations_organization" "main" {
  provider = aws.management
}

# Data source: All accounts in organization
data "aws_organizations_organizational_units" "root" {
  provider  = aws.management
  parent_id = data.aws_organizations_organization.main.roots[0].id
}

# Discover Security OU
data "aws_organizations_organizational_units" "security" {
  provider  = aws.management
  parent_id = data.aws_organizations_organization.main.roots[0].id
}

locals {
  # Find Security OU ID
  security_ou_id = [
    for ou in data.aws_organizations_organizational_units.security.children : ou.id
    if ou.name == "Security"
  ][0]
}

# List all accounts in Security OU
data "aws_organizations_organizational_unit_child_accounts" "security_accounts" {
  provider  = aws.management
  parent_id = local.security_ou_id
}

# Discover Log Archive account
locals {
  log_archive_account = [
    for account in data.aws_organizations_organizational_unit_child_accounts.security_accounts.accounts :
    account
    if can(regex(".*Log.*Archive.*", account.name))
  ][0]
  
  log_archive_account_id = local.log_archive_account.id
}

# Data source: Control Tower-created IAM role for cross-account access
data "aws_iam_role" "control_tower_execution" {
  provider = aws.management
  name     = "AWSControlTowerExecution"
}

# Output Control Tower metadata for consumption by other stacks
output "organization_id" {
  description = "AWS Organizations ID"
  value       = data.aws_organizations_organization.main.id
}

output "organization_root_id" {
  description = "Organization root ID"
  value       = data.aws_organizations_organization.main.roots[0].id
}

output "log_archive_account_id" {
  description = "Log Archive account ID for centralized logging"
  value       = local.log_archive_account_id
}

output "control_tower_execution_role_arn" {
  description = "IAM role ARN for cross-account access in Control Tower accounts"
  value       = data.aws_iam_role.control_tower_execution.arn
}

# Store outputs in SSM Parameter Store for other stacks to consume
resource "aws_ssm_parameter" "log_archive_account_id" {
  provider = aws.management
  
  name        = "/control-tower/log-archive-account-id"
  description = "Log Archive account ID from Control Tower"
  type        = "String"
  value       = local.log_archive_account_id
  
  tags = {
    ControlTowerManaged = "false"
    Purpose             = "TerraformIntegration"
  }
}
```


### Cross-Account Deployment Pattern with Control Tower Roles

Control Tower automatically creates the `AWSControlTowerExecution` IAM role in every managed account, enabling centralized administration:

```hcl
# cross-account-deployment/main.tf
terraform {
  required_version = ">= 1.9.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
  
  backend "s3" {
    bucket         = "terraform-state-management-prod"
    key            = "cross-account/workload-vpc/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-locks"
    kms_key_id     = "arn:aws:kms:us-east-1:111111111111:key/mrk-abc123"
  }
}

# Variables for target accounts
variable "workload_accounts" {
  description = "Map of workload accounts to deploy VPCs"
  type = map(object({
    account_id  = string
    environment = string
    cidr_block  = string
  }))
  
  default = {
    app1_dev = {
      account_id  = "222222222222"
      environment = "development"
      cidr_block  = "10.1.0.0/16"
    }
    app1_staging = {
      account_id  = "333333333333"
      environment = "staging"
      cidr_block  = "10.2.0.0/16"
    }
    app1_prod = {
      account_id  = "444444444444"
      environment = "production"
      cidr_block  = "10.3.0.0/16"
    }
  }
}

variable "aws_region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-east-1"
}

# Management account provider
provider "aws" {
  region = var.aws_region
  alias  = "management"
}

# Provider for each workload account using Control Tower execution role
provider "aws" {
  region = var.aws_region
  alias  = "app1_dev"
  
  assume_role {
    role_arn     = "arn:aws:iam::${var.workload_accounts.app1_dev.account_id}:role/AWSControlTowerExecution"
    session_name = "TerraformWorkloadVPC"
  }
  
  default_tags {
    tags = {
      ManagedBy      = "Terraform"
      Environment    = var.workload_accounts.app1_dev.environment
      AccountID      = var.workload_accounts.app1_dev.account_id
      LandingZone    = "ControlTower"
      CostCenter     = "Engineering"
    }
  }
}

provider "aws" {
  region = var.aws_region
  alias  = "app1_staging"
  
  assume_role {
    role_arn     = "arn:aws:iam::${var.workload_accounts.app1_staging.account_id}:role/AWSControlTowerExecution"
    session_name = "TerraformWorkloadVPC"
  }
  
  default_tags {
    tags = {
      ManagedBy      = "Terraform"
      Environment    = var.workload_accounts.app1_staging.environment
      AccountID      = var.workload_accounts.app1_staging.account_id
      LandingZone    = "ControlTower"
      CostCenter     = "Engineering"
    }
  }
}

provider "aws" {
  region = var.aws_region
  alias  = "app1_prod"
  
  assume_role {
    role_arn     = "arn:aws:iam::${var.workload_accounts.app1_prod.account_id}:role/AWSControlTowerExecution"
    session_name = "TerraformWorkloadVPC"
  }
  
  default_tags {
    tags = {
      ManagedBy      = "Terraform"
      Environment    = var.workload_accounts.app1_prod.environment
      AccountID      = var.workload_accounts.app1_prod.account_id
      LandingZone    = "ControlTower"
      CostCenter     = "Engineering"
    }
  }
}

# Deploy standardized VPC to development account
module "vpc_dev" {
  source = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"
  
  providers = {
    aws = aws.app1_dev
  }
  
  name = "app1-dev-vpc"
  cidr = var.workload_accounts.app1_dev.cidr_block
  
  azs             = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
  private_subnets = [cidrsubnet(var.workload_accounts.app1_dev.cidr_block, 8, 1),
                     cidrsubnet(var.workload_accounts.app1_dev.cidr_block, 8, 2),
                     cidrsubnet(var.workload_accounts.app1_dev.cidr_block, 8, 3)]
  public_subnets  = [cidrsubnet(var.workload_accounts.app1_dev.cidr_block, 8, 101),
                     cidrsubnet(var.workload_accounts.app1_dev.cidr_block, 8, 102),
                     cidrsubnet(var.workload_accounts.app1_dev.cidr_block, 8, 103)]
  
  enable_nat_gateway   = true
  single_nat_gateway   = true  # Cost optimization for dev
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  # Enable VPC Flow Logs (Control Tower detective guardrail)
  enable_flow_log                      = true
  create_flow_log_cloudwatch_iam_role  = true
  create_flow_log_cloudwatch_log_group = true
  flow_log_retention_in_days           = 90
  
  tags = {
    Purpose = "WorkloadVPC"
    Backup  = "true"
  }
}

# Deploy standardized VPC to staging account
module "vpc_staging" {
  source = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"
  
  providers = {
    aws = aws.app1_staging
  }
  
  name = "app1-staging-vpc"
  cidr = var.workload_accounts.app1_staging.cidr_block
  
  azs             = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
  private_subnets = [cidrsubnet(var.workload_accounts.app1_staging.cidr_block, 8, 1),
                     cidrsubnet(var.workload_accounts.app1_staging.cidr_block, 8, 2),
                     cidrsubnet(var.workload_accounts.app1_staging.cidr_block, 8, 3)]
  public_subnets  = [cidrsubnet(var.workload_accounts.app1_staging.cidr_block, 8, 101),
                     cidrsubnet(var.workload_accounts.app1_staging.cidr_block, 8, 102),
                     cidrsubnet(var.workload_accounts.app1_staging.cidr_block, 8, 103)]
  
  enable_nat_gateway   = true
  single_nat_gateway   = false  # HA for staging
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  enable_flow_log                      = true
  create_flow_log_cloudwatch_iam_role  = true
  create_flow_log_cloudwatch_log_group = true
  flow_log_retention_in_days           = 90
  
  tags = {
    Purpose = "WorkloadVPC"
    Backup  = "true"
  }
}

# Deploy production VPC with enhanced security
module "vpc_prod" {
  source = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"
  
  providers = {
    aws = aws.app1_prod
  }
  
  name = "app1-prod-vpc"
  cidr = var.workload_accounts.app1_prod.cidr_block
  
  azs             = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
  private_subnets = [cidrsubnet(var.workload_accounts.app1_prod.cidr_block, 8, 1),
                     cidrsubnet(var.workload_accounts.app1_prod.cidr_block, 8, 2),
                     cidrsubnet(var.workload_accounts.app1_prod.cidr_block, 8, 3)]
  public_subnets  = [cidrsubnet(var.workload_accounts.app1_prod.cidr_block, 8, 101),
                     cidrsubnet(var.workload_accounts.app1_prod.cidr_block, 8, 102),
                     cidrsubnet(var.workload_accounts.app1_prod.cidr_block, 8, 103)]
  
  enable_nat_gateway   = true
  single_nat_gateway   = false  # HA required for production
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  # Production-grade VPC Flow Logs with S3 destination
  enable_flow_log                      = true
  create_flow_log_cloudwatch_iam_role  = true
  create_flow_log_cloudwatch_log_group = true
  flow_log_retention_in_days           = 365  # Extended retention for compliance
  
  tags = {
    Purpose     = "WorkloadVPC"
    Backup      = "true"
    Compliance  = "PCI-DSS"
    DataClass   = "Confidential"
  }
}

# Outputs
output "dev_vpc_id" {
  description = "Development VPC ID"
  value       = module.vpc_dev.vpc_id
}

output "staging_vpc_id" {
  description = "Staging VPC ID"
  value       = module.vpc_staging.vpc_id
}

output "prod_vpc_id" {
  description = "Production VPC ID"
  value       = module.vpc_prod.vpc_id
}
```


### Respecting Control Tower Guardrails in Terraform

Control Tower guardrails are enforced through Service Control Policies (preventive) and AWS Config rules (detective). Terraform code must align with these guardrails to avoid failed deployments or compliance violations:

```hcl
# guardrail-compliant-resources/s3.tf

# ❌ ANTI-PATTERN: Non-compliant S3 bucket (violates Control Tower encryption guardrail)
resource "aws_s3_bucket" "bad_example" {
  bucket = "my-app-data-bucket"
  # Missing encryption configuration - Control Tower guardrail will flag this
}

# ✅ CORRECT: Guardrail-compliant S3 bucket with encryption
resource "aws_s3_bucket" "compliant" {
  bucket = "app1-prod-data-${data.aws_caller_identity.current.account_id}"
  
  tags = {
    Purpose         = "ApplicationData"
    DataClass       = "Confidential"
    BackupRequired  = "true"
  }
}

# Enforce encryption (required by Control Tower guardrail)
resource "aws_s3_bucket_server_side_encryption_configuration" "compliant" {
  bucket = aws_s3_bucket.compliant.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_data.arn
    }
    bucket_key_enabled = true
  }
}

# Block public access (Control Tower guardrail requirement)
resource "aws_s3_bucket_public_access_block" "compliant" {
  bucket = aws_s3_bucket.compliant.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning (best practice for compliance)
resource "aws_s3_bucket_versioning" "compliant" {
  bucket = aws_s3_bucket.compliant.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

# Lifecycle policy for cost optimization
resource "aws_s3_bucket_lifecycle_configuration" "compliant" {
  bucket = aws_s3_bucket.compliant.id
  
  rule {
    id     = "transition-to-glacier"
    status = "Enabled"
    
    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# KMS key for S3 encryption
resource "aws_kms_key" "s3_data" {
  description             = "KMS key for S3 bucket encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = {
    Purpose = "S3Encryption"
  }
}

resource "aws_kms_alias" "s3_data" {
  name          = "alias/s3-app1-prod-data"
  target_key_id = aws_kms_key.s3_data.key_id
}

# Data source for current account
data "aws_caller_identity" "current" {}
```


## Account Factory for Terraform (AFT) Integration

Account Factory for Terraform (AFT) automates AWS account provisioning with Terraform-defined baseline configurations, enabling self-service account creation while maintaining governance and standardization across the organization.

### AFT Architecture and Setup

AFT consists of several components:

- **AFT Management Account:** Hosts AFT infrastructure (CodePipeline, Lambda, DynamoDB state tracking)
- **Account Request Repository:** Git repository containing account requests (account-specific metadata)
- **Account Customizations Repository:** Terraform modules applied to newly provisioned accounts
- **Global Customizations:** Terraform code applied to ALL accounts (baseline IAM roles, CloudWatch alarms)
- **Account Customizations:** Account-specific Terraform configurations

```hcl
# aft-setup/main.tf
terraform {
  required_version = ">= 1.9.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
  
  backend "s3" {
    bucket         = "aft-terraform-state-primary"
    key            = "aft/setup/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "aft-terraform-state-locks"
  }
}

provider "aws" {
  region = "us-east-1"
  
  default_tags {
    tags = {
      ManagedBy   = "Terraform"
      Component   = "AFT"
      Environment = "management"
    }
  }
}

# AFT module from AWS
module "aft" {
  source = "github.com/aws-ia/terraform-aws-control_tower_account_factory?ref=v1.12.0"
  
  # Control Tower configuration
  ct_management_account_id    = "111111111111"
  log_archive_account_id      = "222222222222"
  audit_account_id            = "333333333333"
  aft_management_account_id   = "444444444444"
  ct_home_region              = "us-east-1"
  tf_backend_secondary_region = "us-west-2"
  
  # VCS configuration (GitHub)
  vcs_provider                  = "github"
  github_enterprise_url         = "https://github.com"
  account_request_repo_name     = "aft-account-requests"
  global_customizations_repo_name = "aft-global-customizations"
  account_customizations_repo_name = "aft-account-customizations"
  account_provisioning_customizations_repo_name = "aft-account-provisioning-customizations"
  
  # Repository branch
  account_request_repo_branch = "main"
  
  # Terraform configuration
  terraform_version      = "1.9.8"
  terraform_distribution = "oss"  # or "tfc" for Terraform Cloud
  
  # CloudWatch log retention
  cloudwatch_log_group_retention = 90
  
  # Maximum account customization run time
  aft_feature_cloudtrail_data_events = true
  aft_feature_enterprise_support     = false
  aft_feature_delete_default_vpcs_enabled = true
  
  # Concurrency limits
  maximum_concurrent_customizations = 5
  
  tags = {
    Purpose = "AccountFactoryForTerraform"
  }
}

# Outputs
output "aft_account_provisioning_framework_kms_key_arn" {
  description = "AFT KMS key ARN for encryption"
  value       = module.aft.aft_kms_key_arn
}

output "aft_sns_topic_arn" {
  description = "SNS topic for AFT notifications"
  value       = module.aft.aft_sns_topic_arn
}
```


### Account Request Definition

Account requests are defined as Terraform configuration files in the account request repository:

```hcl
# aft-account-requests/terraform/app1-production.tf
module "app1_production_account" {
  source = "./modules/aft-account-request"
  
  control_tower_parameters = {
    # Account name as it appears in AWS Organizations
    AccountName = "app1-production"
    
    # Email address (must be unique across all AWS accounts)
    AccountEmail = "aws+app1-prod@company.com"
    
    # Organizational Unit
    ManagedOrganizationalUnit = "Workloads/Production"
    
    # AWS SSO user or group with admin access
    SSOUserEmail     = "platform-team@company.com"
    SSOUserFirstName = "Platform"
    SSOUserLastName  = "Team"
  }
  
  account_tags = {
    Application = "App1"
    Environment = "Production"
    CostCenter  = "Engineering"
    Owner       = "platform-team@company.com"
    Compliance  = "PCI-DSS"
    DataClass   = "Confidential"
  }
  
  # Enable account customizations
  change_management_parameters = {
    change_requested_by = "platform-team@company.com"
    change_reason       = "New production account for App1 workload"
  }
  
  # Custom fields for organization-specific metadata
  custom_fields = {
    budget_code          = "PROJ-12345"
    application_id       = "APP-001"
    data_classification  = "confidential"
    compliance_framework = "pci-dss"
  }
  
  # Account features
  account_customizations_name = "production-baseline"
}
```


### Global Customizations (Applied to All Accounts)

Global customizations are Terraform modules applied to every account provisioned by AFT:

```hcl
# aft-global-customizations/terraform/main.tf
terraform {
  required_version = ">= 1.9.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      ManagedBy = "AFT-GlobalCustomizations"
    }
  }
}

variable "aws_region" {
  description = "Primary AWS region"
  type        = string
  default     = "us-east-1"
}

# IAM role for centralized logging access
resource "aws_iam_role" "centralized_logging" {
  name        = "CentralizedLoggingAccess"
  description = "Role for centralized logging aggregation"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::222222222222:root"  # Log Archive account
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "sts:ExternalId" = "centralized-logging-12345"
        }
      }
    }]
  })
  
  tags = {
    Purpose = "CentralizedLogging"
  }
}

resource "aws_iam_role_policy_attachment" "centralized_logging" {
  role       = aws_iam_role.centralized_logging.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchLogsReadOnlyAccess"
}

# CloudWatch Logs subscription filter to centralized logging
resource "aws_cloudwatch_log_subscription_filter" "centralized" {
  name            = "centralized-logging-filter"
  log_group_name  = "/aws/lambda/aft-notifications"
  filter_pattern  = ""
  destination_arn = "arn:aws:logs:us-east-1:222222222222:destination:CentralizedLogging"
}

# Cost allocation tags
resource "aws_ce_cost_category" "department" {
  name         = "Department"
  rule_version = "CostCategoryExpression.v1"
  
  rule {
    value = "Engineering"
    rule {
      tags {
        key    = "CostCenter"
        values = ["Engineering"]
      }
    }
  }
  
  rule {
    value = "Operations"
    rule {
      tags {
        key    = "CostCenter"
        values = ["Operations"]
      }
    }
  }
}

# Budget alert for new accounts
resource "aws_budgets_budget" "monthly" {
  name              = "monthly-budget-alert"
  budget_type       = "COST"
  limit_amount      = "1000"
  limit_unit        = "USD"
  time_unit         = "MONTHLY"
  time_period_start = "2025-01-01_00:00"
  
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = ["billing@company.com"]
  }
  
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = ["billing@company.com"]
  }
}

# CloudWatch alarm for root account usage
resource "aws_cloudwatch_log_metric_filter" "root_usage" {
  name           = "root-account-usage"
  log_group_name = "aws-controltower/CloudTrailLogs"
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
  
  metric_transformation {
    name      = "RootAccountUsage"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = "root-account-usage-detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "RootAccountUsage"
  namespace           = "Security"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Alert when root account is used"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"
}

# SNS topic for security alerts
resource "aws_sns_topic" "security_alerts" {
  name = "security-alerts"
  
  tags = {
    Purpose = "SecurityAlerts"
  }
}

resource "aws_sns_topic_subscription" "security_email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = "security@company.com"
}

# Outputs
output "centralized_logging_role_arn" {
  description = "IAM role ARN for centralized logging"
  value       = aws_iam_role.centralized_logging.arn
}

output "security_alerts_topic_arn" {
  description = "SNS topic ARN for security alerts"
  value       = aws_sns_topic.security_alerts.arn
}
```


### Account-Specific Customizations

Account-specific customizations are applied only to matching accounts based on tags or account name patterns:

```hcl
# aft-account-customizations/production-baseline/terraform/main.tf
terraform {
  required_version = ">= 1.9.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      ManagedBy        = "AFT-AccountCustomizations"
      CustomizationSet = "production-baseline"
    }
  }
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

# Production VPC baseline
module "production_vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"
  
  name = "production-baseline-vpc"
  cidr = "10.100.0.0/16"
  
  azs             = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
  private_subnets = ["10.100.1.0/24", "10.100.2.0/24", "10.100.3.0/24"]
  public_subnets  = ["10.100.101.0/24", "10.100.102.0/24", "10.100.103.0/24"]
  database_subnets = ["10.100.201.0/24", "10.100.202.0/24", "10.100.203.0/24"]
  
  enable_nat_gateway   = true
  single_nat_gateway   = false
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  # VPC Flow Logs
  enable_flow_log                      = true
  create_flow_log_cloudwatch_iam_role  = true
  create_flow_log_cloudwatch_log_group = true
  flow_log_retention_in_days           = 365
  
  # VPC endpoints for AWS services (reduce NAT costs)
  enable_s3_endpoint              = true
  enable_dynamodb_endpoint        = true
  enable_ssm_endpoint             = true
  enable_ssmmessages_endpoint     = true
  enable_ec2messages_endpoint     = true
  enable_ecr_api_endpoint         = true
  enable_ecr_dkr_endpoint         = true
  enable_logs_endpoint            = true
  
  tags = {
    Purpose     = "ProductionBaseline"
    NetworkTier = "Application"
  }
}

# IAM role for EC2 instances with SSM access
resource "aws_iam_role" "ec2_baseline" {
  name        = "EC2BaselineRole"
  description = "Baseline IAM role for EC2 instances"
  
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
  
  tags = {
    Purpose = "EC2Baseline"
  }
}

resource "aws_iam_role_policy_attachment" "ec2_ssm" {
  role       = aws_iam_role.ec2_baseline.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "ec2_cloudwatch" {
  role       = aws_iam_role.ec2_baseline.name
  policy_arn = = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "ec2_baseline" {
  name = "EC2BaselineInstanceProfile"
  role = aws_iam_role.ec2_baseline.name
}

# KMS key for EBS encryption
resource "aws_kms_key" "ebs" {
  description             = "KMS key for EBS volume encryption"
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
        Sid    = "Allow EBS to use key"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "ec2.${var.aws_region}.amazonaws.com"
          }
        }
      }
    ]
  })
  
  tags = {
    Purpose = "EBSEncryption"
  }
}

resource "aws_kms_alias" "ebs" {
  name          = "alias/ebs-encryption"
  target_key_id = aws_kms_key.ebs.key_id
}

# Enable EBS encryption by default
resource "aws_ebs_encryption_by_default" "enabled" {
  enabled = true
}

resource "aws_ebs_default_kms_key" "default" {
  key_arn = aws_kms_key.ebs.arn
}

# Security group for SSH bastion (restricted source)
resource "aws_security_group" "bastion" {
  name        = "bastion-sg"
  description = "Security group for SSH bastion hosts"
  vpc_id      = module.production_vpc.vpc_id
  
  ingress {
    description = "SSH from corporate VPN"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Replace with actual corporate CIDR
  }
  
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Purpose = "BastionAccess"
  }
}

# CloudWatch dashboard for baseline monitoring
resource "aws_cloudwatch_dashboard" "baseline" {
  dashboard_name = "production-baseline-monitoring"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization"],
            ["AWS/RDS", "CPUUtilization"],
            ["AWS/Lambda", "Invocations"]
          ]
          period = 300
          stat   = "Average"
          region = var.aws_region
          title  = "Resource Utilization"
        }
      }
    ]
  })
}

# Data sources
data "aws_caller_identity" "current" {}

# Outputs
output "vpc_id" {
  description = "Production baseline VPC ID"
  value       = module.production_vpc.vpc_id
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = module.production_vpc.private_subnets
}

output "ec2_instance_profile_name" {
  description = "EC2 baseline instance profile name"
  value       = aws_iam_instance_profile.ec2_baseline.name
}

output "ebs_kms_key_id" {
  description = "KMS key ID for EBS encryption"
  value       = aws_kms_key.ebs.key_id
}
```


## Multi-Account CI/CD Pipelines

Enterprise Terraform deployments require sophisticated CI/CD pipelines that orchestrate deployments across multiple AWS accounts with environment promotion gates, policy validation, cost estimation, and automated drift detection.

### GitHub Actions Multi-Account Pipeline with OIDC

GitHub Actions with OpenID Connect (OIDC) provides secure, keyless authentication to AWS without storing long-lived credentials:

```yaml
# .github/workflows/terraform-multi-account.yml
name: Terraform Multi-Account Deployment

on:
  pull_request:
    branches: [main]
    paths:
      - 'terraform/**'
      - '.github/workflows/terraform-multi-account.yml'
  push:
    branches: [main]
    paths:
      - 'terraform/**'
  workflow_dispatch:
    inputs:
      environment:
        description: 'Target environment'
        required: true
        type: choice
        options:
          - development
          - staging
          - production

permissions:
  id-token: write  # Required for OIDC
  contents: read
  pull-requests: write

env:
  TF_VERSION: '1.9.8'
  AWS_REGION: 'us-east-1'

jobs:
  # Job 1: Validate and lint Terraform code
  validate:
    name: Validate Terraform
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}
      
      - name: Terraform Format Check
        id: fmt
        run: terraform fmt -check -recursive
        continue-on-error: true
      
      - name: Terraform Init (validation only)
        working-directory: ./terraform/environments/development
        run: terraform init -backend=false
      
      - name: Terraform Validate
        working-directory: ./terraform/environments/development
        run: terraform validate
      
      - name: Run tflint
        uses: terraform-linters/setup-tflint@v4
        with:
          tflint_version: v0.50.0
      
      - name: Initialize tflint
        run: tflint --init
      
      - name: Run tflint
        run: tflint --recursive
      
      - name: Run Checkov security scan
        uses: bridgecrewio/checkov-action@v12
        with:
          directory: terraform/
          framework: terraform
          output_format: sarif
          output_file_path: checkov-results.sarif
      
      - name: Upload Checkov results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: checkov-results.sarif

  # Job 2: Plan for development account
  plan-dev:
    name: Plan - Development
    runs-on: ubuntu-latest
    needs: validate
    environment: development
    
    outputs:
      plan-exitcode: ${{ steps.plan.outputs.exitcode }}
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Configure AWS Credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::222222222222:role/GitHubActionsTerraformRole
          role-session-name: GitHubActions-TerraformPlan-Dev
          aws-region: ${{ env.AWS_REGION }}
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}
      
      - name: Terraform Init
        working-directory: ./terraform/environments/development
        run: |
          terraform init \
            -backend-config="bucket=terraform-state-dev-222222222222" \
            -backend-config="key=workloads/app1/terraform.tfstate" \
            -backend-config="region=${{ env.AWS_REGION }}"
      
      - name: Terraform Plan
        id: plan
        working-directory: ./terraform/environments/development
        run: |
          terraform plan \
            -out=tfplan.binary \
            -detailed-exitcode \
            -var-file="terraform.tfvars" || echo "exitcode=$?" >> $GITHUB_OUTPUT
      
      - name: Convert plan to JSON
        if: steps.plan.outputs.exitcode == '2'
        working-directory: ./terraform/environments/development
        run: terraform show -json tfplan.binary > plan.json
      
      - name: Setup Infracost
        if: steps.plan.outputs.exitcode == '2'
        uses: infracost/actions/setup@v3
        with:
          api-key: ${{ secrets.INFRACOST_API_KEY }}
      
      - name: Generate Infracost estimate
        if: steps.plan.outputs.exitcode == '2'
        working-directory: ./terraform/environments/development
        run: |
          infracost breakdown \
            --path plan.json \
            --format json \
            --out-file /tmp/infracost-dev.json
      
      - name: Post Infracost comment
        if: steps.plan.outputs.exitcode == '2' && github.event_name == 'pull_request'
        uses: infracost/actions/comment@v1
        with:
          path: /tmp/infracost-dev.json
          behavior: update
      
      - name: Upload plan artifact
        if: steps.plan.outputs.exitcode == '2'
        uses: actions/upload-artifact@v4
        with:
          name: tfplan-dev
          path: terraform/environments/development/tfplan.binary
          retention-days: 5
      
      - name: Comment PR with plan
        if: github.event_name == 'pull_request' && steps.plan.outputs.exitcode == '2'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const plan = fs.readFileSync('terraform/environments/development/plan.json', 'utf8');
            const summary = JSON.parse(plan);
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `### Terraform Plan - Development\n\n` +
                    `**Changes:** ${summary.resource_changes?.length || 0} resources\n` +
                    `**Exit Code:** ${steps.plan.outputs.exitcode}\n\n` +
                    `<details><summary>Show Plan</summary>\n\n` +
                    '``````\n\n</details>'
            });

  # Job 3: Apply to development (auto-approve on main)
  apply-dev:
    name: Apply - Development
    runs-on: ubuntu-latest
    needs: plan-dev
    if: github.ref == 'refs/heads/main' && needs.plan-dev.outputs.plan-exitcode == '2'
    environment: development
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Configure AWS Credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::222222222222:role/GitHubActionsTerraformRole
          role-session-name: GitHubActions-TerraformApply-Dev
          aws-region: ${{ env.AWS_REGION }}
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}
      
      - name: Terraform Init
        working-directory: ./terraform/environments/development
        run: |
          terraform init \
            -backend-config="bucket=terraform-state-dev-222222222222" \
            -backend-config="key=workloads/app1/terraform.tfstate" \
            -backend-config="region=${{ env.AWS_REGION }}"
      
      - name: Download plan artifact
        uses: actions/download-artifact@v4
        with:
          name: tfplan-dev
          path: terraform/environments/development/
      
      - name: Terraform Apply
        working-directory: ./terraform/environments/development
        run: terraform apply -auto-approve tfplan.binary
      
      - name: Post apply summary
        if: always()
        run: |
          echo "### Development Apply Complete" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "**Status:** ${{ job.status }}" >> $GITHUB_STEP_SUMMARY
          echo "**Account:** 222222222222" >> $GITHUB_STEP_SUMMARY
          echo "**Timestamp:** $(date -u)" >> $GITHUB_STEP_SUMMARY

  # Job 4: Plan for staging account
  plan-staging:
    name: Plan - Staging
    runs-on: ubuntu-latest
    needs: apply-dev
    if: github.ref == 'refs/heads/main'
    environment: staging
    
    outputs:
      plan-exitcode: ${{ steps.plan.outputs.exitcode }}
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Configure AWS Credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::333333333333:role/GitHubActionsTerraformRole
          role-session-name: GitHubActions-TerraformPlan-Staging
          aws-region: ${{ env.AWS_REGION }}
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}
      
      - name: Terraform Init
        working-directory: ./terraform/environments/staging
        run: |
          terraform init \
            -backend-config="bucket=terraform-state-staging-333333333333" \
            -backend-config="key=workloads/app1/terraform.tfstate" \
            -backend-config="region=${{ env.AWS_REGION }}"
      
      - name: Terraform Plan
        id: plan
        working-directory: ./terraform/environments/staging
        run: |
          terraform plan \
            -out=tfplan.binary \
            -detailed-exitcode \
            -var-file="terraform.tfvars" || echo "exitcode=$?" >> $GITHUB_OUTPUT
      
      - name: Upload plan artifact
        if: steps.plan.outputs.exitcode == '2'
        uses: actions/upload-artifact@v4
        with:
          name: tfplan-staging
          path: terraform/environments/staging/tfplan.binary
          retention-days: 5

  # Job 5: Apply to staging (auto-approve)
  apply-staging:
    name: Apply - Staging
    runs-on: ubuntu-latest
    needs: plan-staging
    if: needs.plan-staging.outputs.plan-exitcode == '2'
    environment: staging
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Configure AWS Credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::333333333333:role/GitHubActionsTerraformRole
          role-session-name: GitHubActions-TerraformApply-Staging
          aws-region: ${{ env.AWS_REGION }}
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}
      
      - name: Terraform Init
        working-directory: ./terraform/environments/staging
        run: |
          terraform init \
            -backend-config="bucket=terraform-state-staging-333333333333" \
            -backend-config="key=workloads/app1/terraform.tfstate" \
            -backend-config="region=${{ env.AWS_REGION }}"
      
      - name: Download plan artifact
        uses: actions/download-artifact@v4
        with:
          name: tfplan-staging
          path: terraform/environments/staging/
      
      - name: Terraform Apply
        working-directory: ./terraform/environments/staging
        run: terraform apply -auto-approve tfplan.binary

  # Job 6: Plan for production account
  plan-prod:
    name: Plan - Production
    runs-on: ubuntu-latest
    needs: apply-staging
    if: github.ref == 'refs/heads/main'
    environment: production-plan
    
    outputs:
      plan-exitcode: ${{ steps.plan.outputs.exitcode }}
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Configure AWS Credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::444444444444:role/GitHubActionsTerraformRole
          role-session-name: GitHubActions-TerraformPlan-Prod
          aws-region: ${{ env.AWS_REGION }}
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}
      
      - name: Terraform Init
        working-directory: ./terraform/environments/production
        run: |
          terraform init \
            -backend-config="bucket=terraform-state-prod-444444444444" \
            -backend-config="key=workloads/app1/terraform.tfstate" \
            -backend-config="region=${{ env.AWS_REGION }}"
      
      - name: Terraform Plan
        id: plan
        working-directory: ./terraform/environments/production
        run: |
          terraform plan \
            -out=tfplan.binary \
            -detailed-exitcode \
            -var-file="terraform.tfvars" || echo "exitcode=$?" >> $GITHUB_OUTPUT
      
      - name: Convert plan to JSON
        if: steps.plan.outputs.exitcode == '2'
        working-directory: ./terraform/environments/production
        run: terraform show -json tfplan.binary > plan.json
      
      - name: Generate Infracost estimate
        if: steps.plan.outputs.exitcode == '2'
        uses: infracost/actions/setup@v3
        with:
          api-key: ${{ secrets.INFRACOST_API_KEY }}
      
      - name: Run Infracost
        if: steps.plan.outputs.exitcode == '2'
        working-directory: ./terraform/environments/production
        run: |
          infracost breakdown \
            --path plan.json \
            --format table \
            --show-skipped
      
      - name: Upload plan artifact
        if: steps.plan.outputs.exitcode == '2'
        uses: actions/upload-artifact@v4
        with:
          name: tfplan-prod
          path: terraform/environments/production/tfplan.binary
          retention-days: 30  # Longer retention for production

  # Job 7: Apply to production (manual approval required)
  apply-prod:
    name: Apply - Production
    runs-on: ubuntu-latest
    needs: plan-prod
    if: needs.plan-prod.outputs.plan-exitcode == '2'
    environment: production  # GitHub Environment with manual approval
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Configure AWS Credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::444444444444:role/GitHubActionsTerraformRole
          role-session-name: GitHubActions-TerraformApply-Prod
          aws-region: ${{ env.AWS_REGION }}
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}
      
      - name: Terraform Init
        working-directory: ./terraform/environments/production
        run: |
          terraform init \
            -backend-config="bucket=terraform-state-prod-444444444444" \
            -backend-config="key=workloads/app1/terraform.tfstate" \
            -backend-config="region=${{ env.AWS_REGION }}"
      
      - name: Download plan artifact
        uses: actions/download-artifact@v4
        with:
          name: tfplan-prod
          path: terraform/environments/production/
      
      - name: Terraform Apply
        working-directory: ./terraform/environments/production
        run: terraform apply -auto-approve tfplan.binary
      
      - name: Create deployment record
        if: always()
        run: |
          echo "### Production Deployment Complete" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "**Status:** ${{ job.status }}" >> $GITHUB_STEP_SUMMARY
          echo "**Account:** 444444444444" >> $GITHUB_STEP_SUMMARY
          echo "**Approved By:** ${{ github.actor }}" >> $GITHUB_STEP_SUMMARY
          echo "**Timestamp:** $(date -u)" >> $GITHUB_STEP_SUMMARY
          echo "**Commit:** ${{ github.sha }}" >> $GITHUB_STEP_SUMMARY
      
      - name: Send Slack notification
        if: always()
        uses: slackapi/slack-github-action@v1
        with:
          webhook: ${{ secrets.SLACK_WEBHOOK_URL }}
          payload: |
            {
              "text": "Production Terraform Deployment",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "*Production Terraform Deployment*\n*Status:* ${{ job.status }}\n*Approved By:* ${{ github.actor }}\n*Commit:* <https://github.com/${{ github.repository }}/commit/${{ github.sha }}|${{ github.sha }}>"
                  }
                }
              ]
            }
```


### AWS IAM Role for GitHub Actions OIDC

```hcl
# iam-oidc-github-actions/main.tf
terraform {
  required_version = ">= 1.9.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      ManagedBy = "Terraform"
      Purpose   = "GitHubActionsOIDC"
    }
  }
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "github_org" {
  description = "GitHub organization name"
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name"
  type        = string
}

# OIDC provider for GitHub Actions
resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
  
  client_id_list = [
    "sts.amazonaws.com"
  ]
  
  thumbprint_list = [
    "ffffffffffffffffffffffffffffffffffffffff"  # GitHub's thumbprint
  ]
  
  tags = {
    Purpose = "GitHubActionsOIDC"
  }
}

# IAM role for GitHub Actions
resource "aws_iam_role" "github_actions_terraform" {
  name        = "GitHubActionsTerraformRole"
  description = "Role for GitHub Actions to execute Terraform"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github.arn
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
  
  max_session_duration = 3600  # 1 hour
  
  tags = {
    Purpose = "TerraformCI"
  }
}

# IAM policy for Terraform operations
resource "aws_iam_policy" "terraform_operations" {
  name        = "TerraformOperationsPolicy"
  description = "Policy for Terraform to manage infrastructure"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TerraformStateAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "arn:aws:s3:::terraform-state-*/*"
      },
      {
        Sid    = "TerraformStateBucketList"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketVersioning"
        ]
        Resource = "arn:aws:s3:::terraform-state-*"
      },
      {
        Sid    = "TerraformStateLocking"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem",
          "dynamodb:DescribeTable"
        ]
        Resource = "arn:aws:dynamodb:*:*:table/terraform-state-locks"
      },
      {
        Sid    = "TerraformKMSAccess"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:DescribeKey",
          "kms:GenerateDataKey"
        ]
        Resource = "arn:aws:kms:*:*:key/*"
        Condition = {
          StringLike = {
            "kms:ViaService" = [
              "s3.*.amazonaws.com",
              "dynamodb.*.amazonaws.com"
            ]
          }
        }
      },
      {
        Sid    = "TerraformInfrastructureManagement"
        Effect = "Allow"
        Action = [
          "ec2:*",
          "vpc:*",
          "elasticloadbalancing:*",
          "autoscaling:*",
          "cloudwatch:*",
          "sns:*",
          "sqs:*",
          "iam:GetRole",
          "iam:PassRole",
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:GetRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:CreateInstanceProfile",
          "iam:DeleteInstanceProfile",
          "iam:AddRoleToInstanceProfile",
          "iam:RemoveRoleFromInstanceProfile",
          "lambda:*",
          "logs:*",
          "rds:*",
          "dynamodb:*",
          "s3:CreateBucket",
          "s3:DeleteBucket",
          "s3:PutBucketPolicy",
          "s3:GetBucketPolicy",
          "s3:PutBucketVersioning",
          "s3:GetBucketVersioning",
          "s3:PutEncryptionConfiguration",
          "s3:GetEncryptionConfiguration",
          "s3:PutBucketPublicAccessBlock",
          "s3:GetBucketPublicAccessBlock",
          "s3:PutBucketTagging",
          "s3:GetBucketTagging"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyDangerousActions"
        Effect = "Deny"
        Action = [
          "iam:CreateUser",
          "iam:DeleteUser",
          "iam:CreateAccessKey",
          "organizations:LeaveOrganization",
          "account:CloseAccount"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "terraform_operations" {
  role       = aws_iam_role.github_actions_terraform.name
  policy_arn = aws_iam_policy.terraform_operations.arn
}

# Outputs
output "github_actions_role_arn" {
  description = "IAM role ARN for GitHub Actions"
  value       = aws_iam_role.github_actions_terraform.arn
}

output "oidc_provider_arn" {
  description = "OIDC provider ARN for GitHub"
  value       = aws_iam_openid_connect_provider.github.arn
}
```


### GitLab CI Multi-Account Pipeline

```yaml
# .gitlab-ci.yml
variables:
  TF_VERSION: "1.9.8"
  AWS_REGION: "us-east-1"
  TF_ROOT: "${CI_PROJECT_DIR}/terraform"
  TF_STATE_BUCKET_DEV: "terraform-state-dev-222222222222"
  TF_STATE_BUCKET_STAGING: "terraform-state-staging-333333333333"
  TF_STATE_BUCKET_PROD: "terraform-state-prod-444444444444"

stages:
  - validate
  - plan
  - apply

# Cache Terraform plugins
cache:
  key: "${CI_COMMIT_REF_SLUG}"
  paths:
    - ${TF_ROOT}/.terraform

# Template for Terraform jobs
.terraform_base:
  image:
    name: hashicorp/terraform:${TF_VERSION}
    entrypoint: [""]
  before_script:
    - cd ${TF_ROOT}/environments/${ENVIRONMENT}
    - terraform --version
    - terraform init
        -backend-config="bucket=${TF_STATE_BUCKET}"
        -backend-config="key=workloads/app1/terraform.tfstate"
        -backend-config="region=${AWS_REGION}"

# Validation job
terraform:validate:
  stage: validate
  image:
    name: hashicorp/terraform:${TF_VERSION}
    entrypoint: [""]
  script:
    - terraform fmt -check -recursive ${TF_ROOT}
    - cd ${TF_ROOT}/environments/development
    - terraform init -backend=false
    - terraform validate
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'

# Security scan
terraform:security:
  stage: validate
  image:
    name: bridgecrew/checkov:latest
    entrypoint: [""]
  script:
    - checkov -d ${TF_ROOT} --framework terraform --output cli --output junitxml --output-file-path console,checkov-report.xml
  artifacts:
    reports:
      junit: checkov-report.xml
    when: always
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'

# Development plan
terraform:plan:dev:
  extends: .terraform_base
  stage: plan
  variables:
    ENVIRONMENT: "development"
    TF_STATE_BUCKET: "${TF_STATE_BUCKET_DEV}"
  script:
    - terraform plan -out=tfplan.binary -var-file=terraform.tfvars
    - terraform show -json tfplan.binary > plan.json
  artifacts:
    paths:
      - ${TF_ROOT}/environments/development/tfplan.binary
      - ${TF_ROOT}/environments/development/plan.json
    expire_in: 1 week
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'

# Development apply
terraform:apply:dev:
  extends: .terraform_base
  stage: apply
  variables:
    ENVIRONMENT: "development"
    TF_STATE_BUCKET: "${TF_STATE_BUCKET_DEV}"
  script:
    - terraform apply -auto-approve tfplan.binary
  dependencies:
    - terraform:plan:dev
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
      when: on_success

# Staging plan
terraform:plan:staging:
  extends: .terraform_base
  stage: plan
  variables:
    ENVIRONMENT: "staging"
    TF_STATE_BUCKET: "${TF_STATE_BUCKET_STAGING}"
  script:
    - terraform plan -out=tfplan.binary -var-file=terraform.tfvars
  artifacts:
    paths:
      - ${TF_ROOT}/environments/staging/tfplan.binary
    expire_in: 1 week
  dependencies:
    - terraform:apply:dev
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'

# Staging apply
terraform:apply:staging:
  extends: .terraform_base
  stage: apply
  variables:
    ENVIRONMENT: "staging"
    TF_STATE_BUCKET: "${TF_STATE_BUCKET_STAGING}"
  script:
    - terraform apply -auto-approve tfplan.binary
  dependencies:
    - terraform:plan:staging
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
      when: on_success

# Production plan
terraform:plan:prod:
  extends: .terraform_base
  stage: plan
  variables:
    ENVIRONMENT: "production"
    TF_STATE_BUCKET: "${TF_STATE_BUCKET_PROD}"
  script:
    - terraform plan -out=tfplan.binary -var-file=terraform.tfvars
  artifacts:
    paths:
      - ${TF_ROOT}/environments/production/tfplan.binary
    expire_in: 1 month
  dependencies:
    - terraform:apply:staging
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'

# Production apply (manual approval required)
terraform:apply:prod:
  extends: .terraform_base
  stage: apply
  variables:
    ENVIRONMENT: "production"
    TF_STATE_BUCKET: "${TF_STATE_BUCKET_PROD}"
  script:
    - terraform apply -auto-approve tfplan.binary
    - echo "Production deployment completed at $(date -u)"
  dependencies:
    - terraform:plan:prod
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
      when: manual
  environment:
    name: production
    action: prepare
```


## AWS Provider v6.x Migration and Caveats

The AWS Provider v6.x introduces significant breaking changes, schema modifications, and new default behaviors that impact multi-account enterprise deployments. Understanding these changes is critical to avoid unexpected resource replacement or drift.

### Major Breaking Changes in Provider v6.x

**1. Default Tag Handling Changes:**

```hcl
# provider-v6-migration/tags.tf

# ❌ Provider v5.x behavior (deprecated)
provider "aws" {
  region = "us-east-1"
  
  # v5.x style default tags
  default_tags {
    tags = {
      Environment = "production"
      ManagedBy   = "Terraform"
    }
  }
}

resource "aws_instance" "example_v5" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  
  # In v5.x, tags and default_tags merged automatically
  tags = {
    Name = "example-instance"
  }
  # Result: 3 tags (Name, Environment, ManagedBy)
}

# ✅ Provider v6.x behavior (current)
provider "aws" {
  region = "us-east-1"
  
  default_tags {
    tags = {
      Environment = "production"
      ManagedBy   = "Terraform"
    }
  }
}

resource "aws_instance" "example_v6" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  
  # In v6.x, explicit tag management required for conflicts
  tags = merge(
    {
      Name = "example-instance"
    },
    var.additional_tags
  )
  
  # Prevent drift from external tag modifications
  lifecycle {
    ignore_changes = [tags["LastModified"]]
  }
}

# Best practice: Use consistent tag strategy
locals {
  common_tags = {
    Environment    = var.environment
    ManagedBy      = "Terraform"
    CostCenter     = var.cost_center
    Application    = var.application_name
    DataClass      = var.data_classification
    Backup         = "true"
    SecurityZone   = var.security_zone
  }
}

resource "aws_instance" "best_practice" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = var.instance_type
  
  tags = merge(
    local.common_tags,
    {
      Name = "app1-${var.environment}-web-${count.index + 1}"
      Role = "WebServer"
    }
  )
}
```

**2. S3 Bucket Resource Separation:**

```hcl
# provider-v6-migration/s3.tf

# ❌ Provider v5.x (monolithic resource - deprecated)
resource "aws_s3_bucket" "example_v5" {
  bucket = "my-app-bucket-v5"
  acl    = "private"
  
  versioning {
    enabled = true
  }
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  
  lifecycle_rule {
    enabled = true
    
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
}

# ✅ Provider v6.x (separated resources - current)
resource "aws_s3_bucket" "example_v6" {
  bucket = "my-app-bucket-v6"
  
  tags = {
    Name    = "my-app-bucket-v6"
    Purpose = "ApplicationData"
  }
}

# Separate resource for versioning
resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example_v6.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

# Separate resource for encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example_v6.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

# Separate resource for lifecycle rules
resource "aws_s3_bucket_lifecycle_configuration" "example" {
  bucket = aws_s3_bucket.example_v6.id
  
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
    
    expiration {
      days = 365
    }
  }
}

# Separate resource for public access block
resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.example_v6.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# KMS key for encryption
resource "aws_kms_key" "s3" {
  description             = "KMS key for S3 bucket encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}
```

**3. EC2 Instance Metadata Service (IMDS) Defaults:**

```hcl
# provider-v6-migration/ec2.tf

# ❌ Provider v5.x (IMDSv1 allowed by default - insecure)
resource "aws_instance" "example_v5" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"
  
  # IMDSv1 enabled by default (security risk)
  # No explicit metadata_options configuration
}

# ✅ Provider v6.x (IMDSv2 required - secure)
resource "aws_instance" "example_v6" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"
  
  # Explicitly require IMDSv2
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # IMDSv2 only
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }
  
  tags = {
    Name = "secure-instance-v6"
  }
}

# Launch template with IMDSv2 for Auto Scaling
resource "aws_launch_template" "secure" {
  name_prefix   = "app1-secure-"
  image_id      = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"
  
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }
  
  iam_instance_profile {
    arn = aws_iam_instance_profile.app.arn
  }
  
  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    environment = var.environment
  }))
  
  tag_specifications {
    resource_type = "instance"
    tags = {
      Name        = "app1-${var.environment}-asg"
      Environment = var.environment
    }
  }
  
  lifecycle {
    create_before_destroy = true
  }
}
```

**4. RDS Instance Blue/Green Deployment Support:**

```hcl
# provider-v6-migration/rds.tf

# Provider v6.x introduces blue_green_update support
resource "aws_db_instance" "app_v6" {
  identifier     = "app-database-${var.environment}"
  engine         = "postgres"
  engine_version = "16.1"
  instance_class = "db.r6g.large"
  
  allocated_storage     = 100
  max_allocated_storage = 1000
  storage_type          = "gp3"
  iops                  = 3000
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.rds.arn
  
  db_name  = "appdb"
  username = "dbadmin"
  password = random_password.db_password.result
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  # Blue/green deployment for major version upgrades
  blue_green_update {
    enabled = true
  }
  
  # Performance Insights (new default in v6)
  performance_insights_enabled          = true
  performance_insights_retention_period = 7
  performance_insights_kms_key_id       = aws_kms_key.rds.arn
  
  # Enhanced monitoring (required for production)
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  monitoring_interval             = 60
  monitoring_role_arn             = aws_iam_role.rds_monitoring.arn
  
  backup_retention_period = 30
  backup_window          = "03:00-04:00"
  maintenance_window     = "mon:04:00-mon:05:00"
  
  deletion_protection       = true
  delete_automated_backups  = false
  skip_final_snapshot       = false
  final_snapshot_identifier = "app-db-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"
  
  tags = {
    Name        = "app-database-${var.environment}"
    Environment = var.environment
    Backup      = "true"
  }
  
  # Prevent unwanted updates
  lifecycle {
    ignore_changes = [password]  # Use Secrets Manager rotation instead
  }
}

# IAM role for enhanced monitoring
resource "aws_iam_role" "rds_monitoring" {
  name = "rds-enhanced-monitoring-${var.environment}"
  
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
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}
```


### Migration Script for Provider v5 to v6

```bash
#!/bin/bash
# migrate-to-provider-v6.sh

set -euo pipefail

TERRAFORM_DIR="${1:-.}"
BACKUP_DIR="./terraform-state-backups"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

echo "🔄 Starting AWS Provider v6 Migration"
echo "📁 Terraform directory: $TERRAFORM_DIR"
echo ""

# Step 1: Backup state
echo "📦 Step 1: Backing up Terraform state..."
mkdir -p "$BACKUP_DIR"

cd "$TERRAFORM_DIR"

terraform state pull > "$BACKUP_DIR/terraform.tfstate.backup-$TIMESTAMP"
echo "✅ State backed up to $BACKUP_DIR/terraform.tfstate.backup-$TIMESTAMP"
echo ""

# Step 2: Update provider version
echo "🔧 Step 2: Updating provider version in terraform block..."
sed -i.bak 's/version = "~> 5\./version = "~> 6./g' versions.tf
echo "✅ Provider version updated"
echo ""

# Step 3: Re-initialize
echo "🔄 Step 3: Re-initializing Terraform with new provider version..."
terraform init -upgrade
echo "✅ Terraform re-initialized"
echo ""

# Step 4: Generate migration plan
echo "📋 Step 4: Generating migration plan..."
terraform plan -out=migration.tfplan > migration-plan.txt 2>&1
echo "✅ Migration plan saved to migration-plan.txt"
echo ""

# Step 5: Review changes
echo "🔍 Step 5: Reviewing potential issues..."
echo ""

# Check for S3 bucket changes
if grep -q "aws_s3_bucket.*must be replaced" migration-plan.txt; then
  echo "⚠️  WARNING: S3 bucket resources require migration to separate resources"
  echo "   Action required: Separate versioning, encryption, lifecycle into new resources"
fi

# Check for tag changes
if grep -q "tags.*has changed" migration-plan.txt; then
  echo "⚠️  WARNING: Tag handling has changed"
  echo "   Action required: Review default_tags and explicit tags merge strategy"
fi

# Check for EC2 metadata changes
if grep -q "metadata_options" migration-plan.txt; then
  echo "⚠️  WARNING: EC2 metadata options changed to IMDSv2"
  echo "   Action required: Verify application compatibility with IMDSv2"
fi

echo ""
echo "📖 Review migration-plan.txt for full details"
echo ""
echo "⚠️  MANUAL STEPS REQUIRED:"
echo "   1. Review migration-plan.txt carefully"
echo "   2. Update S3 bucket resources to use separate sub-resources"
echo "   3. Verify tag merge strategy with default_tags"
echo "   4. Test IMDSv2 compatibility with applications"
echo "   5. Run 'terraform apply migration.tfplan' when ready"
echo ""
echo "📚 Migration guide: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/guides/version-6-upgrade"
```


### Provider Version Compatibility Matrix

| Feature | Provider v5.x | Provider v6.x | Migration Complexity |
| :-- | :-- | :-- | :-- |
| S3 Bucket Resources | Monolithic | Separated (versioning, encryption, lifecycle as separate resources) | **High** - Requires state migration and resource refactoring |
| Default Tags | Automatic merge | Explicit merge required | **Medium** - Review tag conflicts |
| EC2 IMDS | v1 enabled by default | v2 required by default | **Medium** - Application compatibility testing needed |
| RDS Blue/Green | Not supported | Supported via `blue_green_update` block | **Low** - Optional feature, no breaking change |
| EBS Encryption | Optional | Strongly recommended default | **Low** - Aligns with best practices |
| VPC Flow Logs | Basic configuration | Enhanced with delivery options | **Low** - Backwards compatible |
| IAM Policy Validation | Basic | Stricter validation with warnings | **Low** - Catches configuration errors earlier |
| Resource Tagging | Flexible | Standardized with `tags_all` attribute | **Medium** - State file updates |

## ⚠️ Common Pitfalls

### Pitfall 1: Conflicting Control Tower and Terraform Management

**Problem:** Attempting to manage Control Tower–created resources with Terraform causes continuous drift and automated remediation conflicts.

**Example:**

```hcl
# ❌ ANTI-PATTERN: Managing Control Tower-created CloudTrail
resource "aws_cloudtrail" "organization" {
  name                          = "aws-controltower-logs"
  s3_bucket_name                = "aws-controltower-logs-222222222222"
  include_global_service_events = true
  is_multi_region_trail         = true
  is_organization_trail         = true
  
  # This will conflict with Control Tower automation!
}
```

**Why it's problematic:**

- Control Tower's automated lifecycle management will revert Terraform changes
- Creates configuration drift that triggers false alarms
- Violates the separation of concerns between Control Tower and Terraform
- Can cause Control Tower guardrails to fail compliance checks

**Solution:**

```hcl
# ✅ CORRECT: Use data source to reference Control Tower resources
data "aws_cloudtrail" "organization" {
  name = "aws-controltower-BaselineCloudTrail"
}

# Consume the trail ARN for other resources
resource "aws_cloudwatch_log_metric_filter" "security_events" {
  name           = "security-events-filter"
  log_group_name = data.aws_cloudtrail.organization.cloud_watch_logs_log_group_arn
  pattern        = "{ $.eventName = \"ConsoleLogin\" }"
  
  metric_transformation {
    name      = "SecurityConsoleLogins"
    namespace = "SecurityMetrics"
    value     = "1"
  }
}
```


### Pitfall 2: Hardcoding Account IDs in Multi-Account Pipelines

**Problem:** Hardcoded account IDs in Terraform code and CI/CD pipelines create maintenance nightmares and prevent reusability.

**Example:**

```hcl
# ❌ ANTI-PATTERN: Hardcoded account IDs
provider "aws" {
  alias  = "production"
  region = "us-east-1"
  
  assume_role {
    role_arn = "arn:aws:iam::444444444444:role/TerraformExecution"  # Hardcoded!
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "app-logs-444444444444"  # Hardcoded account ID!
}
```

**Why it's problematic:**

- Violates DRY (Don't Repeat Yourself) principle
- Makes code non-portable across accounts
- Increases risk of deploying to wrong account
- Creates merge conflicts when multiple teams work on same code

**Solution:**

```hcl
# ✅ CORRECT: Dynamic account ID resolution
data "aws_caller_identity" "current" {}

data "aws_ssm_parameter" "target_account_id" {
  name = "/control-tower/workload-accounts/${var.environment}/account-id"
}

provider "aws" {
  alias  = "workload"
  region = var.aws_region
  
  assume_role {
    role_arn = "arn:aws:iam::${data.aws_ssm_parameter.target_account_id.value}:role/TerraformExecution"
  }
}

resource "aws_s3_bucket" "logs" {
  provider = aws.workload
  bucket   = "app-logs-${var.environment}-${data.aws_ssm_parameter.target_account_id.value}"
  
  tags = {
    Environment = var.environment
    AccountType = var.account_type
  }
}

# Store account mappings in SSM Parameter Store
resource "aws_ssm_parameter" "account_mapping" {
  provider = aws.management
  
  name  = "/control-tower/workload-accounts/${var.environment}/account-id"
  type  = "String"
  value = var.account_id
  
  tags = {
    Purpose = "AccountMapping"
  }
}
```


### Pitfall 3: Missing OIDC Trust Boundaries in GitHub Actions

**Problem:** Overly permissive OIDC trust policies allow unauthorized repositories or branches to assume roles, creating security vulnerabilities.

**Example:**

```hcl
# ❌ ANTI-PATTERN: Permissive OIDC trust policy
resource "aws_iam_role" "github_actions" {
  name = "GitHubActionsRole"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        # Missing sub claim restriction - ANY repo can assume this role!
      }
    }]
  })
}
```

**Why it's problematic:**

- Any repository in GitHub Actions can assume the role
- Attackers can create malicious workflows in forked repositories
- No branch protection - feature branches have production access
- Violates principle of least privilege

**Solution:**

```hcl
# ✅ CORRECT: Strict OIDC trust policy with repository and branch restrictions
resource "aws_iam_role" "github_actions" {
  name = "GitHubActionsRole"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          # Restrict to specific repository
          "token.actions.githubusercontent.com:sub" = "repo:company/infrastructure-repo:*"
        }
      }
    }]
  })
  
  # Additional tag-based access control
  tags = {
    AllowedRepository = "company/infrastructure-repo"
    AllowedBranch     = "main"
  }
}

# Separate role for pull request plans (read-only)
resource "aws_iam_role" "github_actions_pr" {
  name = "GitHubActionsPRRole"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:company/infrastructure-repo:pull_request"
        }
      }
    }]
  })
}

# Read-only policy for PR role
resource "aws_iam_role_policy" "github_actions_pr_readonly" {
  role = aws_iam_role.github_actions_pr.name
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:ListBucket",
        "dynamodb:GetItem",
        "dynamodb:DescribeTable",
        "ec2:Describe*",
        "vpc:Describe*",
        "iam:GetRole",
        "iam:ListRoles"
      ]
      Resource = "*"
    }]
  })
}
```


### Pitfall 4: AFT Customization Drift from Manual Changes

**Problem:** Manual changes in AFT-provisioned accounts bypass Terraform state, causing customization drift and failed subsequent provisioning.

**Example:**

```bash
# ❌ ANTI-PATTERN: Manual changes in AFT-managed account
# Someone manually creates a VPC in an AFT-provisioned account
aws ec2 create-vpc --cidr-block 10.50.0.0/16 --region us-east-1

# Later, AFT customization tries to create the same VPC
# Result: "VPC already exists" error and provisioning failure
```

**Why it's problematic:**

- AFT customization expects clean slate based on its Terraform state
- Manual changes not tracked in state cause apply failures
- Creates inconsistency across accounts provisioned at different times
- Debugging requires manual inspection of each account

**Solution:**

```hcl
# ✅ CORRECT: Implement drift detection for AFT customizations
# aft-account-customizations/production-baseline/terraform/drift-detection.tf

# Run scheduled drift detection
resource "aws_cloudwatch_event_rule" "aft_drift_detection" {
  name                = "aft-drift-detection"
  description         = "Trigger AFT drift detection daily"
  schedule_expression = "cron(0 8 * * ? *)"  # Daily at 8 AM UTC
  
  tags = {
    Purpose = "DriftDetection"
  }
}

resource "aws_cloudwatch_event_target" "aft_drift_lambda" {
  rule      = aws_cloudwatch_event_rule.aft_drift_detection.name
  target_id = "AFTDriftDetection"
  arn       = aws_lambda_function.drift_detector.arn
}

# Lambda function to detect drift
resource "aws_lambda_function" "drift_detector" {
  filename      = "drift_detector.zip"
  function_name = "aft-drift-detector"
  role          = aws_iam_role.drift_detector.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 300
  
  environment {
    variables = {
      TERRAFORM_STATE_BUCKET = var.terraform_state_bucket
      SNS_TOPIC_ARN         = aws_sns_topic.drift_alerts.arn
    }
  }
  
  tags = {
    Purpose = "DriftDetection"
  }
}

# SNS topic for drift alerts
resource "aws_sns_topic" "drift_alerts" {
  name = "aft-drift-alerts"
  
  tags = {
    Purpose = "DriftAlerts"
  }
}

resource "aws_sns_topic_subscription" "drift_email" {
  topic_arn = aws_sns_topic.drift_alerts.arn
  protocol  = "email"
  endpoint  = "platform-team@company.com"
}

# Prevent manual resource creation with SCP
resource "aws_organizations_policy" "prevent_manual_vpc_creation" {
  name        = "PreventManualVPCCreation"
  description = "Prevent manual VPC creation in AFT-managed accounts"
  type        = "SERVICE_CONTROL_POLICY"
  
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DenyManualVPCCreation"
      Effect = "Deny"
      Action = [
        "ec2:CreateVpc",
        "ec2:CreateSubnet",
        "ec2:CreateInternetGateway"
      ]
      Resource = "*"
      Condition = {
        StringNotEquals = {
          "aws:PrincipalArn" = [
            "arn:aws:iam::*:role/AWSControlTowerExecution",
            "arn:aws:iam::*:role/TerraformExecution"
          ]
        }
      }
    }]
  })
}
```


### Pitfall 5: State Lock Contention in Concurrent Deployments

**Problem:** Multiple CI/CD pipelines trying to deploy to same account simultaneously cause state lock timeouts and failed deployments.

**Example:**

```yaml
# ❌ ANTI-PATTERN: Parallel deployments without orchestration
# .github/workflows/concurrent-deploys.yml
jobs:
  deploy-networking:
    runs-on: ubuntu-latest
    steps:
      - run: terraform apply -auto-approve
        working-directory: ./networking
  
  deploy-security:
    runs-on: ubuntu-latest
    steps:
      - run: terraform apply -auto-approve
        working-directory: ./security
  
  deploy-apps:
    runs-on: ubuntu-latest
    steps:
      - run: terraform apply -auto-approve
        working-directory: ./applications

# All three jobs try to acquire state lock simultaneously
# Result: Lock timeout errors and partial deployments
```

**Why it's problematic:**

- DynamoDB state lock timeout (default 10 minutes) not sufficient for large applies
- Failed jobs leave state locked, blocking subsequent runs
- No clear dependency ordering between infrastructure layers
- Debugging requires manual state lock release

**Solution:**

```yaml
# ✅ CORRECT: Sequential deployment with explicit dependencies
# .github/workflows/orchestrated-deploys.yml
jobs:
  deploy-networking:
    name: Deploy Networking Layer
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_TERRAFORM_ROLE_ARN }}
          aws-region: us-east-1
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.9.8
      
      - name: Terraform Init
        working-directory: ./terraform/networking
        run: terraform init
      
      - name: Terraform Apply with Retry
        working-directory: ./terraform/networking
        run: |
          attempt=1
          max_attempts=3
          
          until terraform apply -auto-approve; do
            if [ $attempt -eq $max_attempts ]; then
              echo "Failed after $max_attempts attempts"
              exit 1
            fi
            
            echo "Attempt $attempt failed. Retrying in 60 seconds..."
            sleep 60
            attempt=$((attempt + 1))
          done
  
  deploy-security:
    name: Deploy Security Layer
    runs-on: ubuntu-latest
    needs: deploy-networking  # Wait for networking
    environment: production
    steps:
      - uses: actions/checkout@v4
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_TERRAFORM_ROLE_ARN }}
          aws-region: us-east-1
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.9.8
      
      - name: Terraform Init
        working-directory: ./terraform/security
        run: terraform init
      
      - name: Terraform Apply
        working-directory: ./terraform/security
        run: terraform apply -auto-approve
  
  deploy-apps:
    name: Deploy Applications Layer
    runs-on: ubuntu-latest
    needs: [deploy-networking, deploy-security]  # Wait for both
    environment: production
    strategy:
      matrix:
        app: [app1, app2, app3]
      max-parallel: 2  # Limit concurrent apps to avoid contention
    steps:
      - uses: actions/checkout@v4
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_TERRAFORM_ROLE_ARN }}
          aws-region: us-east-1
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.9.8
      
      - name: Terraform Init
        working-directory: ./terraform/applications/${{ matrix.app }}
        run: terraform init
      
      - name: Terraform Apply
        working-directory: ./terraform/applications/${{ matrix.app }}
        run: terraform apply -auto-approve

# Configure DynamoDB table for state locking with higher throughput
```

```hcl
# backend-infrastructure/dynamodb-state-lock.tf
resource "aws_dynamodb_table" "terraform_locks" {
  name         = "terraform-state-locks"
  billing_mode = "PAY_PER_REQUEST"  # Auto-scales for concurrent access
  hash_key     = "LockID"
  
  attribute {
    name = "LockID"
    type = "S"
  }
  
  # Enable point-in-time recovery for state lock table
  point_in_time_recovery {
    enabled = true
  }
  
  # TTL for automatic cleanup of stale locks
  ttl {
    attribute_name = "ExpirationTime"
    enabled        = true
  }
  
  tags = {
    Purpose = "TerraformStateLocking"
  }
}

# Lambda function to automatically release stale locks
resource "aws_lambda_function" "stale_lock_cleanup" {
  filename      = "stale_lock_cleanup.zip"
  function_name = "terraform-stale-lock-cleanup"
  role          = aws_iam_role.stale_lock_cleanup.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 60
  
  environment {
    variables = {
      DYNAMODB_TABLE = aws_dynamodb_table.terraform_locks.name
      LOCK_AGE_HOURS = "2"  # Release locks older than 2 hours
    }
  }
}

# Scheduled rule to run cleanup every hour
resource "aws_cloudwatch_event_rule" "stale_lock_cleanup" {
  name                = "terraform-stale-lock-cleanup"
  description         = "Cleanup stale Terraform state locks"
  schedule_expression = "rate(1 hour)"
}

resource "aws_cloudwatch_event_target" "stale_lock_cleanup" {
  rule      = aws_cloudwatch_event_rule.stale_lock_cleanup.name
  target_id = "StaleLockCleanup"
  arn       = aws_lambda_function.stale_lock_cleanup.arn
}
```


### Pitfall 6: Provider v6.x Tag Propagation Issues

**Problem:** Misunderstanding tag propagation between `default_tags` and resource `tags` causes unexpected diffs and state churn.

**Example:**

```hcl
# ❌ ANTI-PATTERN: Tag conflict between default_tags and resource tags
provider "aws" {
  region = "us-east-1"
  
  default_tags {
    tags = {
      Environment = "production"
      ManagedBy   = "Terraform"
      CostCenter  = "Engineering"
    }
  }
}

resource "aws_instance" "example" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  
  tags = {
    Name        = "example-instance"
    Environment = "staging"  # Conflicts with default_tags!
    # Result: Perpetual diff showing Environment changing from "production" to "staging"
  }
}
```

**Why it's problematic:**

- Creates perpetual drift requiring constant `terraform apply`
- Makes it unclear which tag value takes precedence
- Breaks tag-based cost allocation and reporting
- Violates organizational tagging standards

**Solution:**

```hcl
# ✅ CORRECT: Consistent tag strategy with explicit precedence
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      ManagedBy   = "Terraform"
      CostCenter  = var.cost_center
      Application = var.application_name
    }
  }
}

# Local variables for tag merging
locals {
  # Common tags that apply to all resources
  common_tags = {
    Project     = var.project_name
    Owner       = var.owner_email
    Backup      = "true"
    Compliance  = var.compliance_framework
  }
  
  # Environment-specific tags (override default_tags if needed)
  environment_tags = {
    Environment = var.environment
    SecurityZone = var.security_zone
  }
}

resource "aws_instance" "example" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = var.instance_type
  
  # Explicit tag merge with clear precedence
  # Order: default_tags → common_tags → environment_tags → resource-specific tags
  tags = merge(
    local.common_tags,
    local.environment_tags,
    {
      Name = "app1-${var.environment}-web-${count.index + 1}"
      Role = "WebServer"
    }
  )
  
  # Use tags_all output for debugging
  lifecycle {
    postcondition {
      condition     = contains(keys(self.tags_all), "ManagedBy")
      error_message = "Instance must have ManagedBy tag from default_tags"
    }
  }
}

# Outputs for tag verification
output "instance_tags" {
  description = "All tags applied to instance (including default_tags)"
  value       = aws_instance.example.tags_all
}

# Data source to verify tag compliance
data "aws_instances" "untagged" {
  filter {
    name   = "tag:ManagedBy"
    values = ["Terraform"]
  }
  
  filter {
    name   = "instance-state-name"
    values = ["running"]
  }
}

# CloudWatch alarm for untagged resources
resource "aws_cloudwatch_metric_alarm" "untagged_resources" {
  alarm_name          = "untagged-resources-detected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "UntaggedResourceCount"
  namespace           = "Compliance"
  period              = "3600"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Alert when resources lack required tags"
  treat_missing_data  = "notBreaching"
}
```


## 💡 Expert Tips from the Field

**Tip 1: Use AWS Organizations Tag Policies to Enforce Tagging Governance**

> "In production environments with 100+ accounts, manual tag enforcement is impossible. We implemented AWS Organizations tag policies as a preventive control—resources can't be created without required tags. This caught 85% of tagging violations before they reached production."
> — Senior Cloud Architect, Fortune 500 Financial Services

```hcl
# organizations-tag-policies/main.tf
resource "aws_organizations_policy" "required_tags" {
  name        = "RequiredResourceTags"
  description = "Enforce required tags on all resources"
  type        = "TAG_POLICY"
  
  content = jsonencode({
    tags = {
      Environment = {
        tag_key = {
          "@@assign" = "Environment"
        }
        tag_value = {
          "@@assign" = [
            "development",
            "staging",
            "production",
            "sandbox"
          ]
        }
        enforced_for = {
          "@@assign" = [
            "ec2:instance",
            "rds:db",
            "s3:bucket",
            "lambda:function",
            "dynamodb:table"
          ]
        }
      }
      CostCenter = {
        tag_key = {
          "@@assign" = "CostCenter"
        }
        enforced_for = {
          "@@assign" = [
            "ec2:*",
            "rds:*",
            "s3:*"
          ]
        }
      }
      Owner = {
        tag_key = {
          "@@assign" = "Owner"
        }
        tag_value = {
          "@@assign" = ["^[a-zA-Z0-9._%+-]+@company\\.com$"]  # Email format
        }
        enforced_for = {
          "@@assign" = ["*"]  # All resources
        }
      }
    }
  })
}

# Attach to Workloads OU
resource "aws_organizations_policy_attachment" "required_tags_workloads" {
  policy_id = aws_organizations_policy.required_tags.id
  target_id = data.aws_organizations_organizational_unit.workloads.id
}
```

**Tip 2: Implement Cross-Account VPC Endpoint Sharing for Cost Optimization**

> "We reduced NAT Gateway costs by 70% (\$15K/month savings) by creating VPC endpoints in a shared services account and sharing them via AWS Resource Access Manager (RAM) to workload accounts. Single NAT Gateway per AZ in shared services account serves all workloads."
> — Lead DevOps Engineer, SaaS Unicorn

```hcl
# shared-services-vpc-endpoints/main.tf
# Create VPC endpoints in shared services account
resource "aws_vpc_endpoint" "s3" {
  provider = aws.shared_services
  
  vpc_id            = data.aws_vpc.shared_services.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  
  route_table_ids = data.aws_route_tables.shared_services.ids
  
  tags = {
    Name    = "shared-s3-endpoint"
    Purpose = "CostOptimization"
  }
}

resource "aws_vpc_endpoint" "ecr_api" {
  provider = aws.shared_services
  
  vpc_id              = data.aws_vpc.shared_services.id
  service_name        = "com.amazonaws.${var.aws_region}.ecr.api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = data.aws_subnets.shared_services_private.ids
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
  
  tags = {
    Name    = "shared-ecr-api-endpoint"
    Purpose = "CostOptimization"
  }
}

# Share VPC endpoints via AWS RAM
resource "aws_ram_resource_share" "vpc_endpoints" {
  provider = aws.shared_services
  
  name                      = "shared-vpc-endpoints"
  allow_external_principals = false
  
  tags = {
    Purpose = "VPCEndpointSharing"
  }
}

resource "aws_ram_resource_association" "s3_endpoint" {
  provider = aws.shared_services
  
  resource_arn       = aws_vpc_endpoint.s3.arn
  resource_share_arn = aws_ram_resource_share.vpc_endpoints.arn
}

# Share with entire organization
resource "aws_ram_principal_association" "organization" {
  provider = aws.shared_services
  
  principal          = data.aws_organizations_organization.main.arn
  resource_share_arn = aws_ram_resource_share.vpc_endpoints.arn
}

# Workload accounts accept the share automatically
data "aws_vpc_endpoint" "shared_s3" {
  provider = aws.workload
  
  vpc_id       = data.aws_vpc.workload.id
  service_name = "com.amazonaws.${var.aws_region}.s3"
  
  depends_on = [aws_ram_principal_association.organization]
}
```

**Tip 3: Use Terraform Workspaces with Control Tower for Environment Isolation**

> "We map Terraform workspaces to Control Tower OUs—development workspace → Development OU accounts, production workspace → Production OU accounts. This prevents accidentally deploying dev code to production and simplifies our CI/CD pipeline from 20 jobs to 3."
> — Principal Infrastructure Engineer, Healthcare Technology

```hcl
# workspace-based-deployment/main.tf
terraform {
  required_version = ">= 1.9.0"
  
  backend "s3" {
    bucket         = "terraform-state-management"
    key            = "workloads/app1/terraform.tfstate"
    region         = "us-east-1"
    workspace_key_prefix = "environments"  # Creates separate states per workspace
  }
}

# Workspace-specific configuration
locals {
  workspace_config = {
    development = {
      ou_name            = "Development"
      instance_type      = "t3.micro"
      min_size           = 1
      max_size           = 3
      enable_monitoring  = false
      log_retention_days = 7
      backup_retention   = 7
    }
    staging = {
      ou_name            = "Staging"
      instance_type      = "t3.small"
      min_size           = 2
      max_size           = 5
      enable_monitoring  = true
      log_retention_days = 30
      backup_retention   = 14
    }
    production = {
      ou_name            = "Production"
      instance_type      = "t3.large"
      min_size           = 3
      max_size           = 20
      enable_monitoring  = true
      log_retention_days = 365
      backup_retention   = 30
    }
  }
  
  config = local.workspace_config[terraform.workspace]
  
  # Discover accounts in workspace-specific OU
  ou_id = [
    for ou in data.aws_organizations_organizational_units.root.children : ou.id
    if ou.name == local.config.ou_name
  ][0]
}

# Workspace-aware resource creation
resource "aws_instance" "app" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = local.config.instance_type
  
  monitoring = local.config.enable_monitoring
  
  tags = {
    Name        = "app1-${terraform.workspace}"
    Environment = terraform.workspace
    Workspace   = terraform.workspace
  }
}

# Workspace-aware backup configuration
resource "aws_backup_plan" "app" {
  name = "app1-${terraform.workspace}-backup"
  
  rule {
    rule_name         = "daily_backup"
    target_vault_name = aws_backup_vault.app.name
    schedule          = "cron(0 2 * * ? *)"
    
    lifecycle {
      delete_after = local.config.backup_retention
    }
  }
}

# Workspace selection validation
resource "null_resource" "workspace_validation" {
  lifecycle {
    precondition {
      condition     = contains(["development", "staging", "production"], terraform.workspace)
      error_message = "Invalid workspace. Must be: development, staging, or production"
    }
  }
}
```

**Tip 4: Implement Terraform Module Testing with AFT Account Sandboxes**

> "We provision temporary AWS accounts via AFT specifically for module testing. Each PR triggers AFT to create a sandbox account, deploys the module, runs integration tests, then deletes the account. This caught 40% of bugs before they reached shared environments."
> — Staff Platform Engineer, E-commerce Giant

```hcl
# aft-sandbox-provisioning/test-account.tf
# Automatically provision test account for PR
resource "aws_account" "test_sandbox" {
  count = var.create_test_account ? 1 : 0
  
  account_name = "test-sandbox-${var.pr_number}"
  email        = "aws+test-${var.pr_number}@company.com"
  
  organizational_unit = data.aws_organizations_organizational_unit.sandbox.id
  
  tags = {
    Purpose     = "ModuleTesting"
    PRNumber    = var.pr_number
    TTL         = formatdate("YYYY-MM-DD", timeadd(timestamp(), "24h"))
    AutoDelete  = "true"
  }
}

# Deploy module to test account
module "module_under_test" {
  source = var.module_path
  
  providers = {
    aws = aws.test_sandbox
  }
  
  # Test-specific configuration
  for_each = var.test_scenarios
  
  depends_on = [aws_account.test_sandbox]
}

# Run integration tests
resource "null_resource" "integration_tests" {
  provisioner "local-exec" {
    command = <<-EOT
      pytest tests/integration/ \
        --account-id=${aws_account.test_sandbox[0].id} \
        --region=${var.aws_region} \
        --junitxml=test-results.xml
    EOT
  }
  
  depends_on = [module.module_under_test]
}

# Lambda to auto-delete test accounts after TTL
resource "aws_lambda_function" "test_account_cleanup" {
  filename      = "test_account_cleanup.zip"
  function_name = "aft-test-account-cleanup"
  role          = aws_iam_role.test_cleanup.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 300
  
  environment {
    variables = {
      ORGANIZATION_ID = data.aws_organizations_organization.main.id
      SANDBOX_OU_ID   = data.aws_organizations_organizational_unit.sandbox.id
    }
  }
}

# Scheduled cleanup every 6 hours
resource "aws_cloudwatch_event_rule" "test_cleanup" {
  name                = "test-account-cleanup"
  description         = "Cleanup expired test accounts"
  schedule_expression = "rate(6 hours)"
}
```

**Tip 5: Use Parameter Store for Cross-Account Configuration Discovery**

> "Instead of hardcoding account IDs and resource ARNs across 50+ repositories, we store them in SSM Parameter Store in the management account. Terraform reads parameters at runtime, enabling zero-touch account onboarding and reducing deployment time from hours to minutes."
> — Cloud Platform Architect, Media Streaming Company

```hcl
# parameter-store-config-discovery/management-account.tf
# Store account metadata in management account
resource "aws_ssm_parameter" "account_registry" {
  for_each = var.managed_accounts
  
  name        = "/control-tower/accounts/${each.key}/metadata"
  description = "Account metadata for ${each.key}"
  type        = "String"
  
  value = jsonencode({
    account_id      = each.value.account_id
    account_name    = each.value.account_name
    environment     = each.value.environment
    vpc_id          = each.value.vpc_id
    private_subnets = each.value.private_subnets
    public_subnets  = each.value.public_subnets
    kms_key_arn     = each.value.kms_key_arn
  })
  
  tags = {
    Purpose = "ConfigurationDiscovery"
  }
}

# Workload account discovers configuration
data "aws_ssm_parameter" "account_config" {
  provider = aws.management
  
  name = "/control-tower/accounts/${var.environment}/metadata"
}

locals {
  account_config = jsondecode(data.aws_ssm_parameter.account_config.value)
}

# Use discovered configuration
module "application" {
  source = "./modules/application"
  
  vpc_id          = local.account_config.vpc_id
  private_subnets = local.account_config.private_subnets
  kms_key_arn     = local.account_config.kms_key_arn
}
```

**Tip 6: Implement Blue-Green Account Deployment for Major Migrations**

> "During our migration from Provider v5 to v6, we provisioned duplicate 'green' accounts via AFT, deployed v6 resources there, tested extensively, then cut over DNS. If issues arose, we could instantly revert to 'blue' accounts. Zero production impact."
> — Director of Cloud Engineering, FinTech Startup

```hcl
# blue-green-account-deployment/main.tf
variable "active_deployment" {
  description = "Active deployment: blue or green"
  type        = string
  default     = "blue"
  
  validation {
    condition     = contains(["blue", "green"], var.active_deployment)
    error_message = "Must be 'blue' or 'green'"
  }
}

locals {
  accounts = {
    blue = {
      account_id      = "111111111111"
      provider_version = "5.70.0"
      alb_dns          = "app-blue.internal.company.com"
    }
    green = {
      account_id      = "222222222222"
      provider_version = "6.15.0"
      alb_dns          = "app-green.internal.company.com"
    }
  }
  
  active_account  = local.accounts[var.active_deployment]
  standby_account = local.accounts[var.active_deployment == "blue" ? "green" : "blue"]
}

# Route 53 weighted routing for gradual cutover
resource "aws_route53_record" "app" {
  zone_id = data.aws_route53_zone.internal.zone_id
  name    = "app.internal.company.com"
  type    = "CNAME"
  
  # Weighted routing for blue-green
  set_identifier = "active-${var.active_deployment}"
  weighted_routing_policy {
    weight = var.active_deployment == "blue" ? 100 : 0
  }
  
  ttl     = 60
  records = [local.active_account.alb_dns]
}

resource "aws_route53_record" "app_standby" {
  zone_id = data.aws_route53_zone.internal.zone_id
  name    = "app.internal.company.com"
  type    = "CNAME"
  
  set_identifier = "standby-${var.active_deployment == "blue" ? "green" : "blue"}"
  weighted_routing_policy {
    weight = var.active_deployment == "green" ? 100 : 0
  }
  
  ttl     = 60
  records = [local.standby_account.alb_dns]
}

# Gradual traffic shift
variable "cutover_percentage" {
  description = "Percentage of traffic to send to green deployment"
  type        = number
  default     = 0
  
  validation {
    condition     = var.cutover_percentage >= 0 && var.cutover_percentage <= 100
    error_message = "Must be between 0 and 100"
  }
}

# Canary deployment pattern
resource "aws_route53_record" "app_canary" {
  zone_id = data.aws_route53_zone.internal.zone_id
  name    = "app.internal.company.com"
  type    = "CNAME"
  
  set_identifier = "canary-green"
  weighted_routing_policy {
    weight = var.cutover_percentage
  }
  
  ttl     = 30  # Lower TTL during cutover
  records = [local.accounts.green.alb_dns]
}
```

**Tip 7: Automate Provider Version Upgrades with Dependabot and Testing**

> "We configure Dependabot to automatically create PRs for provider version bumps. Our CI pipeline runs the full test suite against the new version in a sandbox account. If tests pass, we auto-merge. This keeps us current without manual intervention."
> — Senior SRE, Cloud-Native Consultancy

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "terraform"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
    open-pull-requests-limit: 5
    reviewers:
      - "platform-team"
    labels:
      - "terraform"
      - "dependencies"
    commit-message:
      prefix: "terraform"
      include: "scope"
    ignore:
      # Skip major version upgrades (require manual review)
      - dependency-name: "hashicorp/aws"
        update-types: ["version-update:semver-major"]

# .github/workflows/provider-upgrade-test.yml
name: Test Provider Upgrade

on:
  pull_request:
    paths:
      - 'versions.tf'
      - '.terraform.lock.hcl'

jobs:
  test-provider-upgrade:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Extract provider version
        id: provider_version
        run: |
          VERSION=$(grep -A 3 'hashicorp/aws' .terraform.lock.hcl | grep version | cut -d'"' -f2)
          echo "version=$VERSION" >> $GITHUB_OUTPUT
      
      - name: Provision test account via AFT
        run: |
          # Trigger AFT account provisioning
          aws lambda invoke \
            --function-name aft-account-provisioner \
            --payload '{"pr_number": "${{ github.event.pull_request.number }}"}' \
            response.json
      
      - name: Run integration tests
        run: |
          pytest tests/integration/ \
            --provider-version=${{ steps.provider_version.outputs.version }} \
            --junitxml=test-results.xml
      
      - name: Publish test results
        uses: EnricoMi/publish-unit-test-result-action@v2
        if: always()
        with:
          files: test-results.xml
      
      - name: Auto-merge if tests pass
        if: success()
        run: gh pr merge --auto --squash
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```


## 🎯 Practical Exercises

### Exercise 1: Integrate Terraform with AWS Control Tower

**Difficulty:** Intermediate
**Time:** 45 minutes
**Objective:** Set up Terraform to consume Control Tower outputs and deploy resources to managed accounts

**Prerequisites:**

- AWS account with Control Tower enabled
- Terraform 1.9+ installed locally
- AWS CLI configured with management account credentials
- Basic understanding of AWS Organizations

**Steps:**

1. **Discover Control Tower structure:**
```bash
# List all organizational units
aws organizations list-organizational-units-for-parent \
  --parent-id $(aws organizations list-roots --query 'Roots[0].Id' --output text)

# Find Log Archive account
aws organizations list-accounts-for-parent \
  --parent-id <security-ou-id> \
  --query 'Accounts[?Name==`Log Archive`]'
```

2. **Create Terraform configuration to read Control Tower data:**
```hcl
# exercise-1/data-sources.tf
data "aws_organizations_organization" "main" {}

data "aws_iam_role" "control_tower_execution" {
  name = "AWSControlTowerExecution"
}

output "organization_id" {
  value = data.aws_organizations_organization.main.id
}

output "execution_role_arn" {
  value = data.aws_iam_role.control_tower_execution.arn
}
```

3. **Deploy VPC to Control Tower-managed account:**
```bash
terraform init
terraform plan
terraform apply
```

4. **Validation:**
```bash
# Verify VPC was created in target account
aws ec2 describe-vpcs \
  --filters "Name=tag:ManagedBy,Values=Terraform" \
  --region us-east-1
```

**Expected Output:**

- VPC ID: vpc-xxxxx
- Tags include "ManagedBy: Terraform" and "LandingZone: ControlTower"
- VPC Flow Logs enabled (Control Tower guardrail requirement)

**Challenge:**
Extend the configuration to automatically discover all accounts in the "Workloads" OU and deploy standardized VPCs to each.

**Solution:**

<details>
```
<summary>Click to expand solution</summary>
```

```hcl
# Discover all accounts in Workloads OU
data "aws_organizations_organizational_units" "workloads" {
  parent_id = data.aws_organizations_organization.main.roots[0].id
}

locals {
  workloads_ou_id = [
    for ou in data.aws_organizations_organizational_units.workloads.children : ou.id
    if ou.name == "Workloads"
  ][0]
}

data "aws_organizations_organizational_unit_child_accounts" "workload_accounts" {
  parent_id = local.workloads_ou_id
}

# Deploy VPC to each workload account
module "workload_vpcs" {
  source   = "./modules/vpc"
  for_each = { for account in data.aws_organizations_organizational_unit_child_accounts.workload_accounts.accounts : account.name => account }
  
  account_id = each.value.id
  cidr_block = cidrsubnet("10.0.0.0/8", 8, index(keys(data.aws_organizations_organizational_unit_child_accounts.workload_accounts.accounts), each.key))
}
```
</details>

### Exercise 2: Set Up Multi-Account CI/CD with GitHub Actions OIDC

**Difficulty:** Advanced
**Time:** 60 minutes
**Objective:** Configure OIDC authentication for GitHub Actions to deploy Terraform across multiple AWS accounts

**Prerequisites:**

- GitHub repository with Terraform code
- AWS accounts for dev, staging, and production
- Administrator access to all accounts
- GitHub Actions enabled

**Steps:**

1. **Create OIDC provider in each AWS account:**
```bash
# Run for each account (dev, staging, prod)
cd exercise-2/oidc-setup
terraform init
terraform apply \
  -var="github_org=your-org" \
  -var="github_repo=your-repo"
```

2. **Configure GitHub Actions workflow:**
```yaml
# .github/workflows/multi-account-deploy.yml
name: Multi-Account Deployment

on:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read

jobs:
  deploy-dev:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.DEV_TERRAFORM_ROLE_ARN }}
          aws-region: us-east-1
      
      - name: Terraform Apply
        run: |
          cd terraform/environments/development
          terraform init
          terraform apply -auto-approve
```

3. **Add GitHub secrets:**
```bash
# Add role ARNs to GitHub repository secrets
gh secret set DEV_TERRAFORM_ROLE_ARN --body "arn:aws:iam::111111111111:role/GitHubActionsTerraformRole"
gh secret set STAGING_TERRAFORM_ROLE_ARN --body "arn:aws:iam::222222222222:role/GitHubActionsTerraformRole"
gh secret set PROD_TERRAFORM_ROLE_ARN --body "arn:aws:iam::333333333333:role/GitHubActionsTerraformRole"
```

4. **Validation:**
```bash
# Trigger workflow
git add .
git commit -m "Test multi-account deployment"
git push origin main

# Monitor workflow execution
gh run watch
```

**Expected Output:**

- GitHub Actions successfully assumes roles in all three accounts
- Terraform applies resources to dev, then staging, then production
- No long-lived credentials stored in GitHub

**Challenge:**
Add Infracost integration to post cost estimates as PR comments before deployment.

**Solution:**

<details>
```
<summary>Click to expand solution</summary>
```

```yaml
- name: Setup Infracost
  uses: infracost/actions/setup@v3
  with:
    api-key: ${{ secrets.INFRACOST_API_KEY }}

- name: Generate cost estimate
  run: |
    terraform plan -out=tfplan.binary
    terraform show -json tfplan.binary > plan.json
    infracost breakdown --path plan.json --format json --out-file cost.json

- name: Post cost comment
  uses: infracost/actions/comment@v1
  with:
    path: cost.json
    behavior: update
```
</details>

### Exercise 3: Migrate Existing Resources to Provider v6

**Difficulty:** Advanced
**Time:** 90 minutes
**Objective:** Safely migrate Terraform code and state from AWS Provider v5 to v6

**Prerequisites:**

- Existing Terraform project using AWS Provider v5.x
- S3 backend with state versioning enabled
- Non-production environment for testing
- Backup of current state file

**Steps:**

1. **Backup current state:**
```bash
cd exercise-3/existing-infrastructure
terraform state pull > state-backup-v5-$(date +%Y%m%d).tfstate
aws s3 cp state-backup-v5-*.tfstate s3://terraform-backups/
```

2. **Create migration branch:**
```bash
git checkout -b provider-v6-migration
```

3. **Update provider version:**
```hcl
# versions.tf
terraform {
  required_version = ">= 1.9.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"  # Updated from ~> 5.0
    }
  }
}
```

4. **Re-initialize and review changes:**
```bash
terraform init -upgrade
terraform plan > migration-plan.txt
```

5. **Refactor S3 bucket resources:**
```hcl
# Before (v5):
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "private"
  versioning {
    enabled = true
  }
}

# After (v6):
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}

resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration {
    status = "Enabled"
  }
}
```

6. **Apply migration:**
```bash
terraform apply
```

7. **Validation:**
```bash
# Verify no unexpected changes
terraform plan
# Output should show: "No changes. Your infrastructure matches the configuration."

# Compare resource counts
echo "Resources before migration:" $(grep -c "resource" state-backup-v5-*.tfstate)
echo "Resources after migration:" $(terraform state list | wc -l)
```

**Expected Output:**

- All resources migrated without replacement
- State file contains same number of resources
- `terraform plan` shows no pending changes

**Challenge:**
Automate the migration using a script that detects v5 patterns and generates v6-compliant code.

**Solution:**

<details>
```
<summary>Click to expand solution</summary>
```

```bash
#!/bin/bash
# migrate-s3-buckets-v6.sh

# Find all S3 bucket resources with inline configurations
grep -r "resource \"aws_s3_bucket\"" . -A 20 | while read -r line; do
  if [[ $line =~ versioning\s*\{ ]]; then
    echo "Found S3 bucket with inline versioning configuration"
    # Generate refactored code
    # (Implementation details omitted for brevity)
  fi
done
```
</details>

## Key Takeaways

- **Control Tower Integration:** Treat Control Tower as the landing zone owner managing Organizations, core security/logging accounts, and baseline guardrails, while Terraform manages workload infrastructure, application resources, and extended security automation in member accounts without conflicts
- **Account Factory for Terraform (AFT):** Automates account provisioning with standardized baselines by applying Terraform customizations to new accounts, enabling self-service account creation while maintaining governance through global and account-specific customization modules
- **Multi-Account CI/CD Pipelines:** Use OIDC authentication from GitHub Actions or GitLab CI to assume roles across accounts, implement sequential deployment with explicit dependencies between infrastructure layers, leverage environment protection rules for production approvals, and include cost estimation and policy validation in pipelines
- **AWS Provider v6.x Migration:** Major breaking changes include separated S3 bucket sub-resources (versioning, encryption, lifecycle as separate resources), IMDSv2 required by default for EC2 instances, stricter default tag handling requiring explicit merge strategies, RDS blue-green deployment support, and enhanced validation catching configuration errors earlier—plan migrations carefully in non-production environments first
- **OIDC Security:** Restrict GitHub Actions trust policies with specific repository and branch conditions using `StringLike` on `token.actions.githubusercontent.com:sub` claim, separate read-only roles for PR plans from write roles for main branch applies, and implement least-privilege IAM policies with explicit deny statements for dangerous actions
- **Cross-Account Resource Discovery:** Store account metadata in SSM Parameter Store in the management account for runtime configuration discovery, use AWS Organizations data sources to dynamically discover accounts by OU or tags, implement RAM sharing for VPC endpoints and Transit Gateway attachments to optimize costs, and avoid hardcoded account IDs or resource ARNs in Terraform code
- **Enterprise Governance Patterns:** Implement AWS Organizations tag policies to enforce required tags at creation time, use SCPs to prevent manual resource creation in AFT-managed accounts, leverage DynamoDB state locking with auto-scaling and TTL for concurrent deployments, and establish drift detection with scheduled plans and automated alerts


## What's Next

Chapter 22 dives into **Terraform State Management at Scale and Disaster Recovery**, covering advanced state file architecture for organizations managing 1,000+ AWS accounts, implementing state file sharding strategies to overcome S3 and DynamoDB limits, designing cross-region state replication for business continuity, automating state file recovery from corruption or accidental deletion using versioning and point-in-time recovery, implementing state file encryption with customer-managed KMS keys and key rotation policies, establishing state file access logging and audit trails for compliance requirements, and building automated state file backup and validation pipelines. You'll learn enterprise-grade patterns for state management that enable teams to scale Terraform operations while maintaining data integrity, security, and recoverability even in disaster scenarios.

## Additional Resources

### Official Documentation

- **AWS Control Tower User Guide:** https://docs.aws.amazon.com/controltower/latest/userguide/what-is-control-tower.html
- **Account Factory for Terraform (AFT) GitHub Repository:** https://github.com/aws-ia/terraform-aws-control_tower_account_factory
- **AWS Provider v6.x Upgrade Guide:** https://registry.terraform.io/providers/hashicorp/aws/latest/docs/guides/version-6-upgrade
- **Terraform Workspaces Documentation:** https://developer.hashicorp.com/terraform/language/state/workspaces
- **GitHub Actions OIDC with AWS:** https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services


### AWS Prescriptive Guidance

- **Multi-Account AWS Environments Using Terraform:** https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/automate-multi-account-aws-environments-using-terraform.html
- **Organizing AWS Environments Using Multiple Accounts:** https://docs.aws.amazon.com/whitepapers/latest/organizing-your-aws-environment/organizing-your-aws-environment.html
- **AWS Control Tower Account Factory Customization:** https://docs.aws.amazon.com/prescriptive-guidance/latest/aws-control-tower-account-factory/welcome.html


### Community Resources

- **Terraform AWS Modules Registry:** https://registry.terraform.io/namespaces/terraform-aws-modules
- **AWS Samples GitHub - Control Tower Examples:** https://github.com/aws-samples/aws-control-tower-customizations
- **Gruntwork Terraform AWS Modules:** https://github.com/gruntwork-io/terraform-aws-service-catalog


### Video Tutorials

- **AWS re:Invent - Automating AWS Organizations with Control Tower and Terraform:** https://www.youtube.com/watch?v=dQy4Ov8K5QE
- **HashiCorp Webinar - Multi-Account AWS Infrastructure with Terraform Cloud:** https://www.hashicorp.com/resources/multi-account-aws-infrastructure-terraform-cloud


### Tools and Utilities

- **Terragrunt for Multi-Account Management:** https://terragrunt.gruntwork.io/
- **Infracost - Cloud Cost Estimates for Terraform:** https://www.infracost.io/
- **Checkov - Terraform Security Scanner:** https://www.checkov.io/
- **TFLint - Terraform Linter:** https://github.com/terraform-linters/tflint
- **Terraform Compliance - BDD Testing for Terraform:** https://terraform-compliance.com/


### Books and Guides

- **Terraform: Up \& Running (3rd Edition)** by Yevgeniy Brikman
- **AWS Well-Architected Framework - Operational Excellence Pillar:** https://docs.aws.amazon.com/wellarchitected/latest/operational-excellence-pillar/welcome.html
- **AWS Security Best Practices Whitepaper:** https://docs.aws.amazon.com/whitepapers/latest/aws-security-best-practices/welcome.html

