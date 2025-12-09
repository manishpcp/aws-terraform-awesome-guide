# Chapter 3: AWS Provider Configuration

## Introduction

The AWS Provider is the cornerstone of every Terraform configuration targeting Amazon Web Services—it serves as the critical bridge between your declarative infrastructure code and AWS APIs that create, modify, and destroy cloud resources. While many engineers rush through provider configuration to get to resource definitions, mastering provider setup is essential for security, scalability, and operational excellence. A poorly configured provider can lead to security breaches, cross-account deployment failures, and frustrating authentication issues that halt your entire deployment pipeline.

In this chapter, you'll explore the AWS Provider 6.0's groundbreaking features, including enhanced multi-region support that eliminates the need for multiple provider instances and the powerful default_tags feature that ensures consistent tagging across your entire infrastructure. You'll learn seven different authentication methods—from environment variables and IAM roles to advanced cross-account assume role configurations—and understand when to use each approach based on your deployment context. This knowledge is critical whether you're deploying from your laptop, a CI/CD pipeline, or orchestrating infrastructure across multiple AWS accounts in a complex enterprise environment.

By the end of this chapter, you'll have production-ready provider configurations that follow AWS security best practices, handle multi-region deployments elegantly, and scale from simple single-account setups to sophisticated multi-account architectures. You'll understand how to troubleshoot common authentication failures, implement least-privilege access patterns, and leverage provider features that drastically reduce configuration complexity. These foundational skills will serve you throughout your Terraform journey, as every resource you create depends on a properly configured provider.

## Understanding the AWS Provider

### The Provider's Role in Terraform

The AWS Provider is a plugin that translates Terraform's HCL configuration into AWS API calls, managing the complete lifecycle of AWS resources. When you run `terraform apply`, the provider authenticates with AWS, makes the necessary API calls to create or modify resources, and tracks the results in Terraform's state file.

```hcl
# versions.tf - Provider declaration and versioning
terraform {
  required_version = ">= 1.15.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"  # AWS Provider 6.0 or compatible minor versions
    }
  }
}

# provider.tf - Provider configuration
provider "aws" {
  region = "us-east-1"
  
  # Provider configuration determines:
  # 1. Authentication method (how to access AWS)
  # 2. Default region for resource creation
  # 3. Default tags applied to all resources
  # 4. Assume role configurations for cross-account access
  # 5. Custom endpoint configurations for testing
}
```

**Provider Version Selection Strategy:**

```hcl
# Pessimistic constraint operator (~>) recommended
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"  # Allows 6.x.x, blocks 7.0.0
      
      # Alternative approaches:
      # version = ">= 6.0.0, < 7.0.0"  # Explicit range
      # version = "6.15.0"              # Exact version (too strict)
      # version = ">= 6.0"              # Too permissive
    }
  }
}
```

**Why Version Constraints Matter:**


| Constraint | Behavior | Use Case | Risk Level |
| :-- | :-- | :-- | :-- |
| `~> 6.0` | Allows 6.x.x updates | **Recommended** - Balances stability and updates | Low |
| `>= 6.0, < 7.0` | Explicit range | Explicit control, more verbose | Low |
| `6.15.0` | Exact version | Maximum stability, manual updates required | Medium |
| `>= 6.0` | Any version 6.0+ | Breaking changes in major versions | High |
| No constraint | Latest version | Unpredictable behavior, breaking changes | Critical |

### AWS Provider 6.0: Major Enhancements

**Enhanced Multi-Region Support:**

Prior to version 6.0, managing resources across multiple AWS regions required defining separate provider instances with aliases. Version 6.0 introduces region attribute injection at the resource level, dramatically simplifying multi-region deployments and reducing memory consumption.

```hcl
# OLD APPROACH (Pre-6.0): Multiple provider instances
provider "aws" {
  alias  = "us_east"
  region = "us-east-1"
}

provider "aws" {
  alias  = "us_west"
  region = "us-west-2"
}

provider "aws" {
  alias  = "eu_west"
  region = "eu-west-1"
}

resource "aws_s3_bucket" "east" {
  provider = aws.us_east
  bucket   = "data-us-east-1"
}

resource "aws_s3_bucket" "west" {
  provider = aws.us_west
  bucket   = "data-us-west-2"
}

# Problem: 3 provider instances loaded in memory
# Problem: Must update each provider block to change configuration
```

```hcl
# NEW APPROACH (6.0+): Single provider, resource-level region
provider "aws" {
  region = "us-east-1"  # Default region
  
  default_tags {
    tags = {
      ManagedBy = "Terraform"
      Project   = "MultiRegion"
    }
  }
}

# Override region at resource level (NEW in 6.0)
resource "aws_s3_bucket" "east" {
  bucket = "data-us-east-1"
  # Uses default provider region (us-east-1)
}

resource "aws_s3_bucket" "west" {
  bucket = "data-us-west-2"
  # Region can be overridden if needed (6.0 capability)
}

resource "aws_s3_bucket" "europe" {
  bucket = "data-eu-west-1"
  # Region attribute injection at resource level
}

# Benefits:
# - Single provider instance (lower memory)
# - Centralized configuration
# - Simplified multi-region management
```

**Global Service Handling:**

AWS Provider 6.0 intelligently handles global services that don't require region specification:

```hcl
provider "aws" {
  region = "us-west-2"  # Default for regional resources
}

# Global services automatically use appropriate region
resource "aws_iam_role" "lambda_role" {
  # IAM is global - region automatically handled
  name = "lambda-execution-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_cloudfront_distribution" "cdn" {
  # CloudFront is global - automatically uses us-east-1
  enabled = true
  
  origin {
    domain_name = aws_s3_bucket.content.bucket_regional_domain_name
    origin_id   = "S3-Origin"
  }
  
  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-Origin"
    viewer_protocol_policy = "redirect-to-https"
    
    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }
  
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  
  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

resource "aws_route53_zone" "main" {
  # Route 53 is global - region handled automatically
  name = "example.com"
}
```

**Default Tags Feature:**

AWS Provider 6.0 enhanced the default_tags block, allowing you to define tags once that apply to ALL resources:

```hcl
provider "aws" {
  region = var.aws_region
  
  # Tags applied automatically to EVERY AWS resource
  default_tags {
    tags = {
      Environment  = var.environment
      ManagedBy    = "Terraform"
      Project      = var.project_name
      Owner        = var.team_email
      CostCenter   = var.cost_center
      Compliance   = "SOC2"
      BackupPolicy = var.backup_policy
    }
  }
}

# These resources automatically inherit all default tags
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  
  # Additional tags merge with defaults
  tags = {
    Name = "main-vpc"
    Type = "Networking"
  }
  # Final tags: All default_tags + Name + Type
}

resource "aws_s3_bucket" "data" {
  bucket = "data-${var.environment}"
  
  # No tags block needed - inherits defaults
  # But can override if needed
}

resource "aws_db_instance" "main" {
  identifier     = "main-db"
  engine         = "postgres"
  instance_class = "db.t3.medium"
  
  tags = {
    Name     = "main-database"
    Critical = "true"
  }
  # Inherits all default_tags AND adds Name and Critical
}
```

**Benefits of default_tags:**

- **Consistency:** Every resource tagged identically
- **Governance:** Enforce tagging policies at provider level
- **Cost Tracking:** Automatic cost allocation tags
- **Compliance:** Required compliance tags on all resources
- **DRY Principle:** Define once, apply everywhere
- **Reduced Code:** Eliminates repetitive tags blocks


## Authentication Methods

### Method 1: Static Credentials (Development Only)

**⚠️ WARNING: NEVER use in production or commit to version control!**

```hcl
# provider.tf - DEVELOPMENT ONLY
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"  # ❌ NEVER DO THIS
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # ❌ NEVER DO THIS
}

# Problems:
# 1. Credentials visible in code
# 2. Will be committed to Git
# 3. Exposed in Terraform state
# 4. Security breach waiting to happen
# 5. No credential rotation
```

**Use Case:** Local testing only, with temporary credentials that expire quickly.

### Method 2: Environment Variables (Recommended for Local Development)

Environment variables provide a secure way to supply credentials without hardcoding them:

```bash
# ~/.bashrc or ~/.zshrc
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_DEFAULT_REGION="us-east-1"

# Optional: Session token for MFA or temporary credentials
export AWS_SESSION_TOKEN="FwoGZXIvYXdzEBYaDH..."

# For multiple accounts, use functions
function aws-dev() {
  export AWS_PROFILE=dev
  export AWS_REGION=us-east-1
}

function aws-prod() {
  export AWS_PROFILE=production
  export AWS_REGION=us-east-1
}
```

```hcl
# provider.tf - No credentials needed, reads from environment
provider "aws" {
  region = var.aws_region
  # Automatically uses AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
  # from environment variables
}
```

**Advantages:**

- Credentials never in code
- Easy switching between accounts
- CI/CD pipeline compatible
- Works with temporary credentials

**Disadvantages:**

- Must set environment before running Terraform
- Not suitable for long-running processes
- Manual credential rotation


### Method 3: AWS CLI Shared Credentials File (Recommended for Multi-Account)

The AWS CLI credentials file supports multiple named profiles:

```bash
# ~/.aws/credentials
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[development]
aws_access_key_id = AKIAIDEVELOPMENTKEY
aws_secret_access_key = DevSecretKeyExample

[production]
aws_access_key_id = AKIAIPRODUCTIONKEY
aws_secret_access_key = ProdSecretKeyExample

[staging]
aws_access_key_id = AKIAISTAGINGKEY
aws_secret_access_key = StagingSecretKeyExample
```

```bash
# ~/.aws/config
[default]
region = us-east-1
output = json

[profile development]
region = us-west-2
output = json

[profile production]
region = us-east-1
output = json
# MFA requirement for production
mfa_serial = arn:aws:iam::123456789012:mfa/username

[profile staging]
region = us-east-1
output = json
```

```hcl
# provider.tf - Use specific profile
provider "aws" {
  region  = "us-east-1"
  profile = "production"  # References ~/.aws/credentials [production]
}

# Or use variable for flexibility
variable "aws_profile" {
  description = "AWS CLI profile to use"
  type        = string
  default     = "default"
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}
```

```bash
# Deploy to different environments
terraform plan -var="aws_profile=development"
terraform apply -var="aws_profile=development"

terraform plan -var="aws_profile=production"
terraform apply -var="aws_profile=production"
```

**Advantages:**

- Multiple accounts managed easily
- Compatible with AWS CLI
- Supports MFA enforcement
- Industry standard approach


### Method 4: IAM Roles for EC2 Instances (Recommended for EC2/ECS)

When running Terraform on EC2, ECS, or other AWS compute services, use IAM instance profiles:

```hcl
# Create IAM role for EC2 instance running Terraform
resource "aws_iam_role" "terraform_runner" {
  name = "terraform-runner-role"
  
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
}

# Attach policies needed for Terraform operations
resource "aws_iam_role_policy_attachment" "terraform_runner" {
  role       = aws_iam_role.terraform_runner.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
  
  # In production, use custom least-privilege policy
}

# Create instance profile
resource "aws_iam_instance_profile" "terraform_runner" {
  name = "terraform-runner-profile"
  role = aws_iam_role.terraform_runner.name
}

# Attach to EC2 instance
resource "aws_instance" "terraform_runner" {
  ami                  = data.aws_ami.amazon_linux_2.id
  instance_type        = "t3.medium"
  iam_instance_profile = aws_iam_instance_profile.terraform_runner.name
  
  user_data = <<-EOF
              #!/bin/bash
              # Install Terraform
              wget https://releases.hashicorp.com/terraform/1.15.0/terraform_1.15.0_linux_amd64.zip
              unzip terraform_1.15.0_linux_amd64.zip
              sudo mv terraform /usr/local/bin/
              
              # Clone infrastructure repo
              git clone https://github.com/company/terraform-infra.git
              cd terraform-infra
              
              # Run Terraform (credentials automatic from instance profile)
              terraform init
              terraform apply -auto-approve
              EOF
  
  tags = {
    Name = "terraform-runner"
  }
}
```

```hcl
# provider.tf on EC2 instance - No credentials needed!
provider "aws" {
  region = "us-east-1"
  # Automatically uses IAM instance profile credentials
  # No access keys, no secrets to manage
}
```

**Advantages:**

- No credential management
- Automatic credential rotation
- Integrates with AWS security model
- Audit trail via CloudTrail
- Supports cross-account roles

**Best for:** EC2-based CI/CD runners, Jenkins agents, GitLab runners on EC2

### Method 5: AssumeRole for Cross-Account Access (Enterprise Standard)

AssumeRole enables secure cross-account resource management, essential for enterprise multi-account architectures:

**Scenario:** Management account (111111111111) deploys resources to Production account (222222222222)

```hcl
# In Production Account (222222222222)
# Create role that Management account can assume

resource "aws_iam_role" "terraform_deployment" {
  name = "terraform-deployment-role"
  
  # Trust relationship - allow Management account to assume this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::111111111111:user/terraform-user"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "sts:ExternalId" = "unique-external-id-12345"
        }
      }
    }]
  })
}

# Attach permissions for what Terraform can do in this account
resource "aws_iam_role_policy_attachment" "terraform_deployment" {
  role       = aws_iam_role.terraform_deployment.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

# Output role ARN for use in Management account
output "deployment_role_arn" {
  value = aws_iam_role.terraform_deployment.arn
  # arn:aws:iam::222222222222:role/terraform-deployment-role
}
```

```hcl
# In Management Account (111111111111)
# Provider configuration with assume_role

provider "aws" {
  alias  = "production"
  region = "us-east-1"
  
  # Assume role in Production account
  assume_role {
    role_arn     = "arn:aws:iam::222222222222:role/terraform-deployment-role"
    session_name = "terraform-deployment"
    external_id  = "unique-external-id-12345"
    
    # Optional: Additional security
    # duration_seconds = 3600  # Session duration (15min - 12hrs)
  }
}

# Deploy resources to Production account
resource "aws_vpc" "production" {
  provider   = aws.production
  cidr_block = "10.0.0.0/16"
  
  tags = {
    Name        = "production-vpc"
    Environment = "production"
  }
}

resource "aws_s3_bucket" "production_data" {
  provider = aws.production
  bucket   = "production-data-bucket"
}
```

**Multi-Account Pattern:**

```hcl
# variables.tf
variable "account_roles" {
  description = "IAM roles for each account"
  type        = map(string)
  default = {
    dev     = "arn:aws:iam::333333333333:role/terraform-role"
    staging = "arn:aws:iam::444444444444:role/terraform-role"
    prod    = "arn:aws:iam::222222222222:role/terraform-role"
  }
}

# providers.tf
provider "aws" {
  alias  = "dev"
  region = "us-east-1"
  
  assume_role {
    role_arn     = var.account_roles["dev"]
    session_name = "terraform-dev"
  }
}

provider "aws" {
  alias  = "staging"
  region = "us-east-1"
  
  assume_role {
    role_arn     = var.account_roles["staging"]
    session_name = "terraform-staging"
  }
}

provider "aws" {
  alias  = "prod"
  region = "us-east-1"
  
  assume_role {
    role_arn     = var.account_roles["prod"]
    session_name = "terraform-prod"
  }
}

# Deploy to all accounts
resource "aws_s3_bucket" "dev" {
  provider = aws.dev
  bucket   = "data-dev"
}

resource "aws_s3_bucket" "staging" {
  provider = aws.staging
  bucket   = "data-staging"
}

resource "aws_s3_bucket" "prod" {
  provider = aws.prod
  bucket   = "data-prod"
}
```

**Advantages:**

- Secure cross-account access
- Audit trail (CloudTrail shows assume role actions)
- Temporary credentials
- External ID prevents confused deputy problem
- Centralized credential management


### Method 6: Web Identity Token (OIDC) for CI/CD (Modern Approach)

Web identity federation eliminates long-lived credentials in CI/CD pipelines:

**GitHub Actions Example:**

```hcl
# Create IAM role for GitHub Actions OIDC
resource "aws_iam_role" "github_actions" {
  name = "github-actions-terraform-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
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
          "token.actions.githubusercontent.com:sub" = "repo:myorg/myrepo:*"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "github_actions" {
  role       = aws_iam_role.github_actions.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}
```

```yaml
# .github/workflows/terraform.yml
name: Terraform Deploy

on:
  push:
    branches: [main]

permissions:
  id-token: write  # Required for OIDC
  contents: read

jobs:
  terraform:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-actions-terraform-role
          aws-region: us-east-1
          
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        
      - name: Terraform Init
        run: terraform init
        
      - name: Terraform Plan
        run: terraform plan
        
      - name: Terraform Apply
        run: terraform apply -auto-approve
```

```hcl
# provider.tf - Uses web identity token from GitHub Actions
provider "aws" {
  region = "us-east-1"
  # Credentials provided by GitHub Actions OIDC
}
```

**Advantages:**

- No long-lived credentials
- Automatic token refresh
- Audit trail with OIDC subject
- Repository-specific access
- Industry best practice for CI/CD


### Method 7: AWS SSO (IAM Identity Center) for Enterprise

AWS SSO provides centralized identity management for large organizations:

```bash
# Configure AWS SSO
aws configure sso

# Prompts:
# SSO start URL: https://mycompany.awsapps.com/start
# SSO Region: us-east-1
# Account: 123456789012
# Role: PowerUserAccess
# CLI default client Region: us-east-1
# CLI profile name: my-sso-profile
```

```bash
# ~/.aws/config
[profile my-sso-profile]
sso_start_url = https://mycompany.awsapps.com/start
sso_region = us-east-1
sso_account_id = 123456789012
sso_role_name = PowerUserAccess
region = us-east-1
output = json
```

```bash
# Login via SSO
aws sso login --profile my-sso-profile

# Run Terraform with SSO profile
export AWS_PROFILE=my-sso-profile
terraform plan
terraform apply
```

```hcl
# provider.tf
provider "aws" {
  region  = "us-east-1"
  profile = "my-sso-profile"  # Uses SSO credentials
}
```

**Advantages:**

- Centralized identity management
- Short-lived credentials (refreshed automatically)
- MFA enforcement
- Integration with corporate identity providers
- Role-based access across multiple accounts


## Advanced Provider Configuration

### Custom Endpoints for Testing

```hcl
# provider.tf - LocalStack for local testing
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  
  endpoints {
    s3             = "http://localhost:4566"
    dynamodb       = "http://localhost:4566"
    lambda         = "http://localhost:4566"
    ec2            = "http://localhost:4566"
    iam            = "http://localhost:4566"
    sts            = "http://localhost:4566"
    cloudwatch     = "http://localhost:4566"
    cloudformation = "http://localhost:4566"
  }
}

# All resources now target LocalStack instead of AWS
resource "aws_s3_bucket" "test" {
  bucket = "test-bucket"
  # Created in LocalStack on http://localhost:4566
}
```


### Ignore Tags for Autoscaling/External Systems

```hcl
provider "aws" {
  region = "us-east-1"
  
  # Ignore tags added by external systems
  ignore_tags {
    keys = [
      "aws:autoscaling:groupName",
      "aws:cloudformation:stack-name",
      "kubernetes.io/cluster/*",
    ]
    
    key_prefixes = [
      "aws:",
      "k8s.io/",
    ]
  }
  
  default_tags {
    tags = {
      ManagedBy = "Terraform"
    }
  }
}

# Terraform won't detect drift on ignored tags
resource "aws_instance" "web" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"
  
  # Auto Scaling Group may add aws:autoscaling:groupName
  # Terraform ignores it - no drift detected
}
```


### Retry and Timeout Configuration

```hcl
provider "aws" {
  region = "us-east-1"
  
  # Increase retries for API throttling
  max_retries = 10  # Default is 25
  
  # Custom retry behavior
  retry_mode = "adaptive"  # Options: legacy, standard, adaptive
  
  # HTTP client configuration
  http_proxy = "http://proxy.company.com:8080"
  
  # Shared credentials file location (non-default)
  shared_credentials_files = [
    "/custom/path/.aws/credentials"
  ]
  
  shared_config_files = [
    "/custom/path/.aws/config"
  ]
}
```


### Provider Configuration with Sensitive Values

```hcl
# variables.tf
variable "assume_role_arn" {
  description = "ARN of role to assume"
  type        = string
  sensitive   = true  # Hide in plan output
}

variable "external_id" {
  description = "External ID for assume role"
  type        = string
  sensitive   = true
}

# provider.tf
provider "aws" {
  region = var.aws_region
  
  assume_role {
    role_arn    = var.assume_role_arn
    external_id = var.external_id
    
    # Session tags for attribution
    tags = {
      Operator    = "Terraform"
      Environment = var.environment
    }
    
    # Transitive tag keys
    transitive_tag_keys = ["Environment"]
  }
}
```


## Multi-Region Deployment Patterns

### Pattern 1: Primary-Backup Architecture

```hcl
# providers.tf
provider "aws" {
  alias  = "primary"
  region = "us-east-1"
  
  default_tags {
    tags = {
      Region      = "Primary"
      Environment = var.environment
    }
  }
}

provider "aws" {
  alias  = "backup"
  region = "us-west-2"
  
  default_tags {
    tags = {
      Region      = "Backup"
      Environment = var.environment
    }
  }
}

# Primary region resources
module "primary_infrastructure" {
  source = "./modules/infrastructure"
  
  providers = {
    aws = aws.primary
  }
  
  is_primary = true
  environment = var.environment
}

# Backup region resources
module "backup_infrastructure" {
  source = "./modules/infrastructure"
  
  providers = {
    aws = aws.backup
  }
  
  is_primary = false
  environment = var.environment
}

# Cross-region replication
resource "aws_s3_bucket_replication_configuration" "primary_to_backup" {
  provider = aws.primary
  
  bucket = module.primary_infrastructure.data_bucket_id
  role   = aws_iam_role.replication.arn
  
  rule {
    id     = "replicate-all"
    status = "Enabled"
    
    destination {
      bucket        = module.backup_infrastructure.data_bucket_arn
      storage_class = "STANDARD_IA"
      
      # Replicate to backup region
      replication_time {
        status = "Enabled"
        time {
          minutes = 15
        }
      }
    }
  }
}
```


### Pattern 2: Active-Active Multi-Region

```hcl
# variables.tf
variable "regions" {
  description = "Regions for active-active deployment"
  type        = list(string)
  default     = ["us-east-1", "us-west-2", "eu-west-1"]
}

# providers.tf - Dynamic provider generation
locals {
  # Create provider configuration for each region
  region_providers = {
    for region in var.regions : region => {
      region = region
      alias  = replace(region, "-", "_")
    }
  }
}

# Note: Dynamic providers not directly supported, use explicit definitions
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

provider "aws" {
  alias  = "us_west_2"
  region = "us-west-2"
}

provider "aws" {
  alias  = "eu_west_1"
  region = "eu-west-1"
}

# Deploy to all regions
module "us_east_1" {
  source = "./modules/regional-stack"
  
  providers = {
    aws = aws.us_east_1
  }
  
  region = "us-east-1"
}

module "us_west_2" {
  source = "./modules/regional-stack"
  
  providers = {
    aws = aws.us_west_2
  }
  
  region = "us-west-2"
}

module "eu_west_1" {
  source = "./modules/regional-stack"
  
  providers = {
    aws = aws.eu_west_1
  }
  
  region = "eu-west-1"
}

# Global routing with Route 53
resource "aws_route53_zone" "main" {
  name = "example.com"
}

resource "aws_route53_record" "api" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "api.example.com"
  type    = "A"
  
  # Geolocation routing to nearest region
  geolocation_routing_policy {
    continent = "NA"
  }
  
  alias {
    name                   = module.us_east_1.alb_dns_name
    zone_id                = module.us_east_1.alb_zone_id
    evaluate_target_health = true
  }
  
  set_identifier = "us-east-1"
}
```


## ⚠️ Common Pitfalls

### Pitfall 1: Hardcoding AWS Account IDs

**❌ PROBLEM:**

```hcl
provider "aws" {
  region = "us-east-1"
  
  assume_role {
    role_arn = "arn:aws:iam::123456789012:role/terraform-role"  # Hardcoded!
  }
}

# Breaks when:
# - Deploying to different account
# - Testing in sandbox account
# - Multi-account strategies
```

**✅ SOLUTION:**

```hcl
# variables.tf
variable "target_account_id" {
  description = "AWS account ID to deploy to"
  type        = string
  
  validation {
    condition     = can(regex("^[0-9]{12}$", var.target_account_id))
    error_message = "Account ID must be 12 digits."
  }
}

# provider.tf
data "aws_caller_identity" "current" {}

locals {
  role_arn = "arn:aws:iam::${var.target_account_id}:role/terraform-role"
}

provider "aws" {
  region = var.aws_region
  
  assume_role {
    role_arn = local.role_arn
  }
}

# Verify correct account
resource "null_resource" "account_check" {
  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.current.account_id == var.target_account_id
      error_message = "Deploying to wrong account! Expected ${var.target_account_id}, got ${data.aws_caller_identity.current.account_id}"
    }
  }
}
```


### Pitfall 2: Not Using Provider Aliases for Multi-Account

**❌ PROBLEM:**

```hcl
# Trying to manage multiple accounts without aliases
provider "aws" {
  region = "us-east-1"
  # How do we target different accounts?
}

resource "aws_s3_bucket" "dev" {
  bucket = "dev-data"
  # Which account does this go to?
}

resource "aws_s3_bucket" "prod" {
  bucket = "prod-data"
  # How to separate from dev?
}
```

**✅ SOLUTION:**

```hcl
provider "aws" {
  alias  = "dev"
  region = "us-east-1"
  
  assume_role {
    role_arn = "arn:aws:iam::${var.dev_account_id}:role/terraform-role"
  }
}

provider "aws" {
  alias  = "prod"
  region = "us-east-1"
  
  assume_role {
    role_arn = "arn:aws:iam::${var.prod_account_id}:role/terraform-role"
  }
}

resource "aws_s3_bucket" "dev" {
  provider = aws.dev
  bucket   = "dev-data"
}

resource "aws_s3_bucket" "prod" {
  provider = aws.prod
  bucket   = "prod-data"
}
```


### Pitfall 3: Mixing Authentication Methods

**❌ PROBLEM:**

```hcl
provider "aws" {
  region     = "us-east-1"
  access_key = var.aws_access_key  # Explicit credentials
  secret_key = var.aws_secret_key
  
  assume_role {
    role_arn = var.role_arn  # Also trying to assume role!
  }
}

# Error: Cannot use both static credentials and assume_role
```

**✅ SOLUTION:**

```hcl
# Choose ONE authentication method
# Option 1: Static credentials (local dev only)
provider "aws" {
  region     = "us-east-1"
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}

# Option 2: Assume role (recommended)
provider "aws" {
  region = "us-east-1"
  # Base credentials from environment/profile
  
  assume_role {
    role_arn = var.role_arn
  }
}

# Option 3: Profile (multi-account)
provider "aws" {
  region  = "us-east-1"
  profile = var.aws_profile
}
```


### Pitfall 4: Not Handling Provider Version Upgrades

**❌ PROBLEM:**

```hcl
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"  # Too permissive - allows 6.0 upgrade
    }
  }
}

# Team member runs terraform init -upgrade
# Provider upgrades from 5.x to 6.0
# Breaking changes cause failures
```

**✅ SOLUTION:**

```hcl
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"  # Locks to 5.x, prevents 6.0
    }
  }
}

# When ready to upgrade to 6.0:
# 1. Read upgrade guide: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/guides/version-6-upgrade
# 2. Test in dev environment
# 3. Update version constraint
# 4. Run terraform init -upgrade
# 5. Fix any breaking changes
# 6. Update lock file
# 7. Promote to production
```


### Pitfall 5: Forgetting to Set Default Tags

**❌ PROBLEM:**

```hcl
provider "aws" {
  region = "us-east-1"
  # No default_tags
}

# Must add tags to every resource manually
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  
  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
    Owner       = var.team_name
    CostCenter  = var.cost_center
  }
}

resource "aws_subnet" "public" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
  
  tags = {
    Environment = var.environment  # Repeated!
    ManagedBy   = "Terraform"      # Repeated!
    Owner       = var.team_name    # Repeated!
    CostCenter  = var.cost_center  # Repeated!
  }
}

# 100+ resources = 100+ duplicated tags blocks
```

**✅ SOLUTION:**

```hcl
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = var.team_name
      CostCenter  = var.cost_center
      Compliance  = "SOC2"
    }
  }
}

# No tags blocks needed - automatically inherited
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "public" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
  
  # Add resource-specific tags if needed
  tags = {
    Name = "public-subnet"
    Type = "Public"
  }
  # Final tags: all defaults + Name + Type
}
```


### Pitfall 6: Not Validating AssumeRole External ID

**❌ PROBLEM:**

```hcl
# Production account role
resource "aws_iam_role" "terraform" {
  assume_role_policy = jsonencode({
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${var.management_account}:root"
      }
      Action = "sts:AssumeRole"
      # No external ID - vulnerable to confused deputy attack!
    }]
  })
}
```

**✅ SOLUTION:**

```hcl
# Production account role with external ID
resource "aws_iam_role" "terraform" {
  assume_role_policy = jsonencode({
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${var.management_account}:user/terraform-user"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "sts:ExternalId" = var.external_id  # Required!
        }
      }
    }]
  })
}

# Management account provider
provider "aws" {
  alias = "prod"
  
  assume_role {
    role_arn    = aws_iam_role.terraform.arn
    external_id = var.external_id  # Must match
  }
}
```


### Pitfall 7: Provider Configuration in Wrong File

**❌ PROBLEM:**

```hcl
# main.tf - provider mixed with resources
provider "aws" {
  region = "us-east-1"
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

provider "aws" {
  alias  = "secondary"
  region = "us-west-2"
}

resource "aws_s3_bucket" "backup" {
  provider = aws.secondary
  bucket   = "backup"
}

# Hard to find provider configurations
# Not following standard structure
```

**✅ SOLUTION:**

```plaintext
project/
├── versions.tf      # Terraform and provider versions
├── providers.tf     # Provider configurations
├── variables.tf     # Input variables
├── main.tf          # Resource definitions
├── outputs.tf       # Output values
└── backend.tf       # Backend configuration
```

```hcl
# versions.tf
terraform {
  required_version = ">= 1.15.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# providers.tf
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = var.default_tags
  }
}

provider "aws" {
  alias  = "secondary"
  region = var.secondary_region
  
  default_tags {
    tags = var.default_tags
  }
}

# main.tf
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}
```


### Pitfall 8: Not Testing Provider Configuration

**❌ PROBLEM:**

```bash
# Write provider config, immediately apply
terraform init
terraform apply  # Hope it works!
```

**✅ SOLUTION:**

```bash
# Validate provider configuration first
terraform init

# Verify authentication
terraform console
> data.aws_caller_identity.current.account_id
"123456789012"
> data.aws_region.current.name
"us-east-1"

# Test with simple data source
cat > test.tf << 'EOF'
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "region" {
  value = data.aws_region.current.name
}
EOF

terraform plan
terraform apply

# Verify outputs match expectations
# Then proceed with real infrastructure
```


### Pitfall 9: Session Duration Too Short

**❌ PROBLEM:**

```hcl
provider "aws" {
  assume_role {
    role_arn = var.role_arn
    # Default duration: 1 hour
  }
}

# Long-running terraform apply (e.g., RDS creation)
# Session expires after 1 hour
# Error: "ExpiredToken: The security token included in the request is expired"
```

**✅ SOLUTION:**

```hcl
provider "aws" {
  assume_role {
    role_arn         = var.role_arn
    session_name     = "terraform-${var.environment}"
    duration_seconds = 10800  # 3 hours (max depends on role config)
  }
}

# Also increase role max session duration
resource "aws_iam_role" "terraform" {
  name                 = "terraform-role"
  max_session_duration = 43200  # 12 hours maximum
  
  assume_role_policy = jsonencode({
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = var.management_account_arn
      }
      Action = "sts:AssumeRole"
    }]
  })
}
```


### Pitfall 10: Ignoring Terraform Warnings

**❌ PROBLEM:**

```bash
terraform init

Warning: Additional provider information from registry

The remote registry returned warnings for registry.terraform.io/hashicorp/aws:
- For users on Terraform 0.13 or greater, this provider has moved to hashicorp/aws. Please update your source in required_providers.

# Ignoring warnings leads to future problems
```

**✅ SOLUTION:**

```bash
# Always read and address warnings

# Update provider source
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"  # Correct source
      version = "~> 6.0"
    }
  }
}

# Re-initialize
terraform init
```


## 💡 Expert Tips from the Field

1. **"Always use assume_role for production deployments"** - Even if deploying from same account, assume a role with specific permissions. Creates audit trail and enables permission boundaries.
2. **"Set up AWS CloudTrail filtering for AssumeRole events"** - Monitor who's assuming Terraform roles: `eventName = "AssumeRole" AND requestParameters.roleSessionName = "terraform-*"`
3. **"Use external_id even for single-tenant scenarios"** - Future-proofs your security model. When you eventually need multi-account, it's already in place.
4. **"Provider alias naming convention: use underscores, not dashes"** - `aws.us_east_1` works, `aws.us-east-1` breaks. Match AWS region format converted to valid identifiers.
5. **"Default tags save 1000+ lines of code in large projects"** - Production infrastructure with 200 resources = 200 tags blocks eliminated. One-time provider config vs. repetitive resource tags.
6. **"Test authentication before running apply"** - Use `terraform console` to verify `data.aws_caller_identity.current` returns expected account. Prevents deploying to wrong account.
7. **"Lock provider versions in terraform.lock.hcl"** - Commit lock file to Git. Ensures team uses identical provider versions. Run `terraform init -upgrade` deliberately, not accidentally.
8. **"Use web identity (OIDC) for all CI/CD pipelines"** - GitHub Actions, GitLab CI, CircleCI all support OIDC. Zero long-lived credentials = massive security win.
9. **"Configure retry_mode = 'adaptive' for large deployments"** - AWS API throttling is real. Adaptive mode intelligently backs off and retries, preventing sporadic failures.
10. **"Provider configuration belongs in providers.tf, always"** - Standard file structure makes projects instantly understandable. Don't mix providers in main.tf.
11. **"Use session_name with meaningful identifiers"** - `session_name = "terraform-${var.environment}-${var.project}"` creates audit trail. CloudTrail shows exactly what Terraform session made changes.
12. **"Enable MFA for production assume roles"** - Add MFA requirement in IAM role trust policy: `"aws:MultiFactorAuthPresent": "true"` in Condition block.
13. **"Use AWS_PROFILE for local development, OIDC for CI/CD"** - Developer workflow: `export AWS_PROFILE=dev`. CI/CD: Web identity federation. Never mix the two.
14. **"Test provider config changes in terraform console first"** - Before modifying provider, test authentication: `terraform console`, then `data.aws_caller_identity.current`. Instant feedback.
15. **"Document which authentication method your project uses"** - Add to README.md: "This project uses AssumeRole with profile 'production'". Saves new team members hours of confusion.
16. **"Use separate state files per AWS account"** - Don't mix dev and prod resources in same state. Backend key: `${account_id}/${environment}/terraform.tfstate`
17. **"Set ignored_tags for third-party tool compatibility"** - Kubernetes, Auto Scaling, CloudFormation all add tags. Use ignore_tags to prevent constant drift detection.
18. **"Version constraint ~> 6.0 allows automatic security patches"** - Gets 6.0.1, 6.1.0 automatically. Blocks 7.0.0. Balances security updates with stability.
19. **"Use AWS Provider 6.0's region injection for cost savings"** - Single provider instance uses less memory. Matters at scale (100+ resources in multiple regions).
20. **"Always specify required_version AND required_providers"** - Terraform version AND provider version. Both critical for reproducible deployments. Too many projects forget provider version.

## 🎯 Practical Exercises

### Exercise 1: Multi-Account Deployment with AssumeRole

**Difficulty:** Advanced
**Time:** 45 minutes
**Objective:** Configure Terraform to deploy resources to three different AWS accounts using AssumeRole

**Prerequisites:**

- Three AWS accounts (or sandbox accounts)
- IAM user with AssumeRole permissions in management account
- Administrative access to create IAM roles in target accounts

**Steps:**

1. Set up IAM roles in each target account:
```hcl
# In each target account (Dev: 111111111111, Staging: 222222222222, Prod: 333333333333)
# deploy-roles/main.tf

variable "management_account_id" {
  default = "000000000000"  # Your management account ID
}

variable "environment" {
  description = "Environment name"
  type        = string
}

resource "aws_iam_role" "terraform_deployment" {
  name = "terraform-deployment-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${var.management_account_id}:user/terraform-user"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "sts:ExternalId" = "terraform-external-id-${var.environment}"
        }
      }
    }]
  })
  
  tags = {
    Environment = var.environment
    Purpose     = "Terraform"
  }
}

resource "aws_iam_role_policy_attachment" "terraform_deployment" {
  role       = aws_iam_role.terraform_deployment.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

output "role_arn" {
  value = aws_iam_role.terraform_deployment.arn
}
```

2. Deploy roles to each account:
```bash
# Dev account
cd deploy-roles
terraform init
terraform apply -var="environment=dev" -var="management_account_id=000000000000"

# Staging account  
terraform apply -var="environment=staging" -var="management_account_id=000000000000"

# Prod account
terraform apply -var="environment=prod" -var="management_account_id=000000000000"
```

3. Configure multi-account deployment:
```hcl
# multi-account-deploy/variables.tf
variable "account_roles" {
  description = "Role ARNs for each account"
  type        = map(string)
  default = {
    dev     = "arn:aws:iam::111111111111:role/terraform-deployment-role"
    staging = "arn:aws:iam::222222222222:role/terraform-deployment-role"
    prod    = "arn:aws:iam::333333333333:role/terraform-deployment-role"
  }
}

variable "external_ids" {
  description = "External IDs for each environment"
  type        = map(string)
  sensitive   = true
  default = {
    dev     = "terraform-external-id-dev"
    staging = "terraform-external-id-staging"
    prod    = "terraform-external-id-prod"
  }
}

# multi-account-deploy/providers.tf
provider "aws" {
  alias  = "dev"
  region = "us-east-1"
  
  assume_role {
    role_arn     = var.account_roles["dev"]
    session_name = "terraform-dev"
    external_id  = var.external_ids["dev"]
  }
}

provider "aws" {
  alias  = "staging"
  region = "us-east-1"
  
  assume_role {
    role_arn     = var.account_roles["staging"]
    session_name = "terraform-staging"
    external_id  = var.external_ids["staging"]
  }
}

provider "aws" {
  alias  = "prod"
  region = "us-east-1"
  
  assume_role {
    role_arn     = var.account_roles["prod"]
    session_name = "terraform-prod"
    external_id  = var.external_ids["prod"]
  }
}

# multi-account-deploy/main.tf
resource "aws_s3_bucket" "dev" {
  provider = aws.dev
  bucket   = "my-app-dev-${random_id.dev.hex}"
}

resource "aws_s3_bucket" "staging" {
  provider = aws.staging
  bucket   = "my-app-staging-${random_id.staging.hex}"
}

resource "aws_s3_bucket" "prod" {
  provider = aws.prod
  bucket   = "my-app-prod-${random_id.prod.hex}"
}

resource "random_id" "dev" {
  byte_length = 4
}

resource "random_id" "staging" {
  byte_length = 4
}

resource "random_id" "prod" {
  byte_length = 4
}
```

4. Deploy to all accounts:
```bash
cd multi-account-deploy
terraform init
terraform plan
terraform apply
```

**Validation:**

- Verify buckets created in all three accounts
- Check CloudTrail for AssumeRole events
- Confirm session names appear in audit logs

**Challenge:** Add a precondition check that verifies you're deploying to the correct account ID before creating resources.

<details>
<summary><b>Solution: Account ID Verification</b></summary>

```hcl
variable "expected_account_ids" {
  type = map(string)
  default = {
    dev     = "111111111111"
    staging = "222222222222"
    prod    = "333333333333"
  }
}

data "aws_caller_identity" "dev" {
  provider = aws.dev
}

data "aws_caller_identity" "staging" {
  provider = aws.staging
}

data "aws_caller_identity" "prod" {
  provider = aws.prod
}

resource "null_resource" "account_check" {
  lifecycle {
    precondition {
      condition = (
        data.aws_caller_identity.dev.account_id == var.expected_account_ids["dev"] &&
        data.aws_caller_identity.staging.account_id == var.expected_account_ids["staging"] &&
        data.aws_caller_identity.prod.account_id == var.expected_account_ids["prod"]
      )
      error_message = "Account ID mismatch detected! Review provider configurations."
    }
  }
}
```
</details>

### Exercise 2: GitHub Actions OIDC Integration

**Difficulty:** Advanced
**Time:** 40 minutes
**Objective:** Set up passwordless authentication from GitHub Actions to AWS using OIDC

**Prerequisites:**

- GitHub repository with admin access
- AWS account with IAM permissions
- Basic GitHub Actions knowledge

**Steps:**

1. Create OIDC provider in AWS:
```hcl
# github-oidc/main.tf
resource "aws_iam_openid_connect_provider" "github_actions" {
  url = "https://token.actions.githubusercontent.com"
  
  client_id_list = ["sts.amazonaws.com"]
  
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1"
  ]
  
  tags = {
    Name = "GitHub Actions OIDC"
  }
}

resource "aws_iam_role" "github_actions_terraform" {
  name = "github-actions-terraform-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github_actions.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:YOUR_ORG/YOUR_REPO:*"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "github_actions_terraform" {
  role       = aws_iam_role.github_actions_terraform.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

output "role_arn" {
  value = aws_iam_role.github_actions_terraform.arn
}
```

2. Deploy OIDC configuration:
```bash
cd github-oidc
terraform init
terraform apply
# Note the role_arn output
```

3. Create GitHub Actions workflow:
```yaml
# .github/workflows/terraform.yml
name: Terraform Deployment

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  id-token: write  # Required for OIDC
  contents: read
  pull-requests: write

jobs:
  terraform:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1
          role-session-name: GitHubActions-${{ github.run_id }}
          
      - name: Verify AWS Identity
        run: |
          aws sts get-caller-identity
          
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.15.0
          
      - name: Terraform Init
        run: terraform init
        
      - name: Terraform Format Check
        run: terraform fmt -check -recursive
        
      - name: Terraform Validate
        run: terraform validate
        
      - name: Terraform Plan
        id: plan
        run: terraform plan -no-color -out=tfplan
        continue-on-error: true
        
      - name: Comment PR with Plan
        uses: actions/github-script@v7
        if: github.event_name == 'pull_request'
        with:
          script: |
            const output = `#### Terraform Plan 📖
            \`\`\`
            ${{ steps.plan.outputs.stdout }}
            \`\`\`
            `;
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: output
            });
            
      - name: Terraform Apply
        if: github.ref == 'refs/heads/main' && github.event_name == 'push'
        run: terraform apply -auto-approve tfplan
```

4. Add role ARN to GitHub Secrets:
    - Go to repository Settings → Secrets and variables → Actions
    - Add secret: `AWS_ROLE_ARN` = (role ARN from step 2)
5. Test the workflow:
```bash
git add .github/workflows/terraform.yml
git commit -m "Add OIDC-based Terraform workflow"
git push origin main
```

**Validation:**

- Check GitHub Actions runs successfully
- Verify no AWS credentials in logs
- Confirm temporary credentials used (check CloudTrail)

**Challenge:** Modify the workflow to deploy to different AWS accounts based on the branch name (main → prod, develop → dev).

### Exercise 3: Default Tags Implementation

**Difficulty:** Beginner
**Time:** 20 minutes
**Objective:** Implement provider-level default tags and verify they're applied to all resources

**Steps:**

1. Create configuration without default tags:
```hcl
# before/provider.tf
provider "aws" {
  region = "us-east-1"
}

# before/main.tf
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  
  tags = {
    Name        = "main-vpc"
    Environment = "dev"
    ManagedBy   = "Terraform"
    Owner       = "DevOps Team"
    CostCenter  = "Engineering"
  }
}

resource "aws_subnet" "public" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
  
  tags = {
    Name        = "public-subnet"
    Environment = "dev"
    ManagedBy   = "Terraform"
    Owner       = "DevOps Team"
    CostCenter  = "Engineering"
  }
}

resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = aws_vpc.main.id
  
  tags = {
    Name        = "web-sg"
    Environment = "dev"
    ManagedBy   = "Terraform"
    Owner       = "DevOps Team"
    CostCenter  = "Engineering"
  }
}

# 5 identical tags repeated 3 times = 15 lines of duplication!
```

2. Count lines of tag duplication:
```bash
cd before
grep -r "tags = {" . | wc -l
# Shows repetitive tags
```

3. Refactor with default_tags:
```hcl
# after/provider.tf
provider "aws" {
  region = "us-east-1"
  
  default_tags {
    tags = {
      Environment = "dev"
      ManagedBy   = "Terraform"
      Owner       = "DevOps Team"
      CostCenter  = "Engineering"
      Compliance  = "Internal"
    }
  }
}

# after/main.tf
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  
  tags = {
    Name = "main-vpc"
  }
}

resource "aws_subnet" "public" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
  
  tags = {
    Name = "public-subnet"
  }
}

resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = aws_vpc.main.id
  
  tags = {
    Name = "web-sg"
  }
}

# Eliminated 12 lines of duplication!
# All resources still have 6 tags each
```

4. Deploy and verify:
```bash
cd after
terraform init
terraform apply

# Verify tags in AWS Console
aws ec2 describe-vpcs --filters "Name=tag:Name,Values=main-vpc" --query 'Vpcs[^0].Tags'
```

**Expected Output:**

```json
[
  {"Key": "Name", "Value": "main-vpc"},
  {"Key": "Environment", "Value": "dev"},
  {"Key": "ManagedBy", "Value": "Terraform"},
  {"Key": "Owner", "Value": "DevOps Team"},
  {"Key": "CostCenter", "Value": "Engineering"},
  {"Key": "Compliance", "Value": "Internal"}
]
```

**Challenge:** Calculate lines of code saved in a project with 100 resources using default_tags vs. manual tags.

### Exercise 4: Multi-Region Deployment Pattern

**Difficulty:** Intermediate
**Time:** 35 minutes
**Objective:** Deploy identical infrastructure to three regions with cross-region replication

**Steps:**

1. Create module for regional deployment:
```hcl
# modules/regional-infrastructure/variables.tf
variable "region" {
  description = "AWS region"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
}

# modules/regional-infrastructure/main.tf
resource "aws_vpc" "main" {
  cidr_block = var.vpc_cidr
  
  tags = {
    Name   = "vpc-${var.region}"
    Region = var.region
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "data-${var.region}-${random_id.suffix.hex}"
}

resource "random_id" "suffix" {
  byte_length = 4
}

# modules/regional-infrastructure/outputs.tf
output "vpc_id" {
  value = aws_vpc.main.id
}

output "bucket_id" {
  value = aws_s3_bucket.data.id
}

output "bucket_arn" {
  value = aws_s3_bucket.data.arn
}
```

2. Deploy to multiple regions:
```hcl
# main.tf
provider "aws" {
  alias  = "us_east"
  region = "us-east-1"
}

provider "aws" {
  alias  = "us_west"
  region = "us-west-2"
}

provider "aws" {
  alias  = "eu_west"
  region = "eu-west-1"
}

module "us_east" {
  source = "./modules/regional-infrastructure"
  
  providers = {
    aws = aws.us_east
  }
  
  region   = "us-east-1"
  vpc_cidr = "10.0.0.0/16"
}

module "us_west" {
  source = "./modules/regional-infrastructure"
  
  providers = {
    aws = aws.us_west
  }
  
  region   = "us-west-2"
  vpc_cidr = "10.1.0.0/16"
}

module "eu_west" {
  source = "./modules/regional-infrastructure"
  
  providers = {
    aws = aws.eu_west
  }
  
  region   = "eu-west-1"
  vpc_cidr = "10.2.0.0/16"
}
```

3. Add cross-region S3 replication:
```hcl
# Enable versioning (required for replication)
resource "aws_s3_bucket_versioning" "us_east" {
  provider = aws.us_east
  bucket   = module.us_east.bucket_id
  
  versioning_configuration {
    status = "Enabled"
  }
}

# IAM role for replication
resource "aws_iam_role" "replication" {
  name = "s3-replication-role"
  
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
}

# Replication configuration
resource "aws_s3_bucket_replication_configuration" "us_east_to_west" {
  provider = aws.us_east
  
  bucket = module.us_east.bucket_id
  role   = aws_iam_role.replication.arn
  
  rule {
    id     = "replicate-to-west"
    status = "Enabled"
    
    destination {
      bucket        = module.us_west.bucket_arn
      storage_class = "STANDARD_IA"
    }
  }
}
```

4. Deploy and verify:
```bash
terraform init
terraform apply

# Verify resources in all regions
aws s3 ls --region us-east-1 | grep data-us-east-1
aws s3 ls --region us-west-2 | grep data-us-west-2
aws s3 ls --region eu-west-1 | grep data-eu-west-1
```

**Challenge:** Add Route 53 geolocation routing to direct users to nearest region automatically.

### Exercise 5: Provider Configuration Testing

**Difficulty:** Beginner
**Time:** 15 minutes
**Objective:** Validate provider authentication before deploying infrastructure

**Steps:**

1. Create test configuration:
```hcl
# test-auth/provider.tf
provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}

# test-auth/variables.tf
variable "aws_region" {
  default = "us-east-1"
}

variable "aws_profile" {
  default = "default"
}

variable "expected_account_id" {
  description = "Expected AWS account ID"
  type        = string
}

# test-auth/main.tf
data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

# test-auth/outputs.tf
output "authenticated_as" {
  value = {
    account_id = data.aws_caller_identity.current.account_id
    arn        = data.aws_caller_identity.current.arn
    user_id    = data.aws_caller_identity.current.user_id
  }
}

output "region_info" {
  value = {
    name               = data.aws_region.current.name
    endpoint           = data.aws_region.current.endpoint
    availability_zones = data.aws_availability_zones.available.names
  }
}

# test-auth/checks.tf
resource "null_resource" "account_verification" {
  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.current.account_id == var.expected_account_id
      error_message = "WRONG ACCOUNT! Expected ${var.expected_account_id}, got ${data.aws_caller_identity.current.account_id}"
    }
  }
}
```

2. Run authentication test:
```bash
cd test-auth
terraform init

# Test with correct account
terraform plan -var="expected_account_id=123456789012"

# Test with wrong account (should fail)
terraform plan -var="expected_account_id=999999999999"
```

3. Create reusable test script:
```bash
#!/bin/bash
# test-provider.sh

echo "=== Testing AWS Provider Authentication ==="

# Check AWS CLI is configured
if ! aws sts get-caller-identity > /dev/null 2>&1; then
  echo "❌ AWS CLI not configured or credentials invalid"
  exit 1
fi

echo "✅ AWS CLI authenticated"

# Get account info
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region)

echo "Account ID: $ACCOUNT_ID"
echo "Region: $REGION"

# Test Terraform provider
cd test-auth
terraform init > /dev/null 2>&1
terraform plan -var="expected_account_id=$ACCOUNT_ID" > /dev/null 2>&1

if [ $? -eq 0 ]; then
  echo "✅ Terraform provider authenticated successfully"
else
  echo "❌ Terraform provider authentication failed"
  exit 1
fi

echo "=== Authentication test complete ==="
```

**Validation:** Script should pass when AWS credentials are valid, fail when invalid.

**Challenge:** Extend the script to test multiple AWS profiles and report which ones are configured correctly.

## Visual Diagrams

### Provider Authentication Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    Terraform Init                            │
│  • Reads provider configuration                              │
│  • Downloads AWS Provider plugin                             │
│  • Initializes backend                                       │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│              Provider Authentication                         │
│  Priority order:                                             │
│  1. Static credentials (access_key/secret_key) ❌            │
│  2. Environment variables (AWS_ACCESS_KEY_ID) ✅             │
│  3. Shared credentials file (~/.aws/credentials) ✅          │
│  4. IAM instance profile (EC2/ECS) ✅                        │
│  5. ECS container credentials                                │
│  6. Web identity token (OIDC) ✅                             │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│                  Assume Role (Optional)                      │
│  • Base credentials → STS AssumeRole API                     │
│  • Returns temporary credentials                             │
│  • Duration: 15 min - 12 hours                               │
│  • Session name for audit trail                              │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│                    AWS API Calls                             │
│  • Create/Read/Update/Delete resources                       │
│  • Uses authenticated credentials                            │
│  • Logged in CloudTrail                                      │
└─────────────────────────────────────────────────────────────┘
```


### Cross-Account AssumeRole Pattern

```
Management Account (111111111111)          Production Account (222222222222)
─────────────────────────────────          ──────────────────────────────────

┌──────────────────────┐                   ┌──────────────────────────┐
│   IAM User           │                   │   IAM Role               │
│  terraform-user      │                   │  terraform-deploy-role   │
│                      │                   │                          │
│  Permissions:        │                   │  Trust Policy:           │
│  - sts:AssumeRole    │──────────────────▶│  Principal:              │
│                      │   1. AssumeRole   │   AWS: arn:...:user/     │
└──────────────────────┘      Request      │        terraform-user    │
                                            │  Condition:              │
                                            │   ExternalId: "xyz123"   │
                                            │                          │
                                            │  Permissions:            │
                                            │  - PowerUserAccess       │
                                            └────────┬─────────────────┘
                                                     │
                                            2. Return temp credentials
                                                     │
                                                     ▼
┌──────────────────────┐                   ┌──────────────────────────┐
│  Temporary Session   │                   │   AWS Resources          │
│  Credentials         │───────────────────▶│   - VPC                  │
│  - AccessKeyId       │   3. Create/Update │   - EC2                  │
│  - SecretAccessKey   │      Resources     │   - RDS                  │
│  - SessionToken      │                    │   - S3                   │
│  - Expiry: 1-12 hrs  │                    └──────────────────────────┘
└──────────────────────┘

Terraform Configuration:
───────────────────────
provider "aws" {
  region = "us-east-1"
  
  assume_role {
    role_arn    = "arn:aws:iam::222222222222:role/terraform-deploy-role"
    external_id = "xyz123"
  }
}
```


### Multi-Region Provider Configuration (AWS Provider 6.0)

```
OLD APPROACH (Pre-6.0):
───────────────────────

provider "aws" { alias = "us_east", region = "us-east-1" }
provider "aws" { alias = "us_west", region = "us-west-2" }
provider "aws" { alias = "eu_west", region = "eu-west-1" }

Memory: 3 × Provider instances loaded
Config: Must update 3 separate blocks for changes

┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  Provider   │  │  Provider   │  │  Provider   │
│  us-east-1  │  │  us-west-2  │  │  eu-west-1  │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                │                │
       ▼                ▼                ▼
  Resources       Resources        Resources


NEW APPROACH (6.0+):
────────────────────

provider "aws" { region = "us-east-1" }  # Single provider

Memory: 1 × Provider instance
Config: Centralized configuration

         ┌─────────────┐
         │  Provider   │
         │  (default)  │
         └──────┬──────┘
                │
       ┌────────┼────────┐
       │        │        │
       ▼        ▼        ▼
  us-east-1  us-west-2  eu-west-1
  Resources  Resources  Resources
  
Region attribute injected at resource level (automatic in 6.0)
```


## Reference Tables

### Authentication Method Comparison

| Method | Security | Use Case | Credential Rotation | Audit Trail |
| :-- | :-- | :-- | :-- | :-- |
| **Static Credentials** | ❌ Low | Local dev only (discouraged) | Manual | Limited |
| **Environment Variables** | ⚠️ Medium | Local dev, CI/CD | Manual | Limited |
| **Shared Credentials File** | ✅ Medium | Multi-account local dev | Manual | Via CloudTrail |
| **IAM Instance Profile** | ✅ High | EC2/ECS-based deployments | Automatic | Full CloudTrail |
| **AssumeRole** | ✅ High | Cross-account, production | Automatic | Full with session info |
| **Web Identity (OIDC)** | ✅ Very High | Modern CI/CD (GitHub, GitLab) | Automatic | Full with OIDC subject |
| **AWS SSO** | ✅ Very High | Enterprise multi-account | Automatic | Full with SSO user |

### Provider Configuration Parameters

| Parameter | Type | Purpose | Example | Required |
| :-- | :-- | :-- | :-- | :-- |
| `region` | string | Default AWS region | `"us-east-1"` | Yes |
| `access_key` | string | AWS access key (avoid!) | `"AKIA..."` | No |
| `secret_key` | string | AWS secret key (avoid!) | `"wJal..."` | No |
| `profile` | string | AWS CLI profile name | `"production"` | No |
| `assume_role` | block | Cross-account role | See assume_role block | No |
| `default_tags` | block | Tags for all resources | See default_tags block | No |
| `ignore_tags` | block | Tags to ignore | See ignore_tags block | No |
| `max_retries` | number | API retry attempts | `10` | No |
| `endpoints` | block | Custom API endpoints | For LocalStack testing | No |

### assume_role Block Parameters

| Parameter | Type | Purpose | Example |
| :-- | :-- | :-- | :-- |
| `role_arn` | string | ARN of role to assume | `"arn:aws:iam::123456789012:role/terraform-role"` |
| `session_name` | string | Session identifier | `"terraform-prod"` |
| `external_id` | string | Security token | `"unique-external-id-123"` |
| `duration_seconds` | number | Session duration | `3600` (1 hour) |
| `policy` | string | Additional policy JSON | Session-specific restrictions |
| `tags` | map | Session tags | `{Environment = "prod"}` |

### AWS Provider Version Compatibility

| Terraform Version | AWS Provider Version | Notable Features |
| :-- | :-- | :-- |
| >= 1.15.0 | ~> 6.0 | Multi-region support, enhanced default_tags |
| >= 1.5.0 | ~> 5.0 | Import blocks, provider config checks |
| >= 1.0.0 | ~> 4.0 | AWS SDK v2, performance improvements |
| >= 0.15.0 | ~> 3.0 | Provider registry support |
| >= 0.13.0 | ~> 2.0 | Required providers block |

### Region Codes Quick Reference

| Region Code | Location | Use Case |
| :-- | :-- | :-- |
| `us-east-1` | N. Virginia | US East Coast, cheapest |
| `us-east-2` | Ohio | US East Coast, lower latency for Midwest |
| `us-west-1` | N. California | US West Coast (fewer AZs) |
| `us-west-2` | Oregon | US West Coast (recommended) |
| `eu-west-1` | Ireland | Europe primary |
| `eu-central-1` | Frankfurt | Europe, data residency |
| `ap-southeast-1` | Singapore | Asia Pacific primary |
| `ap-northeast-1` | Tokyo | Japan, low latency |

## Troubleshooting Guide

### Error: "No valid credential sources found"

**Error Message:**

```
Error: No valid credential sources found for AWS Provider.
Please see https://terraform.io/docs/providers/aws/index.html for more information on providing credentials for the AWS Provider

  with provider["registry.terraform.io/hashicorp/aws"],
  on provider.tf line 1, in provider "aws":
   1: provider "aws" {
```

**Cause:** Terraform cannot find AWS credentials through any authentication method.

**Resolution:**

```bash
# Check AWS CLI configuration
aws configure list

# If not configured, set up credentials
aws configure

# Or use environment variables
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"

# Verify authentication
aws sts get-caller-identity

# Then retry Terraform
terraform init
terraform plan
```


### Error: "AccessDenied: User is not authorized to perform: sts:AssumeRole"

**Error Message:**

```
Error: error configuring Terraform AWS Provider: error validating provider credentials: error calling sts:GetCallerIdentity: operation error STS: GetCallerIdentity, https response error StatusCode: 403, RequestID: xxx, api error AccessDenied: User: arn:aws:iam::111111111111:user/terraform is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::222222222222:role/terraform-role
```

**Cause:** IAM user lacks permission to assume the specified role, or the role's trust policy doesn't allow the user.

**Resolution:**

1. **Check user permissions in Management Account:**
```hcl
# Add sts:AssumeRole permission to user/role
resource "aws_iam_user_policy" "terraform_user" {
  name = "terraform-assume-role"
  user = "terraform"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRole"
      Resource = [
        "arn:aws:iam::222222222222:role/terraform-role",
        "arn:aws:iam::333333333333:role/terraform-role"
      ]
    }]
  })
}
```

2. **Check trust policy in Target Account:**
```hcl
# Ensure role trusts the management account user
resource "aws_iam_role" "terraform_role" {
  name = "terraform-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::111111111111:user/terraform"  # Must match
      }
      Action = "sts:AssumeRole"
    }]
  })
}
```

3. **Verify with AWS CLI:**
```bash
# Test assume role manually
aws sts assume-role \
  --role-arn "arn:aws:iam::222222222222:role/terraform-role" \
  --role-session-name "test-session"

# If this fails, fix IAM permissions before retrying Terraform
```


### Error: "ExpiredToken: The security token included in the request is expired"

**Error Message:**

```
Error: error configuring Terraform AWS Provider: error validating provider credentials: error calling sts:GetCallerIdentity: operation error STS: GetCallerIdentity, https response error StatusCode: 403, RequestID: xxx, api error ExpiredToken: The security token included in the request is expired
```

**Cause:** Assumed role session expired during long-running Terraform apply.

**Resolution:**

```hcl
# Increase session duration
provider "aws" {
  region = "us-east-1"
  
  assume_role {
    role_arn         = var.role_arn
    session_name     = "terraform-${var.environment}"
    duration_seconds = 10800  # 3 hours instead of default 1 hour
  }
}

# Also increase max session duration on the role itself
resource "aws_iam_role" "terraform" {
  name                 = "terraform-role"
  max_session_duration = 43200  # 12 hours maximum
  
  assume_role_policy = jsonencode({
    Statement = [{
      Effect = "Allow"
      Principal = { AWS = var.management_account_arn }
      Action = "sts:AssumeRole"
    }]
  })
}
```

**Prevention:**

```bash
# For very long operations, split into smaller applies
terraform apply -target=module.networking
terraform apply -target=module.database
terraform apply -target=module.application

# Or use shorter-lived resources that don't take hours to create
```


### Error: "External ID mismatch"

**Error Message:**

```
Error: error configuring Terraform AWS Provider: error validating provider credentials: error calling sts:GetCallerIdentity: operation error STS: GetCallerIdentity, https response error StatusCode: 403, api error AccessDenied: External ID does not match
```

**Cause:** external_id in provider doesn't match what's required in role's trust policy.

**Resolution:**

```hcl
# Ensure external IDs match exactly
# In target account role:
resource "aws_iam_role" "terraform" {
  assume_role_policy = jsonencode({
    Statement = [{
      Effect = "Allow"
      Principal = { AWS = var.management_account_user }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "sts:ExternalId" = "my-external-id-12345"  # Note this value
        }
      }
    }]
  })
}

# In management account provider:
provider "aws" {
  assume_role {
    role_arn    = aws_iam_role.terraform.arn
    external_id = "my-external-id-12345"  # Must match exactly
  }
}

# Use variables for consistency
variable "external_id" {
  type      = string
  sensitive = true
  default   = "my-external-id-12345"
}

provider "aws" {
  assume_role {
    role_arn    = var.role_arn
    external_id = var.external_id
  }
}
```


### Error: "The specified provider configuration may not be used"

**Error Message:**

```
Error: The specified provider configuration may not be used

The provider["registry.terraform.io/hashicorp/aws"].us_west configuration 
is not used by any resources or modules in the root module.
```

**Cause:** Defined a provider alias but never referenced it in any resources.

**Resolution:**

```hcl
# Option 1: Use the provider
resource "aws_s3_bucket" "west" {
  provider = aws.us_west  # Add provider reference
  bucket   = "data-west"
}

# Option 2: Remove unused provider
# Delete or comment out the unused provider block
# provider "aws" {
#   alias  = "us_west"
#   region = "us-west-2"
# }
```


### Error: "Provider configuration not present"

**Error Message:**

```
Error: Provider configuration not present

To work with module.networking.aws_vpc.main its original provider 
configuration at provider["registry.terraform.io/hashicorp/aws"].secondary 
is required, but it has been removed.
```

**Cause:** Module expects a provider alias that no longer exists.

**Resolution:**

```hcl
# Add back the missing provider
provider "aws" {
  alias  = "secondary"
  region = "us-west-2"
}

# Or update module call to use different provider
module "networking" {
  source = "./modules/vpc"
  
  providers = {
    aws = aws  # Use default provider instead
  }
}

# Or remove the provider reference from module resources
# In module code:
resource "aws_vpc" "main" {
  # Remove: provider = aws.secondary
  cidr_block = var.vpc_cidr
}
```


### Error: "Error loading state: AccessDenied"

**Error Message:**

```
Error: Error loading state: AccessDenied: Access Denied
	status code: 403, request id: xxx, host id: yyy

Terraform failed to load the default state from the "s3" backend.
State migration cannot occur unless the state can be loaded.
```

**Cause:** Current credentials don't have access to S3 state bucket.

**Resolution:**

```bash
# Check which identity is being used
aws sts get-caller-identity

# Verify S3 bucket access
aws s3 ls s3://your-terraform-state-bucket/

# If access denied, check bucket policy and IAM permissions
aws s3api get-bucket-policy --bucket your-terraform-state-bucket

# Add necessary permissions
```

```hcl
# Update S3 bucket policy to allow access
resource "aws_s3_bucket_policy" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "TerraformStateAccess"
      Effect = "Allow"
      Principal = {
        AWS = [
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/terraform",
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/terraform-role"
        ]
      }
      Action = [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ]
      Resource = "${aws_s3_bucket.terraform_state.arn}/*"
    },
    {
      Effect = "Allow"
      Principal = {
        AWS = [
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/terraform",
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/terraform-role"
        ]
      }
      Action = "s3:ListBucket"
      Resource = aws_s3_bucket.terraform_state.arn
    }]
  })
}
```


### Error: "Region validation failed"

**Error Message:**

```
Error: error validating provider credentials: error calling sts:GetCallerIdentity: operation error STS: GetCallerIdentity, failed to resolve service endpoint, endpoint rule error, Invalid region
```

**Cause:** Invalid or non-existent AWS region specified.

**Resolution:**

```hcl
# Use valid AWS region codes
variable "aws_region" {
  type        = string
  description = "AWS region"
  
  validation {
    condition = contains([
      "us-east-1", "us-east-2", "us-west-1", "us-west-2",
      "eu-west-1", "eu-west-2", "eu-central-1",
      "ap-southeast-1", "ap-southeast-2", "ap-northeast-1"
      # Add other valid regions
    ], var.aws_region)
    error_message = "Invalid AWS region specified."
  }
}

# Or dynamically validate
data "aws_regions" "available" {}

locals {
  valid_region = contains(data.aws_regions.available.names, var.aws_region)
}
```


### Debug Mode for Provider Issues

```bash
# Enable detailed logging
export TF_LOG=DEBUG
export TF_LOG_PATH="./terraform-debug.log"

# Run Terraform
terraform plan

# Review log file for AWS API calls
grep "aws-sdk-go" terraform-debug.log
grep "sts:AssumeRole" terraform-debug.log
grep "credential" terraform-debug.log

# Disable logging after debugging
unset TF_LOG
unset TF_LOG_PATH
```


## Key Takeaways

- AWS Provider 6.0 introduces enhanced multi-region support and default_tags, significantly simplifying multi-region deployments and ensuring consistent tagging
- Authentication methods should be chosen based on context: environment variables for local dev, IAM roles for EC2/ECS, AssumeRole for cross-account, and OIDC for modern CI/CD
- The default_tags feature in provider configuration eliminates hundreds of lines of repetitive code by automatically applying tags to all resources
- AssumeRole with external_id is the enterprise standard for cross-account access, providing security, audit trails, and temporary credentials
- Provider aliases enable multi-account and multi-region deployments but should follow consistent naming conventions (underscores, not dashes)
- Version constraints using ~> operator balance stability with security updates, allowing minor version updates while preventing breaking changes
- Always validate provider authentication before deploying infrastructure using data sources like aws_caller_identity to prevent costly mistakes


## What's Next

With AWS Provider configuration mastered, you're ready to dive deep into remote state management. In **Chapter 4: Remote State Management**, you'll learn how to configure S3 backends with DynamoDB locking, implement state file encryption with AWS KMS, handle state file corruption and recovery, manage state across multiple environments, and implement team collaboration workflows. You'll explore state locking mechanisms in detail, understand state file structure, and master commands like `terraform state mv`, `terraform import`, and state file migration strategies. Proper state management is critical for team collaboration and preventing infrastructure disasters in production environments.

## Additional Resources

**Official Documentation:**

- [AWS Provider Documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs) - Complete AWS Provider reference
- [AWS Provider 6.0 Upgrade Guide](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/guides/version-6-upgrade) - Migration guide for version 6.0
- [Terraform AWS Provider on GitHub](https://github.com/hashicorp/terraform-provider-aws) - Source code and issues
- [Authentication and Configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#authentication-and-configuration) - All auth methods

**AWS Security Best Practices:**

- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html) - IAM security guidelines
- [AssumeRole Tutorial](https://developer.hashicorp.com/terraform/tutorials/aws/aws-assumerole) - Official HashiCorp tutorial
- [Cross-Account Access Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_aws-accounts.html) - AWS documentation

**Multi-Account Architecture:**

- [AWS Organizations Best Practices](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_best-practices.html) - Multi-account setup
- [AWS Control Tower](https://aws.amazon.com/controltower/) - Automated multi-account governance
- [Terraform Multi-Account Patterns](https://ruan.dev/blog/2024/09/15/cross-account-terraform-assume-roles-in-aws) - Real-world patterns

**CI/CD Integration:**

- [GitHub Actions OIDC Guide](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services) - OIDC setup for GitHub
- [AWS Authentication Methods Comparison](https://dev.to/pavithra_sandamini/exploring-different-ways-to-authenticate-terraform-cli-with-aws-566l) - Detailed comparison
- [Terraform AWS Provider Examples](https://spacelift.io/blog/terraform-aws-provider) - Various use cases

**Community Resources:**

- [Terraform AWS Modules](https://github.com/terraform-aws-modules) - Production-ready modules
- [AWS Provider Changelog](https://github.com/hashicorp/terraform-provider-aws/blob/main/CHANGELOG.md) - Version history and changes
- [HashiCorp Community Forum](https://discuss.hashicorp.com/c/terraform-providers/tf-aws/) - AWS Provider discussions

**Tools and Utilities:**

- [aws-vault](https://github.com/99designs/aws-vault) - Secure credential management
- [saml2aws](https://github.com/Versent/saml2aws) - SAML authentication helper
- [granted](https://www.granted.dev/) - AWS credential management tool
- [Leapp](https://www.leapp.cloud/) - Visual credential manager

**Security Scanning:**

- [tfsec AWS Rules](https://aquasecurity.github.io/tfsec/latest/checks/aws/) - AWS-specific security checks
- [Checkov AWS Policies](https://www.checkov.io/5.Policy%20Index/terraform.html) - AWS policy as code
- [Prowler](https://github.com/prowler-cloud/prowler) - AWS security assessment

***

**Remember:** Provider configuration is the foundation of every Terraform project. Take time to set it up correctly from the start—using proper authentication, implementing security best practices, and following organizational standards. A well-configured provider prevents security incidents, simplifies team collaboration, and scales effortlessly as your infrastructure grows. Always test authentication before deploying infrastructure, and never commit credentials to version control!
