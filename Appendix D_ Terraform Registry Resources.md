# Appendix D: Terraform Registry Resources

## Introduction

The Terraform Registry (registry.terraform.io) serves as the central repository for Terraform providers, modules, and policy libraries, hosting over 3,500 providers and 15,000+ modules as of December 2025. This appendix provides a curated guide to essential registry resources, explaining how to discover, evaluate, and use community modules and providers effectively while maintaining security and reliability standards.

***

## Understanding the Terraform Registry

### Registry Structure

The Terraform Registry is organized into three primary categories:

**Providers:**

- Official providers (HashiCorp-maintained): `hashicorp/aws`, `hashicorp/azurerm`, `hashicorp/google`
- Verified providers (partner-maintained): `datadog/datadog`, `mongodb/mongodbatlas`
- Community providers: Third-party maintained

**Modules:**

- Verified modules (HashiCorp approved): Distinguished badge indicating quality standards
- Community modules: Community-contributed, varying quality levels

**Policy Libraries:**

- Sentinel policies for Terraform Cloud/Enterprise
- Open Policy Agent (OPA) policies


### Accessing the Registry

```hcl
# Provider source format
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"  # registry.terraform.io/hashicorp/aws (implied)
      version = "~> 6.0"
    }
  }
}

# Module source format
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"  # Short form
  version = "5.5.0"
  
  # Full form: registry.terraform.io/terraform-aws-modules/vpc/aws
}
```


***

## Essential AWS Modules

### 1. VPC Module

**Source:** `terraform-aws-modules/vpc/aws`
**Maintainer:** Anton Babenko (Verified)
**Downloads:** 50M+
**Use Case:** Production-grade VPC with subnets, NAT gateways, route tables

**Documentation:** https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws/latest

```hcl
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.5"
  
  name = "production-vpc"
  cidr = "10.0.0.0/16"
  
  azs             = ["us-east-1a", "us-east-1b", "us-east-1c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
  
  enable_nat_gateway = true
  enable_vpn_gateway = false
  enable_dns_hostnames = true
  
  tags = {
    Environment = "production"
  }
}
```

**Why Use This Module:**

- Battle-tested with millions of deployments
- Handles complex subnet calculations automatically
- Supports advanced scenarios (VPN, peering, endpoints)
- Well-documented with 100+ examples


### 2. EKS Module

**Source:** `terraform-aws-modules/eks/aws`
**Maintainer:** Anton Babenko (Verified)
**Downloads:** 10M+
**Use Case:** Production Kubernetes clusters with managed node groups

**Documentation:** https://registry.terraform.io/modules/terraform-aws-modules/eks/aws/latest

```hcl
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"
  
  cluster_name    = "production-eks"
  cluster_version = "1.31"
  
  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnets
  control_plane_subnet_ids = module.vpc.private_subnets
  
  # Managed node groups
  eks_managed_node_groups = {
    general = {
      instance_types = ["t3.large"]
      min_size       = 2
      max_size       = 10
      desired_size   = 3
    }
  }
  
  # Cluster addons
  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
    }
  }
}
```

**Key Features:**

- IRSA (IAM Roles for Service Accounts) support
- Managed node groups and Fargate profiles
- Cluster add-ons management
- Security best practices built-in


### 3. RDS Module

**Source:** `terraform-aws-modules/rds/aws`
**Maintainer:** Anton Babenko (Verified)
**Downloads:** 5M+
**Use Case:** Managed relational databases with sensible defaults

```hcl
module "db" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 6.5"
  
  identifier = "production-postgres"
  
  engine               = "postgres"
  engine_version       = "15.4"
  family               = "postgres15"
  major_engine_version = "15"
  instance_class       = "db.r6g.large"
  
  allocated_storage     = 100
  max_allocated_storage = 500
  storage_encrypted     = true
  
  db_name  = "appdb"
  username = "dbadmin"
  port     = 5432
  
  multi_az               = true
  db_subnet_group_name   = module.vpc.database_subnet_group
  vpc_security_group_ids = [module.security_group.security_group_id]
  
  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"
  
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  
  tags = {
    Environment = "production"
  }
}
```


### 4. Security Group Module

**Source:** `terraform-aws-modules/security-group/aws`
**Maintainer:** Anton Babenko (Verified)
**Downloads:** 15M+
**Use Case:** Reusable security group patterns

```hcl
module "web_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.1"
  
  name        = "web-server-sg"
  description = "Security group for web servers"
  vpc_id      = module.vpc.vpc_id
  
  # Ingress rules
  ingress_with_cidr_blocks = [
    {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = "0.0.0.0/0"
      description = "HTTP from internet"
    },
    {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = "0.0.0.0/0"
      description = "HTTPS from internet"
    }
  ]
  
  # Egress rules
  egress_with_cidr_blocks = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = "0.0.0.0/0"
      description = "All outbound traffic"
    }
  ]
}
```


### 5. S3 Bucket Module

**Source:** `terraform-aws-modules/s3-bucket/aws`
**Maintainer:** Anton Babenko (Verified)
**Downloads:** 8M+
**Use Case:** S3 buckets with security best practices

```hcl
module "s3_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 4.1"
  
  bucket = "my-app-data-bucket"
  
  # Block public access
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
  
  # Versioning
  versioning = {
    enabled = true
  }
  
  # Server-side encryption
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }
  
  # Lifecycle rules
  lifecycle_rule = [
    {
      id      = "archive-old-data"
      enabled = true
      
      transition = [
        {
          days          = 90
          storage_class = "GLACIER"
        }
      ]
      
      expiration = {
        days = 365
      }
    }
  ]
}
```


### 6. ALB Module

**Source:** `terraform-aws-modules/alb/aws`
**Maintainer:** Anton Babenko (Verified)
**Downloads:** 4M+
**Use Case:** Application Load Balancers with target groups

```hcl
module "alb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "~> 9.7"
  
  name               = "app-alb"
  load_balancer_type = "application"
  
  vpc_id  = module.vpc.vpc_id
  subnets = module.vpc.public_subnets
  
  security_groups = [module.alb_sg.security_group_id]
  
  # Target groups
  target_groups = {
    app = {
      name_prefix      = "app-"
      backend_protocol = "HTTP"
      backend_port     = 80
      target_type      = "instance"
      
      health_check = {
        enabled             = true
        path                = "/health"
        port                = "traffic-port"
        healthy_threshold   = 2
        unhealthy_threshold = 3
        timeout             = 5
        interval            = 30
      }
    }
  }
  
  # Listeners
  listeners = {
    http = {
      port     = 80
      protocol = "HTTP"
      
      forward = {
        target_group_key = "app"
      }
    }
  }
}
```


### 7. Lambda Module

**Source:** `terraform-aws-modules/lambda/aws`
**Maintainer:** Anton Babenko (Verified)
**Downloads:** 3M+
**Use Case:** Serverless functions with packaging

```hcl
module "lambda_function" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "~> 7.2"
  
  function_name = "data-processor"
  description   = "Process incoming data"
  handler       = "index.handler"
  runtime       = "python3.11"
  
  source_path = "./lambda/processor"
  
  environment_variables = {
    DYNAMODB_TABLE = aws_dynamodb_table.data.name
    S3_BUCKET      = aws_s3_bucket.processed.id
  }
  
  attach_policy_statements = true
  policy_statements = {
    dynamodb = {
      effect = "Allow"
      actions = [
        "dynamodb:PutItem",
        "dynamodb:GetItem"
      ]
      resources = [aws_dynamodb_table.data.arn]
    }
  }
  
  timeout     = 60
  memory_size = 512
}
```


### 8. IAM Module Collection

**Source:** `terraform-aws-modules/iam/aws`
**Maintainer:** Anton Babenko (Verified)
**Downloads:** 12M+
**Use Case:** IAM roles, policies, users, groups

```hcl
# IAM role for EC2 instances
module "iam_assumable_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "~> 5.34"
  
  role_name         = "ec2-app-role"
  create_role       = true
  role_requires_mfa = false
  
  trusted_role_services = ["ec2.amazonaws.com"]
  
  custom_role_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  ]
}

# IAM user with access keys
module "iam_user" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-user"
  version = "~> 5.34"
  
  name          = "ci-deploy-user"
  force_destroy = true
  
  create_iam_access_key         = true
  create_iam_user_login_profile = false
  
  policy_arns = [
    "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
  ]
}
```


***

## Multi-Cloud Modules

### Azure Modules

**Popular Azure Modules:**


| Module | Source | Use Case |
| :-- | :-- | :-- |
| Azure Network | `Azure/network/azurerm` | Virtual networks |
| AKS | `Azure/aks/azurerm` | Kubernetes clusters |
| Virtual Machine | `Azure/compute/azurerm` | VMs and scale sets |
| SQL Database | `Azure/database/azurerm` | Azure SQL |

**Example:**

```hcl
module "network" {
  source  = "Azure/network/azurerm"
  version = "~> 5.3"
  
  resource_group_name = "production-rg"
  location            = "East US"
  vnet_name           = "production-vnet"
  address_space       = "10.0.0.0/16"
  
  subnet_prefixes = ["10.0.1.0/24", "10.0.2.0/24"]
  subnet_names    = ["subnet1", "subnet2"]
}
```


### Google Cloud Modules

**Popular GCP Modules:**


| Module | Source | Use Case |
| :-- | :-- | :-- |
| GCP Network | `terraform-google-modules/network/google` | VPC networks |
| GKE | `terraform-google-modules/kubernetes-engine/google` | Kubernetes |
| Cloud Storage | `terraform-google-modules/cloud-storage/google` | Object storage |
| SQL Database | `GoogleCloudPlatform/sql-db/google` | Cloud SQL |

**Example:**

```hcl
module "gke" {
  source  = "terraform-google-modules/kubernetes-engine/google"
  version = "~> 30.0"
  
  project_id        = "my-project-id"
  name              = "production-gke"
  region            = "us-central1"
  network           = "vpc-01"
  subnetwork        = "us-central1-01"
  ip_range_pods     = "us-central1-01-gke-01-pods"
  ip_range_services = "us-central1-01-gke-01-services"
}
```


***

## Utility and Framework Modules

### 1. Terraform Module Template

**Source:** `terraform-aws-modules/terraform-module-template`
**Use Case:** Starting point for building custom modules

```bash
# Clone template
git clone https://github.com/terraform-aws-modules/terraform-module-template.git my-module

cd my-module

# Structure:
# ├── README.md
# ├── main.tf
# ├── variables.tf
# ├── outputs.tf
# ├── versions.tf
# ├── examples/
# │   └── complete/
# └── test/
```


### 2. Atlantis Module

**Source:** `terraform-aws-modules/atlantis/aws`
**Use Case:** Self-hosted Terraform automation server

```hcl
module "atlantis" {
  source  = "terraform-aws-modules/atlantis/aws"
  version = "~> 4.0"
  
  name = "atlantis"
  
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnets
  public_subnet_ids  = module.vpc.public_subnets
  
  # GitHub integration
  github_token      = var.github_token
  github_user       = "myorg"
  github_repo_whitelist = ["github.com/myorg/*"]
  
  atlantis_github_webhook_secret = var.webhook_secret
}
```


### 3. Terragrunt Compatible Modules

Many modules designed for Terragrunt DRY patterns:

```hcl
# terragrunt.hcl
terraform {
  source = "tfr:///terraform-aws-modules/vpc/aws?version=5.5.0"
}

inputs = {
  name = "production-vpc"
  cidr = "10.0.0.0/16"
  
  azs             = ["us-east-1a", "us-east-1b"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]
}
```


***

## Evaluating Registry Modules

### Quality Indicators

**✅ Good Indicators:**

- Verified badge (HashiCorp reviewed)
- High download count (500K+)
- Regular updates (last 3 months)
- Comprehensive README with examples
- Active issue tracking
- Semantic versioning
- CI/CD testing

**⚠️ Warning Signs:**

- No updates in 12+ months
- No documentation
- Low or zero downloads
- Open critical issues
- No version tags
- No examples


### Module Evaluation Checklist

```markdown
## Module Evaluation: [Module Name]

### Basic Information
- [ ] Source: [registry URL]
- [ ] Verified: [Yes/No]
- [ ] Downloads: [count]
- [ ] Last Updated: [date]
- [ ] Latest Version: [version]

### Documentation Quality
- [ ] Comprehensive README
- [ ] Input variables documented
- [ ] Output values documented
- [ ] Usage examples provided
- [ ] Architecture diagrams

### Code Quality
- [ ] Terraform validation passes
- [ ] Follows naming conventions
- [ ] Security best practices
- [ ] No hardcoded values
- [ ] Proper variable typing

### Maintenance
- [ ] Active development
- [ ] Responsive to issues
- [ ] Regular releases
- [ ] Changelog maintained
- [ ] Breaking changes documented

### Security
- [ ] No secrets in code
- [ ] Security scanning (tfsec, checkov)
- [ ] Follows least privilege
- [ ] Encryption by default

### Testing
- [ ] Example configurations
- [ ] Test suite present
- [ ] CI/CD pipeline
- [ ] Integration tests
```


### Security Scanning

Before using any module:

```bash
# Clone module repository
git clone https://github.com/terraform-aws-modules/vpc vpc-module

# Scan with tfsec
cd vpc-module
tfsec .

# Scan with Checkov
checkov -d .

# Review output for vulnerabilities
```


***

## Private Module Registry

### Publishing Private Modules

Organizations can host private modules in Terraform Cloud/Enterprise:

```hcl
# Using private module
module "custom_app" {
  source  = "app.terraform.io/myorg/app-stack/aws"
  version = "1.2.0"
  
  environment = "production"
}
```


### Setting Up Private Registry

**Terraform Cloud:**

1. Create module in VCS (GitHub, GitLab, Bitbucket)
2. Tag releases with semantic versioning: `v1.0.0`
3. Connect VCS to Terraform Cloud
4. Publish module from Terraform Cloud UI

**Module Structure:**

```
terraform-aws-app-stack/
├── README.md
├── main.tf
├── variables.tf
├── outputs.tf
├── versions.tf
├── examples/
│   ├── basic/
│   └── complete/
└── modules/
    ├── compute/
    ├── database/
    └── networking/
```


***

## Module Development Best Practices

### 1. Semantic Versioning

```bash
# Breaking change (incompatible)
v2.0.0

# New feature (backward compatible)
v1.1.0

# Bug fix (backward compatible)
v1.0.1
```


### 2. Module Inputs

```hcl
# variables.tf
variable "name" {
  description = "Name prefix for all resources"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod"
  }
}

variable "tags" {
  description = "Additional tags for resources"
  type        = map(string)
  default     = {}
}

variable "enable_monitoring" {
  description = "Enable CloudWatch monitoring"
  type        = bool
  default     = true
}
```


### 3. Module Outputs

```hcl
# outputs.tf
output "vpc_id" {
  description = "The ID of the VPC"
  value       = aws_vpc.main.id
}

output "private_subnet_ids" {
  description = "List of private subnet IDs"
  value       = aws_subnet.private[*].id
}

output "nat_gateway_ips" {
  description = "Elastic IPs of NAT Gateways"
  value       = aws_eip.nat[*].public_ip
}
```


### 4. Documentation Template

```markdown
# Terraform AWS App Stack Module

## Description

This module creates a complete application stack in AWS including VPC, compute, and database resources.

## Usage

```

module "app_stack" {
source  = "myorg/app-stack/aws"
version = "1.0.0"

name        = "myapp"
environment = "production"

vpc_cidr = "10.0.0.0/16"

instance_type = "t3.large"
min_size      = 2
max_size      = 10
}

```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.11.0 |
| aws | >= 6.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| name | Name prefix | `string` | n/a | yes |
| environment | Environment | `string` | n/a | yes |
| vpc_cidr | VPC CIDR block | `string` | `"10.0.0.0/16"` | no |

## Outputs

| Name | Description |
|------|-------------|
| vpc_id | VPC identifier |
| alb_dns_name | Load balancer DNS |

## Examples

- [Basic](./examples/basic)
- [Complete](./examples/complete)

## License

Apache 2.0
```


***

## Module Discovery Tools

### CLI Tools

```bash
# Search registry from CLI
terraform registry search vpc

# Get module details
terraform registry show terraform-aws-modules/vpc/aws

# List module versions
terraform registry versions terraform-aws-modules/vpc/aws
```


### Web Search

**Registry Search:** https://registry.terraform.io/search/modules

**Filters:**

- Provider: AWS, Azure, GCP
- Verified only
- Sort by: Downloads, Recently Updated
- Tag search: kubernetes, networking, security

***

## Summary: Top 20 Essential Modules

| Rank | Module | Source | Use Case | Downloads |
| :-- | :-- | :-- | :-- | :-- |
| 1 | VPC | `terraform-aws-modules/vpc/aws` | Networking | 50M+ |
| 2 | Security Group | `terraform-aws-modules/security-group/aws` | Security | 15M+ |
| 3 | IAM | `terraform-aws-modules/iam/aws` | Identity | 12M+ |
| 4 | EKS | `terraform-aws-modules/eks/aws` | Kubernetes | 10M+ |
| 5 | S3 Bucket | `terraform-aws-modules/s3-bucket/aws` | Storage | 8M+ |
| 6 | RDS | `terraform-aws-modules/rds/aws` | Database | 5M+ |
| 7 | ALB | `terraform-aws-modules/alb/aws` | Load Balancing | 4M+ |
| 8 | Lambda | `terraform-aws-modules/lambda/aws` | Serverless | 3M+ |
| 9 | EC2 Instance | `terraform-aws-modules/ec2-instance/aws` | Compute | 3M+ |
| 10 | DynamoDB | `terraform-aws-modules/dynamodb-table/aws` | NoSQL | 2M+ |
| 11 | ECS | `terraform-aws-modules/ecs/aws` | Containers | 2M+ |
| 12 | ACM | `terraform-aws-modules/acm/aws` | Certificates | 2M+ |
| 13 | CloudFront | `terraform-aws-modules/cloudfront/aws` | CDN | 1M+ |
| 14 | Route53 | `terraform-aws-modules/route53/aws` | DNS | 1M+ |
| 15 | KMS | `terraform-aws-modules/kms/aws` | Encryption | 1M+ |
| 16 | Autoscaling | `terraform-aws-modules/autoscaling/aws` | Scaling | 1M+ |
| 17 | API Gateway | `terraform-aws-modules/apigateway-v2/aws` | APIs | 500K+ |
| 18 | CloudWatch | `terraform-aws-modules/cloudwatch/aws` | Monitoring | 500K+ |
| 19 | SQS | `terraform-aws-modules/sqs/aws` | Queuing | 400K+ |
| 20 | SNS | `terraform-aws-modules/sns/aws` | Notifications | 300K+ |


***

The Terraform Registry provides a wealth of pre-built, tested, and maintained modules that accelerate infrastructure development while maintaining best practices. Always evaluate modules carefully for security, maintenance status, and fit for your use case before adopting them in production environments. Leverage verified modules from established maintainers like Anton Babenko's terraform-aws-modules collection for reliable, well-documented infrastructure components.

