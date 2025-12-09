# Chapter 2: Terraform Fundamentals

## Introduction

Terraform fundamentals form the bedrock of everything you'll build in your Infrastructure as Code journey. While Chapter 1 introduced you to the "why" of IaC, this chapter dives deep into the "how"—the essential building blocks, syntax, and workflows that transform declarative code into real AWS infrastructure. Understanding these core concepts thoroughly will accelerate your learning and prevent costly mistakes in production environments.

In this chapter, you'll master Terraform's HashiCorp Configuration Language (HCL), understand the relationship between providers and resources, and learn how Terraform's dependency graph automatically orchestrates complex infrastructure deployments. You'll explore variables, outputs, data sources, and local values—the tools that make your configurations flexible, reusable, and maintainable. Most importantly, you'll gain hands-on experience with real AWS resources, building confidence through practical exercises that mirror production scenarios.

By the end of this chapter, you'll be equipped to write well-structured, production-grade Terraform configurations following industry best practices. You'll understand state management at a deeper level, know how to troubleshoot common errors, and be able to confidently apply changes to AWS infrastructure. This knowledge forms the foundation for advanced topics like modules, testing, and CI/CD integration covered in later chapters. Let's dive into the mechanics that make Terraform the most powerful IaC tool available today.

## Installing and Configuring Terraform

### Installation Methods for Different Platforms

**Linux Installation (Ubuntu/Debian):**

```bash
# Method 1: Using HashiCorp's official repository (Recommended)
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list

sudo apt update && sudo apt install terraform

# Verify installation
terraform --version
# Expected output: Terraform v1.15.0 or later
```

**macOS Installation:**

```bash
# Using Homebrew (Recommended)
brew tap hashicorp/tap
brew install hashicorp/tap/terraform

# Verify installation
terraform --version

# Update Terraform
brew upgrade hashicorp/tap/terraform
```

**Windows Installation:**

```powershell
# Using Chocolatey
choco install terraform

# Or using Scoop
scoop install terraform

# Verify installation
terraform --version

# Windows ARM64 support added in Terraform 1.15.0
# Download from: https://releases.hashicorp.com/terraform/
```

**Manual Installation (All Platforms):**

```bash
# Download binary from https://releases.hashicorp.com/terraform/
# Example for Linux:
wget https://releases.hashicorp.com/terraform/1.15.0/terraform_1.15.0_linux_amd64.zip

unzip terraform_1.15.0_linux_amd64.zip

sudo mv terraform /usr/local/bin/

# Verify
terraform --version
```


### Environment Setup and Configuration

**Configure AWS CLI (Required):**

```bash
# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Configure credentials
aws configure

# Enter when prompted:
# AWS Access Key ID: [Your Access Key]
# AWS Secret Access Key: [Your Secret Key]
# Default region: us-east-1
# Default output format: json

# Verify configuration
aws sts get-caller-identity
```

**Set Up AWS Credentials for Terraform:**

```bash
# Method 1: Environment variables (Recommended for local development)
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"

# Method 2: AWS CLI profiles
# ~/.aws/credentials
[default]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY

[production]
aws_access_key_id = PROD_ACCESS_KEY
aws_secret_access_key = PROD_SECRET_KEY

# Use with Terraform
export AWS_PROFILE=production
```

**Terraform Environment Variables:**

```bash
# ~/.bashrc or ~/.zshrc

# Enable detailed logging for troubleshooting
export TF_LOG=INFO  # Options: TRACE, DEBUG, INFO, WARN, ERROR
export TF_LOG_PATH="./terraform.log"

# Set plugin cache directory (saves bandwidth)
export TF_PLUGIN_CACHE_DIR="$HOME/.terraform.d/plugin-cache"
mkdir -p $TF_PLUGIN_CACHE_DIR

# Disable color output (useful for CI/CD)
# export TF_CLI_ARGS="-no-color"

# Set input to false (useful for automation)
# export TF_INPUT=false
```

**Editor Setup (VS Code - Recommended):**

```json
// .vscode/settings.json
{
  "terraform.languageServer": {
    "enabled": true,
    "args": []
  },
  "terraform.experimentalFeatures": {
    "validateOnSave": true,
    "prefillRequiredFields": true
  },
  "[terraform]": {
    "editor.defaultFormatter": "hashicorp.terraform",
    "editor.formatOnSave": true,
    "editor.formatOnSaveMode": "file"
  },
  "[terraform-vars]": {
    "editor.defaultFormatter": "hashicorp.terraform",
    "editor.formatOnSave": true
  }
}

// Install recommended extensions:
// - HashiCorp Terraform
// - AWS Toolkit
// - Terraform doc snippets
```


### Version Management with tfenv

```bash
# Install tfenv (Terraform version manager)
git clone https://github.com/tfutils/tfenv.git ~/.tfenv
echo 'export PATH="$HOME/.tfenv/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# List available Terraform versions
tfenv list-remote

# Install specific version
tfenv install 1.15.0

# Install latest version
tfenv install latest

# Use specific version
tfenv use 1.15.0

# Set default version
tfenv use 1.15.0
echo "1.15.0" > ~/.tfenv/version

# Verify
terraform --version
```


## Understanding HashiCorp Configuration Language (HCL)

### HCL Syntax Basics

**Basic Block Structure:**

```hcl
# Basic syntax: <BLOCK_TYPE> "<BLOCK_LABEL>" "<BLOCK_LABEL>" {
#   <IDENTIFIER> = <EXPRESSION>
# }

# Resource block with two labels
resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  
  # Nested block
  tags = {
    Name = "WebServer"
  }
}

# Data source block
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]  # Canonical
  
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

# Variable block
variable "instance_count" {
  description = "Number of instances to create"
  type        = number
  default     = 1
}

# Output block
output "instance_ip" {
  description = "Public IP of the instance"
  value       = aws_instance.web_server.public_ip
}

# Locals block
locals {
  common_tags = {
    Environment = "Production"
    ManagedBy   = "Terraform"
    Team        = "DevOps"
  }
}
```


### Data Types and Values

**Primitive Types:**

```hcl
# variables.tf - Demonstrating all primitive types

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "instance_count" {
  description = "Number of instances"
  type        = number
  default     = 2
}

variable "enable_monitoring" {
  description = "Enable detailed monitoring"
  type        = bool
  default     = true
}

# Using primitive types
resource "aws_instance" "app" {
  count         = var.instance_count                    # number
  ami           = "ami-0c55b159cbfafe1f0"              # string
  instance_type = var.instance_type                    # string
  monitoring    = var.enable_monitoring                # bool
  
  tags = {
    Name = "app-server-${count.index + 1}"
  }
}
```

**Complex Types - Lists:**

```hcl
variable "availability_zones" {
  description = "List of AZs to deploy to"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "subnet_cidrs" {
  description = "CIDR blocks for subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

# Using lists with count
resource "aws_subnet" "private" {
  count             = length(var.availability_zones)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]
  
  tags = {
    Name = "private-subnet-${var.availability_zones[count.index]}"
  }
}
```

**Complex Types - Maps:**

```hcl
variable "instance_types" {
  description = "Instance types per environment"
  type        = map(string)
  default = {
    dev     = "t3.micro"
    staging = "t3.small"
    prod    = "t3.large"
  }
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default = {
    Environment = "production"
    Project     = "web-app"
    Owner       = "devops-team"
  }
}

# Using maps
resource "aws_instance" "app" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = var.instance_types[var.environment]
  
  tags = var.tags
}
```

**Complex Types - Objects:**

```hcl
variable "database_config" {
  description = "Database configuration"
  type = object({
    instance_class    = string
    allocated_storage = number
    engine_version    = string
    multi_az          = bool
    backup_retention  = number
  })
  default = {
    instance_class    = "db.t3.medium"
    allocated_storage = 100
    engine_version    = "8.0.35"
    multi_az          = true
    backup_retention  = 7
  }
}

# Using object type
resource "aws_db_instance" "main" {
  identifier           = "main-database"
  engine              = "mysql"
  engine_version      = var.database_config.engine_version
  instance_class      = var.database_config.instance_class
  allocated_storage   = var.database_config.allocated_storage
  multi_az            = var.database_config.multi_az
  backup_retention_period = var.database_config.backup_retention
  
  username = var.db_username
  password = var.db_password
  
  skip_final_snapshot = false
  final_snapshot_identifier = "main-database-final-snapshot-${timestamp()}"
}
```

**Complex Types - Sets and Tuples:**

```hcl
variable "security_group_rules" {
  description = "List of security group rules"
  type = list(object({
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
  }))
  default = [
    {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    },
    {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
}

# Using complex nested types
resource "aws_security_group" "web" {
  name        = "web-server-sg"
  description = "Security group for web servers"
  vpc_id      = aws_vpc.main.id
  
  dynamic "ingress" {
    for_each = var.security_group_rules
    content {
      from_port   = ingress.value.from_port
      to_port     = ingress.value.to_port
      protocol    = ingress.value.protocol
      cidr_blocks = ingress.value.cidr_blocks
    }
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```


### Expressions and Functions

**String Interpolation and Templates:**

```hcl
locals {
  # String interpolation
  instance_name = "web-server-${var.environment}-${var.region}"
  
  # String concatenation
  bucket_name = "${var.project_name}-${var.environment}-data"
  
  # Conditional expressions
  environment_suffix = var.environment == "prod" ? "" : "-${var.environment}"
  
  # Template rendering
  user_data = templatefile("${path.module}/scripts/user_data.sh", {
    environment = var.environment
    region      = var.region
    app_version = var.app_version
  })
}

# Using string functions
resource "aws_s3_bucket" "logs" {
  # lower() ensures bucket name is lowercase
  bucket = lower("${var.company_name}-logs-${var.environment}")
  
  tags = {
    # upper() for uppercase tags
    Environment = upper(var.environment)
    # title() for title case
    Owner       = title(var.team_name)
  }
}
```

**Collection Functions:**

```hcl
locals {
  # length() - get collection size
  az_count = length(var.availability_zones)
  
  # concat() - combine lists
  all_cidrs = concat(var.public_cidrs, var.private_cidrs)
  
  # merge() - combine maps
  all_tags = merge(
    var.default_tags,
    var.environment_tags,
    {
      ManagedBy = "Terraform"
    }
  )
  
  # lookup() - get map value with default
  instance_type = lookup(var.instance_types, var.environment, "t3.micro")
  
  # element() - get list element (wraps around)
  selected_az = element(var.availability_zones, 0)
  
  # contains() - check if list contains value
  has_prod = contains(var.environments, "prod")
  
  # distinct() - remove duplicates
  unique_azs = distinct(var.all_availability_zones)
  
  # flatten() - flatten nested lists
  all_subnet_cidrs = flatten([
    var.public_subnet_cidrs,
    var.private_subnet_cidrs,
    var.database_subnet_cidrs
  ])
}

# Practical example using collection functions
resource "aws_subnet" "public" {
  count = length(var.public_subnet_cidrs)
  
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.public_subnet_cidrs[count.index]
  availability_zone = element(var.availability_zones, count.index)
  
  tags = merge(
    var.default_tags,
    {
      Name = "public-subnet-${count.index + 1}"
      Type = "Public"
    }
  )
}
```

**Numeric and Encoding Functions:**

```hcl
locals {
  # min() and max()
  min_size = min(var.desired_capacity, var.min_size)
  max_size = max(var.desired_capacity, var.max_size)
  
  # ceil(), floor(), abs()
  rounded_up = ceil(var.calculated_capacity)
  rounded_down = floor(var.calculated_capacity)
  
  # jsonencode() and jsondecode()
  policy_json = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.data.arn}/*"
      }
    ]
  })
  
  # base64encode() and base64decode()
  user_data_encoded = base64encode(local.user_data_script)
  
  # yamlencode() - new in recent versions
  config_yaml = yamlencode({
    app_name = var.app_name
    settings = var.app_settings
  })
}

# Using numeric functions for auto-scaling
resource "aws_autoscaling_group" "app" {
  name                = "app-asg-${var.environment}"
  min_size            = max(1, var.min_size)  # At least 1
  max_size            = min(var.max_size, 10)  # Cap at 10
  desired_capacity    = clamp(var.desired_capacity, 1, 10)  # Between 1-10
  vpc_zone_identifier = aws_subnet.private[*].id
  
  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }
}
```

**Filesystem and Date Functions:**

```hcl
locals {
  # file() - read file contents
  ssh_public_key = file("${path.module}/keys/id_rsa.pub")
  
  # filebase64() - read file as base64
  lambda_zip = filebase64("${path.module}/lambda/function.zip")
  
  # templatefile() - render template with variables
  nginx_config = templatefile("${path.module}/templates/nginx.conf.tpl", {
    server_name = var.domain_name
    app_port    = var.app_port
  })
  
  # Path references
  module_path = path.module          # Current module path
  root_path   = path.root            # Root module path
  cwd_path    = path.cwd             # Current working directory
  
  # timestamp() - current timestamp
  backup_timestamp = timestamp()
  
  # formatdate() - format timestamp
  backup_date = formatdate("YYYY-MM-DD-hhmm", timestamp())
}

# Using filesystem functions
resource "aws_key_pair" "deployer" {
  key_name   = "deployer-key-${var.environment}"
  public_key = file("${path.module}/keys/deployer.pub")
}

resource "aws_lambda_function" "processor" {
  filename         = "${path.module}/lambda/processor.zip"
  function_name    = "data-processor-${var.environment}"
  role            = aws_iam_role.lambda.arn
  handler         = "index.handler"
  source_code_hash = filebase64sha256("${path.module}/lambda/processor.zip")
  runtime         = "nodejs18.x"
}
```

**Conditional Expressions:**

```hcl
locals {
  # Ternary operator: condition ? true_val : false_val
  environment_size = var.environment == "prod" ? "large" : "small"
  
  # Nested conditionals
  instance_type = (
    var.environment == "prod" ? "t3.large" :
    var.environment == "staging" ? "t3.medium" :
    "t3.micro"
  )
  
  # Conditional with boolean
  enable_monitoring = var.environment == "prod" ? true : false
  
  # Using coalescence for defaults
  final_db_name = coalesce(var.db_name, "default_database")
}

# Conditional resource creation
resource "aws_instance" "bastion" {
  count = var.create_bastion ? 1 : 0  # Create only if true
  
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.public[0].id
  
  tags = {
    Name = "bastion-${var.environment}"
  }
}

# Conditional attribute
resource "aws_db_instance" "main" {
  identifier        = "main-db-${var.environment}"
  engine           = "postgres"
  instance_class   = var.environment == "prod" ? "db.r5.xlarge" : "db.t3.medium"
  allocated_storage = var.environment == "prod" ? 500 : 100
  multi_az         = var.environment == "prod" ? true : false
  
  # Conditional backup retention
  backup_retention_period = var.environment == "prod" ? 30 : 7
}
```


## Providers: The Bridge to AWS

### Understanding Terraform Providers

**Provider Configuration Basics:**

```hcl
# versions.tf - Provider requirements
terraform {
  required_version = ">= 1.15.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"  # AWS Provider 6.0 or newer
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

# provider.tf - Provider configuration
provider "aws" {
  region = var.aws_region
  
  # Default tags applied to ALL resources (AWS Provider 6.0+ feature)
  default_tags {
    tags = {
      Environment = var.environment
      ManagedBy   = "Terraform"
      Project     = var.project_name
      Owner       = var.owner_email
      CostCenter  = var.cost_center
    }
  }
  
  # Assume role for cross-account access
  assume_role {
    role_arn     = var.terraform_role_arn
    session_name = "terraform-${var.environment}"
  }
}
```

**AWS Provider 6.0 Multi-Region Enhancement:**

```hcl
# NEW in AWS Provider 6.0: Region attribute injection
# Single provider configuration for multi-region resources

provider "aws" {
  region = "us-east-1"  # Default region
  
  default_tags {
    tags = {
      ManagedBy = "Terraform"
    }
  }
}

# CloudFront (global service) automatically uses us-east-1
resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
  
  origin {
    domain_name = aws_s3_bucket.content.bucket_regional_domain_name
    origin_id   = "S3-Content"
  }
  
  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-Content"
    viewer_protocol_policy = "redirect-to-https"
    
    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }
  
  viewer_certificate {
    cloudfront_default_certificate = true
  }
  
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
}

# Override region for specific resources
resource "aws_s3_bucket" "west_coast" {
  bucket   = "west-coast-data-${var.environment}"
  provider = aws  # Uses default provider but can override region at resource level
}
```

**Multiple Provider Configurations (Alias):**

```hcl
# Primary region
provider "aws" {
  alias  = "primary"
  region = "us-east-1"
  
  default_tags {
    tags = {
      Region = "Primary"
    }
  }
}

# Secondary region for DR
provider "aws" {
  alias  = "secondary"
  region = "us-west-2"
  
  default_tags {
    tags = {
      Region = "Secondary"
    }
  }
}

# Cross-account provider
provider "aws" {
  alias  = "production_account"
  region = "us-east-1"
  
  assume_role {
    role_arn = "arn:aws:iam::123456789012:role/TerraformRole"
  }
}

# Using provider aliases
resource "aws_s3_bucket" "primary" {
  provider = aws.primary
  bucket   = "primary-region-data"
}

resource "aws_s3_bucket" "secondary" {
  provider = aws.secondary
  bucket   = "secondary-region-data-dr"
}

# S3 replication between regions
resource "aws_s3_bucket_replication_configuration" "replication" {
  provider = aws.primary
  
  bucket = aws_s3_bucket.primary.id
  role   = aws_iam_role.replication.arn
  
  rule {
    id     = "replicate-to-secondary"
    status = "Enabled"
    
    destination {
      bucket        = aws_s3_bucket.secondary.arn
      storage_class = "STANDARD_IA"
    }
  }
}
```


### Provider Version Constraints

**Version Constraint Operators:**

```hcl
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      
      # Exact version
      # version = "6.15.0"
      
      # Greater than or equal to
      # version = ">= 6.0.0"
      
      # Greater than
      # version = "> 6.0.0"
      
      # Less than
      # version = "< 7.0.0"
      
      # Pessimistic constraint (recommended)
      # Allows 6.x.x but not 7.0.0
      version = "~> 6.0"
      
      # Range constraint
      # version = ">= 6.0.0, < 7.0.0"
    }
  }
}
```

**Lock File (.terraform.lock.hcl):**

```hcl
# This file is auto-generated during terraform init
# ALWAYS commit this to version control

provider "registry.terraform.io/hashicorp/aws" {
  version     = "6.15.0"
  constraints = "~> 6.0"
  hashes = [
    "h1:xyz123...",
    "zh:abc456...",
  ]
}

# To upgrade providers:
# terraform init -upgrade

# To downgrade (if needed):
# terraform init -upgrade=false
```


## Resources: The Building Blocks

### Resource Syntax and Meta-Arguments

**Basic Resource Structure:**

```hcl
# resource "<PROVIDER>_<TYPE>" "local_name" {
#   argument = value
# }

resource "aws_instance" "web_server" {
  # Required arguments
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  
  # Optional arguments
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.web.id]
  key_name              = aws_key_pair.deployer.key_name
  
  # User data for instance initialization
  user_data = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y httpd
              systemctl start httpd
              systemctl enable httpd
              echo "<h1>Hello from Terraform</h1>" > /var/www/html/index.html
              EOF
  
  # Tags
  tags = {
    Name        = "web-server-${var.environment}"
    Environment = var.environment
  }
}
```

**Meta-Argument: count**

```hcl
# Create multiple similar resources
variable "instance_count" {
  default = 3
}

resource "aws_instance" "app_servers" {
  count = var.instance_count
  
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.private[count.index % length(aws_subnet.private)].id
  
  tags = {
    Name = "app-server-${count.index + 1}"
    # count.index starts at 0, so add 1 for human-readable names
  }
}

# Reference specific instance
output "first_instance_ip" {
  value = aws_instance.app_servers[0].private_ip
}

# Reference all instances
output "all_instance_ips" {
  value = aws_instance.app_servers[*].private_ip
}
```

**Meta-Argument: for_each (Preferred over count)**

```hcl
# Using for_each with map
variable "environments" {
  type = map(object({
    instance_type = string
    subnet_id     = string
  }))
  default = {
    dev = {
      instance_type = "t3.micro"
      subnet_id     = "subnet-dev123"
    }
    staging = {
      instance_type = "t3.small"
      subnet_id     = "subnet-staging456"
    }
    prod = {
      instance_type = "t3.large"
      subnet_id     = "subnet-prod789"
    }
  }
}

resource "aws_instance" "env_servers" {
  for_each = var.environments
  
  ami           = data.aws_ami.amazon_linux.id
  instance_type = each.value.instance_type
  subnet_id     = each.value.subnet_id
  
  tags = {
    Name        = "server-${each.key}"
    Environment = each.key
  }
}

# Using for_each with set of strings
variable "bucket_names" {
  type    = set(string)
  default = ["logs", "data", "backups"]
}

resource "aws_s3_bucket" "storage" {
  for_each = var.bucket_names
  
  bucket = "${var.project_name}-${each.value}-${var.environment}"
  
  tags = {
    Purpose = each.value
  }
}

# Reference specific bucket
output "logs_bucket" {
  value = aws_s3_bucket.storage["logs"].id
}
```

**Meta-Argument: depends_on**

```hcl
# Explicit dependency when Terraform can't infer it
resource "aws_iam_role_policy" "lambda_policy" {
  name = "lambda-execution-policy"
  role = aws_iam_role.lambda.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_lambda_function" "processor" {
  function_name = "data-processor"
  role          = aws_iam_role.lambda.arn
  
  # Explicit dependency ensures policy is attached before function is created
  depends_on = [
    aws_iam_role_policy.lambda_policy,
    aws_cloudwatch_log_group.lambda_logs
  ]
  
  filename         = "lambda.zip"
  source_code_hash = filebase64sha256("lambda.zip")
  handler          = "index.handler"
  runtime          = "python3.11"
}

# Another example: VPN gateway attachment must complete before route creation
resource "aws_vpn_gateway_attachment" "vpn" {
  vpc_id         = aws_vpc.main.id
  vpn_gateway_id = aws_vpn_gateway.main.id
}

resource "aws_route" "to_datacenter" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "192.168.0.0/16"
  gateway_id             = aws_vpn_gateway.main.id
  
  # Ensure attachment completes first
  depends_on = [aws_vpn_gateway_attachment.vpn]
}
```

**Meta-Argument: lifecycle**

```hcl
# Prevent accidental deletion
resource "aws_db_instance" "production" {
  identifier     = "prod-database"
  engine         = "postgres"
  instance_class = "db.r5.2xlarge"
  
  lifecycle {
    prevent_destroy = true  # Terraform will error if you try to destroy
  }
}

# Create replacement before destroying old resource
resource "aws_instance" "web" {
  ami           = var.ami_id
  instance_type = "t3.micro"
  
  lifecycle {
    create_before_destroy = true  # Zero-downtime updates
  }
}

# Ignore changes to specific attributes
resource "aws_instance" "app" {
  ami           = var.ami_id
  instance_type = var.instance_type
  
  # Auto Scaling may change these - ignore to prevent drift
  lifecycle {
    ignore_changes = [
      ami,           # Don't update if AMI changes
      user_data,     # Ignore user_data modifications
      tags["AutoScaling"]  # Ignore specific tag changes
    ]
  }
}

# Replace resource when specific attribute changes
resource "aws_launch_template" "app" {
  name_prefix   = "app-lt-"
  image_id      = var.ami_id
  instance_type = var.instance_type
  
  lifecycle {
    create_before_destroy = true
    replace_triggered_by = [
      aws_security_group.app.id  # Replace when security group changes
    ]
  }
}

# Combine multiple lifecycle rules
resource "aws_elasticache_cluster" "redis" {
  cluster_id           = "app-cache-${var.environment}"
  engine              = "redis"
  node_type           = "cache.t3.micro"
  num_cache_nodes     = var.environment == "prod" ? 3 : 1
  parameter_group_name = "default.redis7"
  
  lifecycle {
    prevent_destroy       = var.environment == "prod" ? true : false
    create_before_destroy = true
    ignore_changes        = [num_cache_nodes]  # Allow manual scaling
  }
}
```

**Meta-Argument: provider**

```hcl
# Override default provider for specific resources
resource "aws_s3_bucket" "primary_logs" {
  provider = aws.primary
  bucket   = "logs-primary-${var.environment}"
}

resource "aws_s3_bucket" "dr_logs" {
  provider = aws.secondary
  bucket   = "logs-dr-${var.environment}"
}
```


### Resource Dependencies and Ordering

**Implicit Dependencies (Automatic):**

```hcl
# Terraform automatically determines order from references
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  
  tags = {
    Name = "main-vpc"
  }
}

resource "aws_subnet" "public" {
  vpc_id     = aws_vpc.main.id  # Implicit dependency on VPC
  cidr_block = "10.0.1.0/24"
  
  tags = {
    Name = "public-subnet"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id  # Implicit dependency on VPC
  
  tags = {
    Name = "main-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id  # Implicit dependency on VPC
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id  # Implicit dependency on IGW
  }
  
  tags = {
    Name = "public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id      # Implicit dependency on subnet
  route_table_id = aws_route_table.public.id # Implicit dependency on route table
}

# Terraform creates in this order:
# 1. aws_vpc.main
# 2. aws_subnet.public, aws_internet_gateway.main (parallel)
# 3. aws_route_table.public
# 4. aws_route_table_association.public
```

**Explicit Dependencies (Manual Override):**

```hcl
# When Terraform can't detect dependencies automatically
resource "aws_s3_bucket" "app_data" {
  bucket = "app-data-${var.environment}"
}

resource "aws_instance" "app" {
  ami           = var.ami_id
  instance_type = "t3.micro"
  
  # IAM instance profile must exist before EC2 instance
  iam_instance_profile = aws_iam_instance_profile.app.name
  
  # Explicit dependency: ensure S3 bucket exists first
  # (even though there's no direct reference)
  depends_on = [
    aws_s3_bucket.app_data,
    aws_iam_role_policy_attachment.app_s3_access
  ]
  
  user_data = <<-EOF
              #!/bin/bash
              aws s3 cp s3://${aws_s3_bucket.app_data.id}/config.json /etc/app/
              EOF
}
```


## Variables: Making Configurations Flexible

### Input Variables Deep Dive

**Complete Variable Declaration:**

```hcl
# variables.tf

variable "aws_region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-east-1"
  
  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]$", var.aws_region))
    error_message = "AWS region must be in format: us-east-1, eu-west-2, etc."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
  
  validation {
    condition     = can(regex("^t3\\.", var.instance_type))
    error_message = "Only t3 instance family allowed for cost optimization."
  }
}

variable "enable_monitoring" {
  description = "Enable detailed CloudWatch monitoring"
  type        = bool
  default     = false
}

variable "allowed_cidr_blocks" {
  description = "List of CIDR blocks allowed to access resources"
  type        = list(string)
  default     = []
  
  validation {
    condition = alltrue([
      for cidr in var.allowed_cidr_blocks : can(cidrhost(cidr, 0))
    ])
    error_message = "All elements must be valid CIDR blocks."
  }
}

variable "tags" {
  description = "Additional tags for resources"
  type        = map(string)
  default     = {}
}

variable "database_config" {
  description = "Database configuration settings"
  type = object({
    engine_version    = string
    instance_class    = string
    allocated_storage = number
    multi_az          = bool
  })
  default = {
    engine_version    = "14.7"
    instance_class    = "db.t3.micro"
    allocated_storage = 20
    multi_az          = false
  }
}

variable "db_password" {
  description = "Database master password"
  type        = string
  sensitive   = true  # Hides value in output
  
  validation {
    condition     = length(var.db_password) >= 16
    error_message = "Password must be at least 16 characters long."
  }
}
```


### Variable Assignment Methods

**Method 1: terraform.tfvars (Recommended for environments):**

```hcl
# terraform.tfvars (auto-loaded)
aws_region  = "us-east-1"
environment = "production"

instance_type     = "t3.large"
enable_monitoring = true

allowed_cidr_blocks = [
  "10.0.0.0/8",
  "172.16.0.0/12"
]

tags = {
  Project   = "WebApp"
  Team      = "Platform"
  ManagedBy = "Terraform"
}

database_config = {
  engine_version    = "14.7"
  instance_class    = "db.r5.xlarge"
  allocated_storage = 500
  multi_az          = true
}
```

**Method 2: Environment-specific variable files:**

```hcl
# environments/dev.tfvars
environment       = "dev"
instance_type     = "t3.micro"
enable_monitoring = false
database_config = {
  engine_version    = "14.7"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  multi_az          = false
}

# environments/prod.tfvars
environment       = "prod"
instance_type     = "t3.xlarge"
enable_monitoring = true
database_config = {
  engine_version    = "14.7"
  instance_class    = "db.r5.2xlarge"
  allocated_storage = 1000
  multi_az          = true
}

# Apply with specific file:
# terraform apply -var-file="environments/prod.tfvars"
```

**Method 3: Command-line flags:**

```bash
# Single variable
terraform apply -var="environment=prod"

# Multiple variables
terraform apply \
  -var="environment=prod" \
  -var="instance_type=t3.large" \
  -var="enable_monitoring=true"

# Variable file
terraform apply -var-file="prod.tfvars"

# Multiple variable files (later files override earlier)
terraform apply \
  -var-file="common.tfvars" \
  -var-file="prod.tfvars"
```

**Method 4: Environment variables:**

```bash
# Format: TF_VAR_<variable_name>
export TF_VAR_environment="production"
export TF_VAR_aws_region="us-west-2"
export TF_VAR_db_password="SuperSecurePassword123!"

terraform apply
# Variables are automatically picked up
```

**Method 5: Interactive prompt:**

```bash
# If variable has no default and isn't provided, Terraform prompts
terraform apply

var.db_password
  Database master password

  Enter a value: 
```

**Variable Precedence (highest to lowest):**

1. Command-line `-var` flags
2. `*.auto.tfvars` files (alphabetical order)
3. `terraform.tfvars` file
4. Environment variables (TF_VAR_*)
5. Default values in variable declarations
6. Interactive prompts

### Local Values (Computed Variables)

```hcl
# locals.tf

locals {
  # Computed timestamp
  deployment_timestamp = formatdate("YYYY-MM-DD-hhmm", timestamp())
  
  # Common tags merged with environment-specific
  common_tags = merge(
    var.default_tags,
    {
      Environment       = var.environment
      DeployedBy        = "Terraform"
      DeploymentDate    = local.deployment_timestamp
      TerraformWorkspace = terraform.workspace
    }
  )
  
  # Conditional naming
  name_prefix = var.environment == "prod" ? var.project_name : "${var.project_name}-${var.environment}"
  
  # Complex calculations
  total_subnet_count = (
    length(var.public_subnet_cidrs) +
    length(var.private_subnet_cidrs) +
    length(var.database_subnet_cidrs)
  )
  
  # Resource naming conventions
  vpc_name     = "${local.name_prefix}-vpc"
  cluster_name = "${local.name_prefix}-eks-cluster"
  
  # Derived configurations
  enable_nat_gateway = var.environment == "prod" ? true : false
  nat_gateway_count  = local.enable_nat_gateway ? length(var.availability_zones) : 1
  
  # Consolidated security group rules
  ingress_rules = concat(
    var.base_ingress_rules,
    var.environment == "prod" ? var.prod_additional_rules : []
  )
  
  # Dynamic user data template
  user_data = templatefile("${path.module}/user_data.tpl", {
    environment     = var.environment
    region          = var.aws_region
    cluster_name    = local.cluster_name
    app_version     = var.app_version
    enable_logging  = var.environment == "prod"
  })
}

# Using locals in resources
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = merge(
    local.common_tags,
    {
      Name = local.vpc_name
    }
  )
}

resource "aws_instance" "app" {
  count = var.instance_count
  
  ami           = data.aws_ami.amazon_linux.id
  instance_type = var.instance_type
  user_data     = local.user_data
  
  tags = merge(
    local.common_tags,
    {
      Name  = "${local.name_prefix}-app-${count.index + 1}"
      Index = count.index
    }
  )
}
```


## Outputs: Exposing Infrastructure Information

### Output Value Declarations

```hcl
# outputs.tf

# Simple string output
output "vpc_id" {
  description = "The ID of the VPC"
  value       = aws_vpc.main.id
}

# Complex object output
output "vpc_details" {
  description = "Complete VPC configuration details"
  value = {
    id                  = aws_vpc.main.id
    cidr_block          = aws_vpc.main.cidr_block
    default_route_table = aws_vpc.main.default_route_table_id
    dhcp_options_id     = aws_vpc.main.dhcp_options_id
  }
}

# List output using splat operator
output "private_subnet_ids" {
  description = "List of private subnet IDs"
  value       = aws_subnet.private[*].id
}

# Map output from for_each
output "application_servers" {
  description = "Map of application server details"
  value = {
    for k, instance in aws_instance.app : k => {
      id         = instance.id
      private_ip = instance.private_ip
      public_ip  = instance.public_ip
    }
  }
}

# Sensitive output (hidden in CLI)
output "database_password" {
  description = "Database master password"
  value       = random_password.db_password.result
  sensitive   = true  # Won't display in terraform output
}

# Conditional output
output "bastion_public_ip" {
  description = "Public IP of bastion host (if created)"
  value       = var.create_bastion ? aws_instance.bastion[0].public_ip : null
}

# Output with depends_on
output "website_endpoint" {
  description = "CloudFront distribution endpoint"
  value       = aws_cloudfront_distribution.website.domain_name
  
  # Ensure distribution is fully deployed before showing
  depends_on = [
    aws_cloudfront_distribution.website
  ]
}

# Formatted output
output "connection_string" {
  description = "Database connection string"
  value       = "postgresql://${aws_db_instance.main.username}@${aws_db_instance.main.endpoint}/${aws_db_instance.main.db_name}"
  sensitive   = true
}

# Output for consumption by other modules
output "security_group_ids" {
  description = "Security group IDs for use in other modules"
  value = {
    web      = aws_security_group.web.id
    app      = aws_security_group.app.id
    database = aws_security_group.database.id
  }
}
```


### Using Outputs from Modules

```hcl
# Root module using child module outputs

module "networking" {
  source = "./modules/vpc"
  
  vpc_cidr     = "10.0.0.0/16"
  environment  = var.environment
  project_name = var.project_name
}

module "database" {
  source = "./modules/rds"
  
  # Use outputs from networking module
  subnet_ids         = module.networking.database_subnet_ids
  vpc_id             = module.networking.vpc_id
  security_group_ids = [module.networking.database_security_group_id]
  
  environment = var.environment
}

module "application" {
  source = "./modules/ecs"
  
  # Use outputs from both previous modules
  vpc_id             = module.networking.vpc_id
  private_subnet_ids = module.networking.private_subnet_ids
  database_endpoint  = module.database.endpoint
  database_name      = module.database.database_name
  
  environment = var.environment
}

# Root module outputs aggregating child outputs
output "infrastructure_summary" {
  description = "Complete infrastructure summary"
  value = {
    vpc = {
      id         = module.networking.vpc_id
      cidr_block = module.networking.vpc_cidr
      subnets    = module.networking.all_subnet_ids
    }
    database = {
      endpoint = module.database.endpoint
      port     = module.database.port
    }
    application = {
      load_balancer_dns = module.application.alb_dns_name
      cluster_name      = module.application.ecs_cluster_name
    }
  }
}
```


### Accessing Outputs

```bash
# View all outputs
terraform output

# View specific output
terraform output vpc_id

# View sensitive output (must explicitly request)
terraform output database_password

# JSON format for scripting
terraform output -json

# Use in bash scripts
VPC_ID=$(terraform output -raw vpc_id)
echo "VPC ID: $VPC_ID"

# Parse JSON output
terraform output -json infrastructure_summary | jq '.database.endpoint.value'
```


## Data Sources: Querying Existing Resources

### Common AWS Data Sources

**Querying AMIs:**

```hcl
# Find latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]
  
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
  
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  
  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}

# Find latest Ubuntu 22.04 LTS
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]  # Canonical
  
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

# Use in resource
resource "aws_instance" "app" {
  ami           = data.aws_ami.amazon_linux_2.id
  instance_type = "t3.micro"
  
  tags = {
    AMI_Name = data.aws_ami.amazon_linux_2.name
    AMI_Date = data.aws_ami.amazon_linux_2.creation_date
  }
}
```

**Querying VPCs and Subnets:**

```hcl
# Find default VPC
data "aws_vpc" "default" {
  default = true
}

# Find VPC by tag
data "aws_vpc" "application" {
  tags = {
    Name = "application-vpc-${var.environment}"
  }
}

# Find subnets in VPC
data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.application.id]
  }
  
  tags = {
    Tier = "Private"
  }
}

# Get detailed subnet information
data "aws_subnet" "private" {
  for_each = toset(data.aws_subnets.private.ids)
  id       = each.value
}

# Use in resources
resource "aws_instance" "app" {
  count = length(data.aws_subnets.private.ids)
  
  ami       = data.aws_ami.amazon_linux_2.id
  instance_type = "t3.micro"
  subnet_id     = data.aws_subnets.private.ids[count.index]
}
```

**Querying AWS Account and Region Information:**

```hcl
# Get current AWS account details
data "aws_caller_identity" "current" {}

# Get current region
data "aws_region" "current" {}

# Get availability zones
data "aws_availability_zones" "available" {
  state = "available"
  
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

# Use in configurations
locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  
  # Create subnets across all AZs
  az_count   = length(data.aws_availability_zones.available.names)
}

resource "aws_subnet" "public" {
  count = local.az_count
  
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  tags = {
    Name      = "public-subnet-${data.aws_availability_zones.available.names[count.index]}"
    AccountID = local.account_id
    Region    = local.region
  }
}
```

**Querying IAM and Security:**

```hcl
# Get IAM policy document
data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"
    
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    
    actions = ["sts:AssumeRole"]
  }
}

# Get existing IAM role
data "aws_iam_role" "existing" {
  name = "existing-role-name"
}

# Get partition (aws, aws-cn, aws-us-gov)
data "aws_partition" "current" {}

# Use in ARN construction
locals {
  kms_key_arn = "arn:${data.aws_partition.current.partition}:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:key/${var.kms_key_id}"
}
```

**Querying Secrets Manager:**

```hcl
# Get secret value
data "aws_secretsmanager_secret" "db_password" {
  name = "prod/database/master-password"
}

data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = data.aws_secretsmanager_secret.db_password.id
}

# Use in database configuration
resource "aws_db_instance" "main" {
  identifier = "production-db"
  engine     = "postgres"
  
  username = "admin"
  password = jsondecode(
    data.aws_secretsmanager_secret_version.db_password.secret_string
  )["password"]
  
  instance_class = "db.r5.large"
}
```

**Querying S3 Buckets:**

```hcl
# Get existing S3 bucket
data "aws_s3_bucket" "existing" {
  bucket = "my-existing-bucket-${var.environment}"
}

# Get S3 object
data "aws_s3_object" "config" {
  bucket = data.aws_s3_bucket.existing.id
  key    = "config/${var.environment}/app-config.json"
}

# Use configuration from S3
locals {
  app_config = jsondecode(data.aws_s3_object.config.body)
}

resource "aws_instance" "app" {
  ami           = data.aws_ami.amazon_linux_2.id
  instance_type = local.app_config.instance_type
  
  user_data = templatefile("${path.module}/user_data.sh", {
    config = local.app_config
  })
}
```


## ⚠️ Common Pitfalls

### Pitfall 1: Not Understanding State File Structure

**❌ PROBLEM:**

```bash
# Manually editing state file
vim terraform.tfstate  # NEVER DO THIS!

# Or trying to "fix" state issues manually
{
  "resources": [
    {
      "type": "aws_instance",
      "name": "web",
      "instances": [
        {
          "attributes": {
            "id": "i-wrong-id"  # Manual edit - WILL BREAK EVERYTHING
          }
        }
      ]
    }
  ]
}
```

**✅ SOLUTION:**

```bash
# Use state commands for modifications
terraform state list
terraform state show aws_instance.web
terraform state mv aws_instance.old aws_instance.new
terraform state rm aws_instance.deprecated

# Import existing resources
terraform import aws_instance.web i-1234567890abcdef0

# Refresh state from actual infrastructure
terraform refresh  # or terraform apply -refresh-only
```


### Pitfall 2: Circular Dependencies

**❌ PROBLEM:**

```hcl
# Resource A depends on B, B depends on A
resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = aws_vpc.main.id
  
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]  # Depends on ALB SG
  }
}

resource "aws_security_group" "alb" {
  name   = "alb-sg"
  vpc_id = aws_vpc.main.id
  
  egress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]  # Depends on Web SG
  }
}

# Error: Cycle: aws_security_group.web, aws_security_group.alb
```

**✅ SOLUTION:**

```hcl
# Break the cycle using separate rule resources
resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = aws_vpc.main.id
  
  # No inline rules - defined separately below
}

resource "aws_security_group" "alb" {
  name   = "alb-sg"
  vpc_id = aws_vpc.main.id
  
  # No inline rules - defined separately below
}

# Define rules separately to break circular dependency
resource "aws_security_group_rule" "web_from_alb" {
  type                     = "ingress"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  security_group_id        = aws_security_group.web.id
  source_security_group_id = aws_security_group.alb.id
}

resource "aws_security_group_rule" "alb_to_web" {
  type                     = "egress"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  security_group_id        = aws_security_group.alb.id
  source_security_group_id = aws_security_group.web.id
}
```


### Pitfall 3: Using count When for_each is Better

**❌ PROBLEM:**

```hcl
# Using count with list of complex objects
variable "users" {
  default = ["alice", "bob", "charlie"]
}

resource "aws_iam_user" "users" {
  count = length(var.users)
  name  = var.users[count.index]
}

# Problem: If you remove "bob" from middle of list:
# variable "users" {
#   default = ["alice", "charlie"]  # Removed bob
# }

# Terraform will:
# - Keep users[0] (alice) unchanged
# - UPDATE users[1] from bob to charlie (not what you want!)
# - DELETE users[2] (charlie)
# Result: Bob still exists, Charlie gets recreated!
```

**✅ SOLUTION:**

```hcl
# Use for_each with set
variable "users" {
  type    = set(string)
  default = ["alice", "bob", "charlie"]
}

resource "aws_iam_user" "users" {
  for_each = var.users
  name     = each.value
}

# Now removing "bob":
# variable "users" {
#   type    = set(string)
#   default = ["alice", "charlie"]
# }

# Terraform will:
# - Keep alice unchanged
# - DELETE bob only
# - Keep charlie unchanged
# Perfect!
```


### Pitfall 4: Not Validating Input Variables

**❌ PROBLEM:**

```hcl
# No validation allows invalid values
variable "environment" {
  type    = string
  default = "dev"
}

# Someone runs:
# terraform apply -var="environment=prodcution"  # Typo!
# Result: Creates resources with wrong environment tag
```

**✅ SOLUTION:**

```hcl
variable "environment" {
  description = "Environment name"
  type        = string
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  
  validation {
    condition = can(regex("^t3\\.(micro|small|medium|large|xlarge)$", var.instance_type))
    error_message = "Instance type must be a valid t3 instance type."
  }
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }
}
```


### Pitfall 5: Ignoring Terraform Formatting

**❌ PROBLEM:**

```hcl
# Inconsistent formatting causes merge conflicts
resource "aws_instance" "web" {
ami="ami-12345"
  instance_type   ="t3.micro"
tags={
Name="web-server"
    Environment="prod"
  }
}
```

**✅ SOLUTION:**

```bash
# Always format before committing
terraform fmt -recursive

# Set up pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
terraform fmt -check -recursive || {
  echo "Terraform files need formatting. Run: terraform fmt -recursive"
  exit 1
}
EOF

chmod +x .git/hooks/pre-commit

# Or use pre-commit framework
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/antonbabenko/pre-commit-terraform
    rev: v1.88.0
    hooks:
      - id: terraform_fmt
      - id: terraform_validate
      - id: terraform_docs
```


### Pitfall 6: Hardcoding Values That Should Be Dynamic

**❌ PROBLEM:**

```hcl
# Hardcoded AMI ID - breaks in different regions
resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"  # us-east-1 only!
  instance_type = "t3.micro"
}

# Breaks when deploying to us-west-2
```

**✅ SOLUTION:**

```hcl
# Use data source to dynamically fetch AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
  
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "web" {
  ami           = data.aws_ami.amazon_linux.id  # Works in any region
  instance_type = "t3.micro"
}
```


### Pitfall 7: Not Using Remote State from Day One

**❌ PROBLEM:**

```bash
# Working with local state
ls -la
# terraform.tfstate
# terraform.tfstate.backup

# Team member makes changes
# State conflict!
# Lost infrastructure tracking
```

**✅ SOLUTION:**

```hcl
# Set up remote state immediately
terraform {
  backend "s3" {
    bucket         = "company-terraform-state"
    key            = "prod/infrastructure.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-locks"
    
    # Prevent accidentally destroying state
    skip_region_validation      = false
    skip_credentials_validation = false
  }
}

# Create backend resources first (one-time)
resource "aws_s3_bucket" "terraform_state" {
  bucket = "company-terraform-state"
  
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_dynamodb_table" "terraform_locks" {
  name         = "terraform-state-locks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"
  
  attribute {
    name = "LockID"
    type = "S"
  }
}
```


### Pitfall 8: Not Understanding Terraform Graph

**❌ PROBLEM:**

```bash
# Resources created in wrong order causing failures
# No understanding of dependencies
```

**✅ SOLUTION:**

```bash
# Visualize dependency graph
terraform graph | dot -Tsvg > graph.svg

# Or use online visualizer
terraform graph | pbcopy  # macOS
# Paste into https://dreampuf.github.io/GraphvizOnline/

# Understand execution plan
terraform plan -out=tfplan
terraform show -json tfplan | jq '.resource_changes'

# See detailed resource dependencies
terraform state list
terraform state show aws_instance.web
```


### Pitfall 9: Using Sensitive Data Incorrectly

**❌ PROBLEM:**

```hcl
# Sensitive value exposed in output
output "database_connection" {
  value = "postgresql://admin:${var.db_password}@${aws_db_instance.main.endpoint}/mydb"
}

# Appears in:
# - terraform output
# - terraform plan
# - Logs
# - State file (visible to anyone with state access)
```

**✅ SOLUTION:**

```hcl
# Mark outputs as sensitive
output "database_connection" {
  description = "Database connection string"
  value       = "postgresql://admin:${var.db_password}@${aws_db_instance.main.endpoint}/mydb"
  sensitive   = true  # Hidden in CLI output
}

# Better: Store in Secrets Manager
resource "aws_secretsmanager_secret" "db_connection" {
  name = "prod/database/connection-string"
}

resource "aws_secretsmanager_secret_version" "db_connection" {
  secret_id = aws_secretsmanager_secret.db_connection.id
  secret_string = jsonencode({
    username = aws_db_instance.main.username
    password = var.db_password
    endpoint = aws_db_instance.main.endpoint
    database = aws_db_instance.main.db_name
  })
}

# Application retrieves from Secrets Manager at runtime
```


### Pitfall 10: Not Planning for State Recovery

**❌ PROBLEM:**

```bash
# State file corrupted or deleted
# No backup strategy
# Infrastructure orphaned
```

**✅ SOLUTION:**

```hcl
# Enable S3 versioning for state bucket
resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

# Enable MFA delete for production state
resource "aws_s3_bucket_versioning" "terraform_state_prod" {
  bucket = aws_s3_bucket.terraform_state.id
  
  versioning_configuration {
    status     = "Enabled"
    mfa_delete = "Enabled"
  }
  
  mfa = "${var.mfa_device_arn} ${var.mfa_token}"
}

# Lifecycle policy for state backups
resource "aws_s3_bucket_lifecycle_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  rule {
    id     = "archive-old-versions"
    status = "Enabled"
    
    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "GLACIER"
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }
}

# Recover from specific version
# aws s3api list-object-versions --bucket company-terraform-state --prefix prod/
# aws s3api get-object --bucket company-terraform-state --key prod/infrastructure.tfstate --version-id VERSION_ID terraform.tfstate
```


## 💡 Expert Tips from the Field

1. **"Use terraform validate before every plan"** - Catches syntax errors immediately without making API calls. Save time and avoid rate limits.
2. **"Always use data.aws_caller_identity to verify you're in the right account"** - Add this check to prevent deploying to wrong AWS accounts: `condition = data.aws_caller_identity.current.account_id == var.expected_account_id`
3. **"Leverage AWS Provider 6.0's default_tags feature"** - Set tags once in provider block, they apply to ALL resources. Saves hundreds of lines of code and ensures consistency.
4. **"Use locals for complex expressions, not inline"** - Makes code readable and DRY. Calculate once, reference everywhere.
5. **"Create a 'bootstrap' Terraform project for state backend"** - Chicken-and-egg problem: use local state to create S3/DynamoDB for remote state, then migrate. Keep bootstrap code separate.
6. **"Use for_each instead of count for anything you might reorder"** - count is index-based (fragile), for_each is key-based (stable). Worth the extra complexity.
7. **"Set lifecycle { create_before_destroy = true } on anything user-facing"** - Zero-downtime deployments for instances, launch templates, DNS records, etc.
8. **"Use terraform workspace for temporary branches only"** - For permanent environments (dev/staging/prod), use separate directories with separate state files. Workspaces are harder to manage at scale.
9. **"Add validation blocks to every variable"** - Fail fast with clear error messages. Better than mysterious AWS API errors 5 minutes into apply.
10. **"Use templatefile() instead of heredoc for complex user_data"** - Easier to test, syntax highlight, and maintain in separate files.
11. **"Always specify provider versions with ~> operator"** - `version = "~> 6.0"` allows 6.x updates but prevents breaking 7.0 changes. Update lock file deliberately.
12. **"Use depends_on sparingly and document why"** - If you need it, there's usually a hidden dependency. Add comment explaining why Terraform can't infer it.
13. **"Export TF_LOG=TRACE only when debugging specific issues"** - Verbose logs are useful but slow. Enable temporarily, capture to file, disable after.
14. **"Use terraform console for testing expressions"** - Interactive REPL for testing functions, variable references, and complex logic before putting in code.
15. **"Set up .terraform.lock.hcl tracking in Git immediately"** - Ensures team uses same provider versions. Prevents "works on my machine" scenarios.
16. **"Use random_id or random_pet for globally unique names"** - S3 buckets, IAM roles, etc. need unique names. `random_pet.server.id` generates memorable names like "happy-dolphin".
17. **"Create a 'common' module for repeated patterns"** - Tagged S3 bucket, VPC with standard subnets, etc. Reuse across projects.
18. **"Use terraform fmt -check in CI/CD pipelines"** - Enforce formatting standards automatically. Fail PR if code isn't formatted.
19. **"Separate networking from applications in state"** - Network changes rarely, apps change frequently. Split reduces blast radius and speeds up applies.
20. **"Use data sources to avoid hardcoded ARNs"** - Find resources dynamically: `data.aws_iam_role.existing.arn` instead of hardcoded ARN strings.

## 🎯 Practical Exercises

### Exercise 1: Complete VPC with All Components

**Difficulty:** Intermediate
**Time:** 45 minutes
**Objective:** Build a production-ready VPC with public/private subnets, NAT gateways, and route tables

**Prerequisites:**

- AWS account with AdministratorAccess
- Terraform 1.15+ installed
- AWS CLI configured

**Steps:**

1. Create project structure:
```bash
mkdir terraform-vpc-complete
cd terraform-vpc-complete
```

2. Create `variables.tf`:
```hcl
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "public_subnet_cidrs" {
  description = "Public subnet CIDR blocks"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "private_subnet_cidrs" {
  description = "Private subnet CIDR blocks"
  type        = list(string)
  default     = ["10.0.11.0/24", "10.0.12.0/24", "10.0.13.0/24"]
}
```

3. Create `main.tf`:
```hcl
terraform {
  required_version = ">= 1.15.0"
  
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
      Environment = var.environment
      ManagedBy   = "Terraform"
      Project     = "VPC-Complete"
    }
  }
}

# VPC
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name = "vpc-${var.environment}"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  
  tags = {
    Name = "igw-${var.environment}"
  }
}

# Public Subnets
resource "aws_subnet" "public" {
  count = length(var.public_subnet_cidrs)
  
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true
  
  tags = {
    Name = "public-subnet-${var.availability_zones[count.index]}"
    Tier = "Public"
  }
}

# Private Subnets
resource "aws_subnet" "private" {
  count = length(var.private_subnet_cidrs)
  
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]
  
  tags = {
    Name = "private-subnet-${var.availability_zones[count.index]}"
    Tier = "Private"
  }
}

# Elastic IPs for NAT Gateways
resource "aws_eip" "nat" {
  count  = var.environment == "prod" ? length(var.availability_zones) : 1
  domain = "vpc"
  
  tags = {
    Name = "eip-nat-${count.index + 1}"
  }
  
  depends_on = [aws_internet_gateway.main]
}

# NAT Gateways
resource "aws_nat_gateway" "main" {
  count = var.environment == "prod" ? length(var.availability_zones) : 1
  
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  
  tags = {
    Name = "nat-gateway-${count.index + 1}"
  }
  
  depends_on = [aws_internet_gateway.main]
}

# Public Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  
  tags = {
    Name = "public-rt"
  }
}

# Public Route Table Associations
resource "aws_route_table_association" "public" {
  count = length(var.public_subnet_cidrs)
  
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Private Route Tables
resource "aws_route_table" "private" {
  count = var.environment == "prod" ? length(var.availability_zones) : 1
  
  vpc_id = aws_vpc.main.id
  
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[count.index].id
  }
  
  tags = {
    Name = "private-rt-${count.index + 1}"
  }
}

# Private Route Table Associations
resource "aws_route_table_association" "private" {
  count = length(var.private_subnet_cidrs)
  
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[var.environment == "prod" ? count.index : 0].id
}
```

4. Create `outputs.tf`:
```hcl
output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "VPC CIDR block"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "List of public subnet IDs"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "List of private subnet IDs"
  value       = aws_subnet.private[*].id
}

output "nat_gateway_ips" {
  description = "NAT Gateway public IPs"
  value       = aws_eip.nat[*].public_ip
}
```

5. Deploy the infrastructure:
```bash
terraform init
terraform validate
terraform plan
terraform apply

# Verify in AWS Console
# Check VPC, Subnets, Route Tables, NAT Gateways

# Clean up
terraform destroy
```

**Expected Output:**

```
Apply complete! Resources: 15 added, 0 changed, 0 destroyed.

Outputs:

nat_gateway_ips = ["54.123.45.67"]
private_subnet_ids = ["subnet-abc123", "subnet-def456", "subnet-ghi789"]
public_subnet_ids = ["subnet-jkl012", "subnet-mno345", "subnet-pqr678"]
vpc_cidr = "10.0.0.0/16"
vpc_id = "vpc-0123456789abcdef0"
```

**Challenge:** Modify the configuration to create database subnets in addition to public/private, with a separate route table that has no internet access.

<details>
<summary><b>Solution: Database Subnets</b></summary>

```hcl
# Add to variables.tf
variable "database_subnet_cidrs" {
  description = "Database subnet CIDR blocks"
  type        = list(string)
  default     = ["10.0.21.0/24", "10.0.22.0/24", "10.0.23.0/24"]
}

# Add to main.tf
resource "aws_subnet" "database" {
  count = length(var.database_subnet_cidrs)
  
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.database_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]
  
  tags = {
    Name = "database-subnet-${var.availability_zones[count.index]}"
    Tier = "Database"
  }
}

resource "aws_route_table" "database" {
  vpc_id = aws_vpc.main.id
  
  # No default route - database subnets are isolated
  
  tags = {
    Name = "database-rt"
  }
}

resource "aws_route_table_association" "database" {
  count = length(var.database_subnet_cidrs)
  
  subnet_id      = aws_subnet.database[count.index].id
  route_table_id = aws_route_table.database.id
}

# Add to outputs.tf
output "database_subnet_ids" {
  description = "List of database subnet IDs"
  value       = aws_subnet.database[*].id
}
```
</details>

### Exercise 2: Dynamic Security Groups with Rules

**Difficulty:** Intermediate
**Time:** 30 minutes
**Objective:** Create security groups with dynamic rules using for_each and dynamic blocks

**Steps:**

1. Create `security-groups.tf`:
```hcl
variable "security_group_rules" {
  description = "Security group ingress rules"
  type = map(object({
    description = string
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
  }))
  default = {
    http = {
      description = "HTTP from internet"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
    https = {
      description = "HTTPS from internet"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
    ssh = {
      description = "SSH from office"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["203.0.113.0/24"]
    }
  }
}

resource "aws_security_group" "web" {
  name        = "web-server-sg"
  description = "Security group for web servers"
  vpc_id      = aws_vpc.main.id
  
  dynamic "ingress" {
    for_each = var.security_group_rules
    content {
      description = ingress.value.description
      from_port   = ingress.value.from_port
      to_port     = ingress.value.to_port
      protocol    = ingress.value.protocol
      cidr_blocks = ingress.value.cidr_blocks
    }
  }
  
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "web-server-sg"
  }
}
```

**Validation:** Run `terraform plan` and verify that three ingress rules are created.

**Challenge:** Add a variable `enable_ssh` that conditionally includes the SSH rule only when true.

### Exercise 3: Multi-Environment Configuration

**Difficulty:** Advanced
**Time:** 40 minutes
**Objective:** Create a configuration that works across dev, staging, and prod with appropriate sizing

**Steps:**

1. Create environment-specific variable files:
```bash
mkdir environments
touch environments/dev.tfvars environments/staging.tfvars environments/prod.tfvars
```

2. `environments/dev.tfvars`:
```hcl
environment       = "dev"
instance_type     = "t3.micro"
min_size          = 1
max_size          = 2
desired_capacity  = 1
enable_monitoring = false
multi_az          = false
backup_retention  = 1
```

3. `environments/prod.tfvars`:
```hcl
environment       = "prod"
instance_type     = "t3.large"
min_size          = 3
max_size          = 10
desired_capacity  = 3
enable_monitoring = true
multi_az          = true
backup_retention  = 30
```

4. Create `main.tf` that uses these variables to size resources appropriately
5. Test deployment to both environments:
```bash
terraform plan -var-file="environments/dev.tfvars"
terraform plan -var-file="environments/prod.tfvars"
```

**Challenge:** Add a validation rule that ensures prod environment always has `multi_az = true` and `backup_retention >= 7`.

### Exercise 4: State Management and Import

**Difficulty:** Advanced
**Time:** 35 minutes
**Objective:** Practice importing existing AWS resources into Terraform state

**Steps:**

1. Manually create an EC2 instance via AWS Console
2. Write Terraform configuration matching the instance
3. Import the instance:
```bash
terraform import aws_instance.existing i-1234567890abcdef0
```

4. Run `terraform plan` to verify no changes needed
5. Add additional resources (security group, EBS volume) and manage them together

**Validation:** `terraform plan` should show "No changes" after successful import.

**Challenge:** Create a script that imports multiple existing resources in bulk using `terraform import` in a loop.

### Exercise 5: Testing Terraform Functions

**Difficulty:** Beginner
**Time:** 20 minutes
**Objective:** Master Terraform functions using the interactive console

**Steps:**

1. Start Terraform console:
```bash
terraform console
```

2. Test string functions:
```hcl
> upper("hello terraform")
"HELLO TERRAFORM"

> lower("PRODUCTION")
"production"

> title("john doe")
"John Doe"

> format("server-%03d", 5)
"server-005"
```

3. Test collection functions:
```hcl
> length(["a", "b", "c"])
3

> concat(["a", "b"], ["c", "d"])
["a", "b", "c", "d"]

> merge({a = 1}, {b = 2})
{
  "a" = 1
  "b" = 2
}
```

4. Test CIDR functions:
```hcl
> cidrsubnet("10.0.0.0/16", 8, 0)
"10.0.0.0/24"

> cidrsubnet("10.0.0.0/16", 8, 1)
"10.0.1.0/24"

> cidrhost("10.0.1.0/24", 5)
"10.0.1.5"
```

**Challenge:** Use terraform console to calculate subnet CIDRs for 6 subnets from a /16 VPC CIDR.

## Visual Diagrams

### Terraform Execution Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    terraform init                            │
│  • Download providers                                        │
│  • Initialize backend                                        │
│  • Create .terraform directory                               │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│                    terraform validate                        │
│  • Syntax check                                              │
│  • Validation rules                                          │
│  • Provider schema verification                              │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼

┌─────────────────────────────────────────────────────────────┐
│                    terraform plan                            │
│  1. Load current state                                       │
│  2. Refresh state from AWS (read real resources)             │
│  3. Build dependency graph                                   │
│  4. Calculate diff (desired vs current)                      │
│  5. Show execution plan                                      │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│                    terraform apply                           │
│  1. Execute plan in dependency order                         │
│  2. Create/Update/Delete resources via AWS API               │
│  3. Update state file after each resource                    │
│  4. Handle errors and rollback if needed                     │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│                  Infrastructure Updated                      │
│  • AWS resources created/modified                            │
│  • State file reflects reality                               │
│  • Outputs displayed                                         │
└─────────────────────────────────────────────────────────────┘
```


### Resource Dependency Graph Example

```
                    ┌──────────────┐
                    │   aws_vpc    │
                    │    main      │
                    └───────┬──────┘
                            │
            ┌───────────────┼───────────────┐
            │               │               │
            ▼               ▼               ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
    │ aws_subnet   │ │ aws_subnet   │ │    aws_igw   │
    │   public     │ │   private    │ │     main     │
    └───────┬──────┘ └──────┬───────┘ └──────┬───────┘
            │               │                 │
            │               │          ┌──────▼───────┐
            │               │          │  aws_eip     │
            │               │          │    nat       │
            │               │          └──────┬───────┘
            │               │                 │
            │               │          ┌──────▼───────┐
            │               │          │aws_nat_gateway
            │               │          │    main      │
            │               │          └──────┬───────┘
            │               │                 │
            ▼               ▼                 ▼
    ┌──────────────┐ ┌──────────────────────────┐
    │aws_route_table│ │   aws_route_table        │
    │    public    │ │      private             │
    └───────┬──────┘ └──────────┬───────────────┘
            │                   │
            ▼                   ▼
    ┌──────────────┐ ┌──────────────────────────┐
    │aws_route_tbl │ │ aws_route_table_assoc    │
    │_association  │ │      private             │
    │   public     │ └──────────────────────────┘
    └──────────────┘

# Terraform automatically determines:
# 1. VPC must exist before subnets
# 2. Subnets and IGW created in parallel
# 3. NAT Gateway needs EIP and public subnet
# 4. Route tables depend on IGW/NAT Gateway
# 5. Associations are last
```


### Variable Precedence Diagram

```
                    Highest Priority
                    ───────────────
                           │
                           ▼
              ┌────────────────────────┐
              │  -var command line     │
              │  terraform apply       │
              │  -var="key=value"      │
              └────────┬───────────────┘
                       │
                       ▼
              ┌────────────────────────┐
              │  -var-file flags       │
              │  terraform apply       │
              │  -var-file="prod.tfvars"│
              └────────┬───────────────┘
                       │
                       ▼
              ┌────────────────────────┐
              │  *.auto.tfvars files   │
              │  (alphabetical order)  │
              └────────┬───────────────┘
                       │
                       ▼
              ┌────────────────────────┐
              │  terraform.tfvars      │
              │  (if present)          │
              └────────┬───────────────┘
                       │
                       ▼
              ┌────────────────────────┐
              │  TF_VAR_* environment  │
              │  variables             │
              └────────┬───────────────┘
                       │
                       ▼
              ┌────────────────────────┐
              │  Variable defaults     │
              │  in variable blocks    │
              └────────┬───────────────┘
                       │
                       ▼
                    Lowest Priority
```


### State Locking Mechanism

```
Developer A                    DynamoDB Lock Table              Developer B
───────────                    ───────────────────              ───────────

terraform apply
     │
     ├──── Acquire Lock ────────▶ ┌─────────────┐
     │                            │  LockID     │
     │                            │  User: DevA │◀──── Lock Check ────┐
     │    ◀──── Lock Granted ──── │  Time: Now  │                     │
     │                            └─────────────┘                     │
     │                                                           terraform apply
     │                                                                 │
     ├──── Read State ─────────▶  S3 State File                      │
     │                                                                 │
     ├──── Modify Resources ──▶   AWS API                             │
     │                                                                 │
     │                            ┌─────────────┐                     │
     │                            │  LockID     │                     │
     │                            │  User: DevA │──── Lock Denied ────┤
     │                            │  Time: Now  │                     │
     ├──── Update State ────────▶ S3 State File                      │
     │                            └─────────────┘                     │
     │                                                           Error: State
     ├──── Release Lock ────────▶ ┌─────────────┐               Locked!
     │                            │   Empty     │                     │
     │    ◀──── Lock Released ─── └─────────────┘                    │
     │                                   │                            │
     │                                   │                            │
     │                                   └──── Can Now Proceed ──────▶│
     ▼                                                                ▼
```


## Reference Tables

### Terraform Meta-Arguments Comparison

| Meta-Argument | Purpose | Use Case | Example |
| :-- | :-- | :-- | :-- |
| `count` | Create multiple similar resources | Fixed number of identical resources | `count = 3` creates 3 instances |
| `for_each` | Create multiple resources from map/set | Resources with unique identifiers | `for_each = var.environments` |
| `depends_on` | Explicit dependency declaration | Hidden dependencies Terraform can't infer | Wait for IAM policy before Lambda |
| `provider` | Override default provider | Multi-region or multi-account | Use `aws.secondary` provider |
| `lifecycle` | Control resource lifecycle behavior | Prevent deletion, ignore changes | `prevent_destroy = true` |

### Terraform Function Categories

| Category | Common Functions | Purpose | Example |
| :-- | :-- | :-- | :-- |
| **String** | `upper`, `lower`, `title`, `format` | String manipulation | `upper("prod")` → `"PROD"` |
| **Collection** | `length`, `concat`, `merge`, `flatten` | Work with lists/maps | `length([1,2,3])` → `3` |
| **Numeric** | `min`, `max`, `ceil`, `floor` | Mathematical operations | `max(5, 10)` → `10` |
| **Encoding** | `jsonencode`, `base64encode`, `yamlencode` | Data encoding | Convert objects to JSON |
| **Filesystem** | `file`, `templatefile`, `filebase64` | Read file contents | Load SSH keys, templates |
| **Date/Time** | `timestamp`, `formatdate` | Time operations | `timestamp()` → current time |
| **IP Network** | `cidrsubnet`, `cidrhost` | CIDR calculations | Calculate subnet ranges |
| **Type Conversion** | `tostring`, `tonumber`, `tolist` | Convert types | `tonumber("42")` → `42` |

### AWS Provider Version History (Major Features)

| Version | Release Date | Key Features | Impact |
| :-- | :-- | :-- | :-- |
| **6.0** | June 2025 | Multi-region single provider, enhanced default_tags | Simplified multi-region deployments |
| **5.0** | March 2023 | Breaking changes, new service support | Major version upgrade required |
| **4.0** | February 2022 | AWS SDK v2, performance improvements | Faster provider operations |
| **3.0** | August 2020 | Provider registry, versioning improvements | Better dependency management |

### Terraform State Commands Reference

| Command | Purpose | Example | When to Use |
| :-- | :-- | :-- | :-- |
| `terraform state list` | List all resources in state | `terraform state list` | Inventory check |
| `terraform state show` | Show detailed resource info | `terraform state show aws_instance.web` | Debug specific resource |
| `terraform state mv` | Rename resource in state | `terraform state mv aws_instance.old aws_instance.new` | Refactor without recreation |
| `terraform state rm` | Remove resource from state | `terraform state rm aws_instance.deprecated` | Stop managing resource |
| `terraform state pull` | Download remote state | `terraform state pull > backup.tfstate` | Manual backup |
| `terraform state push` | Upload state file | `terraform state push backup.tfstate` | Restore from backup |
| `terraform import` | Add existing resource to state | `terraform import aws_instance.web i-abc123` | Manage existing infrastructure |
| `terraform refresh` | Sync state with reality | `terraform refresh` | Detect drift |

### HCL Data Type Reference

| Type | Syntax | Example | Use Case |
| :-- | :-- | :-- | :-- |
| `string` | `type = string` | `"production"` | Text values, names, IDs |
| `number` | `type = number` | `42`, `3.14` | Counts, sizes, ports |
| `bool` | `type = bool` | `true`, `false` | Feature flags, conditionals |
| `list(type)` | `type = list(string)` | `["a", "b", "c"]` | Ordered collections |
| `set(type)` | `type = set(string)` | `["a", "b"]` | Unique unordered items |
| `map(type)` | `type = map(string)` | `{key = "value"}` | Key-value pairs |
| `object({...})` | `type = object({name=string})` | `{name="web"}` | Complex structures |
| `tuple([...])` | `type = tuple([string, number])` | `["web", 80]` | Fixed-length mixed types |
| `any` | `type = any` | Any value | Generic variables |

## Troubleshooting Guide

### Error: "Error locking state"

**Error Message:**

```
Error: Error acquiring the state lock

Error message: ConditionalCheckFailedException: The conditional request failed
Lock Info:
  ID:        abc123-def456
  Operation: OperationTypeApply
  Who:       user@hostname
  Version:   1.15.0
  Created:   2025-12-08 18:30:00 IST
```

**Cause:** Another Terraform process holds the state lock, or a previous run didn't release it.

**Resolution:**

```bash
# Check if lock is stale (no active process)
ps aux | grep terraform

# If no active process, force unlock (USE CAREFULLY)
terraform force-unlock abc123-def456

# Better: Wait for lock to be released
# Or coordinate with team member who has lock
```


### Error: "Provider configuration not present"

**Error Message:**

```
Error: Provider configuration not present

To work with aws_instance.web its original provider configuration at
provider["registry.terraform.io/hashicorp/aws"].alias is required, but it
has been removed.
```

**Cause:** Provider alias referenced in resource no longer exists in configuration.

**Resolution:**

```hcl
# Add missing provider configuration
provider "aws" {
  alias  = "secondary"
  region = "us-west-2"
}

# Or remove provider reference from resource
resource "aws_instance" "web" {
  # Remove: provider = aws.secondary
  ami           = var.ami_id
  instance_type = "t3.micro"
}
```


### Error: "Cycle" dependency detected

**Error Message:**

```
Error: Cycle: aws_security_group.web, aws_security_group.alb
```

**Cause:** Circular dependency between resources.

**Resolution:**

```hcl
# Break cycle by using separate rule resources
resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = aws_vpc.main.id
}

resource "aws_security_group" "alb" {
  name   = "alb-sg"
  vpc_id = aws_vpc.main.id
}

# Define rules separately
resource "aws_security_group_rule" "web_from_alb" {
  type                     = "ingress"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  security_group_id        = aws_security_group.web.id
  source_security_group_id = aws_security_group.alb.id
}
```


### Error: "Invalid index" when using count

**Error Message:**

```
Error: Invalid index

The given key does not identify an element in this collection value:
the collection has no elements.
```

**Cause:** Referencing `count.index` or array element that doesn't exist.

**Resolution:**

```hcl
# Check if count is greater than 0
resource "aws_instance" "bastion" {
  count = var.create_bastion ? 1 : 0
  # ... configuration ...
}

# Reference only if created
output "bastion_ip" {
  value = var.create_bastion ? aws_instance.bastion[^0].public_ip : null
}

# Or use for_each instead
resource "aws_instance" "bastion" {
  for_each = var.create_bastion ? {"bastion" = true} : {}
  # ... configuration ...
}
```


### Error: "ValidationException" from AWS

**Error Message:**

```
Error: Error creating DB Instance: ValidationException: The parameter MasterUserPassword is not a valid password because it is shorter than 8 characters.
```

**Cause:** AWS resource validation failure.

**Resolution:**

```hcl
# Add validation to catch errors early
variable "db_password" {
  type      = string
  sensitive = true
  
  validation {
    condition     = length(var.db_password) >= 8
    error_message = "Password must be at least 8 characters long."
  }
  
  validation {
    condition     = can(regex("[A-Z]", var.db_password))
    error_message = "Password must contain at least one uppercase letter."
  }
}
```


### Error: "Resource not found" after manual deletion

**Error Message:**

```
Error: Error reading EC2 Instance (i-abc123): InvalidInstanceID.NotFound
```

**Cause:** Resource was manually deleted outside Terraform.

**Resolution:**

```bash
# Remove from state
terraform state rm aws_instance.web

# Re-import if resource still needed
terraform import aws_instance.web i-new-id

# Or recreate
terraform apply
```


## Key Takeaways

- Terraform uses HashiCorp Configuration Language (HCL), a declarative syntax that describes desired infrastructure state rather than procedural steps to achieve it
- The AWS Provider 6.0 introduces enhanced multi-region support and default_tags functionality, simplifying resource management across regions and ensuring consistent tagging
- Variables provide flexibility through multiple assignment methods with clear precedence rules, while validation blocks catch errors before API calls
- Data sources enable querying existing AWS resources dynamically, avoiding hardcoded values that break across regions or accounts
- Meta-arguments (`count`, `for_each`, `depends_on`, `lifecycle`, `provider`) control resource behavior and should be chosen based on specific use cases
- State management is critical—always use remote state with locking for team collaboration and enable versioning for recovery scenarios
- Outputs expose infrastructure information for consumption by other modules or external systems, with sensitive values properly protected


## What's Next

With Terraform fundamentals mastered, you're ready to tackle state management in depth. In **Chapter 3: Remote State Management**, you'll learn how to configure S3 backends with DynamoDB locking, implement state file encryption using AWS KMS, handle state migrations between backends, and implement disaster recovery procedures. You'll also explore workspace strategies, state file security best practices, and techniques for managing state at enterprise scale. Understanding state management is crucial before diving into team collaboration and CI/CD pipelines covered in subsequent chapters.

## Additional Resources

**Official Documentation:**

- [Terraform Language Documentation](https://developer.hashicorp.com/terraform/language) - Complete HCL reference
- [AWS Provider 6.0 Documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs) - All AWS resources and data sources
- [Terraform Functions Reference](https://developer.hashicorp.com/terraform/language/functions) - Complete function library
- [Terraform CLI Commands](https://developer.hashicorp.com/terraform/cli/commands) - Command-line reference

**AWS Resources:**

- [AWS Prescriptive Guidance - Terraform Best Practices](https://docs.aws.amazon.com/prescriptive-guidance/latest/terraform-aws-provider-best-practices/) - AWS-specific guidance
- [Terraform Module Registry - AWS Modules](https://registry.terraform.io/namespaces/terraform-aws-modules) - Community-maintained modules
- [AWS Architecture Center](https://aws.amazon.com/architecture/) - Reference architectures

**Community Resources:**

- [Terraform Best Practices](https://www.terraform-best-practices.com/) - Community-driven best practices
- [Spacelift Terraform Best Practices](https://spacelift.io/blog/terraform-best-practices) - 20 curated best practices
- [Anton Babenko's Terraform Modules](https://github.com/terraform-aws-modules) - Production-ready AWS modules

**Tools:**

- [terraform-docs](https://terraform-docs.io/) - Auto-generate documentation
- [tfsec](https://aquasecurity.github.io/tfsec/) - Security scanner for Terraform
- [Infracost](https://www.infracost.io/) - Cost estimation for Terraform
- [Terrascan](https://runterrascan.io/) - Policy as code scanner
- [Checkov](https://www.checkov.io/) - Static code analysis

**Practice Environments:**

- [HashiCorp Learn Tutorials](https://learn.hashicorp.com/terraform) - Interactive tutorials
- [AWS Free Tier](https://aws.amazon.com/free/) - Practice with free AWS resources
- [LocalStack](https://localstack.cloud/) - Local AWS cloud emulator for testing

**Books and Courses:**

- "Terraform: Up \& Running" by Yevgeniy Brikman - Comprehensive guide
- "Infrastructure as Code" by Kief Morris - Principles and patterns
- A Cloud Guru Terraform Courses - Video-based learning

***

**Practice Makes Perfect:** The exercises in this chapter form the foundation for everything that follows. Repeat them until the workflows become second nature. Experiment with different configurations, deliberately break things to understand error messages, and build muscle memory for common patterns. Terraform mastery comes from hands-on experience!