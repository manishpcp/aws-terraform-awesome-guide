# Chapter 9: Advanced Terraform Features

## Introduction

Terraform's advanced features transform static resource definitions into dynamic, intelligent infrastructure code that adapts to changing requirements without duplication. The difference between basic and advanced Terraform usage isn't knowing more resources—it's mastering the meta-arguments, expressions, and patterns that eliminate repetition, enforce safety guardrails, and create self-documenting configurations. A beginner writes 200 lines to create 10 similar security group rules; an expert writes 20 lines with `for_each` and generates those same rules dynamically from a data structure.

These features solve real production problems: `count` and `for_each` eliminate copy-paste configurations that become maintenance nightmares, dynamic blocks turn 50 lines of repeated ingress rules into 5 lines of declarative logic, lifecycle rules prevent accidental deletion of production databases, and data sources enable cross-stack references without hardcoding ARNs. When you find yourself copying and pasting resource blocks with minor variations, or manually updating multiple environments when configuration changes, or nervously running `terraform apply` hoping you don't destroy critical infrastructure—these are signals you need advanced features.

This chapter covers the meta-arguments and patterns that separate operational Terraform code from prototype scripts. You'll learn when to use `for_each` over `count` (hint: almost always), how dynamic blocks create flexible nested configurations, how to conditionally create resources based on environment or feature flags, how data sources and remote state enable module composition, and how lifecycle rules protect production infrastructure from accidents. Master these features and you'll write less code that does more, with built-in safety and predictability that scales from 10 resources to 10,000.

## Working with for_each and count

### Understanding count vs for_each

Both `count` and `for_each` create multiple resource instances, but they address different use cases with critical implications for stability.

**Count: Index-Based Resource Creation**

```hcl
# Creating multiple identical EC2 instances
resource "aws_instance" "web" {
  count = 3
  
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  
  tags = {
    Name = "web-server-${count.index}"
  }
}

# Access instances by index
# aws_instance.web[^0]
# aws_instance.web
# aws_instance.web
```

**Problem with count:** Index-based addressing causes cascading changes when elements are removed from the middle:

```hcl
# Initial state: count = 3
# aws_instance.web[^0] - web-server-0
# aws_instance.web - web-server-1
# aws_instance.web - web-server-2

# If you change count to 2:
# Terraform destroys aws_instance.web
# ✅ Expected behavior

# If you remove the middle instance (index 1):
variable "instance_count" {
  default = 3
}

# But what if you want to remove just web-server-1?
# You can't with count! You'd have to:
# 1. Destroy all instances after the removed one
# 2. Recreate them with new indices
# ❌ This causes unnecessary downtime
```

**for_each: Key-Based Resource Creation (Recommended)**

```hcl
# Using for_each with a map
variable "instances" {
  type = map(object({
    instance_type = string
    ami           = string
  }))
  
  default = {
    web1 = {
      instance_type = "t3.micro"
      ami           = "ami-0c55b159cbfafe1f0"
    }
    web2 = {
      instance_type = "t3.small"
      ami           = "ami-0c55b159cbfafe1f0"
    }
    web3 = {
      instance_type = "t3.micro"
      ami           = "ami-0c55b159cbfafe1f0"
    }
  }
}

resource "aws_instance" "web" {
  for_each = var.instances
  
  ami           = each.value.ami
  instance_type = each.value.instance_type
  
  tags = {
    Name = "web-server-${each.key}"
  }
}

# Access instances by key
# aws_instance.web["web1"]
# aws_instance.web["web2"]
# aws_instance.web["web3"]
```

**Benefit:** Removing "web2" only destroys that specific instance without affecting others:

```hcl
variable "instances" {
  default = {
    web1 = { ... }
    # web2 removed - only that instance destroyed
    web3 = { ... }
  }
}
# ✅ Stable: Only aws_instance.web["web2"] is destroyed
```


### Comparison Table

| Feature | count | for_each |
| :-- | :-- | :-- |
| **Input Type** | Integer | Map or set of strings |
| **Resource Addressing** | Index-based: `resource[^0]` | Key-based: `resource["key"]` |
| **Best For** | Fixed number of identical resources | Dynamic, unique resources |
| **Deletion Stability** | ❌ Shifting indices cause cascades | ✅ Key-based deletion is surgical |
| **Configuration Variance** | Limited (only index differs) | ✅ Full per-instance configuration |
| **Recommended Use** | Rarely (simple cases only) | ✅ Almost always preferred |

**Recommendation:** Use `for_each` by default unless you have a compelling reason for `count`.

### Practical for_each Examples

**1. Creating Multiple S3 Buckets with Unique Configurations**

```hcl
locals {
  buckets = {
    logs = {
      versioning_enabled = true
      lifecycle_days     = 90
      public_access      = false
    }
    assets = {
      versioning_enabled = false
      lifecycle_days     = 30
      public_access      = true
    }
    backups = {
      versioning_enabled = true
      lifecycle_days     = 365
      public_access      = false
    }
  }
}

resource "aws_s3_bucket" "main" {
  for_each = local.buckets
  
  bucket = "${var.environment}-${each.key}"
  
  tags = {
    Name    = "${var.environment}-${each.key}"
    Purpose = each.key
  }
}

resource "aws_s3_bucket_versioning" "main" {
  for_each = local.buckets
  
  bucket = aws_s3_bucket.main[each.key].id
  
  versioning_configuration {
    status = each.value.versioning_enabled ? "Enabled" : "Disabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "main" {
  for_each = local.buckets
  
  bucket = aws_s3_bucket.main[each.key].id
  
  rule {
    id     = "expire-old-objects"
    status = "Enabled"
    
    expiration {
      days = each.value.lifecycle_days
    }
  }
}

resource "aws_s3_bucket_public_access_block" "main" {
  for_each = { for k, v in local.buckets : k => v if !v.public_access }
  
  bucket = aws_s3_bucket.main[each.key].id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

**2. Creating IAM Users from a List**

```hcl
variable "developers" {
  type = set(string)
  default = [
    "alice",
    "bob",
    "charlie"
  ]
}

resource "aws_iam_user" "developers" {
  for_each = var.developers
  
  name = each.key
  
  tags = {
    Team = "Engineering"
    Role = "Developer"
  }
}

resource "aws_iam_user_policy_attachment" "developer_access" {
  for_each = aws_iam_user.developers
  
  user       = each.value.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

# Generate access keys
resource "aws_iam_access_key" "developers" {
  for_each = aws_iam_user.developers
  
  user = each.value.name
}

output "developer_access_keys" {
  value = {
    for username, key in aws_iam_access_key.developers :
    username => {
      access_key = key.id
      secret_key = key.secret
    }
  }
  sensitive = true
}
```

**3. Creating Security Groups with Dynamic Rules**

```hcl
variable "security_groups" {
  type = map(object({
    description = string
    ingress_rules = list(object({
      from_port   = number
      to_port     = number
      protocol    = string
      cidr_blocks = list(string)
      description = string
    }))
    egress_rules = list(object({
      from_port   = number
      to_port     = number
      protocol    = string
      cidr_blocks = list(string)
      description = string
    }))
  }))
  
  default = {
    web = {
      description = "Security group for web servers"
      ingress_rules = [
        {
          from_port   = 80
          to_port     = 80
          protocol    = "tcp"
          cidr_blocks = ["0.0.0.0/0"]
          description = "HTTP from internet"
        },
        {
          from_port   = 443
          to_port     = 443
          protocol    = "tcp"
          cidr_blocks = ["0.0.0.0/0"]
          description = "HTTPS from internet"
        }
      ]
      egress_rules = [
        {
          from_port   = 0
          to_port     = 0
          protocol    = "-1"
          cidr_blocks = ["0.0.0.0/0"]
          description = "All outbound traffic"
        }
      ]
    }
    
    database = {
      description = "Security group for RDS"
      ingress_rules = [
        {
          from_port   = 5432
          to_port     = 5432
          protocol    = "tcp"
          cidr_blocks = ["10.0.0.0/16"]
          description = "PostgreSQL from VPC"
        }
      ]
      egress_rules = []
    }
  }
}

resource "aws_security_group" "main" {
  for_each = var.security_groups
  
  name        = "${var.environment}-${each.key}-sg"
  description = each.value.description
  vpc_id      = var.vpc_id
  
  tags = {
    Name = "${var.environment}-${each.key}-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "main" {
  for_each = merge([
    for sg_name, sg_config in var.security_groups : {
      for idx, rule in sg_config.ingress_rules :
      "${sg_name}-ingress-${idx}" => {
        security_group_id = aws_security_group.main[sg_name].id
        from_port         = rule.from_port
        to_port           = rule.to_port
        ip_protocol       = rule.protocol
        cidr_ipv4         = rule.cidr_blocks[^0]
        description       = rule.description
      }
    }
  ]...)
  
  security_group_id = each.value.security_group_id
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  ip_protocol       = each.value.ip_protocol
  cidr_ipv4         = each.value.cidr_ipv4
  description       = each.value.description
}
```

**4. for_each with Conditional Logic**

```hcl
locals {
  # Create NAT gateways only for production
  nat_gateways = var.environment == "production" ? toset(var.availability_zones) : toset([])
}

resource "aws_eip" "nat" {
  for_each = local.nat_gateways
  
  domain = "vpc"
  
  tags = {
    Name = "${var.environment}-nat-eip-${each.key}"
  }
}

resource "aws_nat_gateway" "main" {
  for_each = local.nat_gateways
  
  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = aws_subnet.public[each.key].id
  
  tags = {
    Name = "${var.environment}-nat-${each.key}"
  }
}
```


### When to Use count

Use `count` only when resources are truly identical and index-based addressing makes sense:

```hcl
# Good use of count: Creating multiple identical database read replicas
resource "aws_db_instance" "read_replica" {
  count = var.read_replica_count
  
  replicate_source_db = aws_db_instance.primary.identifier
  instance_class      = var.replica_instance_class
  
  # Only difference is index
  identifier = "${aws_db_instance.primary.identifier}-replica-${count.index + 1}"
}

# Good use of count: Conditional resource creation
resource "aws_cloudwatch_log_group" "app" {
  count = var.enable_logging ? 1 : 0
  
  name              = "/aws/app/${var.app_name}"
  retention_in_days = 30
}

# Access with: aws_cloudwatch_log_group.app[^0]
```

**Converting count to for_each:**

```hcl
# Before (count)
resource "aws_instance" "web" {
  count = 3
  
  ami           = "ami-123456"
  instance_type = "t3.micro"
  
  tags = {
    Name = "web-${count.index}"
  }
}

# After (for_each - more stable)
locals {
  instances = toset(["web-1", "web-2", "web-3"])
}

resource "aws_instance" "web" {
  for_each = local.instances
  
  ami           = "ami-123456"
  instance_type = "t3.micro"
  
  tags = {
    Name = each.key
  }
}
```


## Dynamic Blocks for Flexible Configurations

Dynamic blocks eliminate repetitive nested blocks using `for_each` syntax.

### Basic Dynamic Block Syntax

```hcl
dynamic "BLOCK_TYPE" {
  for_each = COLLECTION
  
  content {
    # Block configuration using BLOCK_TYPE.value or BLOCK_TYPE.key
  }
}
```


### Example 1: Security Group Rules

**Without Dynamic Blocks (Repetitive):**

```hcl
resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = var.vpc_id
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP"
  }
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS"
  }
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "SSH from VPC"
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound"
  }
}
```

**With Dynamic Blocks (DRY):**

```hcl
locals {
  ingress_rules = [
    {
      port        = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
      description = "HTTP"
    },
    {
      port        = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
      description = "HTTPS"
    },
    {
      port        = 22
      protocol    = "tcp"
      cidr_blocks = ["10.0.0.0/16"]
      description = "SSH from VPC"
    }
  ]
  
  egress_rules = [
    {
      port        = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
      description = "All outbound"
    }
  ]
}

resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = var.vpc_id
  
  dynamic "ingress" {
    for_each = local.ingress_rules
    
    content {
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = ingress.value.protocol
      cidr_blocks = ingress.value.cidr_blocks
      description = ingress.value.description
    }
  }
  
  dynamic "egress" {
    for_each = local.egress_rules
    
    content {
      from_port   = egress.value.port
      to_port     = egress.value.port
      protocol    = egress.value.protocol
      cidr_blocks = egress.value.cidr_blocks
      description = egress.value.description
    }
  }
}
```


### Example 2: ALB Listener Rules with Dynamic Actions

```hcl
variable "alb_listener_rules" {
  type = list(object({
    priority = number
    conditions = list(object({
      path_pattern = optional(list(string))
      host_header  = optional(list(string))
    }))
    actions = list(object({
      type             = string
      target_group_arn = optional(string)
      redirect = optional(object({
        status_code = string
        protocol    = string
        host        = string
        path        = string
      }))
    }))
  }))
}

resource "aws_lb_listener_rule" "main" {
  for_each = { for idx, rule in var.alb_listener_rules : idx => rule }
  
  listener_arn = aws_lb_listener.main.arn
  priority     = each.value.priority
  
  dynamic "condition" {
    for_each = each.value.conditions
    
    content {
      dynamic "path_pattern" {
        for_each = condition.value.path_pattern != null ? [condition.value.path_pattern] : []
        
        content {
          values = path_pattern.value
        }
      }
      
      dynamic "host_header" {
        for_each = condition.value.host_header != null ? [condition.value.host_header] : []
        
        content {
          values = host_header.value
        }
      }
    }
  }
  
  dynamic "action" {
    for_each = each.value.actions
    
    content {
      type             = action.value.type
      target_group_arn = action.value.target_group_arn
      
      dynamic "redirect" {
        for_each = action.value.redirect != null ? [action.value.redirect] : []
        
        content {
          status_code = redirect.value.status_code
          protocol    = redirect.value.protocol
          host        = redirect.value.host
          path        = redirect.value.path
        }
      }
    }
  }
}
```


### Example 3: ECS Task Definition with Dynamic Environment Variables

```hcl
variable "container_definitions" {
  type = list(object({
    name      = string
    image     = string
    cpu       = number
    memory    = number
    essential = bool
    environment = optional(map(string), {})
    secrets     = optional(map(string), {})
    port_mappings = optional(list(object({
      container_port = number
      protocol       = string
    })), [])
  }))
}

resource "aws_ecs_task_definition" "main" {
  family                   = var.task_family
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  
  container_definitions = jsonencode([
    for container in var.container_definitions : {
      name      = container.name
      image     = container.image
      cpu       = container.cpu
      memory    = container.memory
      essential = container.essential
      
      environment = [
        for key, value in container.environment : {
          name  = key
          value = value
        }
      ]
      
      secrets = [
        for key, value in container.secrets : {
          name      = key
          valueFrom = value
        }
      ]
      
      portMappings = [
        for port_mapping in container.port_mappings : {
          containerPort = port_mapping.container_port
          protocol      = port_mapping.protocol
        }
      ]
    }
  ])
}
```


### Using iterator for Nested Dynamic Blocks

When nesting dynamic blocks, use `iterator` to avoid name collisions:

```hcl
variable "cloudfront_origins" {
  type = map(object({
    domain_name = string
    origin_path = string
    custom_headers = list(object({
      name  = string
      value = string
    }))
  }))
}

resource "aws_cloudfront_distribution" "main" {
  enabled = true
  
  dynamic "origin" {
    for_each = var.cloudfront_origins
    iterator = origin_block
    
    content {
      origin_id   = origin_block.key
      domain_name = origin_block.value.domain_name
      origin_path = origin_block.value.origin_path
      
      dynamic "custom_header" {
        for_each = origin_block.value.custom_headers
        iterator = header_block
        
        content {
          name  = header_block.value.name
          value = header_block.value.value
        }
      }
    }
  }
}
```


## Conditional Resource Creation

Create resources based on conditions using `count` or `for_each`:

### Pattern 1: Boolean Toggle

```hcl
variable "enable_monitoring" {
  type    = bool
  default = false
}

# Create CloudWatch dashboard only if monitoring enabled
resource "aws_cloudwatch_dashboard" "main" {
  count = var.enable_monitoring ? 1 : 0
  
  dashboard_name = "${var.environment}-dashboard"
  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization"]
          ]
        }
      }
    ]
  })
}

# Reference conditionally created resource
output "dashboard_arn" {
  value = var.enable_monitoring ? aws_cloudwatch_dashboard.main[^0].dashboard_arn : null
}
```


### Pattern 2: Environment-Based Conditional Creation

```hcl
locals {
  is_production = var.environment == "production"
}

# Create multi-AZ RDS only in production
resource "aws_db_instance" "main" {
  identifier = "${var.environment}-database"
  
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = var.db_instance_class
  
  allocated_storage = var.db_allocated_storage
  storage_encrypted = true
  
  # Multi-AZ only in production
  multi_az = local.is_production
  
  # Backup retention varies by environment
  backup_retention_period = local.is_production ? 30 : 7
  
  # Deletion protection only in production
  deletion_protection = local.is_production
}

# Create read replicas only in production
resource "aws_db_instance" "read_replica" {
  count = local.is_production ? var.read_replica_count : 0
  
  replicate_source_db = aws_db_instance.main.identifier
  instance_class      = var.db_instance_class
  identifier          = "${var.environment}-database-replica-${count.index + 1}"
}
```


### Pattern 3: Feature Flag Pattern

```hcl
variable "feature_flags" {
  type = map(bool)
  default = {
    enable_waf        = true
    enable_cloudfront = true
    enable_cdn_logs   = false
    enable_ipv6       = false
  }
}

# WAF only if feature enabled
resource "aws_wafv2_web_acl" "main" {
  count = var.feature_flags.enable_waf ? 1 : 0
  
  name  = "${var.environment}-waf"
  scope = "REGIONAL"
  
  default_action {
    allow {}
  }
  
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.environment}-waf-metrics"
    sampled_requests_enabled   = true
  }
}

# CloudFront with conditional IPv6
resource "aws_cloudfront_distribution" "main" {
  count = var.feature_flags.enable_cloudfront ? 1 : 0
  
  enabled         = true
  is_ipv6_enabled = var.feature_flags.enable_ipv6
  
  origin {
    domain_name = aws_s3_bucket.main.bucket_regional_domain_name
    origin_id   = "S3-${aws_s3_bucket.main.id}"
  }
  
  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-${aws_s3_bucket.main.id}"
    viewer_protocol_policy = "redirect-to-https"
    
    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }
  
  # Logging configuration only if feature enabled
  dynamic "logging_config" {
    for_each = var.feature_flags.enable_cdn_logs ?  : []
    
    content {
      bucket = aws_s3_bucket.cdn_logs[^0].bucket_domain_name
      prefix = "cloudfront/"
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
```


## Data Sources and terraform_remote_state

Data sources read information from existing infrastructure:

### Common Data Sources

```hcl
# Fetch current AWS account information
data "aws_caller_identity" "current" {}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

# Fetch current region
data "aws_region" "current" {}

# Fetch available availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

# Fetch latest Amazon Linux AMI
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
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"
}

# Fetch VPC by tag
data "aws_vpc" "main" {
  tags = {
    Name = "${var.environment}-vpc"
  }
}

# Fetch subnets in VPC
data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.main.id]
  }
  
  tags = {
    Type = "private"
  }
}

# Fetch specific subnet details
data "aws_subnet" "private" {
  for_each = toset(data.aws_subnets.private.ids)
  id       = each.value
}

# Fetch existing security group
data "aws_security_group" "default" {
  vpc_id = data.aws_vpc.main.id
  name   = "default"
}

# Fetch IAM policy document
data "aws_iam_policy_document" "assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance" {
  name               = "${var.environment}-instance-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}
```


### terraform_remote_state for Cross-Stack References

Share outputs between separate Terraform configurations:

**Network Stack (outputs vpc_id, subnet_ids):**

```hcl
# network-stack/outputs.tf
output "vpc_id" {
  value = aws_vpc.main.id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "database_subnet_ids" {
  value = aws_subnet.database[*].id
}
```

**Application Stack (reads network stack outputs):**

```hcl
# application-stack/main.tf
data "terraform_remote_state" "network" {
  backend = "s3"
  
  config = {
    bucket = "mycompany-terraform-state"
    key    = "${var.environment}/network/terraform.tfstate"
    region = "us-east-1"
  }
}

# Use network stack outputs
resource "aws_instance" "app" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"
  
  # Reference remote state output
  subnet_id = data.terraform_remote_state.network.outputs.private_subnet_ids[^0]
  
  vpc_security_group_ids = [aws_security_group.app.id]
}

resource "aws_security_group" "app" {
  name   = "${var.environment}-app-sg"
  vpc_id = data.terraform_remote_state.network.outputs.vpc_id
  
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_db_instance" "main" {
  identifier = "${var.environment}-database"
  
  # Use database subnets from network stack
  db_subnet_group_name = aws_db_subnet_group.main.name
}

resource "aws_db_subnet_group" "main" {
  name       = "${var.environment}-db-subnet-group"
  subnet_ids = data.terraform_remote_state.network.outputs.database_subnet_ids
}
```


## Local Values and Computed Attributes

### Local Values for Intermediate Calculations

```hcl
locals {
  # Environment detection
  is_production = var.environment == "production"
  
  # Common tags
  common_tags = merge(
    var.tags,
    {
      Environment = var.environment
      ManagedBy   = "Terraform"
      Project     = var.project_name
    }
  )
  
  # Computed naming
  name_prefix = "${var.project_name}-${var.environment}"
  
  # CIDR calculations
  vpc_cidr = "10.${var.environment == "production" ? 0 : var.environment == "staging" ? 10 : 20}.0.0/16"
  
  # Conditional configuration
  instance_type = local.is_production ? "t3.large" : "t3.micro"
  min_size      = local.is_production ? 3 : 1
  max_size      = local.is_production ? 10 : 2
  
  # Complex data transformation
  subnet_config = {
    for az in data.aws_availability_zones.available.names :
    az => {
      public_cidr  = cidrsubnet(local.vpc_cidr, 8, index(data.aws_availability_zones.available.names, az))
      private_cidr = cidrsubnet(local.vpc_cidr, 8, index(data.aws_availability_zones.available.names, az) + 10)
    }
  }
  
  # Flattening nested structures
  all_ingress_rules = flatten([
    for sg_name, sg in var.security_groups : [
      for rule in sg.ingress_rules : {
        sg_name     = sg_name
        from_port   = rule.from_port
        to_port     = rule.to_port
        protocol    = rule.protocol
        cidr_blocks = rule.cidr_blocks
      }
    ]
  ])
}
```


## Resource Dependencies and Ordering

### Implicit Dependencies (Automatic)

```hcl
# Terraform automatically detects dependency
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "public" {
  vpc_id     = aws_vpc.main.id  # Implicit dependency
  cidr_block = "10.0.1.0/24"
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id  # Implicit dependency
}

# Terraform creates in order: VPC → Subnet, IGW
```


### Explicit Dependencies with depends_on

```hcl
# Use depends_on when implicit dependencies aren't detected
resource "aws_iam_role" "instance" {
  name               = "instance-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_role_policy_attachment" "instance" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "instance" {
  name = "instance-profile"
  role = aws_iam_role.instance.name
}

resource "aws_instance" "web" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"
  
  iam_instance_profile = aws_iam_instance_profile.instance.name
  
  # Explicit dependency: ensure policy is attached before launching instance
  depends_on = [
    aws_iam_role_policy_attachment.instance
  ]
}

# Another example: S3 bucket policy
resource "aws_s3_bucket" "main" {
  bucket = "my-bucket"
}

resource "aws_s3_bucket_public_access_block" "main" {
  bucket = aws_s3_bucket.main.id
  
  block_public_acls   = true
  block_public_policy = true
}

resource "aws_s3_bucket_policy" "main" {
  bucket = aws_s3_bucket.main.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.main.arn}/*"
    }]
  })
  
  # Ensure public access block is created first
  depends_on = [aws_s3_bucket_public_access_block.main]
}
```


## Lifecycle Rules and prevent_destroy

Lifecycle meta-arguments control resource behavior:

### prevent_destroy: Protect Critical Resources

```hcl
# Prevent accidental deletion of production database
resource "aws_db_instance" "production" {
  identifier = "production-database"
  
  engine         = "postgres"
  instance_class = "db.r6g.xlarge"
  
  lifecycle {
    prevent_destroy = true
  }
}

# Note: terraform destroy will still fail with error
# To actually destroy, must remove prevent_destroy first

# Prevent deletion of state bucket
resource "aws_s3_bucket" "terraform_state" {
  bucket = "mycompany-terraform-state"
  
  lifecycle {
    prevent_destroy = true
  }
}

# Conditional prevent_destroy based on environment
resource "aws_db_instance" "main" {
  identifier = "${var.environment}-database"
  
  lifecycle {
    prevent_destroy = var.environment == "production"
  }
}
```


### create_before_destroy: Zero-Downtime Updates

```hcl
# Launch configuration must be created before old one destroyed
resource "aws_launch_configuration" "app" {
  name_prefix   = "${var.environment}-app-"
  image_id      = data.aws_ami.amazon_linux.id
  instance_type = var.instance_type
  
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "app" {
  name                 = "${var.environment}-app-asg"
  launch_configuration = aws_launch_configuration.app.name
  min_size             = var.min_size
  max_size             = var.max_size
  
  lifecycle {
    create_before_destroy = true
  }
}

# Blue/green deployment pattern
resource "aws_lb_target_group" "app" {
  name_prefix = "app-"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  
  lifecycle {
    create_before_destroy = true
  }
}
```


### ignore_changes: Prevent Drift Detection

```hcl
# Ignore changes made outside Terraform
resource "aws_instance" "app" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = var.instance_type
  
  # Auto Scaling modifies desired_capacity
  lifecycle {
    ignore_changes = [
      # Ignore all tag changes
      tags,
      # Ignore specific attributes
      user_data,
      # Ignore all attributes
      # all
    ]
  }
}

# Database password rotated externally
resource "aws_db_instance" "main" {
  identifier = "${var.environment}-database"
  
  engine   = "postgres"
  password = var.db_password
  
  lifecycle {
    ignore_changes = [
      password  # Password rotated by AWS Secrets Manager
    ]
  }
}

# ECS service with external auto-scaling
resource "aws_ecs_service" "app" {
  name            = "${var.environment}-app"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = var.desired_count
  
  lifecycle {
    ignore_changes = [
      desired_count  # Application Auto Scaling manages this
    ]
  }
}
```


### replace_triggered_by: Force Replacement

```hcl
# Replace instance when AMI changes
resource "aws_instance" "app" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = var.instance_type
  
  lifecycle {
    replace_triggered_by = [
      data.aws_ami.amazon_linux.id
    ]
  }
}
```


### precondition and postcondition (Terraform 1.2+)

```hcl
resource "aws_instance" "app" {
  ami           = var.ami_id
  instance_type = var.instance_type
  
  lifecycle {
    # Validate before creating
    precondition {
      condition     = data.aws_ami.selected.architecture == "x86_64"
      error_message = "AMI must be x86_64 architecture."
    }
    
    # Validate after creating
    postcondition {
      condition     = self.instance_state == "running"
      error_message = "Instance failed to reach running state."
    }
  }
}
```


## Key Advanced Feature Takeaways

- Use `for_each` instead of `count` for almost all multi-resource scenarios because key-based addressing prevents cascading changes when elements are added or removed from the middle of collections
- Dynamic blocks eliminate 80% of repetitive nested block code through `for_each` iteration over data structures, making security group rules, ALB listeners, and container definitions maintainable from centralized variable definitions
- Lifecycle rules provide essential production safeguards: `prevent_destroy` blocks accidental deletion of critical resources, `create_before_destroy` enables zero-downtime updates, and `ignore_changes` prevents external modifications from triggering unwanted replacements
- Data sources and remote state enable modular architecture where networking, security, and application layers exist in separate state files but share information through explicit dependencies rather than monolithic configurations
- Conditional resource creation using `count` or `for_each` with boolean/environment checks eliminates environment-specific code duplication while maintaining type safety and enabling feature flags for gradual rollouts

