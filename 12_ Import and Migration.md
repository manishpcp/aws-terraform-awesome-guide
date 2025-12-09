# Chapter 12: Import and Migration

## Introduction

Every organization adopting Terraform faces the same foundational challenge: existing infrastructure already runs in production, created through AWS Console clicks, CloudFormation templates, imperative scripts, or competing IaC tools—and this infrastructure cannot be recreated without downtime, data loss, and business disruption. The traditional `terraform import` command addresses this by linking existing resources to Terraform state, but historically required manually writing configuration for every resource—a painstaking process when importing hundreds of VPCs, thousands of EC2 instances, and tens of thousands of security group rules. The gap between "Terraform can manage this" and "we actually manage this with Terraform" has been measured in months of engineering effort, creating a barrier that kept teams trapped in legacy tooling despite knowing better approaches existed.

Terraform 1.5+ revolutionized this workflow with declarative import blocks and 1.14+ added automatic configuration generation through the `-generate-config-out` flag, transforming import from a manual command-line operation into a reviewable, version-controlled process that generates syntactically correct HCL as a starting point. Instead of running 500 individual `terraform import` commands and writing configuration from memory or documentation, you define import blocks in your Terraform code, run `terraform plan -generate-config-out=imported.tf`, review the generated configuration, and apply—bringing entire AWS accounts under Terraform management in hours instead of weeks. This configuration-driven approach enables bulk imports with `for_each`, previews imports during plan, integrates with CI/CD pipelines, and provides clear audit trails showing exactly what was imported when.

This chapter covers the complete spectrum of import and migration scenarios from importing a single S3 bucket to migrating 10,000+ resources from CloudFormation or manual infrastructure. You'll learn the modern import block workflow with automatic configuration generation, bulk import strategies using `for_each` and scripting, migrating from CloudFormation with stack preservation, refactoring imported code to follow best practices, managing mixed Terraform/manual environments during transition periods, and troubleshooting common import failures. Whether you're bringing a single legacy resource under management or executing a multi-month enterprise migration from CloudFormation to Terraform, these patterns will help you import safely, efficiently, and with minimal production risk.

## Modern Import Workflow (Terraform 1.5+)

### Import Blocks: The Declarative Approach

Traditional CLI import required two separate steps—import command and manual configuration writing. Import blocks unify these into a single, version-controlled process.

**Traditional CLI Import (❌ Legacy Approach):**

```bash
# Step 1: Manually write configuration (error-prone)
cat > main.tf << 'EOF'
resource "aws_s3_bucket" "existing" {
  bucket = "my-existing-bucket"
  # What else? Need to check AWS Console/API
  # Missing tags? Encryption? Versioning?
}
EOF

# Step 2: Import resource
terraform import aws_s3_bucket.existing my-existing-bucket

# Step 3: Run plan to discover missing configuration
terraform plan
# Error: Missing required argument "acl"
# Error: attribute "versioning" doesn't match state

# Step 4: Iterate until plan shows no changes
# This cycle repeats 5-10 times per resource!
```

**Modern Import Block Approach (✅ Recommended):**

```hcl
# Step 1: Define import block
import {
  to = aws_s3_bucket.existing
  id = "my-existing-bucket"
}

# Step 2: Generate configuration automatically
# terraform plan -generate-config-out=imported.tf
# Terraform generates complete, accurate configuration

# Step 3: Review and refine generated code
# Step 4: Apply to complete import
# terraform apply
```


### Automatic Configuration Generation (Terraform 1.14+)

The `-generate-config-out` flag produces syntactically correct HCL based on current resource state.

**Single Resource Import Example:**

```hcl
# import.tf - Define what to import
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
  required_version = ">= 1.14.0"
}

provider "aws" {
  region = "us-east-1"
}

# Import existing VPC
import {
  to = aws_vpc.production
  id = "vpc-0a1b2c3d4e5f67890"
}

# Import existing subnets
import {
  to = aws_subnet.public_1a
  id = "subnet-1111aaaa"
}

import {
  to = aws_subnet.public_1b
  id = "subnet-2222bbbb"
}

# Import internet gateway
import {
  to = aws_internet_gateway.main
  id = "igw-0123456789abcdef0"
}
```

**Generate Configuration:**

```bash
# Generate configuration for all import blocks
terraform plan -generate-config-out=generated.tf

# Output:
# aws_vpc.production: Preparing import... [id=vpc-0a1b2c3d4e5f67890]
# aws_vpc.production: Refreshing state... [id=vpc-0a1b2c3d4e5f67890]
# aws_subnet.public_1a: Preparing import... [id=subnet-1111aaaa]
# aws_subnet.public_1a: Refreshing state... [id=subnet-1111aaaa]
# ...
# 
# Terraform will perform the following actions:
#
#   # aws_vpc.production will be imported
#     resource "aws_vpc" "production" {
#         id = "vpc-0a1b2c3d4e5f67890"
#     }
#
# Plan: 4 to import, 0 to add, 0 to change, 0 to destroy.
#
# Terraform has generated configuration and written it to generated.tf.
# Please review the configuration and edit it as necessary before adding it to version control.
```

**Generated Configuration (generated.tf):**

```hcl
# __generated__ by Terraform
# Please review these resources and move them into your main configuration files.

# __generated__ by Terraform from "vpc-0a1b2c3d4e5f67890"
resource "aws_vpc" "production" {
  assign_generated_ipv6_cidr_block     = false
  cidr_block                           = "10.0.0.0/16"
  enable_dns_hostnames                 = true
  enable_dns_support                   = true
  enable_network_address_usage_metrics = false
  instance_tenancy                     = "default"
  ipv4_ipam_pool_id                    = null
  ipv4_netmask_length                  = null
  ipv6_cidr_block                      = null
  ipv6_cidr_block_network_border_group = null
  ipv6_ipam_pool_id                    = null
  ipv6_netmask_length                  = 0
  tags = {
    Environment = "production"
    ManagedBy   = "manual"
    Name        = "production-vpc"
  }
  tags_all = {
    Environment = "production"
    ManagedBy   = "manual"
    Name        = "production-vpc"
  }
}

# __generated__ by Terraform from "subnet-1111aaaa"
resource "aws_subnet" "public_1a" {
  assign_ipv6_address_on_creation                = false
  availability_zone                              = "us-east-1a"
  availability_zone_id                           = "use1-az1"
  cidr_block                                     = "10.0.1.0/24"
  customer_owned_ipv4_pool                       = null
  enable_dns64                                   = false
  enable_lni_at_device_index                     = 0
  enable_resource_name_dns_a_record_on_launch    = false
  enable_resource_name_dns_aaaa_record_on_launch = false
  ipv6_cidr_block                                = null
  ipv6_native                                    = false
  map_customer_owned_ip_on_launch                = false
  map_public_ip_on_launch                        = true
  outpost_arn                                    = null
  private_dns_hostname_type_on_launch            = "ip-name"
  tags = {
    Name = "production-public-1a"
    Type = "public"
  }
  tags_all = {
    Name = "production-public-1a"
    Type = "public"
  }
  vpc_id = "vpc-0a1b2c3d4e5f67890"
}

# ... (additional resources)
```

**Refining Generated Configuration:**

```hcl
# main.tf - Cleaned up version
resource "aws_vpc" "production" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name        = "production-vpc"
    Environment = "production"
    ManagedBy   = "Terraform"  # Update from "manual"
  }
}

resource "aws_subnet" "public_1a" {
  vpc_id                  = aws_vpc.production.id  # Use reference instead of hardcoded
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true
  
  tags = {
    Name = "production-public-1a"
    Type = "public"
  }
}

resource "aws_subnet" "public_1b" {
  vpc_id                  = aws_vpc.production.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true
  
  tags = {
    Name = "production-public-1b"
    Type = "public"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.production.id
  
  tags = {
    Name = "production-igw"
  }
}
```

**Complete the Import:**

```bash
# Remove generated.tf and import.tf after refining
rm generated.tf import.tf

# Verify plan shows no changes
terraform plan
# Plan: 0 to add, 0 to change, 0 to destroy.

# Apply to finalize import
terraform apply
```


### Import Block with Variables

```hcl
# variables.tf
variable "existing_resources" {
  description = "Map of existing resources to import"
  type = map(object({
    resource_type = string
    resource_id   = string
  }))
  
  default = {
    vpc = {
      resource_type = "aws_vpc"
      resource_id   = "vpc-0a1b2c3d4e5f67890"
    }
    igw = {
      resource_type = "aws_internet_gateway"
      resource_id   = "igw-0123456789abcdef0"
    }
  }
}

# imports.tf
import {
  to = aws_vpc.production
  id = var.existing_resources.vpc.resource_id
}

import {
  to = aws_internet_gateway.main
  id = var.existing_resources.igw.resource_id
}
```


## Bulk Import Strategies

### Strategy 1: Import with for_each (Multiple Similar Resources)

Import multiple resources of the same type using `for_each`.

**Example: Import Multiple S3 Buckets:**

```hcl
# locals.tf
locals {
  existing_buckets = {
    logs = {
      id   = "company-logs-prod-123456"
      name = "logs"
    }
    assets = {
      id   = "company-assets-prod-123456"
      name = "assets"
    }
    backups = {
      id   = "company-backups-prod-123456"
      name = "backups"
    }
  }
}

# import.tf
import {
  for_each = local.existing_buckets
  to       = aws_s3_bucket.imported[each.key]
  id       = each.value.id
}

# After generation, this becomes:
# main.tf
resource "aws_s3_bucket" "imported" {
  for_each = local.existing_buckets
  
  bucket = each.value.id
  
  tags = {
    Name    = each.value.name
    Purpose = each.key
  }
}
```

**Generate and Apply:**

```bash
terraform plan -generate-config-out=s3_buckets.tf
# Review s3_buckets.tf, refine, move to main.tf
terraform apply
```


### Strategy 2: Import Security Group Rules

Security groups with many rules require careful import strategy:

```hcl
# Step 1: Import security group
import {
  to = aws_security_group.web
  id = "sg-0123456789abcdef0"
}

# Generate configuration
# terraform plan -generate-config-out=sg_generated.tf

# Step 2: Generated configuration will include inline rules
# Refactor to use aws_vpc_security_group_ingress_rule resources

# main.tf (refactored)
resource "aws_security_group" "web" {
  name        = "production-web-sg"
  description = "Web server security group"
  vpc_id      = aws_vpc.production.id
  
  # No inline rules - use separate resources
  
  tags = {
    Name = "production-web-sg"
  }
}

locals {
  ingress_rules = {
    http = {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
      description = "HTTP from internet"
    }
    https = {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
      description = "HTTPS from internet"
    }
  }
}

resource "aws_vpc_security_group_ingress_rule" "web" {
  for_each = local.ingress_rules
  
  security_group_id = aws_security_group.web.id
  
  from_port   = each.value.from_port
  to_port     = each.value.to_port
  ip_protocol = each.value.protocol
  cidr_ipv4   = each.value.cidr_blocks[^0]
  description = each.value.description
}

# Import individual rules
import {
  for_each = local.ingress_rules
  to       = aws_vpc_security_group_ingress_rule.web[each.key]
  id       = "sgr-${each.key}-id"  # Get from AWS Console or CLI
}
```


### Strategy 3: Scripted Bulk Import

For very large imports, script the process:

**Python Script for Bulk Import (import_ec2_instances.py):**

```python
#!/usr/bin/env python3
"""
Bulk import EC2 instances into Terraform
Generates import blocks and resource skeletons
"""
import boto3
import json
import sys

ec2 = boto3.client('ec2', region_name='us-east-1')

def get_instances_by_tag(tag_key, tag_value):
    """Get all instances matching tag"""
    response = ec2.describe_instances(
        Filters=[
            {'Name': f'tag:{tag_key}', 'Values': [tag_value]},
            {'Name': 'instance-state-name', 'Values': ['running', 'stopped']}
        ]
    )
    
    instances = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instances.append({
                'id': instance['InstanceId'],
                'name': get_tag_value(instance.get('Tags', []), 'Name'),
                'type': instance['InstanceType'],
                'az': instance['Placement']['AvailabilityZone']
            })
    
    return instances

def get_tag_value(tags, key):
    """Extract tag value from tag list"""
    for tag in tags:
        if tag['Key'] == key:
            return tag['Value']
    return 'unnamed'

def generate_import_blocks(instances):
    """Generate Terraform import blocks"""
    import_blocks = []
    
    for instance in instances:
        safe_name = instance['name'].replace('-', '_').replace(' ', '_').lower()
        
        import_block = f'''
import {{
  to = aws_instance.{safe_name}
  id = "{instance['id']}"
}}'''
        import_blocks.append(import_block)
    
    return '\n'.join(import_blocks)

def generate_locals_map(instances):
    """Generate locals map for use with for_each"""
    instances_map = {}
    
    for instance in instances:
        safe_name = instance['name'].replace('-', '_').replace(' ', '_').lower()
        instances_map[safe_name] = {
            'instance_id': instance['id'],
            'instance_type': instance['type'],
            'availability_zone': instance['az']
        }
    
    return f'''
locals {{
  existing_instances = {json.dumps(instances_map, indent=4)}
}}
'''

def main():
    if len(sys.argv) < 3:
        print("Usage: python import_ec2_instances.py <tag_key> <tag_value>")
        print("Example: python import_ec2_instances.py Environment production")
        sys.exit(1)
    
    tag_key = sys.argv
    tag_value = sys.argv
    
    print(f"Finding instances with tag {tag_key}={tag_value}...")
    instances = get_instances_by_tag(tag_key, tag_value)
    
    print(f"Found {len(instances)} instances")
    
    # Generate import.tf
    with open('import.tf', 'w') as f:
        f.write('# Generated import blocks\n')
        f.write(generate_import_blocks(instances))
    
    # Generate locals.tf
    with open('locals.tf', 'w') as f:
        f.write('# Generated locals map\n')
        f.write(generate_locals_map(instances))
    
    print("\nGenerated files:")
    print("  - import.tf (import blocks)")
    print("  - locals.tf (resource map)")
    print("\nNext steps:")
    print("  1. Review generated files")
    print("  2. Run: terraform plan -generate-config-out=ec2_instances.tf")
    print("  3. Review ec2_instances.tf")
    print("  4. Refactor configuration as needed")
    print("  5. Run: terraform apply")

if __name__ == '__main__':
    main()
```

**Usage:**

```bash
# Install boto3
pip install boto3

# Configure AWS credentials
export AWS_PROFILE=production

# Run script to generate import blocks
python import_ec2_instances.py Environment production

# Output:
# Finding instances with tag Environment=production...
# Found 47 instances
#
# Generated files:
#   - import.tf (import blocks)
#   - locals.tf (resource map)

# Generate configuration
terraform init
terraform plan -generate-config-out=ec2_instances.tf

# Review and refine
# vim ec2_instances.tf
# vim locals.tf

# Apply imports
terraform apply
```


### Strategy 4: Import Entire VPC with Dependencies

```bash
# Script: import_vpc.sh
#!/bin/bash
set -e

VPC_ID="vpc-0a1b2c3d4e5f67890"

echo "Generating import configuration for VPC: $VPC_ID"

# Get VPC details
VPC_INFO=$(aws ec2 describe-vpcs --vpc-ids $VPC_ID --output json)

# Get subnets
SUBNETS=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" --output json)

# Get internet gateway
IGW=$(aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$VPC_ID" --output json)

# Get NAT gateways
NAT_GWS=$(aws ec2 describe-nat-gateways --filter "Name=vpc-id,Values=$VPC_ID" --output json)

# Get route tables
ROUTE_TABLES=$(aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$VPC_ID" --output json)

# Get security groups
SECURITY_GROUPS=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" --output json)

# Generate import.tf
cat > import.tf << 'EOF'
# VPC
import {
  to = aws_vpc.main
  id = "VPC_ID_PLACEHOLDER"
}

# Internet Gateway
import {
  to = aws_internet_gateway.main
  id = "IGW_ID_PLACEHOLDER"
}

# Subnets (will be expanded)
# NAT Gateways (will be expanded)
# Route Tables (will be expanded)
# Security Groups (will be expanded)
EOF

# Replace placeholders with actual IDs
sed -i "s/VPC_ID_PLACEHOLDER/$VPC_ID/g" import.tf

# Add subnet imports
echo "$SUBNETS" | jq -r '.Subnets[] | "\nimport {\n  to = aws_subnet.\(.SubnetId | gsub("-"; "_"))\n  id = \"\(.SubnetId)\"\n}"' >> import.tf

# Add IGW import
IGW_ID=$(echo "$IGW" | jq -r '.InternetGateways[^0].InternetGatewayId')
sed -i "s/IGW_ID_PLACEHOLDER/$IGW_ID/g" import.tf

echo "Generated import.tf with $(grep -c '^import {' import.tf) resources"
echo "Run: terraform plan -generate-config-out=vpc_infrastructure.tf"
```


## Migrating from CloudFormation

### CloudFormation Stack Preservation Strategy

When migrating from CloudFormation, you can preserve existing stacks while managing resources with Terraform [][].

**Step 1: Inventory CloudFormation Resources:**

```bash
# List all CloudFormation stacks
aws cloudformation list-stacks \
  --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE \
  --query 'StackSummaries[*].[StackName,StackStatus]' \
  --output table

# Get resources in specific stack
aws cloudformation list-stack-resources \
  --stack-name production-networking \
  --query 'StackResourceSummaries[*].[LogicalResourceId,ResourceType,PhysicalResourceId]' \
  --output table

# Export to JSON for processing
aws cloudformation list-stack-resources \
  --stack-name production-networking \
  --output json > cf_resources.json
```

**Step 2: Generate Terraform Import Configuration:**

```python
# cf_to_terraform_import.py
import json
import sys

# CloudFormation to Terraform resource type mapping
RESOURCE_TYPE_MAP = {
    'AWS::EC2::VPC': 'aws_vpc',
    'AWS::EC2::Subnet': 'aws_subnet',
    'AWS::EC2::InternetGateway': 'aws_internet_gateway',
    'AWS::EC2::RouteTable': 'aws_route_table',
    'AWS::EC2::Route': 'aws_route',
    'AWS::EC2::SubnetRouteTableAssociation': 'aws_route_table_association',
    'AWS::EC2::SecurityGroup': 'aws_security_group',
    'AWS::EC2::Instance': 'aws_instance',
    'AWS::RDS::DBInstance': 'aws_db_instance',
    'AWS::RDS::DBSubnetGroup': 'aws_db_subnet_group',
    'AWS::ElasticLoadBalancingV2::LoadBalancer': 'aws_lb',
    'AWS::ElasticLoadBalancingV2::TargetGroup': 'aws_lb_target_group',
    'AWS::ElasticLoadBalancingV2::Listener': 'aws_lb_listener',
    'AWS::S3::Bucket': 'aws_s3_bucket',
    'AWS::IAM::Role': 'aws_iam_role',
    'AWS::IAM::Policy': 'aws_iam_policy',
}

def generate_terraform_resource_name(logical_id):
    """Convert CloudFormation logical ID to Terraform resource name"""
    return logical_id.replace('-', '_').replace('.', '_').lower()

def generate_import_blocks(cf_resources):
    """Generate Terraform import blocks from CloudFormation resources"""
    import_blocks = []
    resource_counts = {}
    
    for resource in cf_resources:
        cf_type = resource['ResourceType']
        logical_id = resource['LogicalResourceId']
        physical_id = resource['PhysicalResourceId']
        
        # Get Terraform resource type
        tf_type = RESOURCE_TYPE_MAP.get(cf_type)
        if not tf_type:
            print(f"# WARNING: No mapping for {cf_type} ({logical_id})", file=sys.stderr)
            continue
        
        # Generate resource name
        resource_name = generate_terraform_resource_name(logical_id)
        
        # Track resource counts for unique naming
        base_type = tf_type.split('_')[-1]
        resource_counts[base_type] = resource_counts.get(base_type, 0) + 1
        
        # Generate import block
        import_block = f'''
import {{
  to = {tf_type}.{resource_name}
  id = "{physical_id}"
}}'''
        
        import_blocks.append(import_block)
    
    return '\n'.join(import_blocks), resource_counts

def main():
    if len(sys.argv) < 2:
        print("Usage: python cf_to_terraform_import.py cf_resources.json")
        sys.exit(1)
    
    with open(sys.argv) as f:
        data = json.load(f)
    
    resources = data['StackResourceSummaries']
    
    import_blocks, counts = generate_import_blocks(resources)
    
    # Write import.tf
    with open('import.tf', 'w') as f:
        f.write('# Generated from CloudFormation stack\n')
        f.write('# Stack resources:\n')
        for resource_type, count in sorted(counts.items()):
            f.write(f'#   - {count} {resource_type}(s)\n')
        f.write('\n')
        f.write(import_blocks)
    
    print(f"Generated import.tf with {len(resources)} resources")
    print("\nResource breakdown:")
    for resource_type, count in sorted(counts.items()):
        print(f"  {count} {resource_type}(s)")
    
    print("\nNext steps:")
    print("  1. Review import.tf")
    print("  2. terraform plan -generate-config-out=from_cloudformation.tf")
    print("  3. Review and refactor generated configuration")
    print("  4. terraform apply")
    print("  5. After successful import, delete CloudFormation stack (optional)")

if __name__ == '__main__':
    main()
```

**Usage:**

```bash
# Export CloudFormation resources
aws cloudformation list-stack-resources \
  --stack-name production-networking \
  --output json > cf_resources.json

# Generate Terraform imports
python cf_to_terraform_import.py cf_resources.json

# Output:
# Generated import.tf with 47 resources
#
# Resource breakdown:
#   3 vpc(s)
#   6 subnet(s)
#   3 internet_gateway(s)
#   12 route_table(s)
#   15 security_group(s)
#   8 instance(s)

# Generate Terraform configuration
terraform init
terraform plan -generate-config-out=from_cloudformation.tf

# Review and refactor
# After successful import, optionally delete CF stack (preserves resources)
aws cloudformation delete-stack \
  --stack-name production-networking \
  --retain-resources  # Keep resources, only delete stack
```


### CloudFormation to Terraform Conversion Table

| CloudFormation Resource | Terraform Resource | Import ID Format |
| :-- | :-- | :-- |
| `AWS::EC2::VPC` | `aws_vpc` | `vpc-xxxxxxxx` |
| `AWS::EC2::Subnet` | `aws_subnet` | `subnet-xxxxxxxx` |
| `AWS::EC2::InternetGateway` | `aws_internet_gateway` | `igw-xxxxxxxx` |
| `AWS::EC2::NatGateway` | `aws_nat_gateway` | `nat-xxxxxxxx` |
| `AWS::EC2::SecurityGroup` | `aws_security_group` | `sg-xxxxxxxx` |
| `AWS::EC2::Instance` | `aws_instance` | `i-xxxxxxxx` |
| `AWS::RDS::DBInstance` | `aws_db_instance` | `database-name` |
| `AWS::ElasticLoadBalancingV2::LoadBalancer` | `aws_lb` | `arn:aws:elasticloadbalancing:...` |
| `AWS::S3::Bucket` | `aws_s3_bucket` | `bucket-name` |
| `AWS::IAM::Role` | `aws_iam_role` | `role-name` |
| `AWS::Lambda::Function` | `aws_lambda_function` | `function-name` |
| `AWS::ECS::Cluster` | `aws_ecs_cluster` | `cluster-name` |

## Refactoring Imported Code

### Pattern 1: From Hardcoded Values to Variables

**Before (Generated):**

```hcl
resource "aws_instance" "web_1" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  subnet_id     = "subnet-1111aaaa"
  
  tags = {
    Name = "web-server-1"
  }
}

resource "aws_instance" "web_2" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  subnet_id     = "subnet-2222bbbb"
  
  tags = {
    Name = "web-server-2"
  }
}
```

**After (Refactored):**

```hcl
# variables.tf
variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "instance_count" {
  description = "Number of web servers"
  type        = number
  default     = 2
}

# data.tf
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

data "aws_subnets" "public" {
  filter {
    name   = "vpc-id"
    values = [aws_vpc.main.id]
  }
  
  tags = {
    Type = "public"
  }
}

# main.tf
resource "aws_instance" "web" {
  count = var.instance_count
  
  ami           = data.aws_ami.amazon_linux.id
  instance_type = var.instance_type
  subnet_id     = data.aws_subnets.public.ids[count.index % length(data.aws_subnets.public.ids)]
  
  tags = {
    Name        = "web-server-${count.index + 1}"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}
```


### Pattern 2: Extract to Modules

**Before (Monolithic):**

```hcl
# Everything in main.tf - 500+ lines
resource "aws_vpc" "main" { ... }
resource "aws_subnet" "public_1a" { ... }
resource "aws_subnet" "public_1b" { ... }
resource "aws_subnet" "private_1a" { ... }
resource "aws_subnet" "private_1b" { ... }
resource "aws_internet_gateway" "main" { ... }
resource "aws_nat_gateway" "az1" { ... }
resource "aws_nat_gateway" "az2" { ... }
# ... 50 more networking resources ...
resource "aws_instance" "web" { ... }
resource "aws_lb" "web" { ... }
# ... application resources ...
```

**After (Modular):**

```
terraform/
├── modules/
│   ├── networking/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   └── compute/
│       ├── main.tf
│       ├── variables.tf
│       └── outputs.tf
└── environments/
    └── production/
        ├── main.tf          # Uses modules
        ├── variables.tf
        └── outputs.tf
```

```hcl
# environments/production/main.tf
module "networking" {
  source = "../../modules/networking"
  
  vpc_cidr           = "10.0.0.0/16"
  availability_zones = ["us-east-1a", "us-east-1b"]
  environment        = "production"
}

module "compute" {
  source = "../../modules/compute"
  
  vpc_id             = module.networking.vpc_id
  private_subnet_ids = module.networking.private_subnet_ids
  instance_count     = 4
  instance_type      = "t3.large"
}

## ⚠️ Common Pitfalls

### Pitfall 1: Importing Resources Without Understanding Dependencies

**❌ PROBLEM:**

```hcl
# Import VPC without importing subnets, route tables, IGW, etc.
import {
  to = aws_vpc.main
  id = "vpc-0a1b2c3d4e5f67890"
}

# Later trying to manage subnets...
resource "aws_subnet" "public" {
  vpc_id     = aws_vpc.main.id  # Reference to imported VPC
  cidr_block = "10.0.1.0/24"
}

# terraform plan shows:
# Error: Subnet already exists but not in state
# The subnet was created manually with the VPC but not imported
```

**✅ SOLUTION:**
Map entire dependency tree before importing. Use AWS Console/CLI to identify all related resources:

```bash
# Get all resources in VPC
VPC_ID="vpc-0a1b2c3d4e5f67890"

# List all subnets
aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID"

# List route tables
aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$VPC_ID"

# List internet gateways
aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$VPC_ID"

# List NAT gateways
aws ec2 describe-nat-gateways --filter "Name=vpc-id,Values=$VPC_ID"

# List security groups
aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID"

# Import ALL related resources, not just the VPC
```


### Pitfall 2: Not Verifying Import Before Deleting Old Management

**❌ PROBLEM:**

```bash
# Import resource
terraform import aws_s3_bucket.data my-bucket

# Delete CloudFormation stack immediately
aws cloudformation delete-stack --stack-name my-stack

# Later discover import was incomplete
terraform plan
# Error: Expected encryption configuration but not found
# Resource was deleted from CF before verifying Terraform manages it completely!
```

**✅ SOLUTION:**
Always verify with `terraform plan` showing zero changes before removing old management:

```bash
# Step 1: Import
terraform import aws_s3_bucket.data my-bucket

# Step 2: Write/generate configuration
terraform plan -generate-config-out=imported.tf

# Step 3: Refine configuration
# Edit imported.tf until...

# Step 4: VERIFY - plan must show NO CHANGES
terraform plan
# Plan: 0 to add, 0 to change, 0 to destroy.
# ^ This is critical - if plan shows changes, config is incomplete!

# Step 5: Only now delete old management
aws cloudformation delete-stack --stack-name my-stack --retain-resources
```


### Pitfall 3: Importing Resources with Inline Blocks

**❌ PROBLEM:**

```hcl
# Generated configuration includes inline rules
resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = aws_vpc.main.id
  
  # Inline ingress rules (problematic)
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # Problem: Can't use for_each with inline blocks
  # Problem: Adding rules later requires replacing entire SG
}
```

**✅ SOLUTION:**
Refactor inline blocks to separate resources:

```hcl
# Security group without inline rules
resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = aws_vpc.main.id
  
  # No inline rules
  
  tags = {
    Name = "web-sg"
  }
}

# Separate rule resources (manageable with for_each)
locals {
  ingress_rules = {
    http = {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_ipv4   = "0.0.0.0/0"
      description = "HTTP"
    }
    https = {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_ipv4   = "0.0.0.0/0"
      description = "HTTPS"
    }
  }
}

resource "aws_vpc_security_group_ingress_rule" "web" {
  for_each = local.ingress_rules
  
  security_group_id = aws_security_group.web.id
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  ip_protocol       = each.value.protocol
  cidr_ipv4         = each.value.cidr_ipv4
  description       = each.value.description
}

# Import each rule individually
# Get rule IDs: aws ec2 describe-security-group-rules --filters Name=group-id,Values=sg-xxx
import {
  for_each = local.ingress_rules
  to       = aws_vpc_security_group_ingress_rule.web[each.key]
  id       = "sgr-${each.key}-xxxxx"  # Actual rule ID from AWS
}
```


### Pitfall 4: Not Handling Terraform-Managed vs Import Differences

**❌ PROBLEM:**

```hcl
# Importing S3 bucket
import {
  to = aws_s3_bucket.data
  id = "my-data-bucket"
}

# Generated config includes attachment resources as inline (old pattern)
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  
  # Old style (deprecated) - generated from existing config
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
}

# Problem: These should be separate attachment resources in AWS provider 4.0+
```

**✅ SOLUTION:**
Refactor to modern attachment resource pattern:

```hcl
# S3 bucket resource (minimal)
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  
  tags = {
    Name = "data-bucket"
  }
}

# Versioning as separate resource
resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

# Encryption as separate resource
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Import attachment resources separately
import {
  to = aws_s3_bucket.data
  id = "my-data-bucket"
}

import {
  to = aws_s3_bucket_versioning.data
  id = "my-data-bucket"
}

import {
  to = aws_s3_bucket_server_side_encryption_configuration.data
  id = "my-data-bucket"
}
```


### Pitfall 5: Forgetting to Remove Import Blocks After Import

**❌ PROBLEM:**

```hcl
# import.tf
import {
  to = aws_vpc.main
  id = "vpc-0a1b2c3d4e5f67890"
}

# After running terraform apply, import blocks remain
# Next terraform plan shows:
# Plan: 1 to import, 0 to add, 0 to change, 0 to destroy.
# ^ Import happens EVERY time!
```

**✅ SOLUTION:**
Remove or comment out import blocks after successful import:

```bash
# After verifying successful import
terraform plan
# Plan: 0 to add, 0 to change, 0 to destroy.

# Remove import.tf
rm import.tf

# Or move to archive
mkdir -p archive
mv import.tf archive/import_$(date +%Y%m%d).tf

# Or comment out
# import {
#   to = aws_vpc.main
#   id = "vpc-0a1b2c3d4e5f67890"
# }
```


### Pitfall 6: Importing Resources with Complex Identifiers

**❌ PROBLEM:**

```hcl
# Some resources require complex import IDs
import {
  to = aws_route.public
  id = "rtb-1234567890abcdef0_0.0.0.0/0"  # Route table ID + destination CIDR
  # Wrong format → import fails!
}

# Error: Invalid import id format
```

**✅ SOLUTION:**
Consult provider documentation for correct import ID format:

```hcl
# Route: route_table_id_destination
import {
  to = aws_route.public_internet
  id = "rtb-1234567890abcdef0_0.0.0.0/0"
}

# Route table association: subnet_id/route_table_id
import {
  to = aws_route_table_association.public
  id = "subnet-1111aaaa/rtb-1234567890abcdef0"
}

# Security group rule: security_group_rule_id (newer AWS provider)
import {
  to = aws_vpc_security_group_ingress_rule.web_http
  id = "sgr-0123456789abcdef0"
}

# ELB target group attachment: target_group_arn/target_id/port
import {
  to = aws_lb_target_group_attachment.web
  id = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-targets/abc123/i-1234567890abcdef0/80"
}

# IAM role policy attachment: role_name/policy_arn
import {
  to = aws_iam_role_policy_attachment.ec2_ssm
  id = "my-ec2-role/arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
```


### Pitfall 7: Bulk Import Without Batching

**❌ PROBLEM:**

```bash
# Trying to import 5,000 resources at once
terraform plan -generate-config-out=all_resources.tf

# Runs for hours, generates 500MB file, crashes terraform
# Out of memory error or API rate limiting
```

**✅ SOLUTION:**
Batch imports by resource type or logical grouping:

```bash
# Batch 1: Networking (VPCs, subnets, gateways)
terraform plan -target=aws_vpc.main \
               -target=aws_subnet.public \
               -target=aws_internet_gateway.main \
               -generate-config-out=01_networking.tf

# Batch 2: Security Groups
terraform plan -target=aws_security_group.web \
               -target=aws_security_group.db \
               -generate-config-out=02_security.tf

# Batch 3: Compute
terraform plan -target=aws_instance.web \
               -generate-config-out=03_compute.tf

# Each batch is manageable and can be reviewed/refined before next batch
```


### Pitfall 8: Not Documenting Import Process

**❌ PROBLEM:**
Team imports resources ad-hoc without documentation. Six months later:

- "Which resources were imported vs created by Terraform?"
- "What was the original CloudFormation stack name?"
- "Why is this resource configured differently than our standards?"

**✅ SOLUTION:**
Document every import with metadata:

```hcl
# main.tf
resource "aws_vpc" "legacy_production" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name = "legacy-production-vpc"
    # Import metadata
    ImportedFrom      = "CloudFormation"
    ImportedStack     = "production-networking-v1"
    ImportedDate      = "2025-12-08"
    ImportedBy        = "devops-team"
    LegacyIdentifier  = "vpc-0a1b2c3d4e5f67890"
    MigrationTicket   = "INFRA-1234"
  }
}
```

**Create import log:**

```markdown
# IMPORT_LOG.md

## VPC Infrastructure Import - 2025-12-08

### Source
- **Original Management:** AWS CloudFormation
- **Stack Name:** production-networking-v1
- **Stack Created:** 2023-03-15
- **Reason for Migration:** Consolidate IaC on Terraform

### Resources Imported
- 1 VPC (vpc-0a1b2c3d4e5f67890)
- 6 Subnets (3 public, 3 private)
- 1 Internet Gateway
- 3 NAT Gateways
- 12 Route Tables
- 15 Security Groups

### Import Process
1. Exported CF stack resources: `cf_resources.json`
2. Generated import blocks: `import.tf`
3. Generated configuration: `terraform plan -generate-config-out=vpc.tf`
4. Refactored configuration: Moved inline rules to separate resources
5. Verified: `terraform plan` showed 0 changes
6. Deleted CF stack: Retained resources

### Known Issues
- Security group `legacy-db-sg` has 50+ rules, needs refactoring
- NAT Gateway in us-east-1c created manually (not in CF stack)

### Next Steps
- [ ] Refactor security groups to use `for_each`
- [ ] Import NAT Gateway in us-east-1c
- [ ] Update documentation
```


## 💡 Expert Tips from the Field

1. **"Use `-generate-config-out` as starting point, not final configuration"** - Generated code is syntactically correct but not idiomatic. Refactor to use variables, loops, modules, and remove unnecessary computed attributes.
2. **"Import in reverse dependency order to avoid reference errors"** - Import foundation resources (VPC, subnets) before dependent resources (instances, load balancers). Terraform needs resources to exist before creating references.
3. **"Always do dry-run imports in separate workspace or branch"** - Test import process in non-production environment first. Once confident, repeat in production with documented runbook.
4. **"Use `moved` blocks when refactoring imported resources"** - After import, if you rename resources, use `moved` blocks to prevent Terraform from destroying and recreating:
```hcl
# Renamed aws_instance.web to aws_instance.application
moved {
  from = aws_instance.web
  to   = aws_instance.application
}
```

5. **"Create import modules for repetitive patterns"** - If importing dozens of S3 buckets or EC2 instances with similar configs, create module that accepts list and generates import blocks:
```hcl
module "import_s3_buckets" {
  source = "./modules/s3-import"
  
  buckets = {
    logs    = "company-logs-prod"
    assets  = "company-assets-prod"
    backups = "company-backups-prod"
  }
}
```

6. **"Tag imported resources with import metadata"** - Add tags showing import date, source, migration ticket. Critical for auditing and troubleshooting later.
7. **"Use Terraform workspaces for gradual migration"** - Migrate one workspace at a time (dev → staging → prod) to validate process and catch issues early.
8. **"Schedule imports during maintenance windows"** - While imports don't modify resources, they do lock state. Schedule bulk imports when team isn't actively deploying.
9. **"Leverage `-target` for partial imports"** - Import critical resources first (databases, load balancers) then less critical (CloudWatch dashboards, tags) over time.
10. **"Consider terraform-import-generator for legacy workflows"** - Third-party tools like [terraform-import-generator](https://github.com/GoogleCloudPlatform/terraformer) can scan AWS accounts and generate import commands for resources not yet managed.
11. **"Test disaster recovery before deleting old management"** - After import, test `terraform destroy` and `terraform apply` in non-prod to ensure you can recreate infrastructure from Terraform alone.
12. **"Use `import` blocks with `for_each` for resource families"** - Import multiple similar resources in single block:
```hcl
locals {
  instances = {
    web1 = "i-0123456789abcdef0"
    web2 = "i-1234567890abcdef1"
    web3 = "i-2345678901abcdef2"
  }
}

import {
  for_each = local.instances
  to       = aws_instance.web[each.key]
  id       = each.value
}
```

13. **"Document divergence from Terraform best practices"** - Imported resources may have quirks (non-standard naming, missing tags, odd configurations). Document these with `#TODO` comments for future refactoring.
14. **"Use CloudTrail to identify who created resources manually"** - Before importing mystery resources, check CloudTrail to understand why they exist and whether they're still needed.
15. **"Implement policy-as-code checks after import"** - Run OPA/Sentinel policies on imported infrastructure to identify security/compliance issues that need fixing.

## 🎯 Practical Exercises

### Exercise 1: Import Single VPC with Dependencies

**Difficulty:** Beginner
**Time:** 30 minutes
**Objective:** Import existing VPC and all related networking resources using import blocks

**Prerequisites:**

- AWS account with existing VPC
- Terraform 1.14+
- AWS CLI configured

**Steps:**

1. **Create working directory:**
```bash
mkdir vpc-import-demo
cd vpc-import-demo
```

2. **Create provider configuration:**
```hcl
# provider.tf
terraform {
  required_version = ">= 1.14.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}
```

3. **Identify VPC to import:**
```bash
# List your VPCs
aws ec2 describe-vpcs \
  --query 'Vpcs[*].[VpcId,CidrBlock,Tags[?Key==`Name`].Value|[^0]]' \
  --output table

# Choose a VPC and note its ID
# Example: vpc-0a1b2c3d4e5f67890
```

4. **Map VPC dependencies:**
```bash
VPC_ID="vpc-0a1b2c3d4e5f67890"  # Replace with your VPC ID

# Get subnets
aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=$VPC_ID" \
  --query 'Subnets[*].[SubnetId,CidrBlock,AvailabilityZone,Tags[?Key==`Name`].Value|[^0]]' \
  --output table

# Get internet gateway
aws ec2 describe-internet-gateways \
  --filters "Name=attachment.vpc-id,Values=$VPC_ID" \
  --query 'InternetGateways[*].[InternetGatewayId]' \
  --output text
```

5. **Create import blocks:**
```hcl
# import.tf
import {
  to = aws_vpc.main
  id = "vpc-0a1b2c3d4e5f67890"  # Your VPC ID
}

import {
  to = aws_subnet.public_1a
  id = "subnet-1111aaaa"  # Your subnet ID
}

import {
  to = aws_subnet.public_1b
  id = "subnet-2222bbbb"  # Your subnet ID
}

import {
  to = aws_internet_gateway.main
  id = "igw-0123456789abcdef0"  # Your IGW ID
}
```

6. **Generate configuration:**
```bash
terraform init
terraform plan -generate-config-out=generated.tf

# Review generated.tf
cat generated.tf
```

7. **Refine configuration:**
```bash
# Move generated code to main.tf and refactor
# Remove unnecessary computed attributes
# Add variables for CIDR blocks
# Add proper tagging
```

8. **Verify import:**
```bash
terraform plan
# Should show: Plan: 0 to add, 0 to change, 0 to destroy.
```

9. **Apply to finalize:**
```bash
terraform apply
```

**Validation:**

- State file includes all imported resources
- `terraform plan` shows no changes
- Resources properly referenced (no hardcoded IDs)

**Challenge:** Import NAT gateways and route tables associated with the VPC

**Cleanup:**

```bash
# Don't run terraform destroy - this would delete production VPC!
# Simply remove the directory
cd ..
rm -rf vpc-import-demo
```


***

### Exercise 2: Bulk Import S3 Buckets Using Script

**Difficulty:** Intermediate
**Time:** 40 minutes
**Objective:** Import multiple S3 buckets using scripting and `for_each`

**Prerequisites:**

- AWS account with multiple S3 buckets
- Python 3.9+
- boto3 installed
- Terraform 1.14+

**Steps:**

1. **Create project structure:**
```bash
mkdir s3-bulk-import
cd s3-bulk-import
```

2. **Create bucket discovery script:**
```python
# discover_buckets.py
#!/usr/bin/env python3
import boto3
import json

s3 = boto3.client('s3')

def list_buckets_with_tags():
    """List all S3 buckets with their tags"""
    buckets = []
    
    response = s3.list_buckets()
    
    for bucket in response['Buckets']:
        bucket_name = bucket['Name']
        
        try:
            # Get bucket tags
            tag_response = s3.get_bucket_tagging(Bucket=bucket_name)
            tags = {tag['Key']: tag['Value'] for tag in tag_response['TagSet']}
        except:
            tags = {}
        
        # Only include buckets with specific tag
        if tags.get('ManagedBy') == 'manual':
            buckets.append({
                'name': bucket_name,
                'tags': tags
            })
    
    return buckets

def generate_terraform_locals(buckets):
    """Generate Terraform locals for import"""
    bucket_map = {}
    
    for bucket in buckets:
        # Create safe Terraform resource name
        safe_name = bucket['name'].replace('-', '_').replace('.', '_')
        bucket_map[safe_name] = bucket['name']
    
    return f'''
locals {{
  existing_buckets = {json.dumps(bucket_map, indent=4)}
}}
'''

def main():
    print("Discovering S3 buckets...")
    buckets = list_buckets_with_tags()
    
    print(f"Found {len(buckets)} buckets to import")
    
    # Generate locals.tf
    with open('locals.tf', 'w') as f:
        f.write(generate_terraform_locals(buckets))
    
    print("\nGenerated locals.tf")
    print("Next: Add import blocks to import.tf")

if __name__ == '__main__':
    main()
```

3. **Run discovery script:**
```bash
python3 discover_buckets.py
```

4. **Create import configuration:**
```hcl
# import.tf
import {
  for_each = local.existing_buckets
  to       = aws_s3_bucket.imported[each.key]
  id       = each.value
}
```

5. **Create provider configuration:**
```hcl
# provider.tf
terraform {
  required_version = ">= 1.14.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}
```

6. **Generate configuration:**
```bash
terraform init
terraform plan -generate-config-out=s3_buckets.tf
```

7. **Refactor generated code:**
```hcl
# main.tf (refactored from s3_buckets.tf)
resource "aws_s3_bucket" "imported" {
  for_each = local.existing_buckets
  
  bucket = each.value
  
  tags = {
    Name      = each.key
    ManagedBy = "Terraform"  # Update from "manual"
  }
}

# Import versioning configuration separately
resource "aws_s3_bucket_versioning" "imported" {
  for_each = aws_s3_bucket.imported
  
  bucket = each.value.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

# Import encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "imported" {
  for_each = aws_s3_bucket.imported
  
  bucket = each.value.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
```

8. **Import attachment resources:**
```hcl
# Add to import.tf
import {
  for_each = local.existing_buckets
  to       = aws_s3_bucket_versioning.imported[each.key]
  id       = each.value
}

import {
  for_each = local.existing_buckets
  to       = aws_s3_bucket_server_side_encryption_configuration.imported[each.key]
  id       = each.value
}
```

9. **Verify and apply:**
```bash
terraform plan
# Should show: Plan: X to import, 0 to add, 0 to change, 0 to destroy.

terraform apply
```

**Validation:**

- All buckets imported successfully
- Terraform state includes all bucket resources
- `terraform plan` shows no changes after import

**Challenge:** Extend script to also import bucket policies and lifecycle configurations

***

### Exercise 3: Migrate CloudFormation Stack to Terraform

**Difficulty:** Advanced
**Time:** 60 minutes
**Objective:** Complete migration of CloudFormation stack to Terraform with validation

**Prerequisites:**

- AWS account with existing CloudFormation stack
- Terraform 1.14+
- AWS CLI
- Python 3.9+

**Steps:**

1. **Select CloudFormation stack:**
```bash
# List stacks
aws cloudformation list-stacks \
  --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE \
  --query 'StackSummaries[*].[StackName,StackStatus,CreationTime]' \
  --output table

# Choose a non-production stack for testing
STACK_NAME="dev-webapp"
```

2. **Export stack resources:**
```bash
aws cloudformation list-stack-resources \
  --stack-name $STACK_NAME \
  --output json > cf_resources.json

# Review resources
cat cf_resources.json | jq '.StackResourceSummaries[] | {Type: .ResourceType, Id: .PhysicalResourceId}'
```

3. **Create migration directory:**
```bash
mkdir cf-migration
cd cf-migration
cp ../cf_resources.json .
```

4. **Use migration script from earlier (cf_to_terraform_import.py)**
```bash
python3 cf_to_terraform_import.py cf_resources.json
```

5. **Create provider configuration:**
```hcl
# provider.tf
terraform {
  required_version = ">= 1.14.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
  
  backend "s3" {
    bucket = "your-terraform-state"
    key    = "migrations/cf-to-terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = "us-east-1"
}
```

6. **Generate Terraform configuration:**
```bash
terraform init
terraform plan -generate-config-out=from_cloudformation.tf

# Review generated configuration
less from_cloudformation.tf
```

7. **Refactor generated code:**
```bash
# Organize into logical files
mv from_cloudformation.tf temp.tf

# Split into:
# - networking.tf (VPC, subnets, security groups)
# - compute.tf (EC2, ASG, launch templates)
# - storage.tf (S3, EBS volumes)
# - iam.tf (roles, policies)

# Refactor each file:
# - Remove computed attributes
# - Add variables
# - Use data sources for AMIs
# - Implement for_each where appropriate
```

8. **Create variables:**
```hcl
# variables.tf
variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

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
```

9. **Validate migration:**
```bash
# Plan should show 0 changes
terraform plan
# Plan: 0 to add, 0 to change, 0 to destroy.

# If changes shown, refine configuration until plan is clean
```

10. **Test in isolated environment:**
```bash
# Create test workspace
terraform workspace new migration-test

# Apply to verify
terraform apply

# Destroy test resources
terraform destroy
terraform workspace select default
terraform workspace delete migration-test
```

11. **Apply migration:**
```bash
terraform apply
```

12. **Delete CloudFormation stack (retaining resources):**
```bash
# Delete stack but keep resources
aws cloudformation delete-stack \
  --stack-name $STACK_NAME \
  --retain-resources

# Verify stack deleted
aws cloudformation describe-stacks --stack-name $STACK_NAME
# Should show: Stack with id dev-webapp does not exist
```

13. **Verify Terraform management:**
```bash
# Make a change via Terraform
# Add a tag to a resource

terraform plan
terraform apply

# Verify change in AWS Console
```

**Validation:**

- CloudFormation stack deleted
- All resources still exist and operational
- Terraform manages all resources
- No drift between Terraform config and AWS state

**Challenge:** Set up CI/CD pipeline to prevent manual changes to migrated resources

**Cleanup:**

```bash
# Only run if this was a test stack
terraform destroy
```


***

## Troubleshooting Common Import Issues

### Issue 1: Import ID Not Found

**Error:**

```
Error: Cannot import non-existent remote object

While attempting to import an existing object to "aws_instance.web", the provider detected that no object exists with the given id.
```

**Causes:**

- Incorrect resource ID
- Wrong AWS region
- Resource already deleted
- Incorrect AWS account/credentials

**Resolution:**

```bash
# Verify resource exists
aws ec2 describe-instances --instance-ids i-0123456789abcdef0 --region us-east-1

# Check current AWS account
aws sts get-caller-identity

# Verify region matches
export AWS_DEFAULT_REGION=us-east-1

# Try import again with correct ID
```


### Issue 2: Resource Already in State

**Error:**

```
Error: Resource already managed by Terraform

Terraform is already managing a remote object for aws_instance.web.
```

**Causes:**

- Resource previously imported
- Attempting to re-import after successful import

**Resolution:**

```bash
# Check state
terraform state list | grep aws_instance.web

# If resource exists, remove import block
# If you need to re-import, first remove from state
terraform state rm aws_instance.web

# Then import again
```


### Issue 3: Configuration Doesn't Match Imported Resource

**Error:**

```
Error: Invalid or unknown key

After importing, terraform plan shows:
  ~ ami           = "ami-old" -> "ami-new"
  ~ instance_type = "t2.micro" -> "t3.micro"
```

**Resolution:**

```bash
# Use -generate-config-out to get accurate configuration
terraform plan -generate-config-out=accurate.tf

# Update your configuration to match actual resource state
# Or if changes are intended, apply them:
terraform apply
```


### Issue 4: Complex Resource Relationships

**Error:**

```
Error: Missing required argument

The argument "vpc_id" is required, but no definition was found.
```

**Causes:**

- Trying to reference resource that hasn't been imported yet
- Circular dependencies

**Resolution:**

```hcl
# Import dependencies first
import {
  to = aws_vpc.main
  id = "vpc-xxx"
}

# Then dependent resources
import {
  to = aws_subnet.main
  id = "subnet-xxx"
}

# Use data sources as temporary workaround during migration
data "aws_vpc" "existing" {
  id = "vpc-xxx"
}

resource "aws_subnet" "main" {
  vpc_id = data.aws_vpc.existing.id  # Temporary
  # After VPC imported, change to: aws_vpc.main.id
}
```


### Issue 5: State Lock During Bulk Import

**Error:**

```
Error: Error acquiring the state lock

Lock Info:
  ID:        a1b2c3d4-5678-90ab-cdef-1234567890ab
  Operation: OperationTypeApply
  Who:       alice@engineering
  Created:   2025-12-08 14:23:15Z
```

**Resolution:**

```bash
# Check if import is still running
ps aux | grep terraform

# If stuck, force unlock (use with caution)
terraform force-unlock a1b2c3d4-5678-90ab-cdef-1234567890ab

# Prevent by batching imports
# Instead of importing all 5000 resources at once:
terraform plan -target=aws_vpc.main -generate-config-out=batch1.tf
terraform apply -target=aws_vpc.main
```


## Key Takeaways

- **Import blocks with `-generate-config-out` eliminate manual configuration writing** - Terraform 1.14+ automatically generates syntactically correct HCL from existing resource state, reducing import time from days to hours for large infrastructures
- **Bulk imports require strategic batching by resource type or dependency level** - Importing 5,000 resources simultaneously causes memory issues and API throttling; batch by networking → security → compute → databases for manageable review cycles
- **CloudFormation migration is safe with resource retention** - Delete CloudFormation stacks with `--retain-resources` flag after Terraform import verification, preserving infrastructure while shifting management control
- **Generated configuration needs refactoring to production standards** - Auto-generated code includes all attributes (many computed), uses hardcoded IDs, and lacks variables/loops; refactor to idiomatic Terraform before committing
- **Import validation requires zero-change plan before removing legacy management** - Only delete CloudFormation stacks or manual processes after `terraform plan` shows zero changes, proving Terraform completely manages the resource
- **Document every import with metadata tags and audit logs** - Add tags showing import date, source system, migration ticket, and original identifiers for troubleshooting and compliance auditing
- **Use `moved` blocks when refactoring imported resources** - After import, renaming resources triggers destroy/create unless `moved` blocks tell Terraform the resource relocated in state without infrastructure changes


## What's Next

With infrastructure successfully imported and migrated to Terraform management, **Chapter 13: Troubleshooting and Debugging** covers systematic approaches to diagnosing Terraform failures, using `TF_LOG` for detailed debugging output, state recovery procedures when corruption occurs, handling provider API errors and rate limits, resolving dependency cycles and circular references, and building runbooks for common operational issues that arise in production Terraform workflows.

## Additional Resources

**Official Documentation:**

- [Terraform Import](https://developer.hashicorp.com/terraform/language/import) - Import block syntax and usage
- [Generating Configuration](https://developer.hashicorp.com/terraform/language/import/generating-configuration) - Automatic config generation
- [Import Tutorial](https://developer.hashicorp.com/terraform/tutorials/state/state-import) - Step-by-step import guide

**Migration Tools:**

- [Terraformer](https://github.com/GoogleCloudPlatform/terraformer) - Generate Terraform files from existing infrastructure
- [Former2](https://github.com/iann0036/former2) - Generate IaC from AWS resources
- [AWSweeper](https://github.com/jckuester/awsweeper) - Clean up AWS resources before import

**Migration Guides:**

- [AWS Prescriptive Guidance: CloudFormation to Terraform](https://developer.hashicorp.com/validated-patterns/terraform/migrate-from-cloudformation) - Official migration patterns
- [CloudFormation to Terraform Migration](https://www.firefly.ai/blog/cloudformation-to-terraform-migration) - Enterprise migration strategies
- [Spacelift Import Guide](https://spacelift.io/blog/importing-exisiting-infrastructure-into-terraform) - Comprehensive import walkthrough

**Community Resources:**

- [Terraform Import Examples](https://registry.terraform.io) - Provider-specific import documentation
- [AWS Provider Import Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs) - Import ID formats for AWS resources

***

**Importing infrastructure is the bridge from legacy to modern infrastructure-as-code.** Modern import blocks with automatic configuration generation transform what was once a months-long manual process into a repeatable, auditable workflow. The key is patience: import carefully, verify thoroughly, refactor thoughtfully, and document extensively. Every resource you import is one step closer to fully declarative, version-controlled infrastructure.