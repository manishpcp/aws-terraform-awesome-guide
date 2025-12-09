# Appendix F: Troubleshooting Quick Reference

## Introduction

This appendix provides a systematic troubleshooting guide for common Terraform and AWS infrastructure issues encountered in production environments. Each problem includes symptoms, root causes, diagnostic steps, and proven solutions. This quick reference is designed for rapid incident response and daily operational troubleshooting.

***

## Diagnostic Workflow

### Standard Troubleshooting Process

```
1. Identify Symptoms
   ↓
2. Enable Debug Logging
   ↓
3. Isolate Problem Area
   ↓
4. Review Error Messages
   ↓
5. Check State Consistency
   ↓
6. Verify Credentials/Permissions
   ↓
7. Apply Solution
   ↓
8. Verify Resolution
   ↓
9. Document Root Cause
```


### Essential Debug Commands

```bash
# Enable detailed logging
export TF_LOG=DEBUG
export TF_LOG_PATH=terraform-debug.log

# Run operation with debug output
terraform apply

# Review logs
less terraform-debug.log

# Disable logging
unset TF_LOG
unset TF_LOG_PATH
```


***

## Category 1: Initialization Issues

### Problem: Provider Plugin Download Fails

**Symptoms:**

```
Error: Failed to install provider

Error while installing hashicorp/aws v6.0.0: could not query provider
registry for registry.terraform.io/hashicorp/aws
```

**Root Causes:**

- Network connectivity issues
- Corporate proxy blocking registry access
- Rate limiting from Terraform Registry
- Invalid provider version constraint

**Diagnostic Steps:**

```bash
# Test registry connectivity
curl -I https://registry.terraform.io/v1/providers/hashicorp/aws

# Check DNS resolution
nslookup registry.terraform.io

# Verify proxy settings
echo $HTTP_PROXY
echo $HTTPS_PROXY

# Test with verbose output
terraform init -upgrade
```

**Solutions:**

```bash
# Solution 1: Configure proxy
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1

# Solution 2: Use filesystem mirror
terraform {
  provider_installation {
    filesystem_mirror {
      path    = "/usr/local/share/terraform/plugins"
      include = ["registry.terraform.io/*/*"]
    }
  }
}

# Solution 3: Retry with backoff
for i in {1..5}; do
  terraform init && break
  echo "Retry $i/5 in 10 seconds..."
  sleep 10
done

# Solution 4: Use specific version
terraform init -plugin-dir=/path/to/plugins
```


***

### Problem: Backend Initialization Fails

**Symptoms:**

```
Error: Error loading state: AccessDenied: Access Denied
	status code: 403
```

**Root Causes:**

- Insufficient IAM permissions
- Incorrect backend configuration
- S3 bucket doesn't exist
- DynamoDB table missing (for locking)
- Region mismatch

**Diagnostic Steps:**

```bash
# Verify AWS credentials
aws sts get-caller-identity

# Test S3 access
aws s3 ls s3://my-terraform-state/

# Check DynamoDB table
aws dynamodb describe-table --table-name terraform-locks

# Verify region
aws configure get region
```

**Solutions:**

```hcl
# Solution 1: Add required IAM permissions
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::my-terraform-state",
        "arn:aws:s3:::my-terraform-state/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:DescribeTable",
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:DeleteItem"
      ],
      "Resource": "arn:aws:dynamodb:*:*:table/terraform-locks"
    }
  ]
}
```

```bash
# Solution 2: Create missing resources
aws s3 mb s3://my-terraform-state --region us-east-1
aws s3api put-bucket-versioning \
  --bucket my-terraform-state \
  --versioning-configuration Status=Enabled

aws dynamodb create-table \
  --table-name terraform-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST

# Solution 3: Initialize without backend temporarily
terraform init -backend=false
# Fix configuration, then
terraform init -reconfigure
```


***

## Category 2: State Management Issues

### Problem: State Lock Already Held

**Symptoms:**

```
Error: Error acquiring the state lock

Lock Info:
  ID:        xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  Path:      my-terraform-state/terraform.tfstate
  Operation: OperationTypeApply
  Who:       user@hostname
  Created:   2025-12-08 20:00:00.000000000 +0000 UTC
```

**Root Causes:**

- Previous operation crashed or was interrupted
- Another user/process is running Terraform
- Stale lock from zombie process

**Diagnostic Steps:**

```bash
# Check if process is actually running
ps aux | grep terraform

# Check DynamoDB lock table
aws dynamodb scan --table-name terraform-locks

# Verify who has the lock
aws dynamodb get-item \
  --table-name terraform-locks \
  --key '{"LockID":{"S":"my-terraform-state/terraform.tfstate-md5"}}'

# Check CloudTrail for concurrent operations
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=terraform-locks \
  --max-results 10
```

**Solutions:**

```bash
# Solution 1: Wait for operation to complete
# If legitimate operation, wait 5-10 minutes

# Solution 2: Force unlock (use cautiously!)
terraform force-unlock <lock-id>

# Confirm:
# Do you really want to force-unlock?
# Enter a value: yes

# Solution 3: Manual DynamoDB cleanup
aws dynamodb delete-item \
  --table-name terraform-locks \
  --key '{"LockID":{"S":"<lock-id>"}}'

# Solution 4: Restart with clean slate
# Only if certain no other operations running!
terraform init -reconfigure
```

**Prevention:**

```bash
# Use automation with timeout
timeout 30m terraform apply

# CI/CD with job cancellation handling
trap "terraform force-unlock $LOCK_ID" EXIT
```


***

### Problem: State File Corruption

**Symptoms:**

```
Error: state snapshot was created by Terraform v1.9.0, which is newer than current v1.8.0
Error: Failed to load state: state data in S3 does not have the expected content
```

**Root Causes:**

- Concurrent operations corrupted state
- Manual state file editing
- Terraform version mismatch
- Incomplete upload to remote backend

**Diagnostic Steps:**

```bash
# Pull and inspect state
terraform state pull > current-state.json
cat current-state.json | jq '.version, .terraform_version'

# Validate JSON structure
cat current-state.json | jq . > /dev/null && echo "Valid JSON" || echo "Invalid JSON"

# Check S3 object metadata
aws s3api head-object \
  --bucket my-terraform-state \
  --key terraform.tfstate

# List state versions
aws s3api list-object-versions \
  --bucket my-terraform-state \
  --prefix terraform.tfstate
```

**Solutions:**

```bash
# Solution 1: Restore from S3 versioning
# List versions
aws s3api list-object-versions \
  --bucket my-terraform-state \
  --prefix terraform.tfstate

# Download previous version
aws s3api get-object \
  --bucket my-terraform-state \
  --key terraform.tfstate \
  --version-id <version-id> \
  state-restored.json

# Push restored state
terraform state push state-restored.json

# Solution 2: Upgrade Terraform version
tfenv install 1.11.0
tfenv use 1.11.0
terraform version

# Solution 3: Rebuild state from scratch (last resort)
# List all resources
aws resourcegroupstaggingapi get-resources \
  --tag-filters Key=ManagedBy,Values=Terraform \
  --output json > resources.json

# Import each resource
terraform import aws_vpc.main vpc-xxxxxx
terraform import aws_subnet.public subnet-xxxxxx
# ... continue for all resources

# Solution 4: Use state backup
cp terraform.tfstate.backup terraform.tfstate
terraform state push terraform.tfstate
```


***

### Problem: State Drift Detected

**Symptoms:**

```
Terraform detected the following changes made outside of Terraform:

  # aws_instance.web has changed
  ~ resource "aws_instance" "web" {
      ~ instance_type = "t3.micro" -> "t3.large"
        # (other attributes unchanged)
    }
```

**Root Causes:**

- Manual changes in AWS Console
- Changes by other tools (CloudFormation, SDKs)
- Auto Scaling group replaced instances
- Tags modified by automation

**Diagnostic Steps:**

```bash
# Check for drift
terraform plan -refresh-only

# Identify who made changes
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=i-xxxxxx \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%S) \
  --max-results 50

# Get current resource state
aws ec2 describe-instances --instance-ids i-xxxxxx
```

**Solutions:**

```bash
# Solution 1: Accept drift (update Terraform)
terraform apply -refresh-only -auto-approve

# Then update configuration to match
# Edit main.tf to match current state

# Solution 2: Revert drift (force compliance)
terraform apply
# Terraform will restore to configured state

# Solution 3: Ignore specific attributes
resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  
  lifecycle {
    ignore_changes = [
      tags["LastModified"],
      user_data
    ]
  }
}

# Solution 4: Automated drift detection
# Use Terraform Cloud drift detection
# Or schedule regular checks:
0 */4 * * * cd /path/to/terraform && terraform plan -detailed-exitcode || \
  echo "Drift detected" | mail -s "Terraform Drift Alert" ops@example.com
```


***

## Category 3: Resource Creation Failures

### Problem: Dependency Violation Errors

**Symptoms:**

```
Error: Error creating VPC: DependencyViolation: The vpc 'vpc-xxxxx' has dependencies and cannot be deleted
Error: error deleting subnet: DependencyViolation: The subnet 'subnet-xxxxx' has dependencies
```

**Root Causes:**

- Resources created outside Terraform in the VPC
- ENIs still attached
- Implicit dependencies not declared
- Resource deletion order incorrect

**Diagnostic Steps:**

```bash
# Find dependent resources
aws ec2 describe-network-interfaces \
  --filters Name=vpc-id,Values=vpc-xxxxxx

aws ec2 describe-nat-gateways \
  --filter Name=vpc-id,Values=vpc-xxxxxx

aws ec2 describe-security-groups \
  --filters Name=vpc-id,Values=vpc-xxxxxx

# Check for Lambda ENIs
aws lambda list-functions | jq '.Functions[] | select(.VpcConfig.VpcId=="vpc-xxxxxx")'
```

**Solutions:**

```bash
# Solution 1: Add explicit dependencies
resource "aws_subnet" "private" {
  vpc_id = aws_vpc.main.id
  
  depends_on = [
    aws_internet_gateway.main,
    aws_route_table.public
  ]
}

# Solution 2: Manual cleanup
# Delete ENIs
aws ec2 delete-network-interface --network-interface-id eni-xxxxxx

# Delete NAT gateways
aws ec2 delete-nat-gateway --nat-gateway-id nat-xxxxxx

# Wait for deletion
aws ec2 wait nat-gateway-deleted --nat-gateway-ids nat-xxxxxx

# Solution 3: Import external resources
terraform import aws_network_interface.external eni-xxxxxx

# Solution 4: Force destroy (use cautiously!)
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  
  lifecycle {
    # Prevent destroy instead of force
    prevent_destroy = true
  }
}
```


***

### Problem: Resource Quota/Limit Exceeded

**Symptoms:**

```
Error: Error creating VPC: VpcLimitExceeded: The maximum number of VPCs has been reached
Error: error creating DB Instance: DBInstanceQuotaExceeded
Error: Error launching source instance: InstanceLimitExceeded
```

**Root Causes:**

- AWS service limits reached
- Regional capacity constraints
- Insufficient quota for instance type
- Too many resources in account

**Diagnostic Steps:**

```bash
# Check service quotas
aws service-quotas list-service-quotas \
  --service-code ec2 \
  --query 'Quotas[?QuotaName==`Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances`]'

# Check current usage
aws ec2 describe-vpcs --query 'length(Vpcs)'

aws rds describe-db-instances --query 'length(DBInstances)'

# Check regional limits
aws ec2 describe-account-attributes
```

**Solutions:**

```bash
# Solution 1: Request limit increase
aws service-quotas request-service-quota-increase \
  --service-code ec2 \
  --quota-code L-1216C47A \
  --desired-value 20

# Solution 2: Use different region
provider "aws" {
  region = "us-west-2"  # Switch to region with capacity
}

# Solution 3: Use different instance type
resource "aws_instance" "web" {
  # ami           = "ami-12345678"
  # instance_type = "c5.xlarge"  # Quota exceeded
  instance_type = "t3.xlarge"    # Alternative with quota
}

# Solution 4: Clean up unused resources
# Find stopped instances
aws ec2 describe-instances \
  --filters Name=instance-state-name,Values=stopped \
  --query 'Reservations[*].Instances[*].[InstanceId,Tags[?Key==`Name`].Value|[0]]' \
  --output table

# Terminate unused instances
terraform destroy -target=aws_instance.old_test
```


***

### Problem: Insufficient IAM Permissions

**Symptoms:**

```
Error: Error creating EC2 Instance: UnauthorizedOperation: You are not authorized to perform this operation
Error: Error creating IAM Role: AccessDenied: User: arn:aws:iam::xxxxx:user/terraform is not authorized to perform: iam:CreateRole
```

**Root Causes:**

- IAM user/role lacks required permissions
- Service Control Policies (SCPs) blocking action
- Permission boundary restrictions
- Session token expired

**Diagnostic Steps:**

```bash
# Verify current identity
aws sts get-caller-identity

# Test specific permission
aws ec2 run-instances --dry-run \
  --image-id ami-12345678 \
  --instance-type t3.micro

# Check policy simulator
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::xxxx:user/terraform \
  --action-names ec2:RunInstances \
  --resource-arns "*"

# Check for SCPs (if using Organizations)
aws organizations list-policies-for-target \
  --target-id <account-id> \
  --filter SERVICE_CONTROL_POLICY
```

**Solutions:**

```hcl
# Solution 1: Add required IAM permissions
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:RunInstances",
        "ec2:TerminateInstances",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceAttribute",
        "ec2:DescribeInstanceStatus",
        "ec2:ModifyInstanceAttribute"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:GetRole",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PassRole"
      ],
      "Resource": "arn:aws:iam::*:role/terraform-*"
    }
  ]
}
```

```bash
# Solution 2: Use assumed role with permissions
provider "aws" {
  region = "us-east-1"
  
  assume_role {
    role_arn     = "arn:aws:iam::xxxx:role/TerraformExecutionRole"
    session_name = "terraform-session"
  }
}

# Solution 3: Refresh credentials
# For temporary credentials
aws sts get-session-token
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# For SSO
aws sso login --profile production
```


***

## Category 4: Module and Configuration Issues

### Problem: Module Source Not Found

**Symptoms:**

```
Error: Failed to download module
Could not download module "vpc" (main.tf:10) source code from "git::https://github.com/org/terraform-modules.git//vpc":
error downloading 'https://github.com/org/terraform-modules.git': /usr/bin/git exited with 128:
fatal: could not read Username for 'https://github.com': terminal prompts disabled
```

**Root Causes:**

- Git authentication failure
- Invalid module source path
- Private repository without credentials
- Network connectivity issues
- Module version doesn't exist

**Diagnostic Steps:**

```bash
# Test Git access
git clone https://github.com/org/terraform-modules.git

# Verify module path
ls -la terraform-modules/vpc/

# Check SSH keys
ssh -T git@github.com

# Verify module version exists
git ls-remote --tags https://github.com/org/terraform-modules.git
```

**Solutions:**

```bash
# Solution 1: Configure Git credentials
git config --global credential.helper store
echo "https://${GITHUB_TOKEN}:x-oauth-basic@github.com" > ~/.git-credentials

# Solution 2: Use SSH instead of HTTPS
module "vpc" {
  source = "git@github.com:org/terraform-modules.git//vpc?ref=v1.0.0"
}

# Solution 3: Use personal access token
export GITHUB_TOKEN=ghp_xxxxxxxxxxxx

module "vpc" {
  source = "git::https://${var.github_token}@github.com/org/terraform-modules.git//vpc?ref=v1.0.0"
}

# Solution 4: Use local path during development
module "vpc" {
  source = "../../../modules/vpc"
}

# Solution 5: Use Terraform Registry
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.5.0"
}
```


***

### Problem: Variable Type Mismatch

**Symptoms:**

```
Error: Invalid value for input variable

The given value is not suitable for var.subnet_cidrs declared at variables.tf:10:
string required, but list provided
```

**Root Causes:**

- Variable type doesn't match provided value
- Incorrect terraform.tfvars format
- Type conversion failure
- Complex type structure mismatch

**Diagnostic Steps:**

```bash
# Check variable definition
cat variables.tf | grep -A 5 "variable \"subnet_cidrs\""

# Check variable assignment
cat terraform.tfvars | grep subnet_cidrs

# Validate syntax
terraform validate

# Test with explicit type
terraform console
> var.subnet_cidrs
```

**Solutions:**

```hcl
# Solution 1: Fix variable type
# Wrong:
variable "subnet_cidrs" {
  type = string
}

# Correct:
variable "subnet_cidrs" {
  type = list(string)
}

# Solution 2: Fix terraform.tfvars format
# Wrong:
subnet_cidrs = "10.0.1.0/24"

# Correct:
subnet_cidrs = ["10.0.1.0/24", "10.0.2.0/24"]

# Solution 3: Type conversion
variable "subnet_cidr_input" {
  type = string
}

locals {
  subnet_cidrs = split(",", var.subnet_cidr_input)
}

# Solution 4: Complex type validation
variable "instances" {
  type = list(object({
    name          = string
    instance_type = string
    volume_size   = number
  }))
  
  validation {
    condition     = alltrue([for i in var.instances : i.volume_size >= 20])
    error_message = "Volume size must be at least 20 GB"
  }
}
```


***

### Problem: Circular Module Dependencies

**Symptoms:**

```
Error: Cycle: module.network, module.compute, module.network
```

**Root Causes:**

- Module A depends on Module B, which depends on Module A
- Data source circular references
- Output to input circular dependency

**Diagnostic Steps:**

```bash
# Visualize dependency graph
terraform graph | dot -Tpng > graph.png
open graph.png

# Identify circular path
terraform graph | grep -E "(module.network|module.compute)"
```

**Solutions:**

```hcl
# Solution 1: Break dependency with data sources
# Instead of:
module "network" {
  source = "./modules/network"
  security_group_id = module.compute.security_group_id  # Circular!
}

module "compute" {
  source = "./modules/compute"
  vpc_id = module.network.vpc_id
}

# Use data source:
module "network" {
  source = "./modules/network"
}

module "compute" {
  source = "./modules/compute"
  vpc_id = module.network.vpc_id
}

# In network module, use data source:
data "aws_security_group" "compute" {
  tags = {
    Name = "compute-sg"
  }
}

# Solution 2: Refactor module boundaries
# Create three modules: network, compute, security
module "network" {
  source = "./modules/network"
}

module "security" {
  source = "./modules/security"
  vpc_id = module.network.vpc_id
}

module "compute" {
  source            = "./modules/compute"
  vpc_id            = module.network.vpc_id
  security_group_id = module.security.compute_sg_id
}

# Solution 3: Use null_resource as coordination point
resource "null_resource" "network_ready" {
  depends_on = [module.network]
}

module "compute" {
  source = "./modules/compute"
  vpc_id = module.network.vpc_id
  
  depends_on = [null_resource.network_ready]
}
```


***

## Category 5: Performance Issues

### Problem: Slow Terraform Apply/Plan

**Symptoms:**

- `terraform plan` takes 15+ minutes
- `terraform apply` extremely slow
- Timeout errors during long operations

**Root Causes:**

- Too many resources in single state file
- Low parallelism setting
- Slow network connections
- Provider rate limiting
- Large state file

**Diagnostic Steps:**

```bash
# Count resources in state
terraform state list | wc -l

# Check state file size
ls -lh terraform.tfstate

# Time plan operation
time terraform plan

# Check parallelism
terraform apply -help | grep parallelism
```

**Solutions:**

```bash
# Solution 1: Increase parallelism
terraform apply -parallelism=50

# Set permanently
export TF_CLI_ARGS_apply="-parallelism=50"
export TF_CLI_ARGS_plan="-parallelism=50"

# Solution 2: Split state files by domain
# Instead of one monolithic state:
infrastructure/
├── main.tf  # All resources (slow!)

# Use separate state files:
infrastructure/
├── network/
│   ├── main.tf
│   └── backend.tf  # Separate state
├── compute/
│   ├── main.tf
│   └── backend.tf  # Separate state
└── database/
    ├── main.tf
    └── backend.tf  # Separate state

# Solution 3: Use -target for incremental changes
terraform plan -target=module.new_service

# Solution 4: Disable refresh if not needed
terraform plan -refresh=false

# Solution 5: Use local provider cache
terraform {
  provider_installation {
    filesystem_mirror {
      path    = "/usr/local/share/terraform/plugins"
    }
  }
}
```


***

## Category 6: Network and Connectivity Issues

### Problem: Timeout Connecting to AWS API

**Symptoms:**

```
Error: error reading S3 Bucket: RequestError: send request failed
caused by: Post "https://s3.us-east-1.amazonaws.com/": dial tcp: i/o timeout
```

**Root Causes:**

- Network connectivity problems
- Firewall blocking AWS endpoints
- Proxy misconfiguration
- Regional service outage
- VPC endpoint issues

**Diagnostic Steps:**

```bash
# Test AWS connectivity
curl -I https://s3.amazonaws.com

# Check DNS resolution
nslookup s3.amazonaws.com

# Test with AWS CLI
aws s3 ls --region us-east-1

# Check AWS service health
curl https://status.aws.amazon.com/

# Verify proxy settings
env | grep -i proxy
```

**Solutions:**

```bash
# Solution 1: Configure HTTP proxy
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1,169.254.169.254

# Solution 2: Increase timeout
provider "aws" {
  region = "us-east-1"
  
  http_timeout = "10m"
  
  max_retries = 5
}

# Solution 3: Use VPC endpoints
provider "aws" {
  region = "us-east-1"
  
  endpoints {
    s3  = "https://s3.us-east-1.amazonaws.com"
    ec2 = "https://ec2.us-east-1.amazonaws.com"
  }
}

# Solution 4: Switch to different region
provider "aws" {
  region = "us-west-2"  # Try alternative region
}

# Solution 5: Use AWS VPN or Direct Connect
# Ensure stable connectivity to AWS
```


***

## Category 7: Provider-Specific Issues

### Problem: AWS Provider Version Conflicts

**Symptoms:**

```
Error: Unsupported attribute
This object has no argument, nested block, or exported attribute named "vpc"
```

**Root Causes:**

- Provider version too old for resource attribute
- Breaking changes between major versions
- Module requires newer provider version

**Diagnostic Steps:**

```bash
# Check current provider version
terraform version

# Check required version in modules
grep -r "required_providers" . | grep aws

# Review provider changelog
curl https://github.com/hashicorp/terraform-provider-aws/blob/main/CHANGELOG.md
```

**Solutions:**

```hcl
# Solution 1: Upgrade provider version
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"  # Upgrade from 5.x
    }
  }
}

# Then run:
# terraform init -upgrade

# Solution 2: Update deprecated attributes
# Old (AWS Provider 5.x):
resource "aws_eip" "nat" {
  vpc = true
}

# New (AWS Provider 6.0+):
resource "aws_eip" "nat" {
  domain = "vpc"
}

# Solution 3: Pin to specific version temporarily
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.70.0"  # Exact version
    }
  }
}
```


***

## Category 8: Common Error Messages

### Quick Reference Table

| Error Message | Common Cause | Quick Fix |
| :-- | :-- | :-- |
| `state lock already held` | Concurrent operation or crashed process | `terraform force-unlock <id>` |
| `vpc has dependencies` | Resources exist in VPC | Delete dependent resources first |
| `UnauthorizedOperation` | Insufficient IAM permissions | Add required permissions |
| `InstanceLimitExceeded` | Service quota reached | Request limit increase |
| `InvalidParameterValue` | Invalid resource configuration | Check AWS documentation |
| `DependencyViolation` | Resource still has dependents | Use `depends_on` or manual cleanup |
| `ResourceNotFoundException` | Resource already deleted | `terraform apply -refresh-only` |
| `ValidationError` | Syntax or value error | Check configuration syntax |
| `ThrottlingException` | API rate limiting | Reduce parallelism or retry |
| `AccessDenied` | Permission issue | Verify IAM policy |
| `InvalidAMIID.NotFound` | AMI doesn't exist in region | Use correct AMI for region |
| `InvalidGroup.NotFound` | Security group deleted manually | Import or recreate |
| `InvalidSubnet.NotFound` | Subnet doesn't exist | Verify subnet ID |
| `InvalidKeyPair.NotFound` | SSH key pair missing | Create key pair |
| `RequestExpired` | Clock skew or expired token | Sync system time, refresh credentials |


***

## Debugging Tools and Techniques

### Debug Logging Levels

```bash
# Available log levels (most to least verbose)
export TF_LOG=TRACE   # Extremely verbose
export TF_LOG=DEBUG   # Detailed debugging
export TF_LOG=INFO    # General information
export TF_LOG=WARN    # Warnings only
export TF_LOG=ERROR   # Errors only

# Component-specific logging
export TF_LOG_CORE=TRACE       # Terraform core
export TF_LOG_PROVIDER=TRACE   # Provider operations
```


### Interactive Debugging

```bash
# Use Terraform console for testing
terraform console

# Test expressions
> var.instance_type
> aws_vpc.main.id
> length(aws_subnet.private)
> [for s in aws_subnet.private : s.availability_zone]
```


### State Inspection

```bash
# Detailed state examination
terraform state show aws_instance.web

# JSON output for parsing
terraform state show -json aws_instance.web | jq .

# Show specific attributes
terraform state show aws_instance.web | grep instance_type

# Compare state vs configuration
terraform plan -out=tfplan
terraform show -json tfplan | jq '.resource_changes'
```


### Provider Debug Output

```bash
# Enable AWS SDK debug logging
export AWS_SDK_LOAD_CONFIG=1
export TF_LOG=DEBUG

terraform apply

# Review HTTP requests/responses
grep "DEBUG: Request" terraform-debug.log
grep "DEBUG: Response" terraform-debug.log
```


***

## Emergency Procedures

### Rollback Procedure

```bash
# 1. Stop current operation
Ctrl+C (if running)

# 2. Backup current state
terraform state pull > state-emergency-backup.json

# 3. Identify last good state
aws s3api list-object-versions \
  --bucket my-terraform-state \
  --prefix terraform.tfstate

# 4. Restore previous version
aws s3api get-object \
  --bucket my-terraform-state \
  --key terraform.tfstate \
  --version-id <good-version-id> \
  terraform.tfstate.restored

# 5. Push restored state
terraform state push terraform.tfstate.restored

# 6. Verify restoration
terraform plan
```


### State Recovery Procedure

```bash
# If state is completely lost:

# 1. Recreate basic state structure
cat > terraform.tfstate <<EOF
{
  "version": 4,
  "terraform_version": "1.11.0",
  "serial": 1,
  "lineage": "$(uuidgen)",
  "outputs": {},
  "resources": []
}
EOF

# 2. Import all resources
./import-all-resources.sh

# 3. Verify imports
terraform state list

# 4. Run plan to check accuracy
terraform plan
```


***

## Prevention Best Practices

### Pre-Deployment Checklist

```bash
#!/bin/bash
# pre-deploy-check.sh

echo "Running pre-deployment checks..."

# 1. Validate syntax
terraform validate || exit 1

# 2. Format check
terraform fmt -check -recursive || exit 1

# 3. Security scan
tfsec . || exit 1

# 4. Cost estimate
infracost breakdown --path . || exit 1

# 5. Plan review
terraform plan -out=tfplan
terraform show tfplan > plan-output.txt

# 6. Require manual approval
read -p "Review plan-output.txt and approve (yes/no): " approval
if [ "$approval" != "yes" ]; then
  echo "Deployment cancelled"
  exit 1
fi

# 7. Apply
terraform apply tfplan

echo "Deployment complete!"
```


### Monitoring and Alerting

```bash
# Schedule regular drift detection
0 */4 * * * cd /terraform/prod && terraform plan -detailed-exitcode || \
  echo "Drift detected in production" | mail -s "ALERT: Terraform Drift" ops@example.com

# State lock monitoring
*/5 * * * * aws dynamodb scan --table-name terraform-locks | \
  jq '.Items | length' | \
  awk '$1 > 0 {print "State locks held: " $1}' | \
  mail -s "Terraform Lock Alert" ops@example.com
```


***

## Summary Reference Card

### Most Common Issues (Top 10)

1. **State lock held** → `terraform force-unlock <id>`
2. **Insufficient permissions** → Add IAM permissions
3. **Provider version conflict** → `terraform init -upgrade`
4. **Resource dependency error** → Add `depends_on`
5. **Variable type mismatch** → Fix `variables.tf` type
6. **Module source not found** → Check Git credentials
7. **Timeout errors** → Increase `-parallelism`
8. **State drift** → `terraform apply -refresh-only`
9. **Quota exceeded** → Request limit increase
10. **Network timeout** → Configure proxy/retry settings

### Essential Commands for Troubleshooting

```bash
export TF_LOG=DEBUG                    # Enable debug logging
terraform state list                   # List all resources
terraform state show <resource>        # Show resource details
terraform plan -refresh-only           # Check for drift
terraform force-unlock <id>            # Release stuck lock
terraform state pull > backup.json     # Backup state
aws sts get-caller-identity           # Verify credentials
terraform console                      # Interactive debugging
terraform graph | dot -Tpng > graph.png # Visualize dependencies
```

This troubleshooting quick reference provides systematic approaches to diagnose and resolve the most common Terraform and AWS infrastructure issues encountered in production environments. Keep this appendix accessible during incidents for rapid problem resolution.

