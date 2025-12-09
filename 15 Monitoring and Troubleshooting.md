# Chapter 15: Monitoring and Troubleshooting

## Introduction

Terraform failures don't announce themselves politely during business hours—they happen at 2 AM when a `terraform apply` hangs indefinitely, or Friday afternoon when state corruption prevents deployments, or during a critical incident when drift causes application failures and no one knows which resources changed or when. Without systematic monitoring and troubleshooting capabilities, teams resort to tribal knowledge ("ask Sarah, she fixed this once"), panic-driven debugging ("try refreshing the state?"), and hope-based operations ("maybe it'll work if we run it again?"). This reactive approach works until it doesn't—until the engineer who understands the quirks leaves, until the undocumented workaround fails in production, until state corruption destroys the ability to manage infrastructure at all.

Proactive monitoring transforms Terraform from a black box into an observable system with clear signals showing what's happening, what's changing, and what's breaking. Enabling detailed logging with `TF_LOG=TRACE` captures every API call showing exactly where authentication fails or rate limits trigger. Scheduled drift detection runs `terraform plan` every 6 hours, creating GitHub issues when manual changes appear with CloudTrail evidence identifying who made the change. State file monitoring tracks size growth alerting before performance degrades, validates checksums detecting corruption immediately, and maintains versioned backups enabling recovery from any disaster. Performance metrics identify slow provider operations, measure plan/apply duration trends, and pinpoint resources causing bottlenecks.

This chapter covers comprehensive monitoring and troubleshooting strategies for production Terraform operations. You'll learn debug logging techniques showing internal Terraform behavior, systematic approaches to diagnosing common errors (authentication, state lock, resource conflicts), state corruption recovery from backups or AWS resources, automated drift detection with remediation workflows, performance optimization reducing plan times from 10 minutes to 30 seconds, and building runbooks documenting resolution procedures for recurring issues. Whether you're debugging a single cryptic error or building enterprise monitoring infrastructure, these techniques will help you operate Terraform reliably, recover quickly from failures, and maintain infrastructure stability.

## Terraform Logging and Debug Modes

### Understanding Log Levels

Terraform provides five log levels controlled by the `TF_LOG` environment variable:


| Log Level | Verbosity | Use Case | Output Volume |
| :-- | :-- | :-- | :-- |
| `TRACE` | Highest | Deep debugging, provider API calls | Very High (100+ MB) |
| `DEBUG` | High | Function-level debugging | High (10-50 MB) |
| `INFO` | Medium | Operation-level information | Medium (1-5 MB) |
| `WARN` | Low | Warnings and potential issues | Low (< 1 MB) |
| `ERROR` | Lowest | Errors only | Minimal |

### Enabling Debug Logging

**Linux/macOS:**

```bash
# Enable TRACE logging for single command
TF_LOG=TRACE terraform apply

# Enable for entire session
export TF_LOG=TRACE
terraform plan

# Save logs to file
export TF_LOG=DEBUG
export TF_LOG_PATH=./terraform-debug.log
terraform apply

# Verify logging enabled
echo $TF_LOG
# Output: DEBUG

# View log file
tail -f terraform-debug.log
```

**Windows PowerShell:**

```powershell
# Enable logging
$env:TF_LOG="DEBUG"
$env:TF_LOG_PATH=".\terraform-debug.log"
terraform apply

# Verify
echo $env:TF_LOG
```


### Separate Core and Provider Logging

Split Terraform core logs from provider logs for focused debugging:

```bash
# Core Terraform logging only
export TF_LOG_CORE=TRACE
export TF_LOG_PATH_CORE=./terraform-core.log

# Provider logging only (AWS, Azure, etc.)
export TF_LOG_PROVIDER=TRACE
export TF_LOG_PATH_PROVIDER=./terraform-provider.log

# Run Terraform
terraform apply

# Now you have two separate log files:
# - terraform-core.log: Terraform operations (state, graph, planning)
# - terraform-provider.log: AWS API calls, authentication, rate limits
```


### Analyzing Debug Logs

**Example: AWS Authentication Failure**

```bash
# Enable debug logging
export TF_LOG=DEBUG
terraform plan 2>&1 | tee debug.log

# Search for authentication errors
grep -i "credential" debug.log
grep -i "unauthorized" debug.log
grep -i "access denied" debug.log

# Output shows:
# 2025-12-08T20:30:15.123Z [ERROR] provider.aws: Error calling DescribeInstances: 
# UnauthorizedOperation: You are not authorized to perform this operation
# 
# Root cause: IAM role lacks ec2:DescribeInstances permission
```

**Example: State Lock Timeout**

```bash
export TF_LOG=TRACE
terraform apply 2>&1 | tee lock-debug.log

# Search for lock-related messages
grep -i "lock" lock-debug.log

# Output:
# 2025-12-08T20:31:45.456Z [INFO] backend/s3: attempting to acquire state lock
# 2025-12-08T20:31:45.789Z [DEBUG] backend/s3: DynamoDB PutItem attempt 1
# 2025-12-08T20:31:46.012Z [ERROR] backend/s3: Error acquiring state lock: 
# ConditionalCheckFailedException: Lock ID abc123 already exists
# Lock held by: alice@192.168.1.100
# Lock acquired: 2025-12-08T19:15:30Z (1 hour 16 minutes ago)
```


### Automated Log Analysis Script

```python
# analyze_terraform_logs.py
#!/usr/bin/env python3
"""
Analyze Terraform debug logs to identify common issues
"""
import re
import sys
from collections import defaultdict

def analyze_log(log_file):
    """Parse and analyze Terraform log file"""
    
    issues = {
        'auth_errors': [],
        'rate_limits': [],
        'timeouts': [],
        'state_locks': [],
        'api_errors': [],
        'resource_errors': []
    }
    
    api_call_counts = defaultdict(int)
    slow_operations = []
    
    with open(log_file, 'r') as f:
        lines = f.readlines()
    
    for i, line in enumerate(lines):
        # Track API calls
        if 'calling' in line.lower() and 'api' in line.lower():
            match = re.search(r'calling (\w+)', line, re.IGNORECASE)
            if match:
                api_call_counts[match.group(1)] += 1
        
        # Authentication errors
        if any(term in line.lower() for term in ['unauthorized', 'access denied', 'invalid credentials']):
            issues['auth_errors'].append({
                'line': i + 1,
                'content': line.strip(),
                'context': ''.join(lines[max(0, i-2):i+3])
            })
        
        # Rate limiting
        if any(term in line.lower() for term in ['throttl', 'rate limit', 'too many requests']):
            issues['rate_limits'].append({
                'line': i + 1,
                'content': line.strip()
            })
        
        # Timeouts
        if 'timeout' in line.lower():
            issues['timeouts'].append({
                'line': i + 1,
                'content': line.strip()
            })
        
        # State locks
        if 'state lock' in line.lower() or 'conditionalcheckfailed' in line.lower():
            issues['state_locks'].append({
                'line': i + 1,
                'content': line.strip()
            })
        
        # Slow operations (> 10 seconds)
        duration_match = re.search(r'completed in (\d+\.?\d*)s', line)
        if duration_match and float(duration_match.group(1)) > 10:
            slow_operations.append({
                'duration': float(duration_match.group(1)),
                'operation': line.strip()
            })
    
    # Generate report
    print("=" * 80)
    print("TERRAFORM LOG ANALYSIS REPORT")
    print("=" * 80)
    print()
    
    # Summary
    print("SUMMARY")
    print("-" * 80)
    print(f"Total lines analyzed: {len(lines)}")
    print(f"Authentication errors: {len(issues['auth_errors'])}")
    print(f"Rate limit events: {len(issues['rate_limits'])}")
    print(f"Timeout events: {len(issues['timeouts'])}")
    print(f"State lock issues: {len(issues['state_locks'])}")
    print(f"Slow operations (>10s): {len(slow_operations)}")
    print()
    
    # API call statistics
    if api_call_counts:
        print("TOP API CALLS")
        print("-" * 80)
        sorted_calls = sorted(api_call_counts.items(), key=lambda x: x, reverse=True)
        for call, count in sorted_calls[:10]:
            print(f"{call:40} {count:6} calls")
        print()
    
    # Authentication errors (critical)
    if issues['auth_errors']:
        print("⚠️  AUTHENTICATION ERRORS (CRITICAL)")
        print("-" * 80)
        for error in issues['auth_errors'][:5]:
            print(f"Line {error['line']}: {error['content']}")
            print()
        print()
    
    # Rate limiting
    if issues['rate_limits']:
        print("⚠️  RATE LIMITING DETECTED")
        print("-" * 80)
        print(f"Encountered {len(issues['rate_limits'])} rate limit events")
        print("Recommendation: Implement exponential backoff or reduce parallelism")
        print()
    
    # State locks
    if issues['state_locks']:
        print("⚠️  STATE LOCK ISSUES")
        print("-" * 80)
        for lock in issues['state_locks'][:3]:
            print(f"Line {lock['line']}: {lock['content']}")
        print()
        print("Recommendation: Check for stuck locks with 'terraform force-unlock'")
        print()
    
    # Slow operations
    if slow_operations:
        print("⏱️  SLOW OPERATIONS")
        print("-" * 80)
        sorted_slow = sorted(slow_operations, key=lambda x: x['duration'], reverse=True)
        for op in sorted_slow[:5]:
            print(f"{op['duration']:6.1f}s - {op['operation'][:100]}")
        print()
    
    print("=" * 80)
    print("END OF REPORT")
    print("=" * 80)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python analyze_terraform_logs.py <log_file>")
        sys.exit(1)
    
    analyze_log(sys.argv)
```

**Usage:**

```bash
# Capture logs
TF_LOG=TRACE terraform apply 2>&1 | tee terraform.log

# Analyze
python analyze_terraform_logs.py terraform.log

# Output:
# ================================================================================
# TERRAFORM LOG ANALYSIS REPORT
# ================================================================================
# 
# SUMMARY
# --------------------------------------------------------------------------------
# Total lines analyzed: 15,432
# Authentication errors: 0
# Rate limit events: 12
# Timeout events: 3
# State lock issues: 0
# Slow operations (>10s): 8
# 
# TOP API CALLS
# --------------------------------------------------------------------------------
# DescribeInstances                        1,245 calls
# DescribeSecurityGroups                     892 calls
# DescribeSubnets                            456 calls
# ...
```


## Common Errors and Solutions

### Error 1: State Lock Acquisition Failure

**Error Message:**

```
Error: Error acquiring the state lock

Error message: ConditionalCheckFailedException: Lock already held
Lock Info:
  ID:        a1b2c3d4-e5f6-7890-abcd-ef1234567890
  Path:      terraform-state-bucket/production/terraform.tfstate
  Operation: OperationTypeApply
  Who:       alice@engineering-laptop
  Version:   1.11.0
  Created:   2025-12-08 14:30:00 +0000 UTC
  Info:      

Terraform acquires a state lock to protect the state from being written
by multiple users at the same time. Please resolve the issue above and try
again. For most commands, you can disable locking with the "-lock=false"
flag, but this is not recommended.
```

**Root Causes:**

1. Another Terraform process is running
2. Previous Terraform process crashed without releasing lock
3. Network interruption during lock acquisition
4. DynamoDB table issues (remote backend)

**Resolution Steps:**

```bash
# Step 1: Verify no Terraform processes running
ps aux | grep terraform
# If found, wait for completion or kill if stuck

# Step 2: Check lock age
# If lock is > 1 hour old and no one is working, likely stale

# Step 3: Verify with team
# "Hey team, is anyone running terraform apply on production?"

# Step 4: Force unlock (use with extreme caution!)
terraform force-unlock a1b2c3d4-e5f6-7890-abcd-ef1234567890

# Confirmation prompt:
# Do you really want to force-unlock?
#   Terraform will remove the lock on the remote state.
#   This will allow local Terraform commands to modify this state, even though it
#   may still be in use. Only 'yes' will be accepted to confirm.
# 
# Enter a value: yes

# Step 5: Verify lock released
terraform plan
```

**Prevention:**

```hcl
# backend.tf - Configure lock timeout
terraform {
  backend "s3" {
    bucket         = "terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-locks"
    encrypt        = true
    
    # Increase lock acquisition timeout
    max_retries = 10  # Default is 5
  }
}
```


### Error 2: Provider Authentication Failure

**Error Message:**

```
Error: error configuring Terraform AWS Provider: error validating provider credentials: 
retrieving caller identity from STS: operation error STS: GetCallerIdentity, 
https response error StatusCode: 403, RequestID: abc123

with provider["registry.terraform.io/hashicorp/aws"],
  on provider.tf line 10, in provider "aws":
  10: provider "aws" {
```

**Root Causes:**

1. AWS credentials not configured
2. Invalid or expired credentials
3. IAM permissions insufficient
4. Wrong AWS profile selected
5. MFA token required but not provided

**Resolution Steps:**

```bash
# Step 1: Verify AWS credentials exist
aws sts get-caller-identity

# If error: "Unable to locate credentials"
# Configure credentials:
aws configure
# AWS Access Key ID: AKIAIOSFODNN7EXAMPLE
# AWS Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
# Default region name: us-east-1
# Default output format: json

# Step 2: Check credentials file
cat ~/.aws/credentials
# [default]
# aws_access_key_id = AKIAIOSFODNN7EXAMPLE
# aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Step 3: Test with specific profile
export AWS_PROFILE=production
aws sts get-caller-identity

# Step 4: Verify IAM permissions
aws iam get-user
aws iam list-attached-user-policies --user-name YOUR_USERNAME

# Step 5: If using assume role, verify trust relationship
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/TerraformRole \
  --role-session-name terraform-test

# Step 6: Run Terraform with explicit credentials
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
terraform plan
```

**Debugging with TF_LOG:**

```bash
export TF_LOG=DEBUG
terraform plan 2>&1 | grep -i "credential\|auth\|sts"

# Look for lines like:
# [DEBUG] provider.aws: Retrieving credentials from shared credentials file
# [DEBUG] provider.aws: Attempting to assume role: arn:aws:iam::123456789012:role/TerraformRole
# [ERROR] provider.aws: Error assuming role: AccessDenied
```


### Error 3: Resource Already Exists

**Error Message:**

```
Error: error creating EC2 Instance: InvalidParameterValue: 
Instance with name 'web-server-1' already exists
│ 
│   with aws_instance.web,
│   on main.tf line 45, in resource "aws_instance" "web":
│   45: resource "aws_instance" "web" {
```

**Root Causes:**

1. Resource created manually or by other Terraform workspace
2. Previous `terraform apply` failed mid-run
3. State file out of sync with reality
4. Resource not properly imported into state

**Resolution Steps:**

```bash
# Step 1: Verify resource exists in AWS
aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=web-server-1" \
  --query 'Reservations[*].Instances[*].[InstanceId,State.Name,Tags]' \
  --output table

# Output:
# |  i-0123456789abcdef0  |  running  |  Name=web-server-1  |

# Step 2: Check if resource in state
terraform state list | grep aws_instance.web
# (no output = not in state)

# Step 3: Import existing resource
terraform import aws_instance.web i-0123456789abcdef0

# Step 4: Verify import successful
terraform plan
# Should show: No changes. Your infrastructure matches the configuration.

# Alternative: If resource shouldn't exist, delete it
aws ec2 terminate-instances --instance-ids i-0123456789abcdef0
```


### Error 4: Provider Plugin Crash

**Error Message:**

```
Error: Plugin did not respond

The plugin encountered an error, and failed to respond to the plugin.(*GRPCProvider).ValidateResourceConfig call. 
The plugin logs may contain more details.

Stack trace from the terraform-provider-aws_v5.31.0_x5 plugin:

panic: runtime error: invalid memory address or nil pointer dereference
```

**Root Causes:**

1. Provider bug (rare but happens)
2. Corrupted provider binary
3. Resource configuration triggers provider edge case
4. Insufficient system resources (OOM)

**Resolution Steps:**

```bash
# Step 1: Enable crash logs
export TF_LOG=TRACE
export TF_CRASH_LOG_PATH=./crash.log
terraform apply

# Step 2: Review crash log
cat crash.log
# Look for stack trace showing exact line causing crash

# Step 3: Clear provider cache and reinstall
rm -rf .terraform
rm .terraform.lock.hcl
terraform init -upgrade

# Step 4: Try older provider version
# versions.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.30.0"  # Downgrade from 5.31.0
    }
  }
}

# Step 5: Isolate problematic resource
# Comment out resources one by one until crash stops
# Identifies which resource triggers bug

# Step 6: Report bug to provider maintainers
# https://github.com/hashicorp/terraform-provider-aws/issues
```


### Error 5: Cycle Detection in Resource Graph

**Error Message:**

```
Error: Cycle: aws_security_group.web, aws_security_group.app, aws_security_group.web
```

**Root Cause:**

Circular dependency between resources (A depends on B, B depends on C, C depends on A).

**Example:**

```hcl
# Circular dependency example
resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = aws_vpc.main.id
  
  # Allows traffic from app security group
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]  # Depends on app
  }
}

resource "aws_security_group" "app" {
  name   = "app-sg"
  vpc_id = aws_vpc.main.id
  
  # Allows traffic from web security group
  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]  # Depends on web!
  }
}

# Cycle: web → app → web
```

**Resolution:**

```hcl
# Solution: Use separate security group rule resources
resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = aws_vpc.main.id
  
  # No inline rules
}

resource "aws_security_group" "app" {
  name   = "app-sg"
  vpc_id = aws_vpc.main.id
  
  # No inline rules
}

# Separate rule resources (no circular dependency)
resource "aws_vpc_security_group_ingress_rule" "web_from_app" {
  security_group_id            = aws_security_group.web.id
  referenced_security_group_id = aws_security_group.app.id
  from_port                    = 80
  to_port                      = 80
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "app_from_web" {
  security_group_id            = aws_security_group.app.id
  referenced_security_group_id = aws_security_group.web.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}
```


## State Corruption Recovery

### Detecting State Corruption

**Signs of state corruption:**

1. `terraform plan` fails with parsing errors
2. State file contains invalid JSON
3. Resource tracking lost (shows recreation when shouldn't)
4. State file size suddenly drops or becomes 0 bytes
5. Missing resources in `terraform state list`

**Validation script:**

```bash
# validate_state.sh
#!/bin/bash

STATE_FILE="terraform.tfstate"

echo "Validating Terraform state file: $STATE_FILE"

# Check 1: File exists
if [ ! -f "$STATE_FILE" ]; then
    echo "❌ State file not found"
    exit 1
fi

# Check 2: File not empty
if [ ! -s "$STATE_FILE" ]; then
    echo "❌ State file is empty (0 bytes)"
    exit 1
fi

# Check 3: Valid JSON
if ! jq empty "$STATE_FILE" 2>/dev/null; then
    echo "❌ State file is not valid JSON"
    exit 1
fi

# Check 4: Contains required fields
VERSION=$(jq -r '.version' "$STATE_FILE")
TERRAFORM_VERSION=$(jq -r '.terraform_version' "$STATE_FILE")
RESOURCES=$(jq -r '.resources | length' "$STATE_FILE")

echo "✅ State file is valid JSON"
echo "   Version: $VERSION"
echo "   Terraform version: $TERRAFORM_VERSION"
echo "   Resources: $RESOURCES"

# Check 5: No duplicate resource addresses
DUPLICATES=$(jq -r '.resources[].type + "." + .resources[].name' "$STATE_FILE" | sort | uniq -d)
if [ -n "$DUPLICATES" ]; then
    echo "⚠️  Warning: Duplicate resources found:"
    echo "$DUPLICATES"
fi

echo "✅ State file validation complete"
```


### Recovery Option 1: Restore from Backup

**S3 Backend with Versioning:**

```bash
# List state file versions
aws s3api list-object-versions \
  --bucket terraform-state-bucket \
  --prefix production/terraform.tfstate \
  --query 'Versions[*].[VersionId,LastModified,Size]' \
  --output table

# Output:
# |  abc123def456  |  2025-12-08T14:30:00Z  |  1,234,567  |  <- Current (corrupted)
# |  xyz789ghi012  |  2025-12-08T10:15:00Z  |  1,234,890  |  <- Previous (good)
# |  mno345pqr678  |  2025-12-07T18:45:00Z  |  1,233,456  |

# Download previous version
aws s3api get-object \
  --bucket terraform-state-bucket \
  --key production/terraform.tfstate \
  --version-id xyz789ghi012 \
  terraform.tfstate.backup

# Verify backup is valid
jq empty terraform.tfstate.backup
# No output = valid JSON

# Compare resources
echo "Current (corrupted) resources:"
terraform state list

echo "Backup resources:"
terraform state list -state=terraform.tfstate.backup

# Restore backup
cp terraform.tfstate terraform.tfstate.corrupted
cp terraform.tfstate.backup terraform.tfstate

# Push to remote backend
terraform state push terraform.tfstate

# Verify
terraform plan
```


### Recovery Option 2: Rebuild from AWS Resources

When backups fail, reconstruct state from existing infrastructure:

```bash
# Step 1: Initialize empty state
mv terraform.tfstate terraform.tfstate.corrupted
terraform init

# Step 2: List all resources in AWS
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,Tags[?Key==`Name`].Value|[^0]]' --output table
aws ec2 describe-vpcs --query 'Vpcs[*].[VpcId,Tags[?Key==`Name`].Value|[^0]]' --output table
aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupId,GroupName]' --output table
# ... repeat for all resource types

# Step 3: Import resources one by one
terraform import aws_vpc.main vpc-0a1b2c3d4e5f67890
terraform import aws_subnet.public_1a subnet-1111aaaa
terraform import aws_instance.web i-0123456789abcdef0
# ...

# Step 4: Verify after each import
terraform plan
# Should show: No changes (if config matches reality)
```

**Automated import script:**

```python
# rebuild_state.py
#!/usr/bin/env python3
"""
Rebuild Terraform state from AWS resources
"""
import boto3
import subprocess
import json

def get_all_resources():
    """Query AWS for all manageable resources"""
    ec2 = boto3.client('ec2', region_name='us-east-1')
    
    resources = {
        'vpcs': [],
        'subnets': [],
        'instances': [],
        'security_groups': []
    }
    
    # Get VPCs
    vpcs = ec2.describe_vpcs()
    for vpc in vpcs['Vpcs']:
        name = get_tag_value(vpc.get('Tags', []), 'Name')
        resources['vpcs'].append({
            'id': vpc['VpcId'],
            'name': name or vpc['VpcId']
        })
    
    # Get subnets
    subnets = ec2.describe_subnets()
    for subnet in subnets['Subnets']:
        name = get_tag_value(subnet.get('Tags', []), 'Name')
        resources['subnets'].append({
            'id': subnet['SubnetId'],
            'name': name or subnet['SubnetId'],
            'vpc_id': subnet['VpcId']
        })
    
    # Get instances
    instances = ec2.describe_instances()
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            if instance['State']['Name'] != 'terminated':
                name = get_tag_value(instance.get('Tags', []), 'Name')
                resources['instances'].append({
                    'id': instance['InstanceId'],
                    'name': name or instance['InstanceId']
                })
    
    return resources

def get_tag_value(tags, key):
    """Extract tag value"""
    for tag in tags:
        if tag['Key'] == key:
            return tag['Value']
    return None

def import_resource(resource_type, terraform_address, aws_id):
    """Import single resource into Terraform state"""
    cmd = ['terraform', 'import', terraform_address, aws_id]
    
    print(f"Importing {terraform_address} (ID: {aws_id})...")
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        print(f"✅ Successfully imported {terraform_address}")
        return True
    else:
        print(f"❌ Failed to import {terraform_address}")
        print(f"   Error: {result.stderr}")
        return False

def main():
    print("Querying AWS for resources...")
    resources = get_all_resources()
    
    print(f"\nFound:")
    print(f"  {len(resources['vpcs'])} VPCs")
    print(f"  {len(resources['subnets'])} Subnets")
    print(f"  {len(resources['instances'])} Instances")
    
    print("\nStarting import process...\n")
    
    imported_count = 0
    failed_count = 0
    
    # Import VPCs
    for vpc in resources['vpcs']:
        safe_name = vpc['name'].replace('-', '_').lower()
        if import_resource('vpc', f'aws_vpc.{safe_name}', vpc['id']):
            imported_count += 1
        else:
            failed_count += 1
    
    # Import subnets
    for subnet in resources['subnets']:
        safe_name = subnet['name'].replace('-', '_').lower()
        if import_resource('subnet', f'aws_subnet.{safe_name}', subnet['id']):
            imported_count += 1
        else:
            failed_count += 1
    
    # Import instances
    for instance in resources['instances']:
        safe_name = instance['name'].replace('-', '_').lower()
        if import_resource('instance', f'aws_instance.{safe_name}', instance['id']):
            imported_count += 1
        else:
            failed_count += 1
    
    print("\n" + "=" * 60)
    print(f"Import complete!")
    print(f"  ✅ Imported: {imported_count}")
    print(f"  ❌ Failed: {failed_count}")
    print("=" * 60)
    
    print("\nNext steps:")
    print("  1. Run 'terraform plan' to verify")
    print("  2. Update Terraform config to match imported resources")
    print("  3. Run 'terraform plan' again (should show 0 changes)")

if __name__ == '__main__':
    main()
```


### Recovery Option 3: Manual State File Repair

For minor JSON corruption:

```bash
# Backup current state
cp terraform.tfstate terraform.tfstate.backup

# Attempt to pretty-print (reveals syntax errors)
jq . terraform.tfstate > terraform.tfstate.formatted

# If jq fails, manually edit
vi terraform.tfstate

# Common issues to fix:
# 1. Trailing commas in JSON
# 2. Missing closing braces/brackets
# 3. Duplicate resource entries
# 4. Invalid escape sequences

# Validate repaired state
jq empty terraform.tfstate

# Test with Terraform
terraform state list

# If successful, push to remote
terraform state push terraform.tfstate
```


## Drift Detection and Remediation

### Manual Drift Detection

```bash
# Run plan to detect drift
terraform plan -detailed-exitcode

# Exit codes:
# 0 = No changes (no drift)
# 1 = Error
# 2 = Changes detected (drift found)

EXIT_CODE=$?
if [ $EXIT_CODE -eq 2 ]; then
    echo "⚠️  Drift detected!"
    terraform plan -no-color > drift-report.txt
    # Send alert, create ticket, etc.
fi
```


### Automated Drift Detection (CI/CD)

Already covered in Chapter 13, but here's CloudWatch-based approach:

```hcl
# drift-detection-lambda.tf
resource "aws_lambda_function" "drift_detector" {
  filename      = "drift_detector.zip"
  function_name = "terraform-drift-detection"
  role          = aws_iam_role.drift_detector.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 300
  
  environment {
    variables = {
      STATE_BUCKET = "terraform-state-bucket"
      STATE_KEY    = "production/terraform.tfstate"
      SLACK_WEBHOOK = var.slack_webhook_url
    }
  }
}

# Trigger every 6 hours
resource "aws_cloudwatch_event_rule" "drift_detection" {
  name                = "terraform-drift-detection"
  description         = "Detect infrastructure drift"
  schedule_expression = "rate(6 hours)"
}

resource "aws_cloudwatch_event_target" "drift_detector" {
  rule      = aws_cloudwatch_event_rule.drift_detection.name
  target_id = "DriftDetectorLambda"
  arn       = aws_lambda_function.drift_detector.arn
}
```

**Lambda function (drift_detector/index.py):**

```python
import boto3
import subprocess
import json
import os
from urllib.request import Request, urlopen

def handler(event, context):
    """Detect Terraform drift"""
    
    # Download state file
    s3 = boto3.client('s3')
    s3.download_file(
        os.environ['STATE_BUCKET'],
        os.environ['STATE_KEY'],
        '/tmp/terraform.tfstate'
    )
    
    # Run terraform plan
    result = subprocess.run(
        ['terraform', 'plan', '-detailed-exitcode', '-no-color'],
        capture_output=True,
        text=True,
        cwd='/tmp'
    )
    
    if result.returncode == 2:
        # Drift detected
        send_slack_alert(result.stdout)
        create_github_issue(result.stdout)
        
        return {
            'statusCode': 200,
            'body': 'Drift detected and reported'
        }
    
    return {
        'statusCode': 200,
        'body': 'No drift detected'
    }

def send_slack_alert(plan_output):
    """Send Slack notification"""
    webhook_url = os.environ['SLACK_WEBHOOK']
    
    message = {
        'text': '⚠️ Infrastructure Drift Detected',
        'blocks': [
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': '*Infrastructure Drift Detected*\n\nChanges detected outside of Terraform:'
                }
            },
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': f'``````'
                }
            }
        ]
    }
    
    req = Request(webhook_url, json.dumps(message).encode('utf-8'))
    req.add_header('Content-Type', 'application/json')
    urlopen(req)
```


### Investigating Drift with CloudTrail

Identify who made manual changes:

```bash
# Find EC2 instance modifications
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=i-0123456789abcdef0 \
  --max-results 50 \
  --query 'Events[*].[EventTime,EventName,Username]' \
  --output table

# Output shows:
# |  2025-12-08T14:30:00Z  |  ModifyInstanceAttribute  |  john.doe  |
# |  2025-12-08T14:25:00Z  |  CreateTags               |  john.doe  |

# Get full event details
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ModifyInstanceAttribute \
  --start-time "2025-12-08T14:00:00Z" \
  --end-time "2025-12-08T15:00:00Z" \
  --query 'Events[^0].CloudTrailEvent' \
  --output text | jq .

# Shows exact changes made (instance type, security groups, etc.)
```


### Drift Remediation Strategies

**Option 1: Revert to Terraform State (Recommended)**

```bash
# Apply Terraform config to revert manual changes
terraform apply
```

**Option 2: Accept Drift (Update Terraform Config)**

```bash
# Import changes into Terraform config
terraform plan -generate-config-out=drift-changes.tf

# Review generated changes
cat drift-changes.tf

# Merge into main config
# Edit main.tf to incorporate changes

# Verify
terraform plan
# Should show: No changes
```

**Option 3: Selective Remediation**

```bash
# Remediate specific resources only
terraform apply -target=aws_instance.web

# Or ignore certain resources
terraform plan -target=aws_instance.app
# (doesn't check or modify aws_instance.web)
```


## Performance Optimization

### Diagnosing Slow Plans

**Enable performance profiling:**

```bash
# Time terraform operations
time terraform plan

# Output:
# real    8m32.456s  <- Total time (too slow!)
# user    2m15.123s
# sys     0m45.789s

# Enable trace logging to see slow operations
export TF_LOG=TRACE
terraform plan 2>&1 | grep "elapsed"

# Look for lines like:
# aws_instance.web[^47]: Refreshing state... [id=i-xxx] (8m15s elapsed)
# aws_security_group.app: Refreshing state... [id=sg-xxx] (3m42s elapsed)
```


### Optimization 1: Increase Parallelism

Default parallelism is 10 concurrent operations:

```bash
# Increase to 20 (use with caution - may hit API limits)
terraform plan -parallelism=20
terraform apply -parallelism=20

# For very large infrastructures
terraform apply -parallelism=50

# Monitor API throttling
export TF_LOG=DEBUG
terraform apply -parallelism=20 2>&1 | grep -i "throttl\|rate"
```


### Optimization 2: Split Large State Files

When state file > 10 MB or > 1000 resources, split into layers:

```
Before (slow):
terraform/
└── main.tf (5000 resources, 45 MB state)
    ├── Networking (VPCs, subnets, etc.)
    ├── Compute (EC2, ASG, etc.)
    ├── Database (RDS, DynamoDB, etc.)
    ├── Storage (S3, EBS, etc.)
    └── Monitoring (CloudWatch, etc.)
    
Plan time: 8 minutes

After (fast):
terraform/
├── 01-networking/ (500 resources, 4 MB state)
├── 02-compute/ (1200 resources, 8 MB state)
├── 03-database/ (300 resources, 3 MB state)
├── 04-storage/ (2000 resources, 18 MB state)
└── 05-monitoring/ (1000 resources, 12 MB state)

Plan time per layer: 30-90 seconds
Total time (parallel): 90 seconds
```


### Optimization 3: Use -target for Focused Changes

```bash
# Instead of planning everything
terraform plan  # 8 minutes

# Target specific module
terraform plan -target=module.networking  # 30 seconds

# Target specific resource
terraform plan -target=aws_instance.web  # 5 seconds

# Multiple targets
terraform plan \
  -target=aws_instance.web \
  -target=aws_security_group.web \
  -target=aws_lb.web
```


### Optimization 4: Disable Refresh for Known Stable State

```bash
# Skip refresh phase (use when you know state is current)
terraform plan -refresh=false  # Saves 2-5 minutes

# Warning: Only use when:
# - No manual changes have been made
# - Recent plan/apply completed successfully
# - No other team members working on same resources
```


### Optimization 5: Provider Configuration Tuning

```hcl
# provider.tf
provider "aws" {
  region = "us-east-1"
  
  # Increase max retries (default: 25)
  max_retries = 50
  
  # Skip metadata API check (faster in CI/CD)
  skip_metadata_api_check = true
  
  # Skip credential validation (when you know they're valid)
  skip_credentials_validation = true
  
  # Skip region validation (when you know it exists)
  skip_region_validation = true
  
  # Skip requesting account ID (when not needed)
  skip_requesting_account_id = true
}
```

**Benchmark results:**

```bash
# Before optimization
time terraform plan
# real: 8m32s

# After: Split state + parallelism=20
time terraform plan -parallelism=20
# real: 1m45s

# Savings: 78% reduction in plan time
```


## ⚠️ Common Pitfalls

### Pitfall 1: Running terraform apply Without Review

**❌ PROBLEM:**

```bash
# Blindly applying without checking plan
terraform apply -auto-approve

# Destroys production database!
```

**✅ SOLUTION:**

```bash
# Always review plan first
terraform plan -out=tfplan
# Review output carefully
terraform apply tfplan
```


### Pitfall 2: Forgetting to Enable State Versioning

**❌ PROBLEM:**
S3 backend without versioning—state corruption is permanent.

**✅ SOLUTION:**

```hcl
resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  versioning_configuration {
    status = "Enabled"
  }
}
```


### Pitfall 3: Using -refresh=false Without Understanding Risks

**❌ PROBLEM:**
Skipping refresh causes plan to miss manual changes, then apply fails.

**✅ SOLUTION:**
Only use `-refresh=false` when you're certain no drift exists, or use `-refresh-only` to check first:

```bash
# Check for drift first
terraform plan -refresh-only

# If no drift, can safely skip refresh
terraform plan -refresh=false
```


### Pitfall 4: Not Monitoring State File Size Growth

**❌ PROBLEM:**
State grows from 1 MB to 50 MB over time. Plans take 10 minutes.

**✅ SOLUTION:**

```bash
# Monitor state size
aws s3 ls s3://terraform-state-bucket/production/ --recursive --human-readable

# Set alert when > 10 MB
# Consider splitting state files
```


### Pitfall 5: Ignoring Deprecation Warnings

**❌ PROBLEM:**

```
Warning: Deprecated argument

The argument "acl" is deprecated. Use aws_s3_bucket_acl resource instead.
```

Ignoring warnings leads to breaking changes in future provider versions.

**✅ SOLUTION:**
Address warnings immediately:

```hcl
# Before (deprecated)
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "private"
}

# After (current)
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}

resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.example.id
  acl    = "private"
}
```


### Pitfall 6: Not Testing State Recovery Procedures

**❌ PROBLEM:**
State corrupts in production. Team has never tested recovery. Panic ensues.

**✅ SOLUTION:**
Regularly test recovery in non-production:

```bash
# Quarterly drill
# 1. Backup state
# 2. Corrupt it intentionally
# 3. Practice recovery
# 4. Time how long it takes
# 5. Update runbook
```


## 💡 Expert Tips from the Field

1. **"Always save plan output before critical applies"** - `terraform plan -out=tfplan` creates replayable plan file preventing drift between plan and apply.
2. **"Use TF_LOG=TRACE sparingly—log files can reach gigabytes"** - Enable TRACE only for specific debugging sessions, otherwise use DEBUG or INFO.
3. **"Set up state file size alerts at 5 MB threshold"** - Performance degradation becomes noticeable above 5-10 MB. Split before hitting limits.
4. **"Run terraform refresh -refresh-only as drift detection, not terraform refresh"** - `terraform refresh` (deprecated) modifies state file. `-refresh-only` mode just shows drift.
5. **"Keep CloudTrail logs for 90+ days to investigate historical drift"** - Manual changes might have happened weeks ago. Long retention helps root cause analysis.
6. **"Use -parallelism carefully—more isn't always better"** - Exceeding provider API limits causes throttling, slowing overall operations. Start with 20, increase gradually.
7. **"State backups are useless if you never test restoring them"** - Quarterly restore drills ensure recovery procedures work and team knows how to execute.
8. **"Monitor terraform operation duration trends in your monitoring system"** - Plot plan/apply times over weeks. Sudden increases indicate problems (state bloat, API slowness, resource contention).
9. **"Use TF_LOG_PATH instead of piping stderr to file"** - `TF_LOG_PATH=./debug.log` is cleaner and captures all output reliably.
10. **"Create runbooks for top 10 errors your team encounters"** - Document resolution steps after solving each error. Build institutional knowledge.
11. **"Use separate S3 buckets for state and logs"** - Isolating state files from debug logs prevents accidental deletions and simplifies access controls.
12. **"Set DynamoDB state lock TTL to auto-expire old locks"** - Prevents eternal locks from crashed processes. Set TTL to 24 hours as safety net.
13. **"Profile resource refresh times to find slowest providers"** - `TF_LOG=TRACE` shows which resources take longest to refresh. Optimize or split those out.
14. **"Use Terraform Cloud's remote operations for very large states"** - Offloading execution to Terraform Cloud avoids local machine OOM errors on multi-GB states.
15. **"Tag all resources with 'LastTerraformApply' timestamp"** - Helps identify resources that haven't been touched by Terraform recently, potential drift candidates.

## 🎯 Practical Exercises

### Exercise 1: Debug Authentication Failure

**Difficulty:** Beginner
**Time:** 20 minutes
**Objective:** Use debug logging to diagnose and fix AWS authentication error

**Steps:**

1. **Create misconfigured provider:**
```hcl
# provider.tf (intentionally broken)
provider "aws" {
  region  = "us-east-1"
  profile = "nonexistent-profile"  # Doesn't exist
}
```

2. **Enable debug logging:**
```bash
export TF_LOG=DEBUG
export TF_LOG_PATH=./debug.log
terraform plan
```

3. **Analyze debug output:**
```bash
grep -i "credential\|auth\|profile" debug.log

# Find the error showing profile not found
```

4. **Fix configuration:**
```hcl
provider "aws" {
  region  = "us-east-1"
  profile = "default"  # Or remove to use default
}
```

5. **Verify fix:**
```bash
terraform plan
# Should now work
```

**Challenge:** Simulate MFA token expiration and debug

***

### Exercise 2: Recover from State Corruption

**Difficulty:** Intermediate
**Time:** 35 minutes
**Objective:** Simulate state corruption and practice recovery

**Steps:**

1. **Create test infrastructure:**
```hcl
# main.tf
resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"
  
  tags = {
    Name = "recovery-test"
  }
}

resource "aws_subnet" "test" {
  vpc_id     = aws_vpc.test.id
  cidr_block = "10.0.1.0/24"
}
```

2. **Apply and verify:**
```bash
terraform apply
terraform state list
# aws_vpc.test
# aws_subnet.test
```

3. **Backup state:**
```bash
cp terraform.tfstate terraform.tfstate.backup
```

4. **Corrupt state file:**
```bash
# Delete half the file
head -n 50 terraform.tfstate > terraform.tfstate.tmp
mv terraform.tfstate.tmp terraform.tfstate

# Verify corruption
jq . terraform.tfstate
# Should show JSON error
```

5. **Attempt operations:**
```bash
terraform plan
# Should fail with parsing error
```

6. **Restore from backup:**
```bash
cp terraform.tfstate.backup terraform.tfstate
terraform plan
# Should work now
```

7. **Cleanup:**
```bash
terraform destroy
```

**Challenge:** Simulate S3 versioning recovery by uploading corrupted state and restoring previous version

***

### Exercise 3: Implement Automated Drift Detection

**Difficulty:** Advanced
**Time:** 50 minutes
**Objective:** Set up scheduled drift detection with alerting

**Steps:**

1. **Create test infrastructure:**
```hcl
resource "aws_instance" "drift_test" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"
  
  tags = {
    Name = "drift-test"
    ManagedBy = "Terraform"
  }
}
```

2. **Apply infrastructure:**
```bash
terraform apply
```

3. **Create drift detection script:**
```bash
# drift-check.sh
#!/bin/bash

set -e

echo "Running drift detection at $(date)"

terraform init -input=false

# Run plan with exit code check
set +e
terraform plan -detailed-exitcode -no-color > drift-report.txt
EXIT_CODE=$?
set -e

if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ No drift detected"
    exit 0
elif [ $EXIT_CODE -eq 2 ]; then
    echo "⚠️ Drift detected!"
    
    # Send alert (Slack example)
    curl -X POST $SLACK_WEBHOOK_URL \
      -H 'Content-Type: application/json' \
      -d "{\"text\": \"Drift detected in infrastructure\", \"attachments\": [{\"text\": \"$(cat drift-report.txt)\"}]}"
    
    exit 1
else
    echo "❌ Error running terraform plan"
    exit 1
fi
```

4. **Make script executable:**
```bash
chmod +x drift-check.sh
```

5. **Simulate drift by manual change:**
```bash
# Get instance ID
INSTANCE_ID=$(terraform output -raw instance_id)

# Manually change tag
aws ec2 create-tags \
  --resources $INSTANCE_ID \
  --tags Key=Environment,Value=Manual
```

6. **Run drift detection:**
```bash
./drift-check.sh

# Should detect the manual tag change
```

7. **Set up cron job:**
```bash
# Edit crontab
crontab -e

# Add line (runs every 6 hours)
0 */6 * * * cd /path/to/terraform && ./drift-check.sh
```

**Challenge:** Deploy drift detection as Lambda function triggered by CloudWatch Events

***

## Key Takeaways

- **Debug logging with TF_LOG reveals internal Terraform behavior for systematic troubleshooting** - Setting `TF_LOG=TRACE` exposes provider API calls, authentication flows, and state operations showing exactly where failures occur
- **State file corruption is recoverable through S3 versioning, backups, or resource import** - Enable versioning on state buckets, maintain automated backups, and practice recovery procedures quarterly to ensure team readiness
- **Drift detection requires automated scheduled checks, not manual vigilance** - Running `terraform plan -detailed-exitcode` every 6 hours creates actionable drift reports with CloudTrail evidence identifying manual changes
- **Performance optimization starts with state file splitting and parallelism tuning** - States exceeding 10 MB or 1000 resources should be split into layers; parallelism settings balance speed against API rate limits
- **CloudTrail investigation identifies who made manual changes causing drift** - Querying CloudTrail with resource IDs and timeframes reveals the user, timestamp, and exact modifications enabling root cause analysis
- **Systematic error diagnosis beats random troubleshooting attempts** - Following structured debugging workflows (check logs → verify credentials → test connectivity → isolate issue) resolves problems faster than trial-and-error
- **Runbooks and tested recovery procedures prevent panic during incidents** - Documented resolution steps for common errors and practiced state recovery drills enable teams to respond confidently during production issues


## What's Next

With monitoring and troubleshooting capabilities ensuring reliable Terraform operations, **Chapter 16: Advanced Patterns and Real-World Case Studies** synthesizes all previous chapters into comprehensive enterprise architectures, exploring multi-region active-active deployments, disaster recovery implementations, cost optimization strategies saving 40% on AWS bills, security hardening beyond basics, and real-world migration stories moving 10,000+ resources from manual management to Terraform control.

## Additional Resources

**Official Documentation:**

- [Terraform Debugging](https://developer.hashicorp.com/terraform/internals/debugging) - Debug logging and troubleshooting
- [Terraform Environment Variables](https://developer.hashicorp.com/terraform/cli/config/environment-variables) - Complete environment variable reference
- [Terraform State Management](https://spacelift.io/blog/terraform-state) - State best practices

**Monitoring \& Debugging Tools:**

- [Spacelift](https://spacelift.io/blog/terraform-debug) - Terraform debugging tutorial
- [Terraform Drift Detection](https://spacelift.io/blog/terraform-drift-detection) - Comprehensive drift guide
- [Infracost](https://www.infracost.io) - Cost monitoring in CI/CD

**Performance Optimization:**

- [Terraform Optimization Guide](https://scalr.com/learning-center/terraform-optimization-guide/) - Performance tuning strategies
- [Large-Scale Terraform](https://moldstud.com/articles/p-solving-terraform-performance-issues-in-large-scale-environments) - Solving performance issues

**State Recovery:**

- [State Corruption Recovery](https://www.linkedin.com/pulse/recovering-lost-terraform-state-accidental-deletion-corruption-hoang) - Recovery strategies
- [Terraform State File Corruption](https://www.fosstechnix.com/terraform-state-file-corruption-recovery/) - Detailed recovery guide

**AWS Integration:**

- [CloudTrail for Terraform](https://dev.to/devopsfundamentals/terraform-fundamentals-cloudtrail-5d46) - Audit logging integration
- [AWS CloudTrail](https://aws.amazon.com/cloudtrail/) - Service documentation

***

**Monitoring transforms Terraform from a deployment tool into a reliable platform.** Debug logging reveals root causes instantly, automated drift detection catches problems before they compound, state backups enable recovery from any disaster, and performance optimization keeps operations fast as infrastructure scales. The difference between teams that struggle with Terraform and teams that excel isn't the tool—it's the observability and recovery systems they build around it.

## ECS Fargate Microservices Orchestration

### Complete ECS Fargate Stack

Deploy containerized applications on ECS Fargate with load balancing, auto-scaling, and service discovery.

```hcl
# ecs-fargate-stack.tf
terraform {
  required_version = ">= 1.11.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Variables
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "webapp"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "container_image" {
  description = "Docker container image"
  type        = string
}

variable "container_port" {
  description = "Container port"
  type        = number
  default     = 3000
}

variable "desired_count" {
  description = "Desired number of tasks"
  type        = number
  default     = 2
}

variable "cpu" {
  description = "Task CPU units (256, 512, 1024, 2048, 4096)"
  type        = number
  default     = 512
}

variable "memory" {
  description = "Task memory in MB (512, 1024, 2048, 4096, 8192)"
  type        = number
  default     = 1024
}

# VPC and Networking
data "aws_vpc" "main" {
  default = false
  
  tags = {
    Name = "${var.project_name}-vpc"
  }
}

data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.main.id]
  }
  
  tags = {
    Type = "private"
  }
}

data "aws_subnets" "public" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.main.id]
  }
  
  tags = {
    Type = "public"
  }
}

# ECS Cluster
resource "aws_ecs_cluster" "main" {
  name = "${var.project_name}-${var.environment}-cluster"
  
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  
  configuration {
    execute_command_configuration {
      logging = "OVERRIDE"
      
      log_configuration {
        cloud_watch_log_group_name = aws_cloudwatch_log_group.ecs_exec.name
      }
    }
  }
}

# ECS Cluster Capacity Providers
resource "aws_ecs_cluster_capacity_providers" "main" {
  cluster_name = aws_ecs_cluster.main.name
  
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]
  
  default_capacity_provider_strategy {
    base              = 1
    weight            = 100
    capacity_provider = "FARGATE"
  }
  
  default_capacity_provider_strategy {
    weight            = 0
    capacity_provider = "FARGATE_SPOT"
  }
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "ecs_exec" {
  name              = "/ecs/${var.project_name}-exec"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/${var.project_name}-${var.environment}"
  retention_in_days = 14
}

# ECR Repository
resource "aws_ecr_repository" "app" {
  name                 = "${var.project_name}-${var.environment}"
  image_tag_mutability = "MUTABLE"
  
  image_scanning_configuration {
    scan_on_push = true
  }
  
  encryption_configuration {
    encryption_type = "AES256"
  }
}

# Application Load Balancer
resource "aws_lb" "main" {
  name               = "${var.project_name}-${var.environment}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = data.aws_subnets.public.ids
  
  enable_deletion_protection = var.environment == "production" ? true : false
  enable_http2               = true
  enable_cross_zone_load_balancing = true
  
  tags = {
    Name = "${var.project_name}-${var.environment}-alb"
  }
}

# ALB Target Group
resource "aws_lb_target_group" "app" {
  name        = "${var.project_name}-${var.environment}-tg"
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = data.aws_vpc.main.id
  target_type = "ip"
  
  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 3
  }
  
  deregistration_delay = 30
  
  stickiness {
    type            = "lb_cookie"
    cookie_duration = 86400
    enabled         = true
  }
}

# ALB Listener HTTP (redirect to HTTPS)
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"
  
  default_action {
    type = "redirect"
    
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# ALB Listener HTTPS
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.app.arn
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# ACM Certificate (assumes domain validation done separately)
resource "aws_acm_certificate" "app" {
  domain_name       = "${var.project_name}.example.com"
  validation_method = "DNS"
  
  lifecycle {
    create_before_destroy = true
  }
}

# Security Group: ALB
resource "aws_security_group" "alb" {
  name        = "${var.project_name}-${var.environment}-alb-sg"
  description = "Security group for ALB"
  vpc_id      = data.aws_vpc.main.id
  
  ingress {
    description = "HTTP from internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "${var.project_name}-${var.environment}-alb-sg"
  }
}

# Security Group: ECS Tasks
resource "aws_security_group" "ecs_tasks" {
  name        = "${var.project_name}-${var.environment}-ecs-tasks-sg"
  description = "Security group for ECS tasks"
  vpc_id      = data.aws_vpc.main.id
  
  ingress {
    description     = "Traffic from ALB"
    from_port       = var.container_port
    to_port         = var.container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "${var.project_name}-${var.environment}-ecs-tasks-sg"
  }
}

# IAM Role: ECS Task Execution
resource "aws_iam_role" "ecs_task_execution" {
  name = "${var.project_name}-${var.environment}-ecs-task-execution"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Additional permissions for Secrets Manager
resource "aws_iam_role_policy" "ecs_task_execution_secrets" {
  name = "secrets-access"
  role = aws_iam_role.ecs_task_execution.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "kms:Decrypt"
        ]
        Resource = [
          aws_secretsmanager_secret.app_secrets.arn,
          aws_kms_key.secrets.arn
        ]
      }
    ]
  })
}

# IAM Role: ECS Task
resource "aws_iam_role" "ecs_task" {
  name = "${var.project_name}-${var.environment}-ecs-task"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Task permissions (S3, DynamoDB, etc.)
resource "aws_iam_role_policy" "ecs_task_permissions" {
  name = "task-permissions"
  role = aws_iam_role.ecs_task.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.app_data.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:Query"
        ]
        Resource = aws_dynamodb_table.app_data.arn
      }
    ]
  })
}

# Secrets Manager for sensitive data
resource "aws_secretsmanager_secret" "app_secrets" {
  name                    = "${var.project_name}-${var.environment}-secrets"
  description             = "Application secrets"
  kms_key_id              = aws_kms_key.secrets.id
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "app_secrets" {
  secret_id = aws_secretsmanager_secret.app_secrets.id
  
  secret_string = jsonencode({
    DATABASE_URL = "postgresql://user:pass@host:5432/db"
    API_KEY      = "secret-api-key-here"
    JWT_SECRET   = "jwt-signing-secret"
  })
}

# KMS Key for secrets
resource "aws_kms_key" "secrets" {
  description             = "KMS key for application secrets"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${var.project_name}-${var.environment}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

# ECS Task Definition
resource "aws_ecs_task_definition" "app" {
  family                   = "${var.project_name}-${var.environment}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn
  
  container_definitions = jsonencode([
    {
      name      = var.project_name
      image     = var.container_image
      essential = true
      
      portMappings = [
        {
          containerPort = var.container_port
          hostPort      = var.container_port
          protocol      = "tcp"
        }
      ]
      
      environment = [
        {
          name  = "ENVIRONMENT"
          value = var.environment
        },
        {
          name  = "PORT"
          value = tostring(var.container_port)
        }
      ]
      
      secrets = [
        {
          name      = "DATABASE_URL"
          valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:DATABASE_URL::"
        },
        {
          name      = "API_KEY"
          valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:API_KEY::"
        }
      ]
      
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.app.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }
      
      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:${var.container_port}/health || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }
    }
  ])
  
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
}

# ECS Service
resource "aws_ecs_service" "app" {
  name            = "${var.project_name}-${var.environment}-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"
  
  network_configuration {
    subnets          = data.aws_subnets.private.ids
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }
  
  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = var.project_name
    container_port   = var.container_port
  }
  
  deployment_configuration {
    maximum_percent         = 200
    minimum_healthy_percent = 100
    
    deployment_circuit_breaker {
      enable   = true
      rollback = true
    }
  }
  
  enable_execute_command = true
  
  depends_on = [
    aws_lb_listener.https,
    aws_iam_role_policy.ecs_task_permissions
  ]
}

# Auto Scaling Target
resource "aws_appautoscaling_target" "ecs" {
  max_capacity       = 10
  min_capacity       = var.desired_count
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.app.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

# Auto Scaling Policy: CPU
resource "aws_appautoscaling_policy" "ecs_cpu" {
  name               = "${var.project_name}-${var.environment}-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs.service_namespace
  
  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    
    target_value       = 70.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

# Auto Scaling Policy: Memory
resource "aws_appautoscaling_policy" "ecs_memory" {
  name               = "${var.project_name}-${var.environment}-memory-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs.service_namespace
  
  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }
    
    target_value       = 80.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

# S3 bucket for application data
resource "aws_s3_bucket" "app_data" {
  bucket = "${var.project_name}-${var.environment}-data-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "app_data" {
  bucket = aws_s3_bucket.app_data.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

# DynamoDB table
resource "aws_dynamodb_table" "app_data" {
  name           = "${var.project_name}-${var.environment}-data"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"
  range_key      = "timestamp"
  
  attribute {
    name = "id"
    type = "S"
  }
  
  attribute {
    name = "timestamp"
    type = "N"
  }
  
  point_in_time_recovery {
    enabled = true
  }
}

# Data source
data "aws_caller_identity" "current" {}

# Outputs
output "alb_dns_name" {
  description = "ALB DNS name"
  value       = aws_lb.main.dns_name
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.main.name
}

output "ecs_service_name" {
  description = "ECS service name"
  value       = aws_ecs_service.app.name
}

output "ecr_repository_url" {
  description = "ECR repository URL"
  value       = aws_ecr_repository.app.repository_url
}
```


## Systems Manager Parameter Store

### Hierarchical Parameter Management

Parameter Store provides cost-effective configuration management.

```hcl
# parameter-store.tf

# Standard tier parameters (free, up to 10,000 params)
resource "aws_ssm_parameter" "app_config" {
  for_each = {
    "database_host" = "db.example.com"
    "database_port" = "5432"
    "cache_ttl"     = "3600"
    "log_level"     = "INFO"
    "region"        = var.aws_region
  }
  
  name  = "/${var.project_name}/${var.environment}/config/${each.key}"
  type  = "String"
  value = each.value
  
  tags = {
    Environment = var.environment
    Application = var.project_name
  }
}

# SecureString parameters (encrypted with KMS)
resource "aws_ssm_parameter" "database_credentials" {
  name   = "/${var.project_name}/${var.environment}/secrets/database/credentials"
  type   = "SecureString"
  value  = jsonencode({
    username = "dbadmin"
    password = "ChangeMe123!"  # In practice, rotate this
  })
  key_id = aws_kms_key.parameters.id
  
  tags = {
    Environment = var.environment
    Sensitive   = "true"
  }
}

# Advanced tier parameters (for parameters > 4KB or high throughput)
resource "aws_ssm_parameter" "large_config" {
  name  = "/${var.project_name}/${var.environment}/config/large_json"
  type  = "String"
  tier  = "Advanced"  # Supports up to 8 KB
  value = jsonencode({
    # Large configuration object
    feature_flags = {
      new_ui_enabled        = true
      beta_features_enabled = false
      experimental_mode     = false
    }
    api_endpoints = {
      primary   = "https://api.example.com"
      secondary = "https://api-backup.example.com"
    }
    # ... more config
  })
}

# StringList parameter (comma-separated values)
resource "aws_ssm_parameter" "allowed_ips" {
  name  = "/${var.project_name}/${var.environment}/security/allowed_ips"
  type  = "StringList"
  value = "10.0.1.0/24,10.0.2.0/24,192.168.1.0/24"
}

# KMS key for SecureString encryption
resource "aws_kms_key" "parameters" {
  description             = "KMS key for SSM Parameter Store"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_kms_alias" "parameters" {
  name          = "alias/${var.project_name}-${var.environment}-params"
  target_key_id = aws_kms_key.parameters.key_id
}

# Data sources to read parameters in other resources
data "aws_ssm_parameter" "database_host" {
  name = aws_ssm_parameter.app_config["database_host"].name
}

data "aws_ssm_parameter" "database_credentials" {
  name            = aws_ssm_parameter.database_credentials.name
  with_decryption = true
}

# Lambda function reading parameters
resource "aws_lambda_function" "config_reader" {
  filename      = "config_reader.zip"
  function_name = "${var.project_name}-config-reader"
  role          = aws_iam_role.lambda_config_reader.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  
  environment {
    variables = {
      PARAMETER_PATH = "/${var.project_name}/${var.environment}/config/"
    }
  }
}

# IAM permissions for Lambda to read parameters
resource "aws_iam_role" "lambda_config_reader" {
  name = "${var.project_name}-lambda-config-reader"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_ssm_read" {
  name = "ssm-read-policy"
  role = aws_iam_role.lambda_config_reader.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/${var.project_name}/${var.environment}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.parameters.arn
      }
    ]
  })
}
```

**Lambda function reading parameters:**

```python
# config_reader/index.py
import boto3
import os
import json

ssm = boto3.client('ssm')

def handler(event, context):
    """Read configuration from Parameter Store"""
    
    parameter_path = os.environ['PARAMETER_PATH']
    
    # Get all parameters under path
    response = ssm.get_parameters_by_path(
        Path=parameter_path,
        Recursive=True,
        WithDecryption=True  # Decrypt SecureString parameters
    )
    
    config = {}
    for param in response['Parameters']:
        # Extract parameter name (remove path prefix)
        name = param['Name'].replace(parameter_path, '')
        config[name] = param['Value']
    
    print(f"Loaded configuration: {json.dumps(config, indent=2)}")
    
    return {
        'statusCode': 200,
        'body': json.dumps(config)
    }
```


## Secrets Manager with Rotation

### Automatic Database Credential Rotation

Secrets Manager automates credential rotation reducing security risk.

```hcl
# secrets-manager-rotation.tf

# RDS Database
resource "aws_db_instance" "main" {
  identifier     = "${var.project_name}-${var.environment}-db"
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.micro"
  
  allocated_storage     = 20
  max_allocated_storage = 100
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.rds.arn
  
  db_name  = var.database_name
  username = "admin"
  password = random_password.db_master_password.result
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"
  
  skip_final_snapshot       = var.environment != "production"
  final_snapshot_identifier = var.environment == "production" ? "${var.project_name}-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}" : null
}

# Generate random master password
resource "random_password" "db_master_password" {
  length  = 32
  special = true
}

# Store master credentials in Secrets Manager
resource "aws_secretsmanager_secret" "db_master" {
  name                    = "${var.project_name}/${var.environment}/rds/master"
  description             = "RDS master credentials"
  kms_key_id              = aws_kms_key.secrets.id
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "db_master" {
  secret_id = aws_secretsmanager_secret.db_master.id
  
  secret_string = jsonencode({
    username            = aws_db_instance.main.username
    password            = random_password.db_master_password.result
    engine              = "postgres"
    host                = aws_db_instance.main.address
    port                = aws_db_instance.main.port
    dbname              = aws_db_instance.main.db_name
    dbInstanceIdentifier = aws_db_instance.main.identifier
  })
}

# Application credentials (separate from master, will be rotated)
resource "aws_secretsmanager_secret" "db_app" {
  name                    = "${var.project_name}/${var.environment}/rds/app"
  description             = "Application database credentials (auto-rotated)"
  kms_key_id              = aws_kms_key.secrets.id
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "db_app" {
  secret_id = aws_secretsmanager_secret.db_app.id
  
  secret_string = jsonencode({
    username = "app_user"
    password = random_password.db_app_password.result
    engine   = "postgres"
    host     = aws_db_instance.main.address
    port     = aws_db_instance.main.port
    dbname   = aws_db_instance.main.db_name
  })
}

resource "random_password" "db_app_password" {
  length  = 32
  special = true
}

# Lambda function for rotation
resource "aws_lambda_function" "rotate_secret" {
  filename      = "rotation_function.zip"
  function_name = "${var.project_name}-${var.environment}-rotate-secret"
  role          = aws_iam_role.rotation_lambda.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.11"
  timeout       = 30
  
  vpc_config {
    subnet_ids         = data.aws_subnets.private.ids
    security_group_ids = [aws_security_group.rotation_lambda.id]
  }
  
  environment {
    variables = {
      SECRETS_MANAGER_ENDPOINT = "https://secretsmanager.${var.aws_region}.amazonaws.com"
    }
  }
}

# Lambda permission for Secrets Manager
resource "aws_lambda_permission" "rotation" {
  statement_id  = "AllowSecretsManagerInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rotate_secret.function_name
  principal     = "secretsmanager.amazonaws.com"
}

# Enable automatic rotation
resource "aws_secretsmanager_secret_rotation" "db_app" {
  secret_id           = aws_secretsmanager_secret.db_app.id
  rotation_lambda_arn = aws_lambda_function.rotate_secret.arn
  
  rotation_rules {
    automatically_after_days = 30
  }
}

# IAM role for rotation Lambda
resource "aws_iam_role" "rotation_lambda" {
  name = "${var.project_name}-${var.environment}-rotation-lambda"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Lambda VPC execution permissions
resource "aws_iam_role_policy_attachment" "rotation_lambda_vpc" {
  role       = aws_iam_role.rotation_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Rotation Lambda permissions
resource "aws_iam_role_policy" "rotation_lambda_permissions" {
  name = "rotation-permissions"
  role = aws_iam_role.rotation_lambda.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecretVersionStage"
        ]
        Resource = [
          aws_secretsmanager_secret.db_app.arn,
          aws_secretsmanager_secret.db_master.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetRandomPassword"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.secrets.arn
      }
    ]
  })
}

# Security group for rotation Lambda
resource "aws_security_group" "rotation_lambda" {
  name        = "${var.project_name}-${var.environment}-rotation-lambda-sg"
  description = "Security group for rotation Lambda"
  vpc_id      = data.aws_vpc.main.id
  
  egress {
    description = "Postgres to RDS"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    security_groups = [aws_security_group.rds.id]
  }
  
  egress {
    description = "HTTPS to Secrets Manager"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Update RDS security group to allow rotation Lambda
resource "aws_security_group_rule" "rds_from_rotation_lambda" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.rds.id
  source_security_group_id = aws_security_group.rotation_lambda.id
  description              = "Allow rotation Lambda"
}
```


## Step Functions Workflow Orchestration

### Multi-Step Data Processing Pipeline

Step Functions coordinate complex workflows across multiple services.

```hcl
# step-functions-workflow.tf

# Step Functions state machine
resource "aws_sfn_state_machine" "data_pipeline" {
  name     = "${var.project_name}-${var.environment}-data-pipeline"
  role_arn = aws_iam_role.step_functions.arn
  
  definition = jsonencode({
    Comment = "Data processing pipeline"
    StartAt = "ValidateInput"
    States = {
      ValidateInput = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.validate_input.arn
          Payload = {
            "input.$" = "$"
          }
        }
        ResultPath = "$.validation"
        Next       = "CheckValidation"
        Retry = [
          {
            ErrorEquals = ["Lambda.ServiceException", "Lambda.TooManyRequestsException"]
            IntervalSeconds = 2
            MaxAttempts     = 3
            BackoffRate     = 2.0
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            ResultPath  = "$.error"
            Next        = "HandleError"
          }
        ]
      }
      
      CheckValidation = {
        Type = "Choice"
        Choices = [
          {
            Variable      = "$.validation.Payload.valid"
            BooleanEquals = true
            Next          = "ProcessDataParallel"
          }
        ]
        Default = "ValidationFailed"
      }
      
      ValidationFailed = {
        Type = "Fail"
        Error = "ValidationError"
        Cause = "Input validation failed"
      }
      
      ProcessDataParallel = {
        Type = "Parallel"
        Branches = [
          {
            StartAt = "TransformData"
            States = {
              TransformData = {
                Type     = "Task"
                Resource = "arn:aws:states:::lambda:invoke"
                Parameters = {
                  FunctionName = aws_lambda_function.transform_data.arn
                  Payload = {
                    "data.$" = "$.input"
                  }
                }
                End = true
              }
            }
          },
          {
            StartAt = "EnrichData"
            States = {
              EnrichData = {
                Type     = "Task"
                Resource = "arn:aws:states:::lambda:invoke"
                Parameters = {
                  FunctionName = aws_lambda_function.enrich_data.arn
                  Payload = {
                    "data.$" = "$.input"
                  }
                }
                End = true
              }
            }
          }
        ]
        ResultPath = "$.processedData"
        Next       = "MergeResults"
      }
      
      MergeResults = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.merge_results.arn
          Payload = {
            "results.$" = "$.processedData"
          }
        }
        ResultPath = "$.merged"
        Next       = "SaveToS3"
      }
      
      SaveToS3 = {
        Type     = "Task"
        Resource = "arn:aws:states:::aws-sdk:s3:putObject"
        Parameters = {
          Bucket = aws_s3_bucket.pipeline_output.id
          Key    = "output/result-$.execution.startTime.json"
          Body = {
            "data.$" = "$.merged.Payload"
          }
        }
        ResultPath = "$.s3Output"
        Next       = "NotifySuccess"
      }
      
      NotifySuccess = {
        Type     = "Task"
        Resource = "arn:aws:states:::sns:publish"
        Parameters = {
          TopicArn = aws_sns_topic.pipeline_notifications.arn
          Message = {
            "status"        = "SUCCESS"
            "executionArn.$" = "$$.Execution.Id"
            "outputLocation.$" = "$.s3Output.Key"
          }
        }
        End = true
      }
      
      HandleError = {
        Type     = "Task"
        Resource = "arn:aws:states:::sns:publish"
        Parameters = {
          TopicArn = aws_sns_topic.pipeline_notifications.arn
          Message = {
            "status"        = "FAILED"
            "executionArn.$" = "$$.Execution.Id"
            "error.$"        = "$.error"
          }
        }
        Next = "FailState"
      }
      
      FailState = {
        Type  = "Fail"
        Error = "PipelineExecutionFailed"
        Cause = "An error occurred during pipeline execution"
      }
    }
  })
  
  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.step_functions.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }
  
  tracing_configuration {
    enabled = true
  }
}

# CloudWatch Log Group for Step Functions
resource "aws_cloudwatch_log_group" "step_functions" {
  name              = "/aws/stepfunctions/${var.project_name}-${var.environment}"
  retention_in_days = 14
}

# IAM role for Step Functions
resource "aws_iam_role" "step_functions" {
  name = "${var.project_name}-${var.environment}-step-functions"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "states.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Step Functions permissions
resource "aws_iam_role_policy" "step_functions" {
  name = "step-functions-permissions"
  role = aws_iam_role.step_functions.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = [
          aws_lambda_function.validate_input.arn,
          aws_lambda_function.transform_data.arn,
          aws_lambda_function.enrich_data.arn,
          aws_lambda_function.merge_results.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.pipeline_output.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.pipeline_notifications.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:ListLogDeliveries",
          "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords"
        ]
        Resource = "*"
      }
    ]
  })
}

# EventBridge rule to trigger Step Functions
resource "aws_cloudwatch_event_rule" "trigger_pipeline" {
  name                = "${var.project_name}-${var.environment}-trigger-pipeline"
  description         = "Trigger data pipeline daily"
  schedule_expression = "cron(0 2 * * ? *)"
}

resource "aws_cloudwatch_event_target" "step_functions" {
  rule      = aws_cloudwatch_event_rule.trigger_pipeline.name
  target_id = "StepFunctionsTarget"
  arn       = aws_sfn_state_machine.data_pipeline.arn
  role_arn  = aws_iam_role.eventbridge_step_functions.arn
  
  input = jsonencode({
    input = {
      source      = "scheduled"
      date        = "$.time"
      environment = var.environment
    }
  })
}

# IAM role for EventBridge to invoke Step Functions
resource "aws_iam_role" "eventbridge_step_functions" {
  name = "${var.project_name}-${var.environment}-eventbridge-sfn"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "eventbridge_step_functions" {
  name = "start-execution"
  role = aws_iam_role.eventbridge_step_functions.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "states:StartExecution"
        Resource = aws_sfn_state_machine.data_pipeline.arn
      }
    ]
  })
}

# S3 bucket for pipeline output
resource "aws_s3_bucket" "pipeline_output" {
  bucket = "${var.project_name}-${var.environment}-pipeline-output-${data.aws_caller_identity.current.account_id}"
}

# SNS topic for notifications
resource "aws_sns_topic" "pipeline_notifications" {
  name = "${var.project_name}-${var.environment}-pipeline-notifications"
}
```


## ⚠️ Common Pitfalls

### Pitfall 1: Hardcoding Secrets in Container Definitions

**❌ PROBLEM:**

```hcl
container_definitions = jsonencode([{
  environment = [
    {
      name  = "DATABASE_PASSWORD"
      value = "MySecretPassword123!"  # Exposed in state file and logs!
    }
  ]
}])
```

**✅ SOLUTION:**

```hcl
container_definitions = jsonencode([{
  secrets = [
    {
      name      = "DATABASE_PASSWORD"
      valueFrom = "${aws_secretsmanager_secret.db.arn}:password::"
    }
  ]
}])
```


### Pitfall 2: Not Setting ECS Task CPU/Memory Correctly

**❌ PROBLEM:**

```hcl
cpu    = 256
memory = 2048  # Invalid combination! 256 CPU supports max 2 GB
```

**Valid Fargate combinations:**


| CPU | Memory Options |
| :-- | :-- |
| 256 | 512 MB, 1 GB, 2 GB |
| 512 | 1 GB - 4 GB (1 GB increments) |
| 1024 | 2 GB - 8 GB (1 GB increments) |
| 2048 | 4 GB - 16 GB (1 GB increments) |
| 4096 | 8 GB - 30 GB (1 GB increments) |

**✅ SOLUTION:**

```hcl
cpu    = 512   # Must match memory
memory = 2048  # 2 GB (valid for 512 CPU)
```


### Pitfall 3: EventBridge Event Pattern Typos

**❌ PROBLEM:**

```hcl
event_pattern = jsonencode({
  source = ["aws.s3"]
  detail-type = ["Object Created"]  # Correct
  detial = {  # TYPO: should be "detail"
    bucket = { name = ["my-bucket"] }
  }
})
# Events never match due to typo
```

**✅ SOLUTION:**
Validate event patterns with test events:

```bash
aws events test-event-pattern \
  --event-pattern file://pattern.json \
  --event file://test-event.json
```


### Pitfall 4: Lambda Container Images Exceeding 10 GB

**❌ PROBLEM:**

```dockerfile
FROM python:3.11
RUN pip install tensorflow opencv-python pandas numpy scipy
# Image size: 12 GB - Lambda limit is 10 GB!
```

**✅ SOLUTION:**
Use slim base images and multi-stage builds:

```dockerfile
FROM public.ecr.aws/lambda/python:3.11
RUN pip install --no-cache-dir tensorflow-cpu  # CPU version is smaller
```


### Pitfall 5: Not Implementing ECS Deployment Circuit Breaker

**❌ PROBLEM:**

```hcl
# Missing circuit breaker
deployment_configuration {
  maximum_percent         = 200
  minimum_healthy_percent = 100
}
# New bad deployment kills all tasks before rollback
```

**✅ SOLUTION:**

```hcl
deployment_configuration {
  deployment_circuit_breaker {
    enable   = true
    rollback = true  # Auto-rollback on failure
  }
}
```


### Pitfall 6: Secrets Manager Costs Not Monitored

**❌ PROBLEM:**
Creating hundreds of secrets without cost awareness:

- \$0.40/secret/month
- \$0.05 per 10,000 API calls
- 1000 secrets = \$400/month!

**✅ SOLUTION:**
Use Parameter Store for non-sensitive config (free standard tier):

```hcl
# Use Secrets Manager only for sensitive data
resource "aws_secretsmanager_secret" "api_key" {}

# Use Parameter Store for everything else
resource "aws_ssm_parameter" "config" {
  type = "String"  # Free
}
```


### Pitfall 7: Step Functions Synchronous Waits Timing Out

**❌ PROBLEM:**

```hcl
{
  Type     = "Task"
  Resource = "arn:aws:states:::lambda:invoke.waitForTaskToken"
  TimeoutSeconds = 3600  # Default is 60 seconds
}
# Long-running task times out
```

**✅ SOLUTION:**

```hcl
{
  Type           = "Task"
  Resource       = "arn:aws:states:::lambda:invoke.waitForTaskToken"
  TimeoutSeconds = 86400  # 24 hours
  HeartbeatSeconds = 300  # Must send heartbeat every 5 min
}
```


## 💡 Expert Tips from the Field

1. **"Use EventBridge Archive to replay events during debugging"** - Archive stores events for up to 365 days, enabling replay after fixing bugs.
2. **"ECS exec command provides emergency access to running containers"** - Enable with `enable_execute_command = true` for production troubleshooting.
3. **"Parameter Store path hierarchy enables bulk operations"** - Use `/app/env/service/config` structure with `GetParametersByPath`.
4. **"Secrets Manager rotation uses two passwords simultaneously during transition"** - AWSCURRENT and AWSPENDING versions prevent downtime.
5. **"Lambda container images support up to 10 GB vs 250 MB for ZIP"** - Use containers for ML models, large dependencies, custom runtimes.
6. **"ECS Fargate Spot saves 70% but can be interrupted"** - Use for fault-tolerant workloads with graceful shutdown.
7. **"Step Functions Express Workflows cost 1/10th of Standard for high-volume short workflows"** - Under 5 minutes, < 25,000 state transitions.
8. **"EventBridge input transformers reduce Lambda code"** - Transform events before invoking targets using JSON path.
9. **"Use ECS service-linked roles instead of custom roles when possible"** - AWS manages permissions updates automatically.
10. **"Secrets Manager version stages enable zero-downtime rotation"** - Applications read AWSCURRENT, rotation updates AWSPENDING.
11. **"Parameter Store SecureString with default KMS is free"** - Only custom KMS keys incur charges.
12. **"ECS task placement strategies optimize utilization"** - `binpack` minimizes instances, `spread` distributes across AZs.
13. **"Step Functions Map state processes arrays in parallel"** - Alternative to Lambda fan-out patterns.
14. **"EventBridge cross-account events require both sender and receiver policies"** - Source account must grant PutEvents, target account must allow.
15. **"Lambda SnapStart reduces cold starts by 90% for Java containers"** - Enable with `snap_start { apply_on = "PublishedVersions" }`.

## 🎯 Practical Exercises

### Exercise 1: Build EventBridge-Triggered Lambda Pipeline

**Difficulty:** Intermediate
**Time:** 40 minutes
**Objective:** Create S3 → EventBridge → Lambda → DynamoDB pipeline

**Prerequisites:**

- AWS account
- Terraform 1.11+

**Steps:**

1. **Create project structure:**
```bash
mkdir eventbridge-pipeline
cd eventbridge-pipeline
```

2. **Use EventBridge configuration from earlier section**
3. **Create Lambda function:**
```python
# processor/index.py
import boto3
import json
from datetime import datetime

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('document-processing')

def handler(event, context):
    detail = event['detail']
    bucket = detail['bucket']['name']
    key = detail['object']['key']
    
    # Store processing record
    table.put_item(Item={
        'id': f"{bucket}/{key}",
        'timestamp': int(datetime.now().timestamp()),
        'bucket': bucket,
        'key': key,
        'status': 'processed',
        'size': detail['object']['size']
    })
    
    return {'statusCode': 200}
```

4. **Add DynamoDB table to Terraform:**
```hcl
resource "aws_dynamodb_table" "processing" {
  name         = "document-processing"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  range_key    = "timestamp"
  
  attribute {
    name = "id"
    type = "S"
  }
  attribute {
    name = "timestamp"
    type = "N"
  }
}
```

5. **Deploy and test:**
```bash
terraform apply

# Upload test file
aws s3 cp test.txt s3://$(terraform output -raw upload_bucket_name)/documents/test.txt

# Verify DynamoDB record
aws dynamodb scan --table-name document-processing
```

**Challenge:** Add SNS notification when processing fails

***

### Exercise 2: Deploy Containerized Application on ECS Fargate

**Difficulty:** Advanced
**Time:** 60 minutes
**Objective:** Deploy Node.js app on ECS with ALB and auto-scaling

**Steps:**

1. **Create simple Node.js app:**
```javascript
// app.js
const express = require('express');
const app = express();
const port = process.env.PORT || 3000;

app.get('/health', (req, res) => {
  res.json({ status: 'healthy' });
});

app.get('/', (req, res) => {
  res.json({ message: 'Hello from ECS Fargate!' });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
```

2. **Create Dockerfile:**
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .
EXPOSE 3000
CMD ["node", "app.js"]
```

3. **Build and push to ECR:**
```bash
aws ecr create-repository --repository-name myapp
aws ecr get-login-password | docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com
docker build -t myapp .
docker tag myapp:latest <account>.dkr.ecr.us-east-1.amazonaws.com/myapp:latest
docker push <account>.dkr.ecr.us-east-1.amazonaws.com/myapp:latest
```

4. **Deploy with ECS Fargate Terraform configuration from earlier**
5. **Test application:**
```bash
ALB_DNS=$(terraform output -raw alb_dns_name)
curl http://$ALB_DNS/health
```

**Challenge:** Add blue/green deployment with CodeDeploy

***

### Exercise 3: Implement Secrets Rotation

**Difficulty:** Advanced
**Time:** 50 minutes
**Objective:** Set up automatic RDS credential rotation

**Steps:**

1. **Use Secrets Manager rotation configuration from earlier**
2. **Create rotation Lambda (use AWS template):**
```bash
# Download AWS rotation template
wget https://raw.githubusercontent.com/aws-samples/aws-secrets-manager-rotation-lambdas/master/SecretsManagerRDSPostgreSQLRotationSingleUser/lambda_function.py
zip rotation_function.zip lambda_function.py
```

3. **Deploy infrastructure:**
```bash
terraform apply
```

4. **Trigger manual rotation:**
```bash
aws secretsmanager rotate-secret \
  --secret-id $(terraform output -raw secret_id)
```

5. **Verify rotation:**
```bash
aws secretsmanager describe-secret --secret-id $(terraform output -raw secret_id)
# Check RotationEnabled: true
# Check LastRotatedDate
```

**Challenge:** Implement custom rotation for API keys with external service

***

## Key Takeaways

- **EventBridge enables event-driven architectures decoupling services through asynchronous communication** - Rules route events from 20+ AWS services to Lambda, SQS, SNS, Step Functions, and ECS using pattern matching and transformations
- **Lambda container images support custom dependencies up to 10 GB enabling complex applications** - Deploy ML models, large libraries, and custom runtimes in Docker containers pushed to ECR with automated CI/CD
- **ECS Fargate eliminates server management while providing full container orchestration** - Deploy microservices with load balancing, auto-scaling, service discovery, and secrets injection without managing EC2 instances
- **Secrets Manager automatic rotation reduces security risk through credential lifecycle management** - Rotate RDS passwords every 30 days using Lambda functions that update credentials across all consumers without downtime
- **Parameter Store provides hierarchical configuration management with minimal cost** - Store 10,000 parameters free in standard tier using path structures enabling bulk operations with GetParametersByPath
- **Step Functions orchestrate multi-service workflows with built-in error handling and retries** - Coordinate Lambda, ECS, Glue, and SageMaker into reliable state machines supporting parallel execution, conditionals, and wait states
- **Integration patterns compose AWS services into cohesive systems exceeding individual service capabilities** - EventBridge triggers Step Functions executing Lambda and ECS tasks storing results in S3 with SNS notifications creating end-to-end automated pipelines


## What's Next

With advanced AWS service integrations enabling sophisticated architectures, **Chapter 17: Production Best Practices and Enterprise Patterns** synthesizes all previous chapters into comprehensive production-ready patterns, covering multi-account strategies with AWS Organizations, disaster recovery architectures achieving RPO < 1 hour, cost optimization techniques reducing bills 40%, security hardening beyond basics, and real-world case studies showing enterprise migrations managing 10,000+ resources.

## Additional Resources

**Official Documentation:**

- [EventBridge with Terraform](https://spacelift.io/blog/terraform-eventbridge) - Comprehensive EventBridge guide
- [Lambda Container Images](https://docs.aws.amazon.com/lambda/latest/dg/images-create.html) - Official Lambda container documentation
- [ECS Fargate Guide](https://www.gyden.io/en/content-hub/how-to-setup-amazon-ecs-fargate-using-terraform) - Complete Fargate setup
- [Step Functions Best Practices](https://aws.amazon.com/blogs/devops/best-practices-for-writing-step-functions-terraform-projects/) - AWS official guide

**AWS Prescriptive Guidance:**

- [Secrets Manager Rotation](https://docs.aws.amazon.com/prescriptive-guidance/latest/secure-sensitive-data-secrets-manager-terraform/rotate-secrets.html) - Rotation strategies
- [Parameter Store Best Practices](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html) - Official SSM documentation

**Terraform Modules:**

- [terraform-aws-eventbridge](https://github.com/terraform-aws-modules/terraform-aws-eventbridge) - Community EventBridge module
- [terraform-aws-ssm-parameter-store](https://github.com/cloudposse/terraform-aws-ssm-parameter-store) - Parameter Store module

**Additional Resources:**

- [EventBridge Pipes](https://nordcloud.com/tech-community/building-an-event-driven-architecture-eventbridge-pipes-terraform/) - Advanced event routing
- [Lambda Docker Deployment](https://akava.io/blog/deploying-containerized-aws-lambda-functions-w-terraform) - Container deployment guide

***

**Advanced integrations transform isolated AWS services into integrated systems.** EventBridge connects services through events, containers package applications with dependencies, Fargate runs them without servers, Secrets Manager protects credentials, Parameter Store manages configuration, and Step Functions orchestrate it all. Mastering these integrations separates basic cloud usage from sophisticated, production-grade architectures that scale, adapt, and evolve with business needs.
