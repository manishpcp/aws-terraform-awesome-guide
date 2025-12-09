# Chapter 10: Testing Infrastructure Code

## Introduction

Infrastructure testing is the difference between hoping your Terraform code works and knowing it works before it reaches production. Without testing, every `terraform apply` is a gamble—will the VPC CIDR overlap with existing networks? Will the security group rules actually allow the traffic you need? Will the RDS instance survive a failover? Testing transforms infrastructure deployment from a high-stakes manual process into a confident, repeatable operation where failures happen in development, not during customer-facing outages.

The challenge with infrastructure testing is that unlike application code, you can't mock AWS APIs without losing the very integration points where most failures occur. A unit test that validates your HCL syntax is helpful, but it won't catch the reality that your chosen instance type isn't available in your target availability zone, or that your IAM policy is missing a permission that only surfaces during actual resource creation. This creates a testing pyramid unique to infrastructure: static analysis at the base for fast feedback, integration tests in the middle that deploy to real AWS accounts, and end-to-end tests at the top that validate complete system behavior.

This chapter covers the complete spectrum of Terraform testing methodologies used in production environments. You'll learn static analysis with terraform validate, tflint, and tfsec that catch errors in seconds; integration testing with Terratest that deploys actual infrastructure and validates it works; policy-as-code with OPA and Sentinel that enforces organizational standards; contract testing that ensures modules don't break consumers; and the native terraform test command introduced in Terraform 1.6+ that brings testing into the core workflow. Whether you're writing your first module test or building a comprehensive CI/CD testing pipeline that validates infrastructure across multiple AWS accounts, these patterns will help you catch bugs before they cause incidents.

## The Infrastructure Testing Pyramid

The testing pyramid for infrastructure code differs from traditional software testing due to the cost and time of deploying actual cloud resources.

```
                    ▲
                   / \
                  /   \
                 /  E2E \
                / Tests  \
               /__________\
              /            \
             /  Integration \
            /     Tests      \
           /_________________\
          /                   \
         /   Static Analysis   \
        /    & Unit Tests       \
       /_______________________\
```


### Layer 1: Static Analysis (Fastest, Cheapest)

**Tools:** `terraform fmt`, `terraform validate`, `tflint`, `tfsec`, `checkov`, `terrascan`
**Execution Time:** Seconds
**Cost:** Free
**What it catches:** Syntax errors, deprecated resources, security misconfigurations, style violations

**Example Static Analysis Pipeline:**

```bash
#!/bin/bash
# static-analysis.sh

set -e

echo "Running Terraform format check..."
terraform fmt -check -recursive
if [ $? -ne 0 ]; then
  echo "❌ Format check failed. Run: terraform fmt -recursive"
  exit 1
fi

echo "Running Terraform validation..."
terraform init -backend=false
terraform validate
if [ $? -ne 0 ]; then
  echo "❌ Validation failed"
  exit 1
fi

echo "Running tflint..."
tflint --init
tflint --recursive
if [ $? -ne 0 ]; then
  echo "❌ tflint found issues"
  exit 1
fi

echo "Running tfsec security scan..."
tfsec . --minimum-severity MEDIUM
if [ $? -ne 0 ]; then
  echo "❌ Security issues found"
  exit 1
fi

echo "Running Checkov policy scan..."
checkov -d . --compact --quiet
if [ $? -ne 0 ]; then
  echo "❌ Policy violations found"
  exit 1
fi

echo "✅ All static analysis checks passed"
```


### Layer 2: Integration Tests (Medium Speed, AWS Costs)

**Tools:** Terratest, Terraform native tests, Kitchen-Terraform
**Execution Time:** 5-15 minutes
**Cost:** AWS resource charges
**What it catches:** Resource creation failures, configuration errors, dependency issues

**Example Integration Test Structure:**

```
tests/
├── integration/
│   ├── vpc_test.go           # VPC module tests
│   ├── compute_test.go       # EC2/ASG tests
│   ├── database_test.go      # RDS tests
│   └── fixtures/             # Test configurations
│       ├── vpc/
│       │   ├── main.tf
│       │   └── variables.tf
│       └── complete/
│           └── main.tf
└── go.mod
```


### Layer 3: End-to-End Tests (Slowest, Most Comprehensive)

**Tools:** Terratest with full deployments, smoke tests, monitoring validation
**Execution Time:** 15-45 minutes
**Cost:** Full environment AWS charges
**What it catches:** Cross-stack integration issues, actual service functionality, performance problems

### Testing Strategy by Project Size

| Project Size | Static Analysis | Integration Tests | E2E Tests |
| :-- | :-- | :-- | :-- |
| **< 50 resources** | Every commit | Every PR | Pre-release |
| **50-200 resources** | Every commit | Every PR | Daily |
| **200-500 resources** | Every commit | Nightly | Weekly |
| **500+ resources** | Every commit | Critical paths only | On-demand |

## Static Analysis and Validation

### terraform validate: Syntax and Configuration Validation

```bash
# Basic validation
terraform init -backend=false
terraform validate

# Example output for valid configuration:
# Success! The configuration is valid.

# Example output for invalid configuration:
# Error: Unsupported argument
#
#   on main.tf line 15, in resource "aws_instance" "web":
#   15:   instance_typo = "t3.micro"
#
# An argument named "instance_typo" is not expected here.
```

**Validate in CI/CD:**

```yaml
# .github/workflows/validate.yml
name: Terraform Validate

on:
  pull_request:
    paths:
      - '**.tf'
      - '**.tfvars'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.11.0
      
      - name: Terraform Init
        run: terraform init -backend=false
      
      - name: Terraform Validate
        run: terraform validate
```


### tflint: Advanced Linting for AWS

**Installation and Configuration:**

```bash
# Install tflint
curl -s https://raw.githubusercontent.com/terraform-linters/tflint/master/install_linux.sh | bash

# Create configuration file
cat > .tflint.hcl << 'EOF'
plugin "aws" {
  enabled = true
  version = "0.32.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

config {
  module = true
  force  = false
}

# Terraform naming conventions
rule "terraform_naming_convention" {
  enabled = true
  format  = "snake_case"
}

# Deprecated syntax
rule "terraform_deprecated_interpolation" {
  enabled = true
}

# AWS-specific rules
rule "aws_instance_invalid_type" {
  enabled = true
}

rule "aws_db_instance_invalid_type" {
  enabled = true
}

rule "aws_s3_bucket_invalid_acl" {
  enabled = true
}

# Security rules
rule "aws_security_group_unrestricted_ingress" {
  enabled = true
}

rule "aws_iam_policy_too_permissive" {
  enabled = true
}
EOF

# Initialize tflint
tflint --init

# Run tflint
tflint --recursive
```

**Example tflint Output:**

```
2 issue(s) found:

Warning: `instance_type` is invalid instance type (aws_instance_invalid_type)

  on main.tf line 12:
  12:   instance_type = "t3.gigantic"  # Invalid type

Reference: https://github.com/terraform-linters/tflint-ruleset-aws/blob/v0.32.0/docs/rules/aws_instance_invalid_type.md

Warning: Security group should not allow unrestricted ingress access (aws_security_group_unrestricted_ingress)

  on security.tf line 8:
   8:     cidr_blocks = ["0.0.0.0/0"]  # Too permissive
```


### tfsec: Security Scanning

```bash
# Install tfsec
brew install tfsec  # macOS
# or
curl -s https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh | bash

# Run security scan
tfsec .

# Run with specific severity
tfsec . --minimum-severity HIGH

# Output as SARIF for GitHub
tfsec . --format sarif > tfsec.sarif

# Exclude specific checks
tfsec . --exclude AWS001,AWS002

# Custom configuration
cat > .tfsec.yml << 'EOF'
exclude:
  - AWS001  # S3 bucket encryption
  - AWS017  # ECR image scanning

severity_overrides:
  AWS002: ERROR
  AWS089: CRITICAL

minimum_severity: MEDIUM
EOF
```

**Example tfsec Results:**

```
Result #1 HIGH S3 Bucket does not have encryption enabled
─────────────────────────────────────────────────────────
  storage.tf:5-8

    2  resource "aws_s3_bucket" "data" {
    3    bucket = "my-data-bucket"
    4    
    5    # Missing encryption configuration
    6  }

  Impact:     Data stored in S3 bucket is not encrypted
  Resolution: Enable encryption for S3 bucket
  
  More Info:
  - https://tfsec.dev/docs/aws/s3/enable-bucket-encryption

Result #2 CRITICAL Security group allows ingress from 0.0.0.0/0 to port 22
─────────────────────────────────────────────────────────────────────────
  security.tf:12-18

   10  resource "aws_security_group" "web" {
   11    ingress {
   12      from_port   = 22
   13      to_port     = 22
   14      protocol    = "tcp"
   15      cidr_blocks = ["0.0.0.0/0"]  # SSH open to internet!
   16      description = "SSH access"
   17    }
   18  }

  Impact:     SSH access is open to the entire internet
  Resolution: Restrict SSH access to specific IP ranges

  2 potential problems detected.
```


### Checkov: Policy-as-Code Scanning

```bash
# Install Checkov
pip install checkov

# Run scan
checkov -d .

# Scan with specific frameworks
checkov -d . --framework terraform

# Output formats
checkov -d . --output json
checkov -d . --output sarif

# Skip specific checks
checkov -d . --skip-check CKV_AWS_18,CKV_AWS_19

# Configuration file
cat > .checkov.yml << 'EOF'
framework:
  - terraform
  - secrets

skip-check:
  - CKV_AWS_18  # S3 bucket logging
  - CKV_AWS_21  # S3 versioning

check:
  - CKV_AWS_19  # S3 encryption
  - CKV_AWS_20  # S3 public access
  - CKV_AWS_23  # Security group restrictions

soft-fail: false
output: cli
compact: true
EOF

checkov -d . --config-file .checkov.yml
```


## Integration Testing with Terratest

Terratest deploys actual infrastructure to AWS and validates it works.

### Setting Up Terratest

**Prerequisites:**

```bash
# Install Go (1.21+)
brew install go  # macOS
# or download from golang.org

# Verify installation
go version

# Create test directory
mkdir -p tests/integration
cd tests/integration

# Initialize Go module
go mod init github.com/myorg/terraform-aws-modules/tests

# Install Terratest
go get github.com/gruntwork-io/terratest/modules/terraform
go get github.com/stretchr/testify/assert
go get github.com/gruntwork-io/terratest/modules/aws
go get github.com/gruntwork-io/terratest/modules/retry
```


### Example 1: VPC Module Integration Test

**Test File (tests/integration/vpc_test.go):**

```go
package test

import (
    "fmt"
    "testing"
    "time"
    
    "github.com/gruntwork-io/terratest/modules/aws"
    "github.com/gruntwork-io/terratest/modules/random"
    "github.com/gruntwork-io/terratest/modules/terraform"
    "github.com/gruntwork-io/terratest/modules/retry"
    "github.com/stretchr/testify/assert"
)

func TestVPCModule(t *testing.T) {
    t.Parallel()
    
    // Generate random name to avoid conflicts
    uniqueID := random.UniqueId()
    vpcName := fmt.Sprintf("test-vpc-%s", uniqueID)
    
    // Expected values
    expectedVPCCIDR := "10.0.0.0/16"
    expectedRegion := "us-east-1"
    expectedAZs := []string{"us-east-1a", "us-east-1b", "us-east-1c"}
    
    // Terraform options
    terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
        // Path to Terraform code
        TerraformDir: "../../examples/vpc",
        
        // Variables to pass
        Vars: map[string]interface{}{
            "vpc_name":           vpcName,
            "vpc_cidr":           expectedVPCCIDR,
            "availability_zones": expectedAZs,
            "enable_nat_gateway": true,
            "single_nat_gateway": false,
            "environment":        "test",
        },
        
        // Environment variables
        EnvVars: map[string]string{
            "AWS_DEFAULT_REGION": expectedRegion,
        },
        
        // Retry configuration
        MaxRetries:         3,
        TimeBetweenRetries: 5 * time.Second,
    })
    
    // Clean up resources at end of test
    defer terraform.Destroy(t, terraformOptions)
    
    // Deploy infrastructure
    terraform.InitAndApply(t, terraformOptions)
    
    // Retrieve outputs
    vpcID := terraform.Output(t, terraformOptions, "vpc_id")
    publicSubnetIDs := terraform.OutputList(t, terraformOptions, "public_subnet_ids")
    privateSubnetIDs := terraform.OutputList(t, terraformOptions, "private_subnet_ids")
    natGatewayIDs := terraform.OutputList(t, terraformOptions, "nat_gateway_ids")
    
    // Assertions - verify outputs exist
    assert.NotEmpty(t, vpcID, "VPC ID should not be empty")
    assert.Len(t, publicSubnetIDs, 3, "Should have 3 public subnets")
    assert.Len(t, privateSubnetIDs, 3, "Should have 3 private subnets")
    assert.Len(t, natGatewayIDs, 3, "Should have 3 NAT gateways (multi-AZ)")
    
    // Verify VPC exists in AWS and has correct configuration
    vpc := aws.GetVpcById(t, vpcID, expectedRegion)
    assert.Equal(t, expectedVPCCIDR, vpc.CidrBlock, "VPC CIDR should match")
    assert.True(t, vpc.EnableDnsHostnames, "DNS hostnames should be enabled")
    assert.True(t, vpc.EnableDnsSupport, "DNS support should be enabled")
    
    // Verify VPC has correct tags
    assert.Equal(t, vpcName, vpc.Tags["Name"], "VPC name tag should match")
    assert.Equal(t, "test", vpc.Tags["Environment"], "Environment tag should be 'test'")
    assert.Equal(t, "Terraform", vpc.Tags["ManagedBy"], "ManagedBy tag should be 'Terraform'")
    
    // Verify subnets exist and belong to VPC
    for _, subnetID := range publicSubnetIDs {
        subnet := aws.GetSubnetById(t, subnetID, expectedRegion)
        assert.Equal(t, vpcID, subnet.VpcId, "Public subnet should belong to VPC")
        assert.True(t, subnet.MapPublicIpOnLaunch, "Public subnet should auto-assign public IPs")
        assert.Contains(t, expectedAZs, subnet.AvailabilityZone, "Subnet should be in expected AZ")
    }
    
    for _, subnetID := range privateSubnetIDs {
        subnet := aws.GetSubnetById(t, subnetID, expectedRegion)
        assert.Equal(t, vpcID, subnet.VpcId, "Private subnet should belong to VPC")
        assert.False(t, subnet.MapPublicIpOnLaunch, "Private subnet should not auto-assign public IPs")
    }
    
    // Verify Internet Gateway exists
    igw := aws.GetInternetGatewayForVpc(t, vpcID, expectedRegion)
    assert.NotNil(t, igw, "Internet Gateway should exist")
    assert.Contains(t, igw.Attachments, vpcID, "IGW should be attached to VPC")
    
    // Verify NAT Gateways exist and have Elastic IPs
    natGateways := aws.GetNatGatewaysInVpc(t, vpcID, expectedRegion)
    assert.Len(t, natGateways, 3, "Should have 3 NAT gateways")
    
    for _, natGateway := range natGateways {
        assert.Equal(t, "available", natGateway.State, "NAT Gateway should be available")
        assert.NotEmpty(t, natGateway.NatGatewayAddresses, "NAT Gateway should have Elastic IP")
    }
    
    // Verify route tables
    routeTables := aws.GetRouteTablesForVpc(t, vpcID, expectedRegion)
    assert.GreaterOrEqual(t, len(routeTables), 4, "Should have at least 4 route tables (1 public + 3 private)")
    
    // Verify VPC Flow Logs
    flowLogs := aws.GetVpcFlowLogs(t, vpcID, expectedRegion)
    assert.NotEmpty(t, flowLogs, "VPC should have flow logs enabled")
}

// Test VPC with single NAT gateway (cost optimization)
func TestVPCSingleNAT(t *testing.T) {
    t.Parallel()
    
    uniqueID := random.UniqueId()
    vpcName := fmt.Sprintf("test-vpc-single-nat-%s", uniqueID)
    
    terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
        TerraformDir: "../../examples/vpc",
        
        Vars: map[string]interface{}{
            "vpc_name":           vpcName,
            "vpc_cidr":           "10.1.0.0/16",
            "availability_zones": []string{"us-east-1a", "us-east-1b"},
            "enable_nat_gateway": true,
            "single_nat_gateway": true,  // Single NAT for cost savings
            "environment":        "dev",
        },
        
        EnvVars: map[string]string{
            "AWS_DEFAULT_REGION": "us-east-1",
        },
    })
    
    defer terraform.Destroy(t, terraformOptions)
    terraform.InitAndApply(t, terraformOptions)
    
    vpcID := terraform.Output(t, terraformOptions, "vpc_id")
    natGatewayIDs := terraform.OutputList(t, terraformOptions, "nat_gateway_ids")
    
    // Verify only 1 NAT gateway created
    assert.Len(t, natGatewayIDs, 1, "Should have exactly 1 NAT gateway")
    
    natGateways := aws.GetNatGatewaysInVpc(t, vpcID, "us-east-1")
    assert.Len(t, natGateways, 1, "Should have 1 NAT gateway in AWS")
}

// Test VPC without NAT gateway
func TestVPCWithoutNAT(t *testing.T) {
    t.Parallel()
    
    uniqueID := random.UniqueId()
    vpcName := fmt.Sprintf("test-vpc-no-nat-%s", uniqueID)
    
    terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
        TerraformDir: "../../examples/vpc",
        
        Vars: map[string]interface{}{
            "vpc_name":           vpcName,
            "vpc_cidr":           "10.2.0.0/16",
            "availability_zones": []string{"us-east-1a", "us-east-1b"},
            "enable_nat_gateway": false,  // No NAT gateway
            "environment":        "sandbox",
        },
    })
    
    defer terraform.Destroy(t, terraformOptions)
    terraform.InitAndApply(t, terraformOptions)
    
    vpcID := terraform.Output(t, terraformOptions, "vpc_id")
    
    // Verify no NAT gateways exist
    natGateways := aws.GetNatGatewaysInVpc(t, vpcID, "us-east-1")
    assert.Empty(t, natGateways, "Should have no NAT gateways")
}
```


### Example 2: EC2 Instance with SSH Validation

```go
package test

import (
    "fmt"
    "testing"
    "time"
    
    "github.com/gruntwork-io/terratest/modules/aws"
    "github.com/gruntwork-io/terratest/modules/random"
    "github.com/gruntwork-io/terratest/modules/retry"
    "github.com/gruntwork-io/terratest/modules/ssh"
    "github.com/gruntwork-io/terratest/modules/terraform"
    "github.com/stretchr/testify/assert"
)

func TestEC2Instance(t *testing.T) {
    t.Parallel()
    
    uniqueID := random.UniqueId()
    instanceName := fmt.Sprintf("test-instance-%s", uniqueID)
    awsRegion := "us-east-1"
    
    // Generate SSH key pair
    keyPair := ssh.GenerateRSAKeyPair(t, 2048)
    
    terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
        TerraformDir: "../../examples/ec2",
        
        Vars: map[string]interface{}{
            "instance_name": instanceName,
            "instance_type": "t3.micro",
            "public_key":    keyPair.PublicKey,
            "environment":   "test",
        },
        
        EnvVars: map[string]string{
            "AWS_DEFAULT_REGION": awsRegion,
        },
    })
    
    defer terraform.Destroy(t, terraformOptions)
    terraform.InitAndApply(t, terraformOptions)
    
    // Get instance ID and public IP
    instanceID := terraform.Output(t, terraformOptions, "instance_id")
    publicIP := terraform.Output(t, terraformOptions, "public_ip")
    
    // Verify instance exists
    instance := aws.GetEc2Instance(t, instanceID, awsRegion)
    assert.Equal(t, "t3.micro", instance.InstanceType, "Instance type should be t3.micro")
    assert.Equal(t, "running", instance.State, "Instance should be running")
    
    // Wait for instance to be reachable via SSH
    maxRetries := 30
    sleepBetweenRetries := 10 * time.Second
    
    sshHost := ssh.Host{
        Hostname:    publicIP,
        SshUserName: "ec2-user",
        SshKeyPair:  keyPair,
    }
    
    // Retry SSH connection
    retry.DoWithRetry(t, "SSH to instance", maxRetries, sleepBetweenRetries, func() (string, error) {
        _, err := ssh.CheckSshConnectionE(t, sshHost)
        return "", err
    })
    
    // Run command via SSH
    output := ssh.CheckSshCommand(t, sshHost, "echo 'Hello from Terratest'")
    assert.Contains(t, output, "Hello from Terratest", "SSH command should work")
    
    // Verify instance metadata
    instanceMetadata := ssh.CheckSshCommand(t, sshHost, "curl -s http://169.254.169.254/latest/meta-data/instance-id")
    assert.Equal(t, instanceID, instanceMetadata, "Instance metadata should match")
}
```


### Example 3: RDS Database with Connectivity Test

```go
package test

import (
    "database/sql"
    "fmt"
    "testing"
    "time"
    
    _ "github.com/lib/pq"  // PostgreSQL driver
    "github.com/gruntwork-io/terratest/modules/aws"
    "github.com/gruntwork-io/terratest/modules/random"
    "github.com/gruntwork-io/terratest/modules/retry"
    "github.com/gruntwork-io/terratest/modules/terraform"
    "github.com/stretchr/testify/assert"
)

func TestRDSInstance(t *testing.T) {
    t.Parallel()
    
    uniqueID := random.UniqueId()
    dbIdentifier := fmt.Sprintf("test-db-%s", uniqueID)
    dbPassword := random.UniqueId()  // Generate random password
    
    terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
        TerraformDir: "../../examples/rds",
        
        Vars: map[string]interface{}{
            "db_identifier": dbIdentifier,
            "db_name":       "testdb",
            "db_username":   "admin",
            "db_password":   dbPassword,
            "engine":        "postgres",
            "engine_version": "15.4",
            "instance_class": "db.t3.micro",
            "storage_gb":     20,
            "multi_az":       false,
            "environment":    "test",
        },
    })
    
    defer terraform.Destroy(t, terraformOptions)
    terraform.InitAndApply(t, terraformOptions)
    
    // Get database endpoint
    dbEndpoint := terraform.Output(t, terraformOptions, "db_endpoint")
    dbPort := terraform.Output(t, terraformOptions, "db_port")
    
    // Verify RDS instance exists
    dbInstance := aws.GetRdsInstanceDetails(t, dbIdentifier, "us-east-1")
    assert.Equal(t, "postgres", dbInstance.Engine, "Engine should be postgres")
    assert.Equal(t, "available", dbInstance.DBInstanceStatus, "DB should be available")
    assert.Equal(t, "db.t3.micro", dbInstance.DBInstanceClass, "Instance class should match")
    
    // Test database connectivity
    connectionString := fmt.Sprintf(
        "postgres://admin:%s@%s:%s/testdb?sslmode=require",
        dbPassword, dbEndpoint, dbPort,
    )
    
    maxRetries := 30
    sleepBetweenRetries := 10 * time.Second
    
    retry.DoWithRetry(t, "Connect to database", maxRetries, sleepBetweenRetries, func() (string, error) {
        db, err := sql.Open("postgres", connectionString)
        if err != nil {
            return "", err
        }
        defer db.Close()
        
        err = db.Ping()
        if err != nil {
            return "", err
        }
        
        // Create test table
        _, err = db.Exec("CREATE TABLE IF NOT EXISTS test_table (id SERIAL PRIMARY KEY, name VARCHAR(50))")
        if err != nil {
            return "", err
        }
        
        // Insert test data
        _, err = db.Exec("INSERT INTO test_table (name) VALUES ($1)", "Terratest")
        if err != nil {
            return "", err
        }
        
        // Query test data
        var name string
        err = db.QueryRow("SELECT name FROM test_table WHERE name = $1", "Terratest").Scan(&name)
        if err != nil {
            return "", err
        }
        
        assert.Equal(t, "Terratest", name, "Should retrieve inserted data")
        
        return "Connection successful", nil
    })
}
```


### Running Terratest

```bash
# Run all tests
cd tests/integration
go test -v -timeout 30m

# Run specific test
go test -v -timeout 30m -run TestVPCModule

# Run tests in parallel
go test -v -timeout 30m -parallel 3

# Run with coverage
go test -v -timeout 30m -cover

# Generate test report
go test -v -timeout 30m -json > test-results.json
```


### Terratest CI/CD Integration

```yaml
# .github/workflows/integration-tests.yml
name: Integration Tests

on:
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  integration-tests:
    runs-on: ubuntu-latest
    
    strategy:
      matrix:
        test: [vpc, compute, database]
    
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'
      
      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.11.0
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_TEST_ROLE_ARN }}
          aws-region: us-east-1
      
      - name: Run Integration Tests
        run: |
          cd tests/integration
          go test -v -timeout 30m -run Test${{ matrix.test }}
        env:
          AWS_DEFAULT_REGION: us-east-1
      
      - name: Cleanup on Failure
        if: failure()
        run: |
          # Force cleanup if test fails
          cd tests/integration/fixtures/${{ matrix.test }}
          terraform destroy -auto-approve

## Policy-as-Code with OPA and Sentinel

Policy-as-code enforces organizational standards and compliance requirements automatically.

### Open Policy Agent (OPA) for Terraform

OPA uses Rego language to write policies that evaluate Terraform plans.

**Installation:**

```bash
# Install OPA
brew install opa  # macOS
# or
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod +x opa
sudo mv opa /usr/local/bin/

# Verify installation
opa version
```

**Policy Structure:**

```
policies/
├── terraform/
│   ├── deny_unencrypted_s3.rego
│   ├── deny_public_ingress.rego
│   ├── enforce_tags.rego
│   ├── cost_limits.rego
│   └── naming_conventions.rego
└── test/
    ├── deny_unencrypted_s3_test.rego
    └── enforce_tags_test.rego
```


### Example Policy 1: Deny Unencrypted S3 Buckets

```rego
# policies/terraform/deny_unencrypted_s3.rego
package terraform.s3

import future.keywords.in
import future.keywords.if

# Deny S3 buckets without encryption
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    
    # Check if encryption configuration exists
    not has_encryption(resource)
    
    msg := sprintf(
        "S3 bucket '%s' must have encryption enabled. Add aws_s3_bucket_server_side_encryption_configuration resource.",
        [resource.address]
    )
}

# Check if encryption configuration exists for this bucket
has_encryption(resource) if {
    some encryption_resource in input.resource_changes
    encryption_resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    
    # Extract bucket ID from bucket resource
    bucket_id := resource.change.after.id
    
    # Check if encryption resource references this bucket
    encryption_resource.change.after.bucket == bucket_id
}

# Test data structure validation
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    
    # Verify bucket has required tags
    not resource.change.after.tags.Environment
    
    msg := sprintf(
        "S3 bucket '%s' must have 'Environment' tag",
        [resource.address]
    )
}
```

**Test Policy:**

```rego
# policies/test/deny_unencrypted_s3_test.rego
package terraform.s3

import future.keywords.if

test_s3_without_encryption_denied if {
    result := deny with input as {
        "resource_changes": [{
            "address": "aws_s3_bucket.data",
            "type": "aws_s3_bucket",
            "change": {
                "after": {
                    "id": "my-bucket",
                    "bucket": "my-bucket",
                    "tags": {"Environment": "production"}
                }
            }
        }]
    }
    
    count(result) > 0
}

test_s3_with_encryption_allowed if {
    result := deny with input as {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.data",
                "type": "aws_s3_bucket",
                "change": {
                    "after": {
                        "id": "my-bucket",
                        "bucket": "my-bucket",
                        "tags": {"Environment": "production"}
                    }
                }
            },
            {
                "address": "aws_s3_bucket_server_side_encryption_configuration.data",
                "type": "aws_s3_bucket_server_side_encryption_configuration",
                "change": {
                    "after": {
                        "bucket": "my-bucket",
                        "rule": [{
                            "apply_server_side_encryption_by_default": {
                                "sse_algorithm": "AES256"
                            }
                        }]
                    }
                }
            }
        ]
    }
    
    count(result) == 0
}
```


### Example Policy 2: Deny Public Security Group Rules

```rego
# policies/terraform/deny_public_ingress.rego
package terraform.security

import future.keywords.in
import future.keywords.if

# Deny security groups with unrestricted SSH access
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    
    some rule in resource.change.after.ingress
    rule.from_port == 22
    rule.to_port == 22
    
    some cidr in rule.cidr_blocks
    cidr == "0.0.0.0/0"
    
    msg := sprintf(
        "Security group '%s' allows SSH (port 22) from 0.0.0.0/0. Restrict to specific IP ranges.",
        [resource.address]
    )
}

# Deny security groups with unrestricted RDP access
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    
    some rule in resource.change.after.ingress
    rule.from_port == 3389
    rule.to_port == 3389
    
    some cidr in rule.cidr_blocks
    cidr == "0.0.0.0/0"
    
    msg := sprintf(
        "Security group '%s' allows RDP (port 3389) from 0.0.0.0/0. Restrict to specific IP ranges.",
        [resource.address]
    )
}

# Warn on overly permissive security groups
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    
    some rule in resource.change.after.ingress
    rule.from_port == 0
    rule.to_port == 65535
    
    msg := sprintf(
        "Security group '%s' allows all ports (0-65535). Consider restricting to specific ports.",
        [resource.address]
    )
}
```


### Example Policy 3: Enforce Tagging Standards

```rego
# policies/terraform/enforce_tags.rego
package terraform.tagging

import future.keywords.in
import future.keywords.if

# Required tags for all taggable resources
required_tags := ["Environment", "Project", "ManagedBy", "Owner"]

# Resources that support tagging
taggable_resources := [
    "aws_instance",
    "aws_db_instance",
    "aws_s3_bucket",
    "aws_vpc",
    "aws_subnet",
    "aws_security_group",
    "aws_lb",
    "aws_ecs_cluster",
    "aws_lambda_function",
]

# Deny resources missing required tags
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type in taggable_resources
    
    some required_tag in required_tags
    not resource.change.after.tags[required_tag]
    
    msg := sprintf(
        "Resource '%s' (type: %s) is missing required tag: %s",
        [resource.address, resource.type, required_tag]
    )
}

# Validate tag values
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type in taggable_resources
    
    env := resource.change.after.tags.Environment
    env != null
    not env in ["dev", "staging", "production"]
    
    msg := sprintf(
        "Resource '%s' has invalid Environment tag value '%s'. Must be: dev, staging, or production",
        [resource.address, env]
    )
}

# Enforce naming conventions
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type in taggable_resources
    
    name := resource.change.after.tags.Name
    name != null
    
    # Name must start with environment prefix
    env := resource.change.after.tags.Environment
    not startswith(name, sprintf("%s-", [env]))
    
    msg := sprintf(
        "Resource '%s' Name tag '%s' must start with environment prefix '%s-'",
        [resource.address, name, env]
    )
}
```


### Example Policy 4: Cost Limits

```rego
# policies/terraform/cost_limits.rego
package terraform.cost

import future.keywords.in
import future.keywords.if

# Maximum allowed instance types by environment
max_instance_types := {
    "dev": ["t3.micro", "t3.small"],
    "staging": ["t3.small", "t3.medium"],
    "production": ["t3.large", "t3.xlarge", "t3.2xlarge", "m5.large", "m5.xlarge"]
}

# Deny instances exceeding environment limits
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"
    
    instance_type := resource.change.after.instance_type
    environment := resource.change.after.tags.Environment
    
    allowed_types := max_instance_types[environment]
    not instance_type in allowed_types
    
    msg := sprintf(
        "Instance '%s' type '%s' exceeds limit for %s environment. Allowed: %v",
        [resource.address, instance_type, environment, allowed_types]
    )
}

# Deny expensive RDS instance classes in non-production
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    
    instance_class := resource.change.after.instance_class
    environment := resource.change.after.tags.Environment
    
    environment != "production"
    
    # Expensive instance classes (memory-optimized, 4+ vCPUs)
    expensive_classes := ["db.r5.xlarge", "db.r5.2xlarge", "db.r6g.xlarge"]
    instance_class in expensive_classes
    
    msg := sprintf(
        "RDS instance '%s' class '%s' is too expensive for %s environment",
        [resource.address, instance_class, environment]
    )
}

# Warn on large storage allocations
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    
    storage := resource.change.after.allocated_storage
    storage > 500
    
    environment := resource.change.after.tags.Environment
    environment != "production"
    
    msg := sprintf(
        "RDS instance '%s' allocates %d GB storage in %s environment. Consider reducing.",
        [resource.address, storage, environment]
    )
}
```


### Running OPA Policy Checks

```bash
# Generate Terraform plan JSON
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Run OPA policy evaluation
opa eval \
  --data policies/ \
  --input tfplan.json \
  --format pretty \
  "data.terraform"

# Check for violations (exit 1 if any deny rules triggered)
opa exec \
  --decision terraform/deny \
  --bundle policies/ \
  tfplan.json

# Run specific policy
opa eval \
  --data policies/terraform/deny_unencrypted_s3.rego \
  --input tfplan.json \
  "data.terraform.s3.deny"

# Test policies
opa test policies/ -v

# Example output:
# policies/terraform/deny_unencrypted_s3_test.rego:
#   test_s3_without_encryption_denied: PASS (0.5ms)
#   test_s3_with_encryption_allowed: PASS (0.3ms)
# PASS: 2/2
```


### OPA in CI/CD Pipeline

```yaml
# .github/workflows/opa-policy.yml
name: OPA Policy Validation

on:
  pull_request:
    paths:
      - '**.tf'
      - 'policies/**'

jobs:
  policy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.11.0
      
      - name: Install OPA
        run: |
          curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
          chmod +x opa
          sudo mv opa /usr/local/bin/
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1
      
      - name: Terraform Init
        run: terraform init
      
      - name: Generate Terraform Plan
        run: |
          terraform plan -out=tfplan
          terraform show -json tfplan > tfplan.json
      
      - name: Run OPA Policy Tests
        run: opa test policies/ -v
      
      - name: Evaluate OPA Policies
        run: |
          # Evaluate all deny rules
          DENY_RESULTS=$(opa eval \
            --data policies/ \
            --input tfplan.json \
            --format pretty \
            "data.terraform.deny")
          
          # Evaluate all warn rules
          WARN_RESULTS=$(opa eval \
            --data policies/ \
            --input tfplan.json \
            --format pretty \
            "data.terraform.warn")
          
          echo "## Policy Violations" >> $GITHUB_STEP_SUMMARY
          echo "$DENY_RESULTS" >> $GITHUB_STEP_SUMMARY
          
          echo "## Policy Warnings" >> $GITHUB_STEP_SUMMARY
          echo "$WARN_RESULTS" >> $GITHUB_STEP_SUMMARY
          
          # Fail if deny rules triggered
          if [ -n "$DENY_RESULTS" ]; then
            echo "❌ Policy violations found"
            exit 1
          fi
          
          echo "✅ No policy violations"
      
      - name: Comment PR with Results
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const summary = fs.readFileSync(process.env.GITHUB_STEP_SUMMARY, 'utf8');
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: summary
            });
```


### Sentinel Policies (Terraform Cloud/Enterprise)

Sentinel is HashiCorp's policy-as-code framework integrated with Terraform Cloud.

**Example Sentinel Policy:**

```hcl
# sentinel.hcl
policy "restrict-instance-type" {
  source            = "./policies/restrict-instance-type.sentinel"
  enforcement_level = "hard-mandatory"  # Must pass
}

policy "enforce-tagging" {
  source            = "./policies/enforce-tagging.sentinel"
  enforcement_level = "soft-mandatory"  # Can override with reason
}

policy "cost-estimation" {
  source            = "./policies/cost-estimation.sentinel"
  enforcement_level = "advisory"  # Warning only
}
```

**Sentinel Policy Example:**

```sentinel
# policies/restrict-instance-type.sentinel
import "tfplan/v2" as tfplan
import "strings"

# Allowed instance types by environment
allowed_types = {
  "dev": [
    "t3.micro",
    "t3.small",
  ],
  "staging": [
    "t3.small",
    "t3.medium",
  ],
  "production": [
    "t3.large",
    "t3.xlarge",
    "m5.large",
    "m5.xlarge",
  ],
}

# Get all EC2 instances
instances = filter tfplan.resource_changes as _, rc {
  rc.type is "aws_instance" and
  rc.mode is "managed" and
  (rc.change.actions contains "create" or rc.change.actions contains "update")
}

# Validate instance types
instance_type_validated = rule {
  all instances as address, rc {
    rc.change.after.instance_type in allowed_types[rc.change.after.tags.Environment]
  }
}

# Main rule
main = rule {
  instance_type_validated
}
```


## Native Terraform Testing (terraform test)

Terraform 1.6+ includes built-in testing capabilities.

### Test File Structure

```
tests/
├── vpc.tftest.hcl
├── compute.tftest.hcl
├── database.tftest.hcl
└── fixtures/
    ├── vpc/
    └── compute/
```


### Example Test Configuration

```hcl
# tests/vpc.tftest.hcl

# Variables used across all test runs
variables {
  environment = "test"
  project     = "terraform-testing"
}

# Test run 1: Basic VPC creation
run "create_vpc" {
  command = apply
  
  variables {
    vpc_cidr           = "10.0.0.0/16"
    availability_zones = ["us-east-1a", "us-east-1b"]
    enable_nat_gateway = false
  }
  
  # Assertions
  assert {
    condition     = output.vpc_id != ""
    error_message = "VPC ID should not be empty"
  }
  
  assert {
    condition     = length(output.public_subnet_ids) == 2
    error_message = "Should have 2 public subnets"
  }
  
  assert {
    condition     = output.vpc_cidr == var.vpc_cidr
    error_message = "VPC CIDR should match input"
  }
}

# Test run 2: VPC with NAT gateway
run "create_vpc_with_nat" {
  command = apply
  
  variables {
    vpc_cidr           = "10.1.0.0/16"
    availability_zones = ["us-east-1a", "us-east-1b"]
    enable_nat_gateway = true
    single_nat_gateway = true
  }
  
  assert {
    condition     = length(output.nat_gateway_ids) == 1
    error_message = "Should have 1 NAT gateway"
  }
  
  assert {
    condition     = length(output.private_subnet_ids) == 2
    error_message = "Should have 2 private subnets"
  }
}

# Test run 3: Validate multi-AZ NAT
run "validate_multi_az_nat" {
  command = apply
  
  variables {
    vpc_cidr           = "10.2.0.0/16"
    availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]
    enable_nat_gateway = true
    single_nat_gateway = false
  }
  
  assert {
    condition     = length(output.nat_gateway_ids) == 3
    error_message = "Should have 3 NAT gateways for multi-AZ"
  }
}

# Test run 4: Plan-only test (no apply)
run "plan_validation" {
  command = plan
  
  variables {
    vpc_cidr           = "10.3.0.0/16"
    availability_zones = ["us-east-1a"]
    enable_nat_gateway = false
  }
  
  # Validate plan without applying
  assert {
    condition     = length(var.availability_zones) > 0
    error_message = "Must specify at least one AZ"
  }
}
```


### Running Native Tests

```bash
# Run all tests
terraform test

# Run specific test file
terraform test tests/vpc.tftest.hcl

# Run with verbose output
terraform test -verbose

# Run tests in specific directory
terraform test -test-directory=tests/integration

# Filter tests by name
terraform test -filter=create_vpc

# Example output:
# tests/vpc.tftest.hcl... in progress
#   run "create_vpc"... pass
#   run "create_vpc_with_nat"... pass
#   run "validate_multi_az_nat"... pass
#   run "plan_validation"... pass
# tests/vpc.tftest.hcl... tearing down
# tests/vpc.tftest.hcl... pass
#
# Success! 4 passed, 0 failed.
```


### Advanced Test Patterns

**Using Mock Providers:**

```hcl
# tests/mock_example.tftest.hcl

mock_provider "aws" {
  source = "./mocks/aws"
  
  # Mock data sources
  mock_data "aws_ami" {
    defaults = {
      id = "ami-12345678"
      architecture = "x86_64"
    }
  }
  
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["us-east-1a", "us-east-1b"]
    }
  }
}

run "test_with_mocks" {
  command = plan
  
  # Test uses mocked AWS provider
  assert {
    condition     = data.aws_ami.main.id == "ami-12345678"
    error_message = "AMI ID should use mock value"
  }
}
```

**Using Fixtures:**

```hcl
# tests/fixtures/minimal_vpc/main.tf
module "vpc" {
  source = "../../../modules/vpc"
  
  vpc_cidr           = var.vpc_cidr
  environment        = var.environment
  availability_zones = var.availability_zones
}

# tests/vpc_minimal.tftest.hcl
run "minimal_vpc" {
  command = apply
  
  module {
    source = "./fixtures/minimal_vpc"
  }
  
  variables {
    vpc_cidr           = "10.0.0.0/16"
    environment        = "test"
    availability_zones = ["us-east-1a"]
  }
  
  assert {
    condition     = module.vpc.vpc_id != ""
    error_message = "VPC should be created"
  }
}
```


## Contract Testing for Modules

Contract tests ensure module interfaces remain stable for consumers.

### Contract Test Example

```hcl
# tests/module_contract.tftest.hcl

# Test required inputs
run "missing_required_input" {
  command = plan
  
  # Don't provide vpc_cidr (required)
  variables {
    environment = "test"
  }
  
  expect_failures = [
    var.vpc_cidr,
  ]
}

# Test output structure
run "output_structure" {
  command = apply
  
  variables {
    vpc_cidr    = "10.0.0.0/16"
    environment = "test"
  }
  
  # Verify required outputs exist
  assert {
    condition     = can(output.vpc_id)
    error_message = "Module must output vpc_id"
  }
  
  assert {
    condition     = can(output.public_subnet_ids)
    error_message = "Module must output public_subnet_ids"
  }
  
  assert {
    condition     = can(output.private_subnet_ids)
    error_message = "Module must output private_subnet_ids"
  }
  
  # Verify output types
  assert {
    condition     = can(regex("^vpc-", output.vpc_id))
    error_message = "vpc_id must be valid VPC ID format"
  }
  
  assert {
    condition     = can(tolist(output.public_subnet_ids))
    error_message = "public_subnet_ids must be a list"
  }
}

# Test backward compatibility
run "legacy_variable_support" {
  command = plan
  
  variables {
    vpc_cidr    = "10.0.0.0/16"
    environment = "test"
    
    # Legacy variable (deprecated but still supported)
    create_vpc = true
  }
  
  # Should not fail with deprecated variable
  assert {
    condition     = var.create_vpc == true
    error_message = "Legacy variable should still work"
  }
}
```


## ⚠️ Common Testing Pitfalls

### Pitfall 1: Not Cleaning Up Test Resources

**❌ PROBLEM:**

```go
func TestVPC(t *testing.T) {
    terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
        TerraformDir: "../../examples/vpc",
    })
    
    terraform.InitAndApply(t, terraformOptions)
    
    // Missing: defer terraform.Destroy(t, terraformOptions)
    // Resources left running → AWS charges accumulate!
}
```

**✅ SOLUTION:**

```go
func TestVPC(t *testing.T) {
    terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
        TerraformDir: "../../examples/vpc",
    })
    
    // Always defer destroy BEFORE apply
    defer terraform.Destroy(t, terraformOptions)
    
    terraform.InitAndApply(t, terraformOptions)
    
    // Even if test fails, defer ensures cleanup
}

// Additional: Use test-specific naming
func TestVPCWithCleanup(t *testing.T) {
    uniqueID := random.UniqueId()
    vpcName := fmt.Sprintf("test-vpc-%s", uniqueID)
    
    // Easier to identify and manually cleanup if needed
}
```


### Pitfall 2: Tests Interfering with Each Other

**❌ PROBLEM:**

```go
// Both tests create resources with same names
func TestVPC1(t *testing.T) {
    terraform.InitAndApply(t, &terraform.Options{
        Vars: map[string]interface{}{
            "vpc_name": "test-vpc",  // Hardcoded name
        },
    })
}

func TestVPC2(t *testing.T) {
    terraform.InitAndApply(t, &terraform.Options{
        Vars: map[string]interface{}{
            "vpc_name": "test-vpc",  // Same name → conflict!
        },
    })
}
```

**✅ SOLUTION:**

```go
func TestVPC1(t *testing.T) {
    t.Parallel()  // Enable parallel execution
    
    uniqueID := random.UniqueId()
    terraform.InitAndApply(t, &terraform.Options{
        Vars: map[string]interface{}{
            "vpc_name": fmt.Sprintf("test-vpc-1-%s", uniqueID),
        },
    })
}

func TestVPC2(t *testing.T) {
    t.Parallel()  // Enable parallel execution
    
    uniqueID := random.UniqueId()
    terraform.InitAndApply(t, &terraform.Options{
        Vars: map[string]interface{}{
            "vpc_name": fmt.Sprintf("test-vpc-2-%s", uniqueID),
        },
    })
}
```


### Pitfall 3: No Retry Logic for Eventual Consistency

**❌ PROBLEM:**

```go
func TestInstance(t *testing.T) {
    terraform.InitAndApply(t, terraformOptions)
    
    instanceID := terraform.Output(t, terraformOptions, "instance_id")
    
    // Fails immediately if instance not ready
    instance := aws.GetEc2Instance(t, instanceID, "us-east-1")
    assert.Equal(t, "running", instance.State)  // May fail!
}
```

**✅ SOLUTION:**

```go
func TestInstance(t *testing.T) {
    terraform.InitAndApply(t, terraformOptions)
    
    instanceID := terraform.Output(t, terraformOptions, "instance_id")
    
    // Retry until instance is running
    maxRetries := 30
    sleepBetweenRetries := 10 * time.Second
    
    retry.DoWithRetry(t, "Wait for instance", maxRetries, sleepBetweenRetries, func() (string, error) {
        instance := aws.GetEc2Instance(t, instanceID, "us-east-1")
        
        if instance.State != "running" {
            return "", fmt.Errorf("instance not running yet: %s", instance.State)
        }
        
        return "Instance running", nil
    })
}
```


### Pitfall 4: Testing Only Happy Path

**❌ PROBLEM:**

```go
// Only tests successful creation
func TestVPC(t *testing.T) {
    terraform.InitAndApply(t, terraformOptions)
    
    vpcID := terraform.Output(t, terraformOptions, "vpc_id")
    assert.NotEmpty(t, vpcID)
}
// Missing: What if CIDR overlaps? Invalid AZ? Resource limits?
```

**✅ SOLUTION:**

```go
// Test successful creation
func TestVPCSuccess(t *testing.T) {
    t.Parallel()
    
    terraform.InitAndApply(t, terraformOptions)
    vpcID := terraform.Output(t, terraformOptions, "vpc_id")
    assert.NotEmpty(t, vpcID)
}

// Test invalid CIDR
func TestVPCInvalidCIDR(t *testing.T) {
    t.Parallel()
    
    _, err := terraform.InitAndApplyE(t, &terraform.Options{
        Vars: map[string]interface{}{
            "vpc_cidr": "not-a-cidr",  // Invalid
        },
    })
    
    assert.Error(t, err, "Should fail with invalid CIDR")
}

// Test overlapping CIDR
func TestVPCOverlappingCIDR(t *testing.T) {
    t.Parallel()
    
    // Create first VPC
    terraform.InitAndApply(t, firstVPCOptions)
    
    // Try to create second VPC with overlapping CIDR
    _, err := terraform.InitAndApplyE(t, &terraform.Options{
        Vars: map[string]interface{}{
            "vpc_cidr": "10.0.0.0/16",  // Same as first VPC
            "peer_vpc": terraform.Output(t, firstVPCOptions, "vpc_id"),
        },
    })
    
    assert.Error(t, err, "Should fail with overlapping CIDR in peered VPCs")
}
```


### Pitfall 5: No Cost Guardrails in Tests

**❌ PROBLEM:**

```go
// Test spins up expensive resources
func TestProduction(t *testing.T) {
    terraform.InitAndApply(t, &terraform.Options{
        Vars: map[string]interface{}{
            "instance_type": "m5.24xlarge",  // $4.608/hour!
            "instance_count": 10,             // $46/hour!
        },
    })
    // Forgot defer destroy → $1,000+ AWS bill
}
```

**✅ SOLUTION:**

```go
// Use small instances for testing
func TestCompute(t *testing.T) {
    terraform.InitAndApply(t, &terraform.Options{
        Vars: map[string]interface{}{
            "instance_type": "t3.micro",  // $0.0104/hour
            "instance_count": 1,          // Minimal for testing
        },
    })
    
    defer terraform.Destroy(t, terraformOptions)
}

// Set test timeouts to limit runaway costs
func TestWithTimeout(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
    defer cancel()
    
    // Test will be killed after 15 minutes max
}

// Use environment-specific configurations
func getTestConfig(env string) map[string]interface{} {
    if env == "test" {
        return map[string]interface{}{
            "instance_type": "t3.micro",
            "multi_az": false,
            "backup_retention": 0,
        }
    }
    return nil
}
```


## 💡 Expert Tips from the Field

1. **"Run static analysis on every commit, integration tests on PR, E2E tests nightly"** - Static analysis is free and fast (seconds), integration tests cost money and time (5-15 min), E2E tests are expensive (30+ min). Optimize for feedback speed.
2. **"Use unique identifiers for every test resource"** - Add `random.UniqueId()` to all resource names. Makes parallel testing safe, cleanup easier, and debugging simpler when multiple developers run tests simultaneously.
3. **"Always use `defer terraform.Destroy` immediately after defining options"** - Place defer before apply so cleanup happens even if test fails. Prevents accumulating test resources that cost hundreds per month.
4. **"Test failure modes, not just success"** - 80% of production incidents come from error handling. Test invalid inputs, resource limits, dependency failures, and rollback scenarios explicitly.
5. **"Use separate AWS accounts for integration testing"** - Isolate test infrastructure from development/production. Use Organizations with SCPs to enforce budget limits and prevent expensive resource types.
6. **"Implement test cost budgets with AWS Budgets alerts"** - Set \$50/day alert for test accounts. One forgotten NAT gateway costs \$1,000/month. Alerts catch runaway test resources within hours, not months.
7. **"Cache Terraform providers in CI/CD to speed up tests"** - GitHub Actions with `hashicorp/setup-terraform` caches providers, reducing init time from 60s to 5s. Multiplied across tests, saves 10+ minutes per run.
8. **"Use Terratest retry helpers religiously"** - AWS has eventual consistency. `retry.DoWithRetry` with 30 retries × 10s prevents flaky tests that fail 10% of the time due to timing issues.
9. **"Tag all test resources with `test=true` and expiration date"** - Enables automated cleanup of orphaned resources. Lambda function queries tags and destroys resources past expiration, preventing cost leaks.
10. **"Run policy checks before plan, not after"** - OPA/Sentinel evaluation on plan JSON catches violations before AWS API calls. Saves time and prevents partially-created resources when policies fail mid-apply.
11. **"Use Infracost in CI/CD to show cost impact of changes"** - PR comment shows "\$243/month → \$891/month change". Makes cost-benefit explicit before merging. Caught production RDS upsizing that would cost \$8,000/year.
12. **"Test module versioning explicitly with contract tests"** - Verify v2.0 doesn't break consumers expecting v1.x interface. Use `terraform test` with fixtures representing actual consumer code patterns.
13. **"Parallelize Terratest with `t.Parallel()` and matrix strategies"** - Run 5 tests in parallel instead of serial, reducing total test time from 75 minutes to 15 minutes. Critical for maintaining fast feedback loops.
14. **"Use terraform test for quick feedback, Terratest for deep validation"** - Native tests (1-2 min) catch basic issues, Terratest (10-15 min) validates actual AWS behavior. Layer them effectively.
15. **"Store test results and metrics in S3 for trend analysis"** - Track test duration, success rate, cost over time. Detect degrading performance or increasing flakiness before they become critical.

## 🎯 Practical Exercises

### Exercise 1: Implement Static Analysis Pipeline

**Difficulty:** Beginner
**Time:** 30 minutes
**Objective:** Create GitHub Actions workflow with comprehensive static analysis

**Steps:**

1. Create workflow file:
```bash
mkdir -p .github/workflows
touch .github/workflows/static-analysis.yml
```

2. Add multi-tool scanning workflow:
```yaml
name: Static Analysis

on:
  pull_request:
  push:
    branches: [main]

jobs:
  static-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.11.0
      
      - name: Terraform Format Check
        run: terraform fmt -check -recursive
      
      - name: Terraform Validate
        run: |
          terraform init -backend=false
          terraform validate
      
      - name: tfsec Security Scan
        uses: aquasecurity/tfsec-action@v1.0.3
        with:
          soft_fail: false
      
      - name: Checkov Policy Scan
        uses: bridgecrewio/checkov-action@v12
        with:
          framework: terraform
          soft_fail: false
```

3. Commit and push:
```bash
git add .github/workflows/static-analysis.yml
git commit -m "Add static analysis pipeline"
git push
```

4. Verify workflow runs on PR

**Validation:**

- Workflow runs on every PR
- Catches format, validation, and security issues
- Blocks merge if checks fail

**Challenge:** Add Infracost to show cost impact of changes

### Exercise 2: Write Terratest Integration Test

**Difficulty:** Intermediate
**Time:** 45 minutes
**Objective:** Create integration test for S3 bucket module

**Steps:**

1. Create test structure:
```bash
mkdir -p tests/integration
cd tests/integration
go mod init github.com/myorg/terraform-modules/tests
go get github.com/gruntwork-io/terratest/modules/terraform
go get github.com/stretchr/testify/assert
```

2. Write test (tests/integration/s3_test.go):
```go
package test

import (
    "testing"
    "github.com/gruntwork-io/terratest/modules/aws"
    "github.com/gruntwork-io/terratest/modules/terraform"
    "github.com/stretchr/testify/assert"
)

func TestS3Bucket(t *testing.T) {
    t.Parallel()
    
    terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
        TerraformDir: "../../examples/s3",
        Vars: map[string]interface{}{
            "bucket_name": "test-bucket-" + random.UniqueId(),
        },
    })
    
    defer terraform.Destroy(t, terraformOptions)
    terraform.InitAndApply(t, terraformOptions)
    
    bucketName := terraform.Output(t, terraformOptions, "bucket_name")
    
    // Verify bucket exists
    aws.AssertS3BucketExists(t, "us-east-1", bucketName)
    
    // Verify encryption
    encryption := aws.GetS3BucketServerSideEncryption(t, "us-east-1", bucketName)
    assert.NotNil(t, encryption)
}
```

3. Run test:
```bash
go test -v -timeout 30m
```

**Validation:**

- Test deploys actual S3 bucket to AWS
- Verifies encryption is enabled
- Cleans up resources after test

**Challenge:** Add test for versioning and lifecycle policies

### Exercise 3: Create OPA Policy for Tagging

**Difficulty:** Intermediate
**Time:** 40 minutes
**Objective:** Write and test OPA policy enforcing tagging standards

**Steps:**

1. Install OPA:
```bash
brew install opa
```

2. Create policy (policies/terraform/tagging.rego):
```rego
package terraform.tagging

required_tags := ["Environment", "Project", "Owner"]

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"
    
    some tag in required_tags
    not resource.change.after.tags[tag]
    
    msg := sprintf("Instance '%s' missing tag: %s", [resource.address, tag])
}
```

3. Create test (policies/test/tagging_test.rego):
```rego
package terraform.tagging

test_missing_tag_denied {
    result := deny with input as {
        "resource_changes": [{
            "address": "aws_instance.web",
            "type": "aws_instance",
            "change": {
                "after": {
                    "tags": {"Environment": "prod"}
                }
            }
        }]
    }
    
    count(result) > 0
}
```

4. Test policy:
```bash
opa test policies/ -v
```

5. Apply to Terraform plan:
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
opa eval --data policies/ --input tfplan.json "data.terraform.tagging.deny"
```

**Validation:**

- Policy tests pass
- Policy catches missing tags
- Can be integrated into CI/CD

**Challenge:** Add policy for naming conventions

## Key Takeaways

- The testing pyramid for infrastructure code prioritizes static analysis (seconds, free) over integration tests (minutes, AWS costs) over E2E tests (30+ minutes, full environment costs)—run what's appropriate for each stage
- Terratest deploys actual infrastructure to AWS for integration testing, catching real-world issues like resource availability, IAM permissions, and service limits that static analysis cannot detect
- Policy-as-code with OPA or Sentinel enforces organizational standards automatically, preventing security violations, cost overruns, and compliance issues before terraform apply executes
- Native `terraform test` command introduced in 1.6+ brings testing into core Terraform workflow with declarative test files that validate inputs, outputs, and resource behavior without external frameworks
- Contract testing ensures module interface stability across versions, preventing breaking changes that affect downstream consumers who depend on specific input variables and output values
- Always use `defer terraform.Destroy` immediately after defining test options and add unique identifiers to all test resources to enable parallel testing and prevent cost accumulation from orphaned infrastructure
- Implement retry logic with exponential backoff for all AWS API validations because eventual consistency means resources may not be immediately available after creation, causing flaky test failures


## What's Next

With comprehensive testing strategies mastered, **Chapter 11: CI/CD Integration** will cover automated deployment pipelines with GitHub Actions and GitLab CI, drift detection and remediation workflows, approval gates for production changes, automated rollback strategies, and GitOps patterns that enable teams to deploy infrastructure changes through pull requests with confidence and auditability.

## Additional Resources

**Official Documentation:**

- [Terratest Documentation](https://terratest.gruntwork.io) - Go testing library for infrastructure
- [Terraform Testing Guide](https://developer.hashicorp.com/terraform/language/tests) - Native testing features
- [Open Policy Agent](https://www.openpolicyagent.org) - Policy-as-code framework

**Testing Tools:**

- [tfsec](https://github.com/aquasecurity/tfsec) - Security scanner for Terraform
- [Checkov](https://www.checkov.io) - Policy-as-code scanner
- [Infracost](https://www.infracost.io) - Cloud cost estimation
- [Kitchen-Terraform](https://github.com/newcontext-oss/kitchen-terraform) - Testing framework

**Best Practices:**

- [Google Cloud Terraform Testing](https://cloud.google.com/docs/terraform/best-practices/testing) - Testing strategies
- [Azure Terratest Guide](https://learn.microsoft.com/en-us/azure/developer/terraform/azurerm/best-practices-end-to-end-testing) - E2E testing
- [Gruntwork Blog](https://blog.gruntwork.io) - Infrastructure testing insights

***

**Testing infrastructure code transforms deployment from gambling to engineering.** Static analysis catches syntax errors in seconds, integration tests validate AWS behavior in minutes, and policy-as-code prevents violations before apply. Invest in comprehensive testing—the cost of a bug caught in testing is minutes; the cost of the same bug in production is millions.
