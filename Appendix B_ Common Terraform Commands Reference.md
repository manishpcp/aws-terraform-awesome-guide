# Appendix B: Common Terraform Commands Reference

## Introduction

This appendix provides a comprehensive quick-reference guide to essential Terraform commands organized by workflow phase: initialization, planning, applying, state management, workspace operations, troubleshooting, and advanced operations. Each command includes syntax, common flags, practical examples, and expected outputs to serve as a desktop reference during daily infrastructure operations.

***

## Initialization Commands

### `terraform init`

Initializes a Terraform working directory by downloading providers, modules, and configuring backend.

**Basic Syntax:**

```bash
terraform init [options]
```

**Common Options:**


| Flag | Description | Example |
| :-- | :-- | :-- |
| `-upgrade` | Upgrade providers and modules to latest versions | `terraform init -upgrade` |
| `-reconfigure` | Reconfigure backend ignoring existing config | `terraform init -reconfigure` |
| `-migrate-state` | Migrate state to new backend | `terraform init -migrate-state` |
| `-backend=false` | Skip backend initialization | `terraform init -backend=false` |
| `-get=false` | Skip module download | `terraform init -get=false` |
| `-plugin-dir=DIR` | Use custom plugin directory | `terraform init -plugin-dir=./plugins` |

**Examples:**

```bash
# Standard initialization
terraform init

# Expected output:
# Initializing the backend...
# Initializing provider plugins...
# - Finding hashicorp/aws versions matching "~> 6.0"...
# - Installing hashicorp/aws v6.16.0...
# Terraform has been successfully initialized!

# Upgrade providers to latest matching version constraint
terraform init -upgrade

# Migrate state from local to S3 backend
terraform init -migrate-state

# Prompt:
# Do you want to copy existing state to the new backend?
# Enter a value: yes

# Reconfigure backend (force new configuration)
terraform init -reconfigure

# Initialize without backend (local state only)
terraform init -backend=false
```

**Troubleshooting:**

```bash
# Clear plugin cache if corruption suspected
rm -rf .terraform/
terraform init

# Initialize with specific provider versions
terraform init -upgrade=false
```


***

## Planning Commands

### `terraform plan`

Generates execution plan showing what actions Terraform will take.

**Basic Syntax:**

```bash
terraform plan [options]
```

**Common Options:**


| Flag | Description | Example |
| :-- | :-- | :-- |
| `-out=FILE` | Save plan to file | `terraform plan -out=tfplan` |
| `-var 'key=value'` | Set variable value | `terraform plan -var 'instance_type=t3.large'` |
| `-var-file=FILE` | Load variables from file | `terraform plan -var-file=prod.tfvars` |
| `-target=RESOURCE` | Plan specific resource only | `terraform plan -target=aws_instance.web` |
| `-refresh=false` | Skip refreshing state | `terraform plan -refresh=false` |
| `-refresh-only` | Only update state, no changes | `terraform plan -refresh-only` |
| `-destroy` | Plan resource destruction | `terraform plan -destroy` |
| `-detailed-exitcode` | Exit code indicates changes | `terraform plan -detailed-exitcode` |

**Examples:**

```bash
# Standard plan
terraform plan

# Expected output:
# Terraform will perform the following actions:
# 
#   # aws_instance.web will be created
#   + resource "aws_instance" "web" {
#       + ami           = "ami-12345678"
#       + instance_type = "t3.micro"
#       ...
#     }
# 
# Plan: 1 to add, 0 to change, 0 to destroy.

# Save plan to file for later apply
terraform plan -out=tfplan

# Plan with variable override
terraform plan -var 'environment=staging' -var 'instance_count=2'

# Plan specific resource only (targeted plan)
terraform plan -target=aws_instance.web

# Plan destruction
terraform plan -destroy

# Refresh state only (no changes)
terraform plan -refresh-only

# Exit codes for CI/CD
terraform plan -detailed-exitcode
# Exit code 0: No changes
# Exit code 1: Error
# Exit code 2: Successful plan with changes
```

**Advanced Planning:**

```bash
# Plan and filter output
terraform plan | grep "Plan:"

# Plan with JSON output
terraform plan -json > plan.json

# Plan and show specific resource details
terraform plan | grep -A 20 "aws_instance.web"

# Compare plans between environments
diff <(terraform plan -var-file=dev.tfvars) \
     <(terraform plan -var-file=prod.tfvars)
```


***

## Apply Commands

### `terraform apply`

Applies changes to reach desired state defined in configuration.

**Basic Syntax:**

```bash
terraform apply [options] [plan-file]
```

**Common Options:**


| Flag | Description | Example |
| :-- | :-- | :-- |
| `-auto-approve` | Skip interactive approval | `terraform apply -auto-approve` |
| `-target=RESOURCE` | Apply to specific resource | `terraform apply -target=aws_instance.web` |
| `-var 'key=value'` | Set variable value | `terraform apply -var 'enable_monitoring=true'` |
| `-var-file=FILE` | Load variables from file | `terraform apply -var-file=prod.tfvars` |
| `-parallelism=N` | Concurrent operations limit | `terraform apply -parallelism=20` |
| `-refresh=false` | Skip state refresh | `terraform apply -refresh=false` |

**Examples:**

```bash
# Interactive apply (requires confirmation)
terraform apply

# Prompt:
# Do you want to perform these actions?
#   Terraform will perform the actions described above.
#   Only 'yes' will be accepted to approve.
# 
# Enter a value: yes

# Apply saved plan
terraform plan -out=tfplan
terraform apply tfplan

# Auto-approve (no confirmation)
terraform apply -auto-approve

# Apply with variable overrides
terraform apply -var 'instance_type=t3.large' -var 'enable_backup=true'

# Apply specific resource only
terraform apply -target=aws_instance.web -auto-approve

# Apply with increased parallelism (faster)
terraform apply -parallelism=50 -auto-approve

# Refresh state only
terraform apply -refresh-only -auto-approve
```

**Production Apply Pattern:**

```bash
# Safe production deployment workflow
terraform plan -out=prod.tfplan
terraform show prod.tfplan > prod-plan-review.txt

# Team reviews prod-plan-review.txt
# After approval:
terraform apply prod.tfplan

# Verify deployment
terraform output
```


***

## Destroy Commands

### `terraform destroy`

Destroys all resources managed by Terraform configuration.

**Basic Syntax:**

```bash
terraform destroy [options]
```

**Common Options:**


| Flag | Description | Example |
| :-- | :-- | :-- |
| `-auto-approve` | Skip confirmation | `terraform destroy -auto-approve` |
| `-target=RESOURCE` | Destroy specific resource | `terraform destroy -target=aws_instance.test` |
| `-var 'key=value'` | Set variable value | `terraform destroy -var 'environment=test'` |

**Examples:**

```bash
# Interactive destroy (requires confirmation)
terraform destroy

# Prompt:
# Do you really want to destroy all resources?
#   Terraform will destroy all your managed infrastructure.
#   There is no undo. Only 'yes' will be accepted to confirm.
# 
# Enter a value: yes

# Auto-approve destroy
terraform destroy -auto-approve

# Destroy specific resource
terraform destroy -target=aws_instance.test -auto-approve

# Plan destruction first
terraform plan -destroy -out=destroy.tfplan
terraform apply destroy.tfplan
```

**⚠️ Safety Warning:**

```bash
# Prevent accidental destruction with lifecycle
resource "aws_db_instance" "production" {
  # ... configuration ...
  
  lifecycle {
    prevent_destroy = true
  }
}

# Error when attempting destroy:
# Error: Instance cannot be destroyed
# Resource aws_db_instance.production has lifecycle.prevent_destroy set
```


***

## State Management Commands

### `terraform state list`

Lists all resources in state.

```bash
# List all resources
terraform state list

# Output:
# aws_vpc.main
# aws_subnet.public[0]
# aws_subnet.public[1]
# aws_instance.web[0]
# aws_instance.web[1]

# Filter resources by type
terraform state list | grep aws_instance

# Count resources
terraform state list | wc -l
```


### `terraform state show`

Shows detailed attributes of a resource in state.

```bash
# Show specific resource
terraform state show aws_instance.web

# Output:
# resource "aws_instance" "web" {
#     ami                          = "ami-12345678"
#     availability_zone            = "us-east-1a"
#     instance_type                = "t3.micro"
#     id                           = "i-0123456789abcdef0"
#     ...
# }

# Show with JSON output
terraform state show -json aws_instance.web | jq .
```


### `terraform state mv`

Moves/renames resources in state.

```bash
# Rename resource
terraform state mv aws_instance.old aws_instance.new

# Move resource to module
terraform state mv aws_instance.web module.app.aws_instance.web

# Move resource from module to root
terraform state mv module.app.aws_instance.web aws_instance.web

# Move entire module
terraform state mv module.old_app module.new_app

# Move resource between count indexes
terraform state mv 'aws_instance.web[0]' 'aws_instance.web[2]'
```


### `terraform state rm`

Removes resources from state without destroying them.

```bash
# Remove single resource
terraform state rm aws_instance.test

# Remove multiple resources
terraform state rm aws_instance.test aws_security_group.test_sg

# Remove entire module
terraform state rm module.old_app

# Remove resources matching pattern (use carefully!)
terraform state list | grep test | xargs -n1 terraform state rm
```


### `terraform state pull`

Downloads and outputs current state.

```bash
# Pull state to stdout
terraform state pull

# Save state to file
terraform state pull > state-backup.json

# Backup with timestamp
terraform state pull > "state-backup-$(date +%Y%m%d-%H%M%S).json"

# View state with jq
terraform state pull | jq '.resources[] | {type: .type, name: .name}'
```


### `terraform state push`

Uploads local state to remote backend.

```bash
# Push local state file to backend
terraform state push state-backup.json

# Force push (overwrite remote state)
terraform state push -force state-backup.json
```

**⚠️ Warning:** Use `state push` cautiously—incorrect usage can corrupt state.

### `terraform state replace-provider`

Replaces provider source in state.

```bash
# Example: Migrate from community to official provider
terraform state replace-provider \
  registry.terraform.io/terraform-providers/aws \
  registry.terraform.io/hashicorp/aws

# Useful when provider source changes
```


***

## Workspace Commands

### `terraform workspace list`

Lists all workspaces with current workspace marked.

```bash
terraform workspace list

# Output:
#   default
# * production
#   staging
#   development
```


### `terraform workspace new`

Creates new workspace.

```bash
# Create and switch to new workspace
terraform workspace new staging

# Create without switching
terraform workspace new -lock=false development
```


### `terraform workspace select`

Switches to different workspace.

```bash
# Switch to production workspace
terraform workspace select production

# Verify current workspace
terraform workspace show
# Output: production
```


### `terraform workspace delete`

Deletes workspace.

```bash
# Delete workspace (must be empty)
terraform workspace delete staging

# Force delete non-empty workspace
terraform workspace delete -force staging
```

**Workspace Usage Pattern:**

```bash
# Development workflow
terraform workspace new dev
terraform apply -var-file=dev.tfvars

# Staging deployment
terraform workspace new staging
terraform apply -var-file=staging.tfvars

# Production deployment
terraform workspace new production
terraform apply -var-file=prod.tfvars

# Check current workspace before operations
if [ "$(terraform workspace show)" != "production" ]; then
  echo "Error: Not in production workspace"
  exit 1
fi
```


***

## Output Commands

### `terraform output`

Reads output values from state.

```bash
# Show all outputs
terraform output

# Output:
# alb_dns_name = "app-alb-123456.us-east-1.elb.amazonaws.com"
# vpc_id = "vpc-0123456789abcdef0"
# db_endpoint = "mydb.abcdef.us-east-1.rds.amazonaws.com:5432"

# Show specific output
terraform output alb_dns_name

# Output in JSON format
terraform output -json

# Raw output (no quotes, for scripting)
terraform output -raw alb_dns_name

# Use in scripts
ALB_DNS=$(terraform output -raw alb_dns_name)
curl https://$ALB_DNS/health
```


***

## Validation and Formatting Commands

### `terraform fmt`

Formats Terraform configuration files.

```bash
# Format current directory
terraform fmt

# Format recursively
terraform fmt -recursive

# Check formatting without changes
terraform fmt -check

# Show differences
terraform fmt -diff

# CI/CD formatting check
terraform fmt -check -recursive || {
  echo "Error: Terraform files not formatted"
  exit 1
}
```


### `terraform validate`

Validates configuration syntax and consistency.

```bash
# Validate current directory
terraform validate

# Output:
# Success! The configuration is valid.

# Validate with JSON output
terraform validate -json

# CI/CD validation
terraform init -backend=false
terraform validate
```


***

## Import and Refresh Commands

### `terraform import`

Imports existing infrastructure into state.

```bash
# Import EC2 instance
terraform import aws_instance.web i-0123456789abcdef0

# Import VPC
terraform import aws_vpc.main vpc-0123456789abcdef0

# Import into module
terraform import module.networking.aws_vpc.main vpc-0123456789abcdef0

# Import with provider alias
terraform import -provider=aws.us_west_2 aws_vpc.west vpc-abcdef0123456789

# Import multiple resources (scripted)
while IFS=, read -r resource_address resource_id; do
  terraform import "$resource_address" "$resource_id"
done < import-list.csv
```

**Import List Example (import-list.csv):**

```
aws_instance.web1,i-0123456789abcdef0
aws_instance.web2,i-0123456789abcdef1
aws_security_group.web,sg-0123456789abcdef0
```


### `terraform refresh`

Updates state to match real infrastructure (deprecated—use `terraform apply -refresh-only`).

```bash
# Refresh state (legacy)
terraform refresh

# Modern approach
terraform apply -refresh-only -auto-approve

# Plan refresh only
terraform plan -refresh-only
```


***

## Troubleshooting Commands

### `terraform console`

Interactive console for evaluating expressions.

```bash
# Launch console
terraform console

# Example session:
> var.instance_type
"t3.micro"

> aws_instance.web.id
"i-0123456789abcdef0"

> length(aws_subnet.private)
3

> [for s in aws_subnet.private : s.id]
[
  "subnet-0123456789abcdef0",
  "subnet-0123456789abcdef1",
  "subnet-0123456789abcdef2"
]

# Exit console
> exit
```


### `terraform graph`

Generates visual dependency graph.

```bash
# Generate DOT format graph
terraform graph > graph.dot

# Convert to PNG with Graphviz
terraform graph | dot -Tpng > graph.png

# Open in browser
terraform graph | dot -Tsvg > graph.svg
open graph.svg
```


### `terraform show`

Shows human-readable output of plan or state.

```bash
# Show current state
terraform show

# Show saved plan
terraform show tfplan

# Show in JSON
terraform show -json | jq .

# Show specific resource
terraform show -json | jq '.values.root_module.resources[] | select(.address=="aws_instance.web")'
```


### `terraform force-unlock`

Manually unlocks state if lock stuck.

```bash
# Get lock ID from error message
# Error: Error acquiring the state lock
# Lock Info:
#   ID:        abc123-def456-ghi789
#   ...

# Force unlock
terraform force-unlock abc123-def456-ghi789

# Confirmation required
# Do you really want to force-unlock?
# Enter a value: yes
```

**⚠️ Warning:** Only use when certain no other operations are running.

***

## Advanced Commands

### `terraform taint` / `terraform untaint`

Marks resource for replacement (deprecated in Terraform 1.x—use `terraform apply -replace` instead).

```bash
# Modern approach: Replace specific resource
terraform apply -replace=aws_instance.web

# Legacy taint (still works)
terraform taint aws_instance.web
terraform apply

# Untaint if marked accidentally
terraform untaint aws_instance.web
```


### `terraform providers`

Shows provider requirements and versions.

```bash
# List providers
terraform providers

# Output:
# Providers required by configuration:
# .
# ├── provider[registry.terraform.io/hashicorp/aws] ~> 6.0
# ├── provider[registry.terraform.io/hashicorp/random] ~> 3.6
# └── module.vpc
#     └── provider[registry.terraform.io/hashicorp/aws]

# Show provider schemas
terraform providers schema -json > provider-schemas.json
```


### `terraform version`

Shows Terraform and provider versions.

```bash
# Show version
terraform version

# Output:
# Terraform v1.11.0
# on linux_amd64
# + provider registry.terraform.io/hashicorp/aws v6.16.0
# + provider registry.terraform.io/hashicorp/random v3.6.0

# Check if upgrade available
terraform version -check
```


***

## Environment Variables

Common Terraform environment variables:


| Variable | Purpose | Example |
| :-- | :-- | :-- |
| `TF_LOG` | Enable debug logging | `export TF_LOG=DEBUG` |
| `TF_LOG_PATH` | Log output file | `export TF_LOG_PATH=terraform.log` |
| `TF_INPUT` | Disable interactive prompts | `export TF_INPUT=false` |
| `TF_VAR_name` | Set input variable | `export TF_VAR_instance_type=t3.large` |
| `TF_CLI_ARGS` | Pass CLI args to all commands | `export TF_CLI_ARGS="-no-color"` |
| `TF_DATA_DIR` | Override .terraform directory | `export TF_DATA_DIR=/tmp/tf-data` |

**Debug Example:**

```bash
# Enable debug logging
export TF_LOG=DEBUG
export TF_LOG_PATH=terraform-debug.log

# Run operation
terraform apply

# View detailed logs
less terraform-debug.log

# Disable logging
unset TF_LOG
unset TF_LOG_PATH
```


***

## Command Aliases and Shortcuts

Useful shell aliases for daily work:

```bash
# Add to ~/.bashrc or ~/.zshrc

# Terraform shortcuts
alias tf='terraform'
alias tfi='terraform init'
alias tfp='terraform plan'
alias tfa='terraform apply'
alias tfd='terraform destroy'
alias tfo='terraform output'
alias tfs='terraform state'
alias tfv='terraform validate'
alias tff='terraform fmt -recursive'

# Common workflows
alias tfrefresh='terraform apply -refresh-only -auto-approve'
alias tfplan='terraform plan -out=tfplan'
alias tfapply='terraform apply tfplan'

# Safety checks
alias tfcheck='terraform fmt -check -recursive && terraform validate'

# Backup state before operations
tfbackup() {
  terraform state pull > "state-backup-$(date +%Y%m%d-%H%M%S).json"
  echo "State backed up"
}
```


***

## CI/CD Command Patterns

### GitHub Actions Example

```yaml
- name: Terraform Init
  run: terraform init -backend-config=backend-prod.hcl

- name: Terraform Format Check
  run: terraform fmt -check -recursive

- name: Terraform Validate
  run: terraform validate

- name: Terraform Plan
  run: |
    terraform plan -out=tfplan -detailed-exitcode
    echo "exit_code=$?" >> $GITHUB_OUTPUT

- name: Terraform Apply
  if: github.ref == 'refs/heads/main'
  run: terraform apply tfplan
```


### Safe Production Deployment Script

```bash
#!/bin/bash
set -e

echo "=== Production Terraform Deployment ==="

# Verify correct workspace
WORKSPACE=$(terraform workspace show)
if [ "$WORKSPACE" != "production" ]; then
  echo "Error: Not in production workspace"
  exit 1
fi

# Backup state
terraform state pull > "state-backup-$(date +%Y%m%d-%H%M%S).json"

# Format and validate
terraform fmt -recursive
terraform validate

# Plan with output
terraform plan -out=prod.tfplan | tee plan-output.txt

# Require manual approval
read -p "Review plan and confirm apply (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
  echo "Deployment cancelled"
  exit 0
fi

# Apply
terraform apply prod.tfplan

# Verify outputs
terraform output

echo "=== Deployment Complete ==="
```


***

## Quick Reference Summary

**Essential Daily Commands:**

```bash
terraform init              # Initialize working directory
terraform fmt -recursive    # Format all files
terraform validate          # Check syntax
terraform plan              # Preview changes
terraform apply             # Apply changes
terraform output           # View outputs
terraform state list        # List managed resources
```

**Common Workflows:**

```bash
# New environment setup
terraform init
terraform workspace new staging
terraform plan -var-file=staging.tfvars
terraform apply -var-file=staging.tfvars

# Safe production deployment
terraform plan -out=prod.tfplan
# Review plan
terraform apply prod.tfplan

# State management
terraform state list
terraform state show aws_instance.web
terraform state mv aws_instance.old aws_instance.new

# Troubleshooting
terraform console
terraform graph | dot -Tpng > graph.png
export TF_LOG=DEBUG
terraform apply
```


***

This command reference provides immediate access to Terraform's most commonly used operations. Bookmark this appendix for quick lookups during daily infrastructure work, incident response, and deployment automation. For detailed documentation on any command, use `terraform [command] -help` or consult the official Terraform CLI documentation.

