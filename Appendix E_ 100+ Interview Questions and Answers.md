# Appendix E: 100+ Interview Questions and Answers

## Introduction

This appendix provides a comprehensive collection of Terraform and AWS infrastructure interview questions organized by difficulty level and topic area. The questions range from fundamental concepts to advanced scenario-based challenges commonly asked in DevOps, Cloud Engineer, Site Reliability Engineer (SRE), and Solutions Architect interviews as of 2025. Each answer includes practical examples and real-world context to demonstrate production-level expertise.

***

## Beginner Level Questions (1-30)

### Core Concepts

**Q1: What is Terraform and why is it used?**

**Answer:** Terraform is an open-source Infrastructure as Code (IaC) tool created by HashiCorp that enables declarative provisioning and management of cloud infrastructure across multiple providers. It allows you to define infrastructure using configuration files written in HashiCorp Configuration Language (HCL), version control your infrastructure, and apply changes consistently and predictably. Unlike imperative scripting approaches, Terraform's declarative model means you describe the desired end state, and Terraform determines the necessary steps to reach that state.

**Q2: What are the core components of Terraform architecture?**

**Answer:** Terraform consists of three main components:

1. **Terraform Core:** Takes two inputs—configuration files (infrastructure definition) and state files (current infrastructure snapshot)—and creates an execution plan
2. **Providers:** Plugins that interact with cloud platforms, SaaS providers, and APIs (e.g., AWS, Azure, GCP, Kubernetes)
3. **State:** Maintains a record of managed infrastructure, enabling Terraform to determine what changes are needed

**Q3: Explain the Terraform workflow.**

**Answer:** The core Terraform workflow has three steps:

1. **Write:** Create infrastructure as code in `.tf` files using HCL
2. **Plan:** Run `terraform plan` to preview changes before applying them
3. **Apply:** Execute `terraform apply` to provision or modify infrastructure

This workflow ensures repeatability, version control, and predictability in infrastructure changes.

**Q4: What is a Terraform provider?**

**Answer:** A provider is a plugin that enables Terraform to interact with APIs of cloud platforms and services. Providers are responsible for understanding API interactions and exposing resources. Examples include `hashicorp/aws` for AWS services, `hashicorp/azurerm` for Azure, and `hashicorp/google` for GCP. Each provider must be declared in the `required_providers` block with a source and version constraint.

```hcl
terraform {
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

**Q5: What is the difference between `terraform plan` and `terraform apply`?**

**Answer:**

- **`terraform plan`:** Creates an execution plan showing what actions Terraform will take to reach the desired state. It does not modify actual infrastructure—it only shows proposed changes. This is a safe, read-only operation.
- **`terraform apply`:** Executes the actions proposed in the plan, actually creating, updating, or destroying infrastructure. It can be run directly (which internally runs a plan first) or can apply a saved plan file.

**Q6: What is a Terraform state file?**

**Answer:** The state file (`terraform.tfstate`) is a JSON file that maps your Terraform configuration to real-world resources. It tracks resource metadata, dependencies, and current infrastructure state. The state file is critical because it enables Terraform to determine what changes are needed during planning and to manage resource lifecycles accurately.

**Q7: What are the risks of using local state in a team environment?**

**Answer:** Local state files pose several risks in team environments:

1. **No collaboration:** Team members can't share state, leading to conflicts and inconsistencies
2. **No locking:** Simultaneous operations can corrupt state
3. **No backup:** Local file loss means losing track of infrastructure
4. **Security:** Sensitive data stored in plaintext locally

**Mitigation:** Use remote backends like S3 with DynamoDB locking, version control, and encryption at rest.

**Q8: What is a Terraform module?**

**Answer:** A module is a container for multiple resources that are used together. It's a way to organize and reuse Terraform code. Every Terraform configuration has at least one module (the root module). Modules enable:

- **Reusability:** Write once, use multiple times
- **Organization:** Group related resources logically
- **Encapsulation:** Hide complexity, expose simple interfaces

```hcl
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.5.0"
  
  name = "my-vpc"
  cidr = "10.0.0.0/16"
}
```

**Q9: What are Terraform variables and how are they used?**

**Answer:** Variables allow you to parameterize your Terraform configurations, making them reusable and flexible. They're defined in `variables.tf`:

```hcl
variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "environment" {
  description = "Environment name"
  type        = string
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod"
  }
}
```

Variables can be set via CLI (`-var`), files (`terraform.tfvars`), environment variables (`TF_VAR_*`), or interactively.

**Q10: What are Terraform outputs?**

**Answer:** Outputs expose values from your Terraform configuration for use by other configurations or for display to users. They're defined in `outputs.tf`:

```hcl
output "instance_ip" {
  description = "Public IP of EC2 instance"
  value       = aws_instance.web.public_ip
}

output "db_endpoint" {
  description = "RDS endpoint"
  value       = aws_db_instance.main.endpoint
  sensitive   = true  # Prevents display in logs
}
```

**Q11: What is the purpose of `terraform init`?**

**Answer:** `terraform init` initializes a Terraform working directory by:

1. Downloading and installing required provider plugins
2. Downloading modules referenced in configuration
3. Configuring the backend for state storage
4. Creating the `.terraform` directory with necessary files

It must be run before any other Terraform commands and should be re-run when adding new providers or modules.

**Q12: Explain `terraform destroy`.**

**Answer:** `terraform destroy` removes all infrastructure managed by the current Terraform configuration. It's equivalent to `terraform apply` but for deletion. Before destroying, Terraform shows a plan of what will be removed and requires confirmation. Use with extreme caution in production environments.

**Q13: What is a Terraform backend?**

**Answer:** A backend determines where Terraform stores its state file. Backends support two main functions:

1. **State storage:** Where the state file lives (local file, S3, Azure Storage, Terraform Cloud)
2. **State locking:** Prevents concurrent operations that could corrupt state
```hcl
terraform {
  backend "s3" {
    bucket         = "my-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
  }
}
```

**Q14: What is the difference between `count` and `for_each`?**

**Answer:**

**`count`:** Creates multiple instances using a numeric index. Best for simple scenarios creating identical resources.

```hcl
resource "aws_instance" "web" {
  count         = 3
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  
  tags = {
    Name = "web-${count.index}"
  }
}
```

**`for_each`:** Creates instances using a map or set, making each resource identifiable by key rather than numeric index. More flexible and safer for dynamic resources.

```hcl
resource "aws_instance" "web" {
  for_each = toset(["web1", "web2", "web3"])
  
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  
  tags = {
    Name = each.key
  }
}
```

**Key difference:** Removing an item from the middle of a `count` list causes Terraform to recreate all subsequent resources. With `for_each`, only the specific item is affected.

**Q15: What are Terraform data sources?**

**Answer:** Data sources allow Terraform to fetch information defined outside of Terraform or by another Terraform configuration. Unlike resources, data sources are read-only.

```hcl
# Fetch latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]
  
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# Use in resource
resource "aws_instance" "web" {
  ami           = data.aws_ami.amazon_linux_2.id
  instance_type = "t3.micro"
}
```

**When to use data sources vs. variables:** Use data sources to fetch dynamic information from cloud APIs (e.g., latest AMI IDs, existing VPC IDs). Use variables for static, configurable values.

**Q16: What is `terraform fmt`?**

**Answer:** `terraform fmt` automatically formats Terraform configuration files to a canonical style. It ensures consistent formatting across teams and is typically run as a pre-commit hook or in CI/CD pipelines.

```bash
terraform fmt -recursive  # Format all .tf files in directory tree
terraform fmt -check      # Check if formatting is needed (exit code indicates status)
```

**Q17: What is `terraform validate`?**

**Answer:** `terraform validate` checks configuration syntax and internal consistency without accessing remote services. It validates:

- Syntax correctness
- Variable and resource references
- Type constraints
- Required arguments

It does not check if resources can actually be created in the cloud provider.

**Q18: What are Terraform provisioners?**

**Answer:** Provisioners execute scripts on local or remote machines during resource creation or destruction. They're used for bootstrapping, configuration management, or cleanup tasks. Examples include `local-exec`, `remote-exec`, and `file`.

```hcl
resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  
  provisioner "remote-exec" {
    inline = [
      "sudo yum update -y",
      "sudo yum install -y httpd",
      "sudo systemctl start httpd"
    ]
    
    connection {
      type        = "ssh"
      user        = "ec2-user"
      private_key = file("~/.ssh/id_rsa")
      host        = self.public_ip
    }
  }
}
```

**Best practice:** Use provisioners sparingly. Prefer configuration management tools (Ansible, Chef, Puppet) or user data/cloud-init for post-provisioning tasks.

**Q19: What is a Terraform workspace?**

**Answer:** Workspaces allow you to manage multiple instances of the same configuration with separate state files. They're useful for managing dev, staging, and production environments from a single configuration.

```bash
terraform workspace new staging
terraform workspace select production
terraform workspace list
terraform workspace show
```

**Q20: What is `terraform import`?**

**Answer:** `terraform import` brings existing infrastructure under Terraform management without destroying and recreating it. It adds the resource to state so Terraform can manage it going forward.

```bash
# Import existing EC2 instance
terraform import aws_instance.web i-1234567890abcdef0

# Import VPC
terraform import aws_vpc.main vpc-0123456789abcdef0
```

**Important:** Import only adds to state—you must manually write the corresponding configuration.

**Q21: What are lifecycle rules in Terraform?**

**Answer:** Lifecycle rules control how Terraform handles resource creation, updates, and deletion:

```hcl
resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  
  lifecycle {
    create_before_destroy = true   # Create replacement before destroying
    prevent_destroy       = true   # Prevent accidental deletion
    ignore_changes        = [tags] # Ignore external tag changes
  }
}
```

**Q22: What is the purpose of `depends_on`?**

**Answer:** `depends_on` explicitly defines dependencies between resources when Terraform can't automatically infer them. It's needed when dependencies are based on behavior rather than direct attribute references.

```hcl
resource "aws_iam_role_policy" "app" {
  role   = aws_iam_role.app.id
  policy = data.aws_iam_policy_document.app.json
}

resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.app.name
  
  # Ensure policy is attached before instance launches
  depends_on = [aws_iam_role_policy.app]
}
```

**Q23: What are Terraform locals?**

**Answer:** Locals assign names to expressions, making configurations more readable and reducing repetition:

```hcl
locals {
  common_tags = {
    Project     = "MyApp"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
  
  instance_name = "${var.project}-${var.environment}-web"
}

resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  
  tags = merge(
    local.common_tags,
    {
      Name = local.instance_name
    }
  )
}
```

**Q24: What is the difference between `terraform.tfvars` and `variables.tf`?**

**Answer:**

- **`variables.tf`:** Declares variables (type, description, default, validation)
- **`terraform.tfvars`:** Provides values for those variables

```hcl
# variables.tf - Declaration
variable "instance_type" {
  type    = string
  default = "t3.micro"
}

# terraform.tfvars - Values
instance_type = "t3.large"
```

**Q25: What is a dynamic block in Terraform?**

**Answer:** Dynamic blocks generate repeated nested blocks based on a collection:

```hcl
resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = aws_vpc.main.id
  
  dynamic "ingress" {
    for_each = [80, 443, 8080]
    
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}
```

**Q26: What are Terraform functions?**

**Answer:** Built-in functions transform and combine values. Common categories include:

- **String:** `lower()`, `upper()`, `join()`, `split()`
- **Collection:** `length()`, `merge()`, `concat()`, `flatten()`
- **Numeric:** `min()`, `max()`, `ceil()`, `floor()`
- **Type conversion:** `tostring()`, `tonumber()`, `tolist()`, `tomap()`

```hcl
locals {
  availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]
  az_count           = length(local.availability_zones)
  
  tags = merge(
    var.common_tags,
    {
      Environment = upper(var.environment)
    }
  )
}
```

**Q27: What is `terraform refresh`?**

**Answer:** `terraform refresh` updates the state file to match real-world infrastructure. As of Terraform 0.15.4+, it's deprecated in favor of `terraform apply -refresh-only`.

```bash
# Modern approach
terraform apply -refresh-only -auto-approve

# Plan only refresh
terraform plan -refresh-only
```

**Q28: What is `terraform taint`?**

**Answer:** `terraform taint` marks a resource for recreation on the next apply. In Terraform 1.x, it's deprecated in favor of `terraform apply -replace`.

```bash
# Legacy
terraform taint aws_instance.web
terraform apply

# Modern approach
terraform apply -replace=aws_instance.web
```

**Q29: What is the Terraform Registry?**

**Answer:** The Terraform Registry (registry.terraform.io) is a repository of providers and reusable modules maintained by HashiCorp, third-party vendors, and the community. It hosts thousands of verified and community modules for common infrastructure patterns.

**Q30: How do you pin provider versions?**

**Answer:** Version pinning ensures consistent behavior across team members and over time:

```hcl
terraform {
  required_version = ">= 1.11.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"  # Allow minor and patch updates
    }
  }
}
```

**Version constraint operators:**

- `=`: Exact version
- `~>`: Pessimistic constraint (allow rightmost version component to increment)
- `>=`, `<=`, `>`, `<`: Comparison operators

***

## Intermediate Level Questions (31-60)

### State Management

**Q31: How do you migrate Terraform state from local to remote backend?**

**Answer:** State migration involves updating backend configuration and running `terraform init -migrate-state`:

```hcl
# 1. Add remote backend configuration
terraform {
  backend "s3" {
    bucket         = "my-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
  }
}
```

```bash
# 2. Initialize and migrate
terraform init -migrate-state

# Terraform prompts:
# Do you want to copy existing state to the new backend?
# Enter a value: yes

# 3. Verify migration
terraform state list
```

**Q32: What is state locking and why is it important?**

**Answer:** State locking prevents concurrent operations from corrupting state. When enabled, Terraform acquires a lock before operations and releases it afterward. Most remote backends (S3+DynamoDB, Terraform Cloud) support locking automatically.

```hcl
terraform {
  backend "s3" {
    bucket         = "my-terraform-state"
    key            = "terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-locks"  # Enables locking
  }
}
```

**Q33: How do you handle a stuck state lock?**

**Answer:** If a lock becomes stuck (e.g., process killed mid-operation), force-unlock using the lock ID from the error message:

```bash
# Error shows lock ID
terraform force-unlock <lock-id>

# Confirmation required
# Do you really want to force-unlock?
# Enter a value: yes
```

**⚠️ Warning:** Only force-unlock when certain no other operations are running.

**Q34: What is configuration drift and how do you detect it?**

**Answer:** Configuration drift occurs when infrastructure diverges from Terraform's expected state due to manual changes. Detection methods:

1. **Regular refresh:** `terraform plan -refresh-only`
2. **Automated drift detection:** Terraform Cloud continuous validation
3. **Third-party tools:** Spacelift, env0 drift detection features
4. **AWS Config:** Track resource configuration changes

**Resolution:**

- **Import drift:** Update Terraform to match reality
- **Revert drift:** Apply Terraform to restore desired state

**Q35: How do you share state between multiple Terraform configurations?**

**Answer:** Use `terraform_remote_state` data source:

```hcl
# Configuration A outputs
output "vpc_id" {
  value = aws_vpc.main.id
}

# Configuration B reads state
data "terraform_remote_state" "network" {
  backend = "s3"
  
  config = {
    bucket = "my-terraform-state"
    key    = "network/terraform.tfstate"
    region = "us-east-1"
  }
}

resource "aws_instance" "web" {
  vpc_id = data.terraform_remote_state.network.outputs.vpc_id
}
```

**Q36: How do you remove a resource from state without destroying it?**

**Answer:** Use `terraform state rm` to remove from state management without destroying the actual resource:

```bash
# Remove single resource
terraform state rm aws_instance.web

# Remove module
terraform state rm module.vpc

# Resource continues existing but Terraform no longer manages it
```

**Use case:** Transitioning resource management to another Terraform configuration or removing accidentally imported resources.

**Q37: What happens if you delete the state file?**

**Answer:** Deleting the state file is catastrophic:

1. Terraform loses track of all managed infrastructure
2. Running `terraform apply` will attempt to create duplicate resources
3. Resource conflicts and errors will occur

**Recovery:**

1. Restore from backup (remote backends typically version state)
2. If no backup: manually `terraform import` each resource
3. Consider using remote backend with versioning and locking

**Q38: How do you manage secrets in Terraform?**

**Answer:** Best practices for secret management:

1. **Never commit secrets to version control**
2. **Use environment variables:** `TF_VAR_db_password`
3. **External secret stores:** AWS Secrets Manager, HashiCorp Vault
4. **Terraform Cloud:** Secure variable storage
5. **Mark outputs as sensitive:** `sensitive = true`
```hcl
# Fetch from Secrets Manager
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = "prod/db/password"
}

resource "aws_db_instance" "main" {
  password = data.aws_secretsmanager_secret_version.db_password.secret_string
}

# Sensitive output
output "db_endpoint" {
  value     = aws_db_instance.main.endpoint
  sensitive = true
}
```

**Q39: What is the difference between implicit and explicit dependencies?**

**Answer:**

**Implicit dependencies:** Terraform automatically infers dependencies from attribute references:

```hcl
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "public" {
  vpc_id = aws_vpc.main.id  # Implicit dependency
}
```

**Explicit dependencies:** Manually specified using `depends_on` when relationship isn't captured by attribute references:

```hcl
resource "aws_iam_role_policy" "app" {
  role = aws_iam_role.app.id
}

resource "aws_instance" "web" {
  depends_on = [aws_iam_role_policy.app]  # Explicit
}
```

**Q40: How do you handle Terraform provider version upgrades?**

**Answer:** Safe upgrade process:

1. **Review changelog:** Check for breaking changes
2. **Update constraint:** Modify version in `required_providers`
3. **Test in lower environments:** Dev → Staging → Production
4. **Backup state:** Create state snapshot
5. **Run refresh:** `terraform apply -refresh-only`
6. **Verify plan:** Check for unexpected changes
7. **Apply incrementally:** Apply to non-critical resources first
```bash
# Upgrade workflow
terraform state pull > state-backup.json
terraform init -upgrade
terraform plan -refresh-only
terraform apply -refresh-only
terraform plan
```

**Q41: What are Terraform workspaces best used for?**

**Answer:** Workspaces are best for managing similar infrastructure with minimal configuration differences. They share the same configuration but maintain separate state files.

**Good use cases:**

- Feature branch testing
- Short-lived environments
- Developer sandboxes

**Not recommended for:**

- Production vs. non-production (use separate directories instead)
- Significantly different topologies
- Different compliance requirements

**Q42: What is the alternative to workspaces for managing environments?**

**Answer:** Separate directories with shared modules:

```
infrastructure/
├── modules/
│   ├── vpc/
│   ├── compute/
│   └── database/
├── environments/
│   ├── dev/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── terraform.tfvars
│   ├── staging/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── terraform.tfvars
│   └── prod/
│       ├── main.tf
│       ├── variables.tf
│       └── terraform.tfvars
```

**Benefits:**

- Clear separation
- Different backends per environment
- Environment-specific configurations
- Better for production governance

**Q43: How do you implement zero-downtime deployments with Terraform?**

**Answer:** Strategies for zero-downtime updates:

1. **Blue-Green deployment:**
```hcl
resource "aws_lb_target_group" "blue" {
  name     = "app-blue"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id
}

resource "aws_lb_target_group" "green" {
  name     = "app-green"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id
}

# Switch listener between blue and green
resource "aws_lb_listener" "app" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  
  default_action {
    type             = "forward"
    target_group_arn = var.active_deployment == "blue" ? 
                       aws_lb_target_group.blue.arn : 
                       aws_lb_target_group.green.arn
  }
}
```

2. **Create before destroy:**
```hcl
resource "aws_launch_template" "app" {
  lifecycle {
    create_before_destroy = true
  }
}
```

3. **Rolling updates via Auto Scaling:**
```hcl
resource "aws_autoscaling_group" "app" {
  min_size         = 3
  max_size         = 6
  desired_capacity = 3
  
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }
}
```

**Q44: How do you test Terraform configurations?**

**Answer:** Multiple testing approaches:

1. **Validation:** `terraform validate`
2. **Formatting:** `terraform fmt -check`
3. **Static analysis:** tfsec, Checkov, Terrascan
4. **Plan testing:** Review `terraform plan` output
5. **Integration testing:** Terratest (Go-based testing)
6. **Policy-as-code:** Sentinel, OPA

**Example Terratest:**

```go
func TestVPCCreation(t *testing.T) {
    terraformOptions := &terraform.Options{
        TerraformDir: "../examples/vpc",
    }
    
    defer terraform.Destroy(t, terraformOptions)
    terraform.InitAndApply(t, terraformOptions)
    
    vpcID := terraform.Output(t, terraformOptions, "vpc_id")
    assert.NotEmpty(t, vpcID)
}
```

**Q45: What is Terraform Cloud and how does it differ from Terraform CLI?**

**Answer:** Terraform Cloud is HashiCorp's SaaS offering providing:

- Remote execution environment
- State storage and locking
- Private module registry
- Team collaboration features
- Policy as code (Sentinel)
- Cost estimation
- VCS integration
- Automated workflows

**Terraform CLI:**

- Local execution
- Manual state management
- No built-in collaboration
- Self-managed infrastructure

**Q46: How do you implement disaster recovery in Terraform?**

**Answer:** DR implementation strategies:

1. **Multi-region deployment:**
```hcl
# Primary region
provider "aws" {
  region = "us-east-1"
  alias  = "primary"
}

# DR region
provider "aws" {
  region = "us-west-2"
  alias  = "dr"
}

module "primary_infrastructure" {
  source = "./modules/infrastructure"
  providers = {
    aws = aws.primary
  }
}

module "dr_infrastructure" {
  source = "./modules/infrastructure"
  providers = {
    aws = aws.dr
  }
}
```

2. **Cross-region replication:**
```hcl
resource "aws_s3_bucket_replication_configuration" "main" {
  bucket = aws_s3_bucket.primary.id
  role   = aws_iam_role.replication.arn
  
  rule {
    id     = "replicate-all"
    status = "Enabled"
    
    destination {
      bucket        = aws_s3_bucket.dr.arn
      storage_class = "STANDARD_IA"
    }
  }
}
```

3. **State backups:** Enable versioning on state bucket

**Q47: How do you manage Terraform in a CI/CD pipeline?**

**Answer:** CI/CD integration pattern:

```yaml
# GitHub Actions example
name: Terraform

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  terraform:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.11.0
      
      - name: Terraform Init
        run: terraform init
      
      - name: Terraform Format
        run: terraform fmt -check -recursive
      
      - name: Terraform Validate
        run: terraform validate
      
      - name: Terraform Plan
        run: terraform plan -out=tfplan
        
      - name: Terraform Apply
        if: github.ref == 'refs/heads/main'
        run: terraform apply -auto-approve tfplan
```

**Q48: What is the null_resource and when would you use it?**

**Answer:** `null_resource` implements standard resource lifecycle but doesn't create actual infrastructure. Use cases:

1. **Running scripts without resource creation:**
```hcl
resource "null_resource" "database_migration" {
  triggers = {
    migration_version = var.migration_version
  }
  
  provisioner "local-exec" {
    command = "python run_migrations.py"
  }
  
  depends_on = [aws_db_instance.main]
}
```

2. **Grouping dependencies:**
```hcl
resource "null_resource" "cluster_ready" {
  depends_on = [
    aws_eks_cluster.main,
    aws_eks_node_group.main,
    kubernetes_config_map.aws_auth
  ]
}
```

**Q49: How do you handle circular dependencies?**

**Answer:** Strategies to resolve circular dependencies:

1. **Break the cycle:** Refactor to remove circular references
2. **Use data sources:** Fetch information instead of referencing directly
3. **Split into multiple applies:** Apply in stages
4. **Reorder resources:** Sometimes resources can be reordered
```hcl
# Problem: Circular dependency
resource "aws_security_group" "app" {
  ingress {
    security_groups = [aws_security_group.db.id]  # Depends on db
  }
}

resource "aws_security_group" "db" {
  ingress {
    security_groups = [aws_security_group.app.id]  # Depends on app
  }
}

# Solution: Use security group rules instead
resource "aws_security_group" "app" {
  name = "app-sg"
}

resource "aws_security_group" "db" {
  name = "db-sg"
}

resource "aws_security_group_rule" "app_to_db" {
  type                     = "egress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.app.id
  source_security_group_id = aws_security_group.db.id
}

resource "aws_security_group_rule" "db_from_app" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.db.id
  source_security_group_id = aws_security_group.app.id
}
```

**Q50: What are the best practices for naming resources in Terraform?**

**Answer:** Consistent naming conventions:

1. **Use descriptive names:** `aws_instance.web_server` not `aws_instance.i1`
2. **Follow patterns:** `<service>_<component>_<role>`
3. **Use underscores:** `aws_subnet.private_app` not `aws-subnet-private-app`
4. **Include environment in AWS names:** `myapp-prod-web-sg`
5. **Avoid redundancy:** `aws_vpc.main_vpc` → `aws_vpc.main`
```hcl
# Good naming
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  
  tags = {
    Name = "${var.project}-${var.environment}-vpc"
  }
}

resource "aws_subnet" "public_web" {
  vpc_id = aws_vpc.main.id
  
  tags = {
    Name = "${var.project}-${var.environment}-public-web-subnet"
  }
}
```

**Q51: How do you implement conditional resource creation?**

**Answer:** Use `count` or `for_each` with conditions:

```hcl
# Using count
variable "create_database" {
  type    = bool
  default = false
}

resource "aws_db_instance" "main" {
  count = var.create_database ? 1 : 0
  
  identifier     = "myapp-db"
  engine         = "postgres"
  instance_class = "db.t3.micro"
}

# Using for_each with map
variable "databases" {
  type = map(object({
    engine         = string
    instance_class = string
  }))
  default = {}
}

resource "aws_db_instance" "dbs" {
  for_each = var.databases
  
  identifier     = each.key
  engine         = each.value.engine
  instance_class = each.value.instance_class
}
```

**Q52: What is the Terraform graph and how is it used?**

**Answer:** The resource graph represents dependencies between resources. Terraform uses it to determine parallel execution and proper ordering:

```bash
# Generate graph
terraform graph > graph.dot

# Visualize with Graphviz
terraform graph | dot -Tpng > graph.png

# View graph structure
terraform graph | grep -v "meta"
```

**Use cases:**

- Understanding complex dependencies
- Debugging dependency issues
- Optimizing parallel execution
- Documentation

**Q53: How do you handle sensitive outputs?**

**Answer:** Mark outputs as sensitive to prevent display in logs:

```hcl
output "db_password" {
  value     = aws_db_instance.main.password
  sensitive = true
}

output "api_key" {
  value     = random_password.api_key.result
  sensitive = true
}
```

**Accessing sensitive outputs:**

```bash
# Outputs are masked in console
terraform output
# db_password = <sensitive>

# View specific sensitive output
terraform output -raw db_password
```

**Q54: What are moved blocks and when would you use them?**

**Answer:** `moved` blocks (Terraform 1.1+) refactor resources without destroying them:

```hcl
# Original configuration
resource "aws_instance" "server" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
}

# Rename to web_server
resource "aws_instance" "web_server" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
}

# Track the move
moved {
  from = aws_instance.server
  to   = aws_instance.web_server
}
```

**Use cases:**

- Renaming resources
- Moving resources into modules
- Restructuring code organization

**Q55: How do you implement multi-account AWS deployments?**

**Answer:** Use provider aliases with assume_role:

```hcl
# Assume role in different accounts
provider "aws" {
  region = "us-east-1"
  alias  = "production"
  
  assume_role {
    role_arn = "arn:aws:iam::111111111111:role/TerraformExecution"
  }
}

provider "aws" {
  region = "us-east-1"
  alias  = "staging"
  
  assume_role {
    role_arn = "arn:aws:iam::222222222222:role/TerraformExecution"
  }
}

# Use in resources
resource "aws_vpc" "prod" {
  provider   = aws.production
  cidr_block = "10.0.0.0/16"
}

resource "aws_vpc" "stage" {
  provider   = aws.staging
  cidr_block = "10.1.0.0/16"
}
```

**Q56: What are preconditions and postconditions?**

**Answer:** Validation checks that run before and after resource operations:

```hcl
resource "aws_instance" "web" {
  ami           = var.ami_id
  instance_type = var.instance_type
  
  lifecycle {
    # Check before creating/updating
    precondition {
      condition     = data.aws_ami.selected.architecture == "x86_64"
      error_message = "AMI must be x86_64 architecture"
    }
    
    # Verify after creation
    postcondition {
      condition     = self.instance_state == "running"
      error_message = "Instance failed to reach running state"
    }
  }
}
```

**Q57: How do you implement Terraform module versioning best practices?**

**Answer:** Module versioning strategy:

1. **Semantic versioning:** Use Git tags (v1.0.0, v1.1.0, v2.0.0)
2. **Version constraints:** Pin to known-good versions
```hcl
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.5"  # Allow 5.x updates, not 6.x
}

# Private modules
module "custom_app" {
  source = "git::https://github.com/org/terraform-modules.git//app?ref=v1.2.0"
}
```

3. **CHANGELOG:** Document breaking changes
4. **Examples:** Provide usage examples for each version
5. **CI/CD testing:** Test modules before releasing

**Q58: What is the replace_triggered_by meta-argument?**

**Answer:** Forces resource replacement when specified attributes change (Terraform 1.2+):

```hcl
resource "aws_instance" "web" {
  ami           = var.ami_id
  instance_type = var.instance_type
  
  replace_triggered_by = [
    aws_security_group.web.id
  ]
}

# When security group is replaced, instance is also replaced
```

**Q59: How do you handle Terraform drift in production?**

**Answer:** Comprehensive drift management strategy:

1. **Detection:**
    - Schedule regular `terraform plan` runs
    - Enable Terraform Cloud drift detection
    - Use AWS Config rules
2. **Prevention:**
    - Restrict console access via IAM policies
    - Use Service Control Policies (SCPs)
    - Implement approval workflows
    - Tag all Terraform-managed resources
3. **Resolution:**
    - **Minor drift:** Import changes to Terraform
    - **Major drift:** Revert via `terraform apply`
    - **Intentional drift:** Use `lifecycle.ignore_changes`
```hcl
resource "aws_instance" "web" {
  ami           = var.ami_id
  instance_type = var.instance_type
  
  lifecycle {
    ignore_changes = [
      tags["LastModified"],  # Allow external tag updates
      user_data              # Don't replace on user_data changes
    ]
  }
}
```

**Q60: What are Terraform check blocks?**

**Answer:** Check blocks (Terraform 1.5+) perform continuous validation without affecting apply:

```hcl
check "health_check" {
  data "http" "app_health" {
    url = "https://${aws_lb.app.dns_name}/health"
  }
  
  assert {
    condition     = data.http.app_health.status_code == 200
    error_message = "Application health check failed"
  }
}
```

**Difference from preconditions:** Checks run during plan and don't block applies, providing warnings instead.

***

## Advanced Level Questions (61-100)

### Architecture \& Design

**Q61: How would you design a Terraform project structure for a large enterprise?**

**Answer:** Enterprise-grade structure:

```
terraform-infrastructure/
├── modules/                    # Reusable modules
│   ├── networking/
│   │   ├── vpc/
│   │   ├── transit-gateway/
│   │   └── direct-connect/
│   ├── compute/
│   │   ├── ec2/
│   │   ├── eks/
│   │   └── lambda/
│   ├── database/
│   │   ├── rds/
│   │   ├── dynamodb/
│   │   └── elasticache/
│   └── security/
│       ├── iam/
│       ├── kms/
│       └── security-groups/
├── environments/               # Environment-specific configs
│   ├── shared-services/        # Shared across accounts
│   │   ├── backend.tf
│   │   ├── main.tf
│   │   └── terraform.tfvars
│   ├── development/
│   │   ├── backend.tf
│   │   └── terraform.tfvars
│   ├── staging/
│   └── production/
├── policies/                   # Sentinel/OPA policies
│   ├── security/
│   ├── cost/
│   └── compliance/
├── scripts/                    # Automation scripts
│   ├── validate.sh
│   ├── plan.sh
│   └── apply.sh
└── docs/                       # Architecture docs
    ├── architecture.md
    ├── runbooks/
    └── diagrams/
```

**Key principles:**

- Module reusability
- Environment isolation
- Centralized policy enforcement
- Clear ownership boundaries
- Comprehensive documentation

**Q62: How do you implement zero-trust networking with Terraform?**

**Answer:** Zero-trust implementation pattern:

```hcl
# 1. Default deny all traffic
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  
  # No ingress/egress rules - deny all
}

# 2. Explicit allow per service
resource "aws_security_group" "web" {
  vpc_id = aws_vpc.main.id
  
  # Only allow from ALB
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
}

# 3. VPC endpoints for AWS services (no internet)
resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.main.id
  service_name = "com.amazonaws.${var.region}.s3"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [
        aws_s3_bucket.app.arn,
        "${aws_s3_bucket.app.arn}/*"
      ]
    }]
  })
}

# 4. Private subnets only, no IGW access
resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = false  # No public IPs
}

# 5. Session Manager for access (no SSH)
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
```

**Q63: How do you implement cross-region failover with Terraform?**

**Answer:** Multi-region failover architecture:

```hcl
# Primary region provider
provider "aws" {
  region = "us-east-1"
  alias  = "primary"
}

# DR region provider
provider "aws" {
  region = "us-west-2"
  alias  = "dr"
}

# Deploy infrastructure in both regions
module "primary_infrastructure" {
  source = "./modules/infrastructure"
  
  providers = {
    aws = aws.primary
  }
  
  environment = "production"
  region_type = "primary"
}

module "dr_infrastructure" {
  source = "./modules/infrastructure"
  
  providers = {
    aws = aws.dr
  }
  
  environment = "production"
  region_type = "dr"
}

# Route 53 health check and failover
resource "aws_route53_health_check" "primary" {
  fqdn              = module.primary_infrastructure.alb_dns_name
  port              = 443
  type              = "HTTPS"
  resource_path     = "/health"
  failure_threshold = 3
  request_interval  = 30
}

resource "aws_route53_record" "app" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "app.example.com"
  type    = "A"
  
  # Primary record
  alias {
    name                   = module.primary_infrastructure.alb_dns_name
    zone_id                = module.primary_infrastructure.alb_zone_id
    evaluate_target_health = true
  }
  
  set_identifier = "primary"
  
  failover_routing_policy {
    type = "PRIMARY"
  }
  
  health_check_id = aws_route53_health_check.primary.id
}

resource "aws_route53_record" "app_failover" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "app.example.com"
  type    = "A"
  
  # DR record
  alias {
    name                   = module.dr_infrastructure.alb_dns_name
    zone_id                = module.dr_infrastructure.alb_zone_id
    evaluate_target_health = true
  }
  
  set_identifier = "dr"
  
  failover_routing_policy {
    type = "SECONDARY"
  }
}

# Database replication
resource "aws_db_instance" "primary" {
  provider = aws.primary
  
  identifier     = "app-db-primary"
  engine         = "postgres"
  instance_class = "db.r6g.large"
  
  backup_retention_period = 7
}

resource "aws_db_instance" "replica" {
  provider = aws.dr
  
  identifier           = "app-db-replica"
  replicate_source_db  = aws_db_instance.primary.arn
  instance_class       = "db.r6g.large"
  
  # Can be promoted to standalone during failover
}
```

**Q64: How do you handle Terraform at scale (1000+ resources)?**

**Answer:** Strategies for large-scale Terraform:

1. **Modularization:** Break into logical modules
2. **State separation:** Multiple state files per service/team
3. **Targeted applies:** Use `-target` for specific changes
4. **Parallelism tuning:** Increase `-parallelism` flag
5. **Local caching:** Cache provider plugins
6. **Automation:** Atlantis, Terraform Cloud, Spacelift
```bash
# Increase parallelism (default 10)
terraform apply -parallelism=50

# Targeted apply for faster iterations
terraform apply -target=module.networking

# Selective refresh
terraform apply -refresh=false  # Skip refresh if not needed
```

**Q65: How would you migrate 500 manually-created AWS resources to Terraform?**

**Answer:** Systematic migration approach:

**Phase 1: Inventory and Planning**

```bash
# 1. Audit existing resources
aws resourcegroupstaggingapi get-resources --output json > inventory.json

# 2. Categorize by service and priority
# 3. Create migration plan (networking → compute → databases)
```

**Phase 2: Import Strategy**

```bash
# 4. Create import script
cat > import.sh <<'EOF'
#!/bin/bash
while IFS=, read -r resource_type resource_address resource_id; do
  echo "Importing $resource_address..."
  terraform import "$resource_address" "$resource_id"
done < import-list.csv
EOF

# 5. Generate import-list.csv
# resource_type,resource_address,resource_id
# aws_vpc,aws_vpc.main,vpc-0123456789
# aws_subnet,aws_subnet.public[^0],subnet-abc123
```

**Phase 3: Validation**

```bash
# 6. Import all resources
bash import.sh

# 7. Generate configuration from state
terraform show -json | jq '.values.root_module.resources'

# 8. Write Terraform configurations matching imported state

# 9. Verify no changes
terraform plan  # Should show "No changes"
```

**Phase 4: Refactor**

```bash
# 10. Refactor into modules
# 11. Add variables and outputs
# 12. Test in staging
# 13. Roll out to production
```

**Q66: How do you implement custom Terraform providers?**

**Answer:** Custom provider development (advanced):

```go
// main.go - Provider skeleton
package main

import (
    "github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
    "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func Provider() *schema.Provider {
    return &schema.Provider{
        Schema: map[string]*schema.Schema{
            "api_key": {
                Type:        schema.TypeString,
                Required:    true,
                Sensitive:   true,
                DefaultFunc: schema.EnvDefaultFunc("API_KEY", nil),
            },
        },
        ResourcesMap: map[string]*schema.Resource{
            "custom_resource": resourceCustom(),
        },
        DataSourcesMap: map[string]*schema.Resource{
            "custom_data_source": dataSourceCustom(),
        },
        ConfigureContextFunc: providerConfigure,
    }
}

func main() {
    plugin.Serve(&plugin.ServeOpts{
        ProviderFunc: Provider,
    })
}
```

**Use cases:**

- Internal APIs not covered by existing providers
- Proprietary systems integration
- Custom business logic

**Q67: How do you handle Terraform upgrades across 20+ repositories?**

**Answer:** Coordinated upgrade strategy:

1. **Centralize version requirements:**
```hcl
# shared/versions.tf (referenced by all repos)
terraform {
  required_version = ">= 1.11.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}
```

2. **Automated upgrade script:**
```bash
#!/bin/bash
# upgrade-terraform.sh

REPOS=(
  "infrastructure-networking"
  "infrastructure-compute"
  "infrastructure-databases"
  # ... 17 more repos
)

for repo in "${REPOS[@]}"; do
  echo "Upgrading $repo..."
  
  cd "$repo"
  
  # Update version constraint
  sed -i 's/required_version = ">= 1.9.0"/required_version = ">= 1.11.0"/' versions.tf
  
  # Initialize with new version
  terraform init -upgrade
  
  # Verify
  terraform validate
  terraform plan
  
  # Create PR if successful
  git checkout -b "upgrade-terraform-1.11"
  git add versions.tf
  git commit -m "Upgrade Terraform to 1.11.0"
  git push origin upgrade-terraform-1.11
  
  # Create PR via GitHub CLI
  gh pr create --title "Upgrade Terraform to 1.11.0" --body "Automated upgrade"
  
  cd ..
done
```

3. **Phased rollout:** Dev → Staging → Production
4. **Monitoring:** Watch for unexpected behavior

**Q68: How do you implement policy-as-code with Terraform?**

**Answer:** Policy enforcement using Sentinel or OPA:

**Sentinel Example (Terraform Cloud):**

```sentinel
# policy/require-tags.sentinel
import "tfplan/v2" as tfplan

required_tags = ["Environment", "Owner", "Project"]

# Check all resources for required tags
main = rule {
  all tfplan.resource_changes as _, rc {
    rc.change.after.tags contains required_tags[^0] and
    rc.change.after.tags contains required_tags and
    rc.change.after.tags contains required_tags
  }
}
```

**OPA Example:**

```rego
# policy/encryption.rego
package terraform.encryption

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket"
  not resource.change.after.server_side_encryption_configuration
  
  msg := sprintf("S3 bucket %s must have encryption enabled", [resource.address])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_db_instance"
  resource.change.after.storage_encrypted == false
  
  msg := sprintf("RDS instance %s must have encryption enabled", [resource.address])
}
```

**Integration:**

```bash
# Run OPA policy check
terraform show -json tfplan.out | opa eval --data policy/ --input - "data.terraform.encryption.deny"
```

**Q69: How do you implement cost governance with Terraform?**

**Answer:** Multi-layered cost control:

1. **Pre-deployment estimation:**
```bash
# Infracost integration
infracost breakdown --path . --format json | jq '.totalMonthlyCost'

# Block if exceeds threshold
COST=$(infracost breakdown --path . --format json | jq -r '.totalMonthlyCost')
if (( $(echo "$COST > 10000" | bc -l) )); then
  echo "Cost exceeds $10,000 threshold"
  exit 1
fi
```

2. **Policy enforcement:**
```sentinel
# policy/cost-limit.sentinel
import "tfrun"
import "decimal"

max_monthly_cost = decimal.new(5000)

main = rule {
  decimal.new(tfrun.cost_estimate.proposed_monthly_cost) < max_monthly_cost
}
```

3. **Instance size restrictions:**
```rego
# Only allow t3, t3a instance families
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_instance"
  instance_type := resource.change.after.instance_type
  not startswith(instance_type, "t3")
  
  msg := sprintf("Instance %s uses %s - only t3 families allowed", 
                 [resource.address, instance_type])
}
```

4. **Budget alerts:**
```hcl
resource "aws_budgets_budget" "terraform_managed" {
  name         = "terraform-infrastructure"
  budget_type  = "COST"
  limit_amount = "5000"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  
  notification {
    comparison_operator = "GREATER_THAN"
    threshold           = 80
    threshold_type      = "PERCENTAGE"
    notification_type   = "ACTUAL"
    
    subscriber_email_addresses = ["finance@example.com"]
  }
}
```

**Q70: How would you implement blue-green deployment for a complete application stack?**

**Answer:** Full stack blue-green pattern:

```hcl
variable "active_environment" {
  type    = string
  default = "blue"
  
  validation {
    condition     = contains(["blue", "green"], var.active_environment)
    error_message = "Active environment must be blue or green"
  }
}

# Blue environment
module "blue_environment" {
  source = "./modules/application-stack"
  
  environment = "blue"
  
  vpc_id      = aws_vpc.main.id
  subnet_ids  = aws_subnet.private[*].id
  
  instance_count = var.active_environment == "blue" ? 3 : 0
  
  target_group_arn = aws_lb_target_group.blue.arn
}

# Green environment
module "green_environment" {
  source = "./modules/application-stack"
  
  environment = "green"
  
  vpc_id      = aws_vpc.main.id
  subnet_ids  = aws_subnet.private[*].id
  
  instance_count = var.active_environment == "green" ? 3 : 0
  
  target_group_arn = aws_lb_target_group.green.arn
}

# Load balancer switches between blue and green
resource "aws_lb_listener" "app" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate.app.arn
  
  default_action {
    type             = "forward"
    target_group_arn = var.active_environment == "blue" ? 
                       aws_lb_target_group.blue.arn : 
                       aws_lb_target_group.green.arn
  }
}

# Database uses single instance with connection from both environments
resource "aws_db_instance" "main" {
  identifier     = "app-database"
  engine         = "postgres"
  instance_class = "db.r6g.large"
  
  # Both blue and green security groups can access
  vpc_security_group_ids = [
    module.blue_environment.database_security_group_id,
    module.green_environment.database_security_group_id
  ]
}
```

**Deployment process:**

```bash
# 1. Deploy new version to inactive environment
terraform apply -var 'active_environment=blue'  # Green is inactive

# 2. Test green environment via direct target group
curl https://green.test.example.com/health

# 3. Switch traffic to green
terraform apply -var 'active_environment=green'

# 4. Monitor for issues
# 5. If problems, rollback instantly
terraform apply -var 'active_environment=blue'

# 6. Once stable, scale down old environment
```

**Q71-Q100: Rapid-Fire Scenario Questions**



**Q71: How do you prevent accidental destruction of critical resources?**
**A:** Use `lifecycle { prevent_destroy = true }`, implement approval workflows, and require `-target` for deletions.

**Q72: How do you handle Terraform state for ephemeral environments?**
**A:** Use separate state files per environment with automatic cleanup via TTL tags and Lambda functions.

**Q73: How do you implement canary deployments with Terraform?**
**A:** Use weighted target groups in ALB, gradually shifting traffic percentages.

**Q74: How do you manage Terraform secrets in CI/CD?**
**A:** Use OIDC federation for AWS, GitHub Actions secrets, or HashiCorp Vault integration.

**Q75: How do you implement Terraform workload isolation?**
**A:** Separate AWS accounts per environment, use Organizations, and SCPs for guardrails.

**Q76: How do you handle Terraform provider rate limiting?**
**A:** Implement retry logic, reduce parallelism, use provider-level max_retries configuration.

**Q77: How do you perform Terraform state surgery?**
**A:** Use `terraform state mv` for refactoring, `terraform state rm` for removal, always backup first.

**Q78: How do you implement Terraform approval workflows?**
**A:** Use Atlantis with PR-based approvals, Terraform Cloud with policy checks, or custom CI/CD gates.

**Q79: How do you handle Terraform provider authentication in CI/CD?**
**A:** Use OIDC (GitHub Actions), IAM roles (EC2/ECS), or temporary credentials from Vault.

**Q80: How do you implement Terraform code reuse across organizations?**
**A:** Private module registry, Git submodules, or Terraform Cloud's private registry.

**Q81: How do you handle Terraform destroy protection in production?**
**A:** Require manual approval, use `-target` only, implement delete policies via Sentinel/OPA.

**Q82: How do you implement Terraform drift remediation automation?**
**A:** Schedule `terraform plan`, detect drift, open PR for manual review and apply.

**Q83: How do you handle Terraform circular module dependencies?**
**A:** Refactor module boundaries, use data sources, or split into multiple state files.

**Q84: How do you implement Terraform change freeze windows?**
**A:** CI/CD calendar checks, block applies during freeze via automation, use maintenance mode flags.

**Q85: How do you handle Terraform provider plugin crashes?**
**A:** Enable debug logging (`TF_LOG=DEBUG`), report to provider maintainers, use older stable version.

**Q86: How do you implement Terraform resource tagging standards?**
**A:** Use default_tags in provider config, modules enforce via variables, policy-as-code validation.

**Q87: How do you handle Terraform plan size limits in CI/CD?**
**A:** Split into multiple state files, use `-target` for incremental changes, increase CI timeout.

**Q88: How do you implement Terraform compliance scanning?**
**A:** Integrate tfsec, Checkov, Terrascan in CI/CD pipeline, fail on critical findings.

**Q89: How do you handle Terraform backend migrations without downtime?**
**A:** Use `terraform init -migrate-state`, maintain parallel backends temporarily, validate state integrity.

**Q90: How do you implement Terraform disaster recovery testing?**
**A:** Scheduled DR drills, deploy to DR region, test failover, validate RTO/RPO metrics.

**Q91: How do you handle Terraform provider version conflicts across modules?**
**A:** Pin versions strictly, use dependabot for updates, test modules independently.

**Q92: How do you implement Terraform resource naming conventions enforcement?**
**A:** Validation rules in variables, Sentinel policies, pre-commit hooks.

**Q93: How do you handle Terraform state locking failures?**
**A:** Investigate running processes, use `force-unlock` only when safe, implement monitoring.

**Q94: How do you implement Terraform testing in pipelines?**
**A:** Unit tests (Terratest), integration tests (deploy/destroy), policy tests (Sentinel/OPA).

**Q95: How do you handle Terraform resource import at scale?**
**A:** Automated import scripts, Terraformer tool, gradual migration per service.

**Q96: How do you implement Terraform cost allocation tagging?**
**A:** Required tags in modules, activate cost allocation tags in AWS, generate reports via Cost Explorer.

**Q97: How do you handle Terraform sensitive data in modules?**
**A:** Mark variables sensitive, use data sources for secrets, never output sensitive values.

**Q98: How do you implement Terraform infrastructure versioning?**
**A:** Git tags for configurations, semantic versioning for modules, maintain CHANGELOG.

**Q99: How do you handle Terraform provider deprecations?**
**A:** Monitor changelogs, plan migrations early, test in non-prod, communicate timeline to teams.

**Q100: How do you measure Terraform infrastructure quality?**
**A:** Code coverage (Terratest), policy compliance rate, drift detection frequency, apply success rate, MTTR for issues.

***

## Summary

This collection covers fundamental Terraform concepts through advanced architectural patterns commonly encountered in 2025 DevOps and Cloud Engineering interviews. Key focus areas include state management, security best practices, disaster recovery, multi-account strategies, policy enforcement, and real-world problem-solving scenarios. Mastering these questions demonstrates production-level Terraform expertise suitable for senior engineering roles.