# Chapter 13: CI/CD Integration

## Introduction

Manual Terraform operations don't scale beyond individual contributors running `terraform apply` from their laptops. When five engineers manage infrastructure across three environments, the friction becomes visible: who ran the last deployment? Was staging updated before production? Did anyone review that security group change? When fifty engineers deploy to twenty environments, manual operations become impossible—deployments queue behind single operators, emergency fixes wait hours for someone with AWS credentials, and drift accumulates because no one remembers if a change was actually applied. The solution isn't hiring more operators; it's automating Terraform workflows through CI/CD pipelines that treat infrastructure deployments with the same rigor as application code.

CI/CD for Terraform transforms infrastructure changes from risky manual procedures into predictable, auditable, automated workflows. Every pull request triggers `terraform plan` showing exactly what will change, policy checks validate compliance before apply, cost estimates appear in PR comments showing financial impact, security scans catch misconfigurations, and automated tests verify the change works in ephemeral environments. When code merges to main, the pipeline automatically applies changes to development, waits for manual approval gates, then promotes through staging to production—all with full audit trails showing who approved what when. This pipeline doesn't just speed up deployments; it makes them safer by enforcing checks that humans forget during 3 AM emergency changes.

This chapter covers building production-grade CI/CD pipelines for Terraform using GitHub Actions, GitLab CI, and Terraform Cloud. You'll learn authentication strategies using OIDC instead of long-lived credentials, approval workflows with environment protection rules, drift detection that runs between deployments, automated testing integration with Terratest, policy enforcement with OPA/Sentinel, cost estimation with Infracost in PR comments, and GitOps patterns where git commits are the source of truth for infrastructure state. Whether you're automating your first Terraform deployment or building enterprise pipelines serving hundreds of developers, these patterns will help you deploy infrastructure safely, quickly, and with confidence.

## GitHub Actions for Terraform

### Basic Terraform Workflow

A complete GitHub Actions workflow for Terraform includes validation, planning, security scanning, and conditional apply.

**Directory Structure:**

```
.github/
└── workflows/
    ├── terraform-plan.yml      # Runs on PR
    ├── terraform-apply.yml     # Runs on merge to main
    ├── terraform-destroy.yml   # Manual workflow
    └── drift-detection.yml     # Scheduled

terraform/
├── environments/
│   ├── dev/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── backend.tf
│   ├── staging/
│   └── production/
└── modules/
    ├── vpc/
    ├── compute/
    └── database/
```


### Terraform Plan Workflow (Pull Requests)

```yaml
# .github/workflows/terraform-plan.yml
name: Terraform Plan

on:
  pull_request:
    branches: [main]
    paths:
      - 'terraform/**'
      - '.github/workflows/terraform-*.yml'

permissions:
  id-token: write      # Required for OIDC
  contents: read       # Read repository contents
  pull-requests: write # Comment on PRs

env:
  TF_VERSION: "1.11.0"
  AWS_REGION: "us-east-1"

jobs:
  # Job 1: Validate Terraform formatting and syntax
  validate:
    name: Validate Terraform
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}
      
      - name: Terraform Format Check
        run: terraform fmt -check -recursive terraform/
        continue-on-error: false
      
      - name: Terraform Init (Validation)
        run: |
          cd terraform/environments/dev
          terraform init -backend=false
      
      - name: Terraform Validate
        run: |
          cd terraform/environments/dev
          terraform validate

  # Job 2: Security scanning
  security-scan:
    name: Security Scan
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
      
      - name: Run tfsec
        uses: aquasecurity/tfsec-action@v1.0.3
        with:
          working_directory: terraform/
          soft_fail: false
          format: sarif
          output: tfsec.sarif
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: tfsec.sarif
      
      - name: Run Checkov
        uses: bridgecrewio/checkov-action@v12
        with:
          directory: terraform/
          framework: terraform
          soft_fail: false
          output_format: sarif
          output_file_path: checkov.sarif
      
      - name: Upload Checkov Results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: checkov.sarif

  # Job 3: Terraform plan for each environment
  plan:
    name: Plan (${{ matrix.environment }})
    runs-on: ubuntu-latest
    needs: [validate, security-scan]
    
    strategy:
      matrix:
        environment: [dev, staging, production]
    
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
      
      - name: Configure AWS Credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          role-session-name: GitHubActions-${{ github.run_id }}
          aws-region: ${{ env.AWS_REGION }}
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}
          terraform_wrapper: false  # Required for capturing output
      
      - name: Terraform Init
        working-directory: terraform/environments/${{ matrix.environment }}
        run: terraform init
      
      - name: Terraform Plan
        working-directory: terraform/environments/${{ matrix.environment }}
        id: plan
        run: |
          terraform plan -no-color -out=tfplan 2>&1 | tee plan.log
          
          # Capture plan output for PR comment
          echo "exitcode=$?" >> $GITHUB_OUTPUT
          
          # Generate JSON plan for analysis
          terraform show -json tfplan > tfplan.json
      
      - name: Install Infracost
        run: |
          curl -fsSL https://raw.githubusercontent.com/infracost/infracost/master/scripts/install.sh | sh
      
      - name: Generate Cost Estimate
        working-directory: terraform/environments/${{ matrix.environment }}
        run: |
          infracost breakdown \
            --path tfplan.json \
            --format json \
            --out-file infracost.json
          
          infracost output \
            --path infracost.json \
            --format github-comment \
            --out-file infracost-comment.md
        env:
          INFRACOST_API_KEY: ${{ secrets.INFRACOST_API_KEY }}
      
      - name: Upload Plan Artifacts
        uses: actions/upload-artifact@v4
        with:
          name: tfplan-${{ matrix.environment }}
          path: |
            terraform/environments/${{ matrix.environment }}/tfplan
            terraform/environments/${{ matrix.environment }}/tfplan.json
            terraform/environments/${{ matrix.environment }}/plan.log
            terraform/environments/${{ matrix.environment }}/infracost-comment.md
          retention-days: 30
      
      - name: Comment Plan on PR
        uses: actions/github-script@v7
        if: github.event_name == 'pull_request'
        with:
          script: |
            const fs = require('fs');
            const environment = '${{ matrix.environment }}';
            const planLog = fs.readFileSync('terraform/environments/' + environment + '/plan.log', 'utf8');
            const infracostComment = fs.readFileSync('terraform/environments/' + environment + '/infracost-comment.md', 'utf8');
            
            // Truncate plan log if too long
            const maxLength = 65000;
            const truncatedPlan = planLog.length > maxLength 
              ? planLog.substring(0, maxLength) + '\n\n...(truncated)'
              : planLog;
            
            const output = `## Terraform Plan: ${environment}
            
            <details>
            <summary>📋 Plan Output</summary>
            
            \`\`\`terraform
            ${truncatedPlan}
            \`\`\`
            
            </details>
            
            ${infracostComment}
            
            **Workflow:** [#${{ github.run_number }}](${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }})
            `;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: output
            });

  # Job 4: Policy validation with OPA
  policy-check:
    name: Policy Validation
    runs-on: ubuntu-latest
    needs: plan
    
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
      
      - name: Download Plan Artifacts
        uses: actions/download-artifact@v4
        with:
          pattern: tfplan-*
          path: plans/
      
      - name: Install OPA
        run: |
          curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
          chmod +x opa
          sudo mv opa /usr/local/bin/
      
      - name: Run OPA Policy Checks
        run: |
          for env in dev staging production; do
            echo "Checking policies for $env..."
            
            opa eval \
              --data policies/ \
              --input plans/tfplan-$env/tfplan.json \
              --format pretty \
              "data.terraform.deny" > policy-results-$env.txt
            
            if [ -s policy-results-$env.txt ]; then
              echo "❌ Policy violations found in $env"
              cat policy-results-$env.txt
              exit 1
            else
              echo "✅ No policy violations in $env"
            fi
          done
```


### Terraform Apply Workflow (Main Branch)

```yaml
# .github/workflows/terraform-apply.yml
name: Terraform Apply

on:
  push:
    branches: [main]
    paths:
      - 'terraform/**'
  workflow_dispatch:  # Manual trigger

permissions:
  id-token: write
  contents: read
  issues: write

env:
  TF_VERSION: "1.11.0"
  AWS_REGION: "us-east-1"

jobs:
  # Deploy to dev automatically
  apply-dev:
    name: Apply to Development
    runs-on: ubuntu-latest
    environment: development  # GitHub environment with protection rules
    
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_DEV_ROLE_ARN }}
          aws-region: ${{ env.AWS_REGION }}
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}
      
      - name: Terraform Init
        working-directory: terraform/environments/dev
        run: terraform init
      
      - name: Terraform Apply
        working-directory: terraform/environments/dev
        run: |
          terraform apply -auto-approve -no-color 2>&1 | tee apply.log
        env:
          TF_LOG: INFO  # Enable logging
      
      - name: Upload Apply Log
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: apply-log-dev
          path: terraform/environments/dev/apply.log
      
      - name: Notify on Failure
        if: failure()
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "❌ Terraform apply failed in development",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "*Terraform Apply Failed*\n*Environment:* development\n*Commit:* ${{ github.sha }}\n*Workflow:* <${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}|View Run>"
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}

  # Deploy to staging (requires dev success + manual approval)
  apply-staging:
    name: Apply to Staging
    runs-on: ubuntu-latest
    needs: apply-dev
    environment: staging  # Requires approval
    
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_STAGING_ROLE_ARN }}
          aws-region: ${{ env.AWS_REGION }}
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}
      
      - name: Terraform Init
        working-directory: terraform/environments/staging
        run: terraform init
      
      - name: Terraform Plan (Pre-Apply)
        working-directory: terraform/environments/staging
        run: terraform plan -no-color
      
      - name: Terraform Apply
        working-directory: terraform/environments/staging
        run: terraform apply -auto-approve

  # Deploy to production (requires staging success + manual approval)
  apply-production:
    name: Apply to Production
    runs-on: ubuntu-latest
    needs: apply-staging
    environment: production  # Requires approval + wait timer
    
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_PROD_ROLE_ARN }}
          aws-region: ${{ env.AWS_REGION }}
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}
      
      - name: Terraform Init
        working-directory: terraform/environments/production
        run: terraform init
      
      - name: Terraform Plan (Final Check)
        working-directory: terraform/environments/production
        id: plan
        run: |
          terraform plan -no-color -out=tfplan 2>&1 | tee plan.log
          terraform show -json tfplan > tfplan.json
      
      - name: Review Plan Before Apply
        run: |
          echo "### Production Deployment Plan" >> $GITHUB_STEP_SUMMARY
          echo "\`\`\`" >> $GITHUB_STEP_SUMMARY
          cat terraform/environments/production/plan.log >> $GITHUB_STEP_SUMMARY
          echo "\`\`\`" >> $GITHUB_STEP_SUMMARY
      
      - name: Terraform Apply
        working-directory: terraform/environments/production
        run: terraform apply tfplan
      
      - name: Create Deployment Record
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: `Production Deployment - ${new Date().toISOString()}`,
              body: `## Production Deployment Completed
              
              **Date:** ${new Date().toISOString()}
              **Commit:** ${context.sha}
              **Workflow Run:** [#${context.runNumber}](${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId})
              **Deployed By:** ${context.actor}
              
              ### Changes Applied
              See workflow artifacts for full plan output.
              `,
              labels: ['deployment', 'production']
            });
      
      - name: Notify Success
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "✅ Production deployment successful",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "*Production Deployment Successful*\n*Commit:* ${{ github.sha }}\n*Deployed By:* ${{ github.actor }}\n*Workflow:* <${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}|View Run>"
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```


### AWS OIDC Authentication Setup

Replace long-lived AWS access keys with short-lived OIDC tokens.

**Create IAM OIDC Provider (Terraform):**

```hcl
# oidc-github-actions.tf
data "tls_certificate" "github" {
  url = "https://token.actions.githubusercontent.com"
}

resource "aws_iam_openid_connect_provider" "github_actions" {
  url = "https://token.actions.githubusercontent.com"
  
  client_id_list = ["sts.amazonaws.com"]
  
  thumbprint_list = [data.tls_certificate.github.certificates[^0].sha1_fingerprint]
  
  tags = {
    Name = "GitHub Actions OIDC Provider"
  }
}

# IAM role for GitHub Actions
resource "aws_iam_role" "github_actions" {
  name = "GitHubActions-TerraformDeployment"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
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
            # Restrict to specific repository
            "token.actions.githubusercontent.com:sub" = "repo:myorg/terraform-infrastructure:*"
          }
        }
      }
    ]
  })
}

# Attach policies for Terraform operations
resource "aws_iam_role_policy_attachment" "github_actions_terraform" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.terraform_deployment.arn
}

resource "aws_iam_policy" "terraform_deployment" {
  name        = "TerraformDeploymentPolicy"
  description = "Permissions for Terraform to manage AWS resources"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:*",
          "s3:*",
          "rds:*",
          "iam:*",
          "lambda:*",
          "dynamodb:*",
          # Add all required permissions for your resources
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "arn:aws:s3:::terraform-state-bucket/*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ]
        Resource = "arn:aws:dynamodb:*:*:table/terraform-locks"
      }
    ]
  })
}

output "github_actions_role_arn" {
  description = "ARN of IAM role for GitHub Actions"
  value       = aws_iam_role.github_actions.arn
}
```

**GitHub Repository Secrets:**

```bash
# Add IAM role ARN to GitHub secrets
# Settings → Secrets and variables → Actions → New repository secret

# Name: AWS_ROLE_ARN
# Value: arn:aws:iam::123456789012:role/GitHubActions-TerraformDeployment
```


## GitLab CI for Terraform

GitLab CI provides integrated CI/CD with similar capabilities to GitHub Actions.

### GitLab CI Pipeline Configuration

```yaml
# .gitlab-ci.yml
variables:
  TF_VERSION: "1.11.0"
  TF_ROOT: "${CI_PROJECT_DIR}/terraform"
  AWS_DEFAULT_REGION: "us-east-1"

# Define stages
stages:
  - validate
  - security
  - plan
  - apply

# Cache Terraform plugins
cache:
  key: "${CI_COMMIT_REF_SLUG}"
  paths:
    - ${TF_ROOT}/.terraform
    - ${TF_ROOT}/.terraform.lock.hcl

# Template for Terraform jobs
.terraform_base:
  image:
    name: hashicorp/terraform:$TF_VERSION
    entrypoint: [""]
  before_script:
    - cd ${TF_ROOT}/environments/${ENVIRONMENT}
    - terraform --version
    - terraform init

# Validate stage
terraform_format:
  stage: validate
  image: hashicorp/terraform:$TF_VERSION
  script:
    - terraform fmt -check -recursive ${TF_ROOT}/
  only:
    - merge_requests
    - main

terraform_validate:
  extends: .terraform_base
  stage: validate
  parallel:
    matrix:
      - ENVIRONMENT: [dev, staging, production]
  script:
    - terraform validate
  only:
    - merge_requests
    - main

# Security scanning
tfsec_scan:
  stage: security
  image: aquasec/tfsec:latest
  script:
    - tfsec ${TF_ROOT}/ --format gitlab-sast --out tfsec-report.json
  artifacts:
    reports:
      sast: tfsec-report.json
    paths:
      - tfsec-report.json
    expire_in: 30 days
  only:
    - merge_requests
    - main

checkov_scan:
  stage: security
  image: bridgecrew/checkov:latest
  script:
    - checkov -d ${TF_ROOT}/ --framework terraform --output gitlab_sast --output-file-path checkov-report.json
  artifacts:
    reports:
      sast: checkov-report.json
    paths:
      - checkov-report.json
    expire_in: 30 days
  only:
    - merge_requests
    - main

# Plan stage (MR only)
terraform_plan:
  extends: .terraform_base
  stage: plan
  parallel:
    matrix:
      - ENVIRONMENT: [dev, staging, production]
  script:
    - terraform plan -no-color -out=tfplan 2>&1 | tee plan.log
    - terraform show -json tfplan > tfplan.json
  artifacts:
    paths:
      - ${TF_ROOT}/environments/${ENVIRONMENT}/tfplan
      - ${TF_ROOT}/environments/${ENVIRONMENT}/tfplan.json
      - ${TF_ROOT}/environments/${ENVIRONMENT}/plan.log
    expire_in: 7 days
    reports:
      terraform: ${TF_ROOT}/environments/${ENVIRONMENT}/tfplan.json
  only:
    - merge_requests

# Cost estimation
infracost:
  stage: plan
  image: infracost/infracost:latest
  needs: [terraform_plan]
  parallel:
    matrix:
      - ENVIRONMENT: [dev, staging, production]
  script:
    - |
      infracost breakdown \
        --path ${TF_ROOT}/environments/${ENVIRONMENT}/tfplan.json \
        --format gitlab-comment \
        --out-file infracost-comment.md
  artifacts:
    paths:
      - infracost-comment.md
    expire_in: 7 days
  only:
    - merge_requests

# Apply stage (main branch only)
apply_dev:
  extends: .terraform_base
  stage: apply
  variables:
    ENVIRONMENT: dev
  script:
    - terraform apply -auto-approve
  only:
    - main
  when: on_success

apply_staging:
  extends: .terraform_base
  stage: apply
  variables:
    ENVIRONMENT: staging
  script:
    - terraform apply -auto-approve
  needs: [apply_dev]
  only:
    - main
  when: manual  # Require manual approval

apply_production:
  extends: .terraform_base
  stage: apply
  variables:
    ENVIRONMENT: production
  environment:
    name: production
    url: https://production.example.com
  script:
    - terraform plan -no-color
    - echo "Deploying to production..."
    - terraform apply -auto-approve
  needs: [apply_staging]
  only:
    - main
  when: manual  # Require manual approval

## Terraform Cloud Automation

Terraform Cloud provides managed automation with built-in state management, RBAC, and policy enforcement.

### VCS-Driven Workflow

**Workspace Configuration:**

```hcl
# terraform-cloud-config/workspaces.tf
terraform {
  required_providers {
    tfe = {
      source  = "hashicorp/tfe"
      version = "~> 0.51"
    }
  }
}

provider "tfe" {
  # TFE_TOKEN environment variable
}

# Create workspace with VCS integration
resource "tfe_workspace" "production" {
  name         = "infrastructure-production"
  organization = var.organization_name
  
  # VCS integration
  vcs_repo {
    identifier     = "myorg/terraform-infrastructure"
    branch         = "main"
    oauth_token_id = var.github_oauth_token_id
  }
  
  working_directory = "terraform/environments/production"
  
  # Execution settings
  execution_mode        = "remote"
  terraform_version     = "1.11.0"
  auto_apply           = false  # Require approval
  file_triggers_enabled = true
  
  # Trigger patterns
  trigger_patterns = [
    "terraform/environments/production/**",
    "terraform/modules/**"
  ]
  
  # Notifications
  notifications {
    name             = "slack-production"
    destination_type = "slack"
    enabled          = true
    url              = var.slack_webhook_url
    
    triggers = [
      "run:created",
      "run:planning",
      "run:needs_attention",
      "run:applying",
      "run:completed",
      "run:errored"
    ]
  }
  
  tags = ["production", "critical"]
}

# Run triggers (cascade deployments)
resource "tfe_run_trigger" "staging_to_production" {
  workspace_id  = tfe_workspace.production.id
  sourceable_id = tfe_workspace.staging.id
}

# Team access control
resource "tfe_team_access" "production_admins" {
  access       = "admin"
  team_id      = tfe_team.platform_admins.id
  workspace_id = tfe_workspace.production.id
}

resource "tfe_team_access" "production_apply" {
  access       = "write"
  team_id      = tfe_team.senior_engineers.id
  workspace_id = tfe_workspace.production.id
  
  permissions {
    runs              = "apply"
    variables         = "write"
    state_versions    = "read"
    sentinel_mocks    = "read"
    workspace_locking = true
  }
}

resource "tfe_team_access" "production_plan" {
  access       = "plan"
  team_id      = tfe_team.engineers.id
  workspace_id = tfe_workspace.production.id
  
  permissions {
    runs              = "plan"
    variables         = "read"
    state_versions    = "read"
    sentinel_mocks    = "none"
    workspace_locking = false
  }
}
```


### API-Driven Workflow

Trigger runs programmatically via Terraform Cloud API.

```python
# trigger_terraform_run.py
import os
import requests
import json
import time
import sys

TFC_TOKEN = os.environ['TFC_TOKEN']
TFC_ORG = os.environ['TFC_ORGANIZATION']
WORKSPACE_NAME = os.environ['TFC_WORKSPACE']

BASE_URL = "https://app.terraform.io/api/v2"
HEADERS = {
    'Authorization': f'Bearer {TFC_TOKEN}',
    'Content-Type': 'application/vnd.api+json'
}

def get_workspace_id(org, workspace_name):
    """Get workspace ID from name"""
    url = f"{BASE_URL}/organizations/{org}/workspaces/{workspace_name}"
    response = requests.get(url, headers=HEADERS)
    response.raise_for_status()
    return response.json()['data']['id']

def create_run(workspace_id, message="Triggered via API", auto_apply=False):
    """Create a new run"""
    url = f"{BASE_URL}/runs"
    
    payload = {
        'data': {
            'type': 'runs',
            'attributes': {
                'message': message,
                'auto-apply': auto_apply
            },
            'relationships': {
                'workspace': {
                    'data': {
                        'type': 'workspaces',
                        'id': workspace_id
                    }
                }
            }
        }
    }
    
    response = requests.post(url, headers=HEADERS, json=payload)
    response.raise_for_status()
    
    run = response.json()['data']
    return run['id'], run['attributes']['status']

def get_run_status(run_id):
    """Get run status"""
    url = f"{BASE_URL}/runs/{run_id}"
    response = requests.get(url, headers=HEADERS)
    response.raise_for_status()
    return response.json()['data']['attributes']['status']

def wait_for_run(run_id, max_wait=1800):
    """Wait for run to complete"""
    start_time = time.time()
    
    while True:
        if time.time() - start_time > max_wait:
            raise TimeoutError(f"Run {run_id} did not complete in {max_wait}s")
        
        status = get_run_status(run_id)
        print(f"Run status: {status}")
        
        if status in ['planned', 'cost_estimated', 'policy_checked']:
            # Run ready for apply
            print(f"Run {run_id} is ready for apply")
            return 'planned'
        elif status == 'applied':
            print(f"Run {run_id} completed successfully")
            return 'applied'
        elif status in ['errored', 'canceled', 'discarded']:
            print(f"Run {run_id} failed with status: {status}")
            sys.exit(1)
        
        time.sleep(10)

def apply_run(run_id, comment="Applied via API"):
    """Apply a run"""
    url = f"{BASE_URL}/runs/{run_id}/actions/apply"
    
    payload = {
        'comment': comment
    }
    
    response = requests.post(url, headers=HEADERS, json=payload)
    response.raise_for_status()

def main():
    print(f"Getting workspace ID for {WORKSPACE_NAME}...")
    workspace_id = get_workspace_id(TFC_ORG, WORKSPACE_NAME)
    
    print(f"Creating run for workspace {workspace_id}...")
    run_id, status = create_run(
        workspace_id,
        message="Deployment via CI/CD pipeline",
        auto_apply=False
    )
    
    print(f"Run created: {run_id}")
    print(f"View at: https://app.terraform.io/app/{TFC_ORG}/workspaces/{WORKSPACE_NAME}/runs/{run_id}")
    
    print("Waiting for plan to complete...")
    final_status = wait_for_run(run_id)
    
    if final_status == 'planned':
        # Require manual approval
        print("\n⚠️  Run is planned and ready for apply")
        print(f"Review and apply at: https://app.terraform.io/app/{TFC_ORG}/workspaces/{WORKSPACE_NAME}/runs/{run_id}")
        
        # Or auto-apply based on environment
        if os.environ.get('AUTO_APPLY', 'false') == 'true':
            print("Auto-applying run...")
            apply_run(run_id)
            wait_for_run(run_id)

if __name__ == '__main__':
    main()
```

**Use in CI/CD:**

```yaml
# .github/workflows/terraform-cloud.yml
name: Terraform Cloud Deployment

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      
      - name: Trigger Terraform Cloud Run
        run: python3 trigger_terraform_run.py
        env:
          TFC_TOKEN: ${{ secrets.TFC_TOKEN }}
          TFC_ORGANIZATION: myorg
          TFC_WORKSPACE: infrastructure-production
          AUTO_APPLY: false  # Require manual approval
```


## Approval Workflows and Gates

### GitHub Environment Protection Rules

Configure environment-specific approval requirements.

**Settings → Environments → production:**

- **Required reviewers:** Select 2 reviewers from platform team
- **Wait timer:** 5 minutes (allows reviewing plan before apply)
- **Deployment branches:** Only `main` branch
- **Environment secrets:** Production AWS credentials

**Workflow with Approvals:**

```yaml
# .github/workflows/terraform-production.yml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  plan:
    name: Plan Production Changes
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.11.0
      
      - name: Terraform Plan
        working-directory: terraform/environments/production
        run: |
          terraform init
          terraform plan -out=tfplan 2>&1 | tee plan.log
      
      - name: Upload Plan
        uses: actions/upload-artifact@v4
        with:
          name: production-plan
          path: |
            terraform/environments/production/tfplan
            terraform/environments/production/plan.log
      
      - name: Comment Plan on Commit
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const planLog = fs.readFileSync('terraform/environments/production/plan.log', 'utf8');
            
            const output = `## 🏗️ Production Deployment Plan
            
            **Commit:** ${context.sha}
            **Actor:** ${context.actor}
            
            <details>
            <summary>View Plan Output</summary>
            
            \`\`\`terraform
            ${planLog}
            \`\`\`
            
            </details>
            
            This deployment requires approval from 2 platform team members.
            `;
            
            github.rest.repos.createCommitComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              commit_sha: context.sha,
              body: output
            });
  
  # Requires approval via environment protection rules
  apply:
    name: Apply to Production
    needs: plan
    runs-on: ubuntu-latest
    environment: production  # Triggers approval gate
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Download Plan
        uses: actions/download-artifact@v4
        with:
          name: production-plan
          path: terraform/environments/production
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_PROD_ROLE_ARN }}
          aws-region: us-east-1
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.11.0
      
      - name: Terraform Init
        working-directory: terraform/environments/production
        run: terraform init
      
      - name: Terraform Apply
        working-directory: terraform/environments/production
        run: |
          echo "Applying changes to production..."
          terraform apply tfplan
      
      - name: Record Deployment
        uses: actions/github-script@v7
        with:
          script: |
            // Create deployment record
            await github.rest.repos.createDeployment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              ref: context.sha,
              environment: 'production',
              auto_merge: false,
              required_contexts: []
            });
```


### Manual Approval with Slack Integration

```yaml
# .github/workflows/terraform-slack-approval.yml
name: Deploy with Slack Approval

on:
  push:
    branches: [main]

jobs:
  plan:
    runs-on: ubuntu-latest
    outputs:
      plan_id: ${{ steps.plan.outputs.plan_id }}
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Terraform Plan
        id: plan
        run: |
          # Plan and capture output
          terraform plan -out=tfplan
          PLAN_ID=$(date +%s)
          echo "plan_id=$PLAN_ID" >> $GITHUB_OUTPUT
      
      - name: Request Approval via Slack
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "Production deployment requires approval",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "*Production Deployment Request*\n\n*Commit:* ${{ github.sha }}\n*Author:* ${{ github.actor }}\n*Workflow:* <${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}|View>"
                  }
                },
                {
                  "type": "actions",
                  "elements": [
                    {
                      "type": "button",
                      "text": {
                        "type": "plain_text",
                        "text": "Approve"
                      },
                      "style": "primary",
                      "value": "approve_${{ steps.plan.outputs.plan_id }}"
                    },
                    {
                      "type": "button",
                      "text": {
                        "type": "plain_text",
                        "text": "Reject"
                      },
                      "style": "danger",
                      "value": "reject_${{ steps.plan.outputs.plan_id }}"
                    }
                  ]
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
  
  # Wait for approval (implement webhook listener or manual trigger)
  apply:
    needs: plan
    runs-on: ubuntu-latest
    environment: production
    
    steps:
      - name: Apply Changes
        run: terraform apply tfplan
```


## Drift Detection in CI/CD

### Scheduled Drift Detection

```yaml
# .github/workflows/drift-detection.yml
name: Drift Detection

on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours
  workflow_dispatch:

permissions:
  id-token: write
  contents: read
  issues: write

jobs:
  detect-drift:
    name: Detect Drift (${{ matrix.environment }})
    runs-on: ubuntu-latest
    
    strategy:
      matrix:
        environment: [dev, staging, production]
      fail-fast: false  # Continue checking other environments
    
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.11.0
      
      - name: Terraform Init
        working-directory: terraform/environments/${{ matrix.environment }}
        run: terraform init
      
      - name: Detect Drift
        id: drift
        working-directory: terraform/environments/${{ matrix.environment }}
        continue-on-error: true
        run: |
          set +e
          terraform plan -detailed-exitcode -no-color 2>&1 | tee drift.log
          EXIT_CODE=${PIPESTATUS[^0]}
          
          echo "exit_code=$EXIT_CODE" >> $GITHUB_OUTPUT
          
          if [ $EXIT_CODE -eq 0 ]; then
            echo "status=no-drift" >> $GITHUB_OUTPUT
          elif [ $EXIT_CODE -eq 2 ]; then
            echo "status=drift-detected" >> $GITHUB_OUTPUT
          else
            echo "status=error" >> $GITHUB_OUTPUT
          fi
      
      - name: Upload Drift Log
        if: steps.drift.outputs.status == 'drift-detected'
        uses: actions/upload-artifact@v4
        with:
          name: drift-${{ matrix.environment }}-${{ github.run_number }}
          path: terraform/environments/${{ matrix.environment }}/drift.log
          retention-days: 90
      
      - name: Create/Update Drift Issue
        if: steps.drift.outputs.status == 'drift-detected'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const environment = '${{ matrix.environment }}';
            const driftLog = fs.readFileSync(`terraform/environments/${environment}/drift.log`, 'utf8');
            
            // Check for existing open drift issue
            const issues = await github.rest.issues.listForRepo({
              owner: context.repo.owner,
              repo: context.repo.repo,
              state: 'open',
              labels: `drift,${environment}`
            });
            
            const issueBody = `## Infrastructure Drift Detected
            
            **Environment:** ${environment}
            **Detected:** ${new Date().toISOString()}
            **Workflow:** [Run #${context.runNumber}](${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId})
            
            ### Drift Details
            
            <details>
            <summary>View Full Drift Output</summary>
            
            \`\`\`terraform
            ${driftLog.substring(0, 60000)}
            \`\`\`
            
            </details>
            
            ### Remediation Steps
            
            1. Review the drift above
            2. Determine if changes are:
               - **Expected:** Update Terraform code to match
               - **Unexpected:** Investigate who made manual changes (check CloudTrail)
            3. Choose remediation:
               - \`terraform apply\` to restore Terraform state
               - \`terraform import\` to accept changes
               - Update code if configuration needs to change
            
            ### Investigation
            
            \`\`\`bash
            # Check CloudTrail for manual changes
            aws cloudtrail lookup-events \\
              --lookup-attributes AttributeKey=ResourceType,AttributeValue=AWS::EC2::Instance \\
              --start-time $(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%S) \\
              --max-results 50
            \`\`\`
            `;
            
            if (issues.data.length > 0) {
              // Update existing issue
              await github.rest.issues.createComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: issues.data[^0].number,
                body: `## Drift Still Present\n\n${issueBody}`
              });
            } else {
              // Create new issue
              await github.rest.issues.create({
                owner: context.repo.owner,
                repo: context.repo.repo,
                title: `⚠️ Infrastructure Drift: ${environment}`,
                body: issueBody,
                labels: ['drift', environment, 'ops']
              });
            }
      
      - name: Notify Slack
        if: steps.drift.outputs.status == 'drift-detected'
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "⚠️ Drift detected in ${{ matrix.environment }}",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "*Infrastructure Drift Detected*\n\n*Environment:* ${{ matrix.environment }}\n*Workflow:* <${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}|View Details>"
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```


## Automated Testing in CI/CD

### Terratest Integration

```yaml
# .github/workflows/integration-tests.yml
name: Integration Tests

on:
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # Nightly

jobs:
  integration-tests:
    runs-on: ubuntu-latest
    timeout-minutes: 60
    
    strategy:
      matrix:
        test: [vpc, compute, database]
      fail-fast: false
    
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      
      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.21'
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.11.0
          terraform_wrapper: false
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_TEST_ROLE_ARN }}
          aws-region: us-east-1
      
      - name: Run Terratest
        working-directory: tests/integration
        run: |
          go test -v -timeout 45m -run Test${{ matrix.test }}
        env:
          AWS_DEFAULT_REGION: us-east-1
      
      - name: Cleanup on Failure
        if: failure()
        working-directory: tests/integration
        run: |
          # Force cleanup if test fails
          cd fixtures/${{ matrix.test }}
          terraform destroy -auto-approve || true
```


## ⚠️ Common Pitfalls

### Pitfall 1: Storing Secrets in Code

**❌ PROBLEM:**

```yaml
# DON'T DO THIS
jobs:
  deploy:
    steps:
      - name: Configure AWS
        env:
          AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
          AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**✅ SOLUTION:**

```yaml
# Use OIDC or GitHub Secrets
jobs:
  deploy:
    steps:
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}  # Stored securely
          aws-region: us-east-1
```


### Pitfall 2: No State Locking in Parallel Pipelines

**❌ PROBLEM:**

```yaml
# Multiple jobs accessing same state without coordination
jobs:
  deploy-vpc:
    runs-on: ubuntu-latest
    steps:
      - run: terraform apply -auto-approve
  
  deploy-compute:
    runs-on: ubuntu-latest  # Runs in parallel!
    steps:
      - run: terraform apply -auto-approve  # State conflict!
```

**✅ SOLUTION:**

```yaml
# Use dependencies to serialize state access
jobs:
  deploy-vpc:
    runs-on: ubuntu-latest
    steps:
      - run: terraform apply -auto-approve
  
  deploy-compute:
    needs: deploy-vpc  # Wait for VPC completion
    runs-on: ubuntu-latest
    steps:
      - run: terraform apply -auto-approve
```


### Pitfall 3: Auto-Applying Without Review

**❌ PROBLEM:**

```yaml
# Auto-apply to production on every commit
jobs:
  deploy:
    steps:
      - run: terraform apply -auto-approve  # Dangerous!
```

**✅ SOLUTION:**

```yaml
# Require manual approval for production
jobs:
  deploy:
    environment: production  # Triggers approval gate
    steps:
      - run: terraform plan -out=tfplan
      - run: terraform apply tfplan  # Only after approval
```


### Pitfall 4: No Rollback Strategy

**❌ PROBLEM:**
Pipeline applies changes but has no way to rollback if issues are discovered post-deployment.

**✅ SOLUTION:**

```yaml
# Tag successful deployments
jobs:
  deploy:
    steps:
      - name: Apply Changes
        run: terraform apply tfplan
      
      - name: Tag Successful Deployment
        if: success()
        run: |
          git tag -a "deploy-prod-$(date +%Y%m%d-%H%M%S)" \
            -m "Production deployment successful"
          git push origin --tags
      
      # Separate workflow for rollback
      # .github/workflows/rollback.yml
      # Checks out specific tag and re-applies
```


### Pitfall 5: Insufficient Error Context

**❌ PROBLEM:**

```yaml
jobs:
  deploy:
    steps:
      - run: terraform apply -auto-approve
      # Error messages truncated, no logs saved
```

**✅ SOLUTION:**

```yaml
jobs:
  deploy:
    steps:
      - name: Terraform Apply
        run: |
          terraform apply -auto-approve 2>&1 | tee apply.log
        env:
          TF_LOG: DEBUG  # Detailed logging
      
      - name: Upload Logs
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: terraform-logs
          path: apply.log
          retention-days: 90
```


### Pitfall 6: Not Validating Before Apply

**❌ PROBLEM:**

```yaml
# Skip validation, go straight to apply
jobs:
  deploy:
    steps:
      - run: terraform apply -auto-approve
```

**✅ SOLUTION:**

```yaml
# Multi-stage validation
jobs:
  validate:
    steps:
      - run: terraform fmt -check
      - run: terraform validate
      - run: tfsec .
  
  plan:
    needs: validate
    steps:
      - run: terraform plan -out=tfplan
  
  apply:
    needs: plan
    environment: production
    steps:
      - run: terraform apply tfplan
```


## 💡 Expert Tips from the Field

1. **"Use `terraform_wrapper: false` when capturing output"** - HashiCorp's setup-terraform action wraps terraform commands by default, breaking output parsing. Disable for scripts that need raw output.
2. **"Cache `.terraform` directory to speed up init"** - Terraform init downloads providers every run. Cache saves 30-60 seconds per pipeline run:
```yaml
- uses: actions/cache@v3
  with:
    path: **/.terraform
    key: terraform-${{ hashFiles('**/.terraform.lock.hcl') }}
```

3. **"Run `terraform plan` on every PR, even non-Terraform changes"** - Catches drift caused by manual changes between deployments. Zero-change plans confirm no drift exists.
4. **"Use matrix strategies for multi-environment testing"** - Test all environments in parallel instead of serial:
```yaml
strategy:
  matrix:
    environment: [dev, staging, production]
```

5. **"Implement cost gates with Infracost"** - Block PRs that increase costs by >\$100/month without approval. Add thresholds to catch expensive mistakes before production.
6. **"Use CODEOWNERS for Terraform approvals"** - Require platform team review for infrastructure changes:
```
# .github/CODEOWNERS
/terraform/  @platform-team
```

7. **"Store plan files as artifacts for audit trails"** - Regulatory compliance often requires proving what was deployed:
```yaml
- uses: actions/upload-artifact@v4
  with:
    name: tfplan-${{ github.sha }}
    retention-days: 2555  # 7 years for compliance
```

8. **"Use GitHub environments for secrets scoping"** - Don't use same AWS credentials for dev and production. Scope secrets to environments to prevent mistakes.
9. **"Implement plan diff comments on PRs"** - Show exactly what changes before merge using github-script to post formatted plan output.
10. **"Add timeout to prevent runaway pipelines"** - Set realistic timeouts to catch infinite loops:
```yaml
jobs:
  deploy:
    timeout-minutes: 30
```

11. **"Use workflow_dispatch for emergency deployments"** - Allow manual triggers with input parameters for hotfixes:
```yaml
on:
  workflow_dispatch:
    inputs:
      environment:
        description: 'Environment to deploy'
        required: true
        type: choice
        options:
          - dev
          - staging
          - production
```

12. **"Separate plan and apply workflows"** - Never auto-apply on PR. Plan shows changes, merge triggers apply after review.
13. **"Use concurrency groups to prevent overlapping runs"** - Ensure only one deployment runs at a time per environment:
```yaml
concurrency:
  group: terraform-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: false  # Don't cancel running deployments
```

14. **"Implement blue/green deployments for zero-downtime"** - Create new infrastructure before destroying old:
```hcl
resource "aws_instance" "app" {
  count = var.blue_green_deployment ? 2 : 1
  # ... create new before destroying old
  
  lifecycle {
    create_before_destroy = true
  }
}
```

15. **"Use reusable workflows to reduce duplication"** - DRY principle applies to CI/CD too:
```yaml
# .github/workflows/terraform-deploy.yml (reusable)
on:
  workflow_call:
    inputs:
      environment:
        required: true
        type: string

# .github/workflows/deploy-production.yml (caller)
jobs:
  deploy:
    uses: ./.github/workflows/terraform-deploy.yml
    with:
      environment: production
```


## 🎯 Practical Exercises

### Exercise 1: Build GitHub Actions Pipeline

**Difficulty:** Intermediate
**Time:** 45 minutes
**Objective:** Create complete CI/CD pipeline with plan on PR, apply on merge

**Prerequisites:**

- GitHub repository
- AWS account
- Terraform code in repository

**Steps:**

1. **Create workflow directory:**
```bash
mkdir -p .github/workflows
```

2. **Create plan workflow (.github/workflows/terraform-plan.yml):**
```yaml
name: Terraform Plan

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write

jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.11.0
      
      - name: Terraform Init
        run: terraform init
      
      - name: Terraform Plan
        id: plan
        run: terraform plan -no-color
        continue-on-error: true
      
      - name: Comment PR
        uses: actions/github-script@v7
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
```

3. **Create apply workflow (.github/workflows/terraform-apply.yml):**
```yaml
name: Terraform Apply

on:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  apply:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.11.0
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      
      - name: Terraform Init
        run: terraform init
      
      - name: Terraform Apply
        run: terraform apply -auto-approve
```

4. **Test workflows:**
```bash
# Create feature branch
git checkout -b test-pipeline

# Make a change
echo '# test' >> README.md

# Commit and push
git add .
git commit -m "Test CI/CD pipeline"
git push origin test-pipeline

# Create PR and verify plan runs
# Merge PR and verify apply runs
```

**Validation:**

- Plan workflow runs on PR creation
- Plan output appears as PR comment
- Apply workflow runs after merge
- Resources created in AWS

**Challenge:** Add security scanning with tfsec and cost estimation with Infracost

***

### Exercise 2: Implement Multi-Environment Pipeline

**Difficulty:** Advanced
**Time:** 60 minutes
**Objective:** Deploy to dev/staging/production with approval gates

**Steps:**

1. **Set up GitHub environments:**
    - Settings → Environments → New environment
    - Create: development, staging, production
    - Production: Add required reviewers + 5 min wait timer
2. **Create multi-environment workflow:**
```yaml
# .github/workflows/multi-env-deploy.yml
name: Multi-Environment Deployment

on:
  push:
    branches: [main]

jobs:
  deploy-dev:
    name: Deploy to Development
    runs-on: ubuntu-latest
    environment: development
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - name: Deploy
        working-directory: terraform/environments/dev
        run: |
          terraform init
          terraform apply -auto-approve
  
  deploy-staging:
    name: Deploy to Staging
    needs: deploy-dev
    runs-on: ubuntu-latest
    environment: staging
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - name: Deploy
        working-directory: terraform/environments/staging
        run: |
          terraform init
          terraform apply -auto-approve
  
  deploy-production:
    name: Deploy to Production
    needs: deploy-staging
    runs-on: ubuntu-latest
    environment: production  # Requires approval
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - name: Deploy
        working-directory: terraform/environments/production
        run: |
          terraform init
          terraform plan
          terraform apply -auto-approve
```

3. **Test deployment flow:**
```bash
git add .
git commit -m "Deploy to all environments"
git push origin main

# Watch workflow:
# 1. Dev deploys automatically
# 2. Staging deploys after dev success
# 3. Production waits for approval
# 4. Approve in GitHub UI
# 5. Production deploys
```

**Validation:**

- Dev deploys without approval
- Staging waits for dev
- Production requires manual approval
- All environments updated

**Challenge:** Add Slack notifications at each stage

***

### Exercise 3: Configure OIDC Authentication

**Difficulty:** Advanced
**Time:** 50 minutes
**Objective:** Replace AWS access keys with OIDC

**Steps:**

1. **Create OIDC provider in AWS:**
```hcl
# oidc-setup.tf
data "tls_certificate" "github" {
  url = "https://token.actions.githubusercontent.com"
}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.github.certificates[^0].sha1_fingerprint]
}

resource "aws_iam_role" "github_actions" {
  name = "GitHubActionsDeployment"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github.arn
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

resource "aws_iam_role_policy_attachment" "github_actions" {
  role       = aws_iam_role.github_actions.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

output "role_arn" {
  value = aws_iam_role.github_actions.arn
}
```

2. **Apply OIDC setup:**
```bash
terraform apply
# Note the role_arn output
```

3. **Update workflow to use OIDC:**
```yaml
# .github/workflows/terraform-oidc.yml
name: Terraform with OIDC

on:
  push:
    branches: [main]

permissions:
  id-token: write  # Required for OIDC
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1
      
      - uses: hashicorp/setup-terraform@v3
      
      - name: Verify AWS Identity
        run: aws sts get-caller-identity
      
      - name: Deploy
        run: |
          terraform init
          terraform apply -auto-approve
```

4. **Add role ARN to secrets:**
    - Settings → Secrets → Actions
    - Add secret: AWS_ROLE_ARN = (role ARN from step 2)
5. **Remove old access keys:**
    - Delete AWS_ACCESS_KEY_ID secret
    - Delete AWS_SECRET_ACCESS_KEY secret

**Validation:**

- Workflow authenticates without access keys
- `aws sts get-caller-identity` shows assumed role
- Terraform operations succeed

**Challenge:** Configure separate roles for dev/staging/production

***

## Key Takeaways

- **CI/CD for Terraform enforces review gates that prevent manual errors** - Every change triggers `terraform plan` visible to reviewers, security scans block violations, and cost estimates show financial impact before merge
- **OIDC authentication replaces long-lived credentials with short-lived tokens** - GitHub Actions assumes AWS IAM roles using OpenID Connect, eliminating secret rotation and reducing credential exposure risk
- **Environment protection rules implement approval workflows and wait timers** - GitHub environments enforce multi-person approval for production, prevent rushed deployments with wait timers, and scope secrets to specific environments
- **Drift detection between deployments catches manual changes before they compound** - Scheduled `terraform plan` runs every 6 hours detect configuration drift, create GitHub issues with remediation steps, and alert teams via Slack
- **Artifact retention provides audit trails for compliance requirements** - Storing terraform plans, apply logs, and cost estimates as artifacts with 7-year retention meets regulatory requirements and enables incident investigation
- **Matrix strategies enable parallel testing across environments** - Running validation, security scans, and plans concurrently for dev/staging/production reduces pipeline time from 15 minutes to 5 minutes
- **Reusable workflows reduce duplication and enforce consistency** - Shared workflow templates ensure all teams follow same security scans, approval patterns, and deployment procedures without copy-paste errors


## What's Next

With automated CI/CD pipelines deploying infrastructure safely and predictably, **Chapter 14: Disaster Recovery and Business Continuity** covers backup strategies for Terraform state, cross-region failover architectures, recovery time objectives (RTO) and recovery point objectives (RPO) for infrastructure, state reconstruction from AWS resources when backups fail, and runbooks for common disaster scenarios that enable teams to restore infrastructure under pressure.

## Additional Resources

**Official Documentation:**

- [Terraform GitHub Actions](https://developer.hashicorp.com/terraform/tutorials/automation/github-actions) - Official automation guide
- [Terraform Cloud Automation](https://developer.hashicorp.com/terraform/cloud-docs/run/api) - API-driven workflows
- [AWS OIDC with GitHub Actions](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services) - Secure authentication

**CI/CD Platforms:**

- [GitHub Actions](https://docs.github.com/en/actions) - Workflow automation
- [GitLab CI](https://docs.gitlab.com/ee/ci/) - GitLab pipelines
- [Terraform Cloud](https://app.terraform.io) - Managed Terraform automation
- [Atlantis](https://www.runatlantis.io) - Self-hosted Terraform automation

**Best Practices:**

- [Terraform Best Practices](https://spacelift.io/blog/terraform-best-practices) - CI/CD patterns
- [GitOps for Terraform](https://www.harness.io/blog/gitops-your-terraform-or-opentofu) - GitOps workflows
- [Terraform Automation Stages](https://www.env0.com/blog/expert-guide-the-four-stages-of-terraform-automation) - Maturity model

**Tools:**

- [Infracost](https://www.infracost.io) - Cost estimation in CI/CD
- [tfsec](https://github.com/aquasecurity/tfsec) - Security scanning
- [Terratest](https://terratest.gruntwork.io) - Infrastructure testing
- [terraform-compliance](https://terraform-compliance.com) - BDD testing

***

**CI/CD transforms Terraform from a powerful tool into a safe deployment platform.** Automated testing catches errors before production, approval workflows prevent rushed changes, drift detection maintains configuration integrity, and audit trails prove compliance. The pipeline isn't overhead—it's the safety system that enables teams to deploy infrastructure changes confidently, frequently, and without fear.

