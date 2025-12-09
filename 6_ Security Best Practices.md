# Chapter 6: Security Best Practices

## Introduction

Security in Terraform isn't an afterthought—it's a fundamental requirement that must be embedded into every aspect of infrastructure-as-code from the first line of configuration. While Terraform enables rapid infrastructure deployment, it also introduces unique security challenges: state files containing sensitive data, credentials required for cloud provider access, secrets embedded in configurations, and the risk of misconfigurations that create vulnerabilities at scale. A single misconfigured S3 bucket or overly permissive IAM policy deployed through Terraform can expose an entire organization to data breaches.

Modern Terraform security extends beyond traditional access controls to include ephemeral values introduced in Terraform 1.10 and enhanced in 1.11, which prevent sensitive data from persisting in state files. These capabilities transform how we handle secrets, passwords, and tokens by ensuring they exist only during runtime execution and never appear in plan files, state snapshots, or logs. Combined with AWS Secrets Manager integration, write-only arguments, and encrypted remote state, you can build infrastructure that maintains security without sacrificing automation velocity.

This chapter provides production-ready patterns for implementing least privilege IAM policies, managing secrets securely across their entire lifecycle, encrypting and controlling access to remote state, and continuously scanning infrastructure for vulnerabilities. You'll learn how to prevent secrets from leaking into version control, how to use security scanning tools like Checkov and tfsec in CI/CD pipelines, how to implement AWS-native dynamic scanning with Security Hub and Inspector, and how to build a defense-in-depth security posture that catches issues before they reach production. Security vulnerabilities caught during development cost minutes to fix; the same vulnerabilities discovered in production cost millions.

## Implementing Principle of Least Privilege

### IAM Policies with Minimal Permissions

```hcl
# security/iam-least-privilege.tf

# Terraform Service Account Role (Minimal Permissions)
resource "aws_iam_role" "terraform_deployer" {
  name        = "${var.environment}-terraform-deployer"
  description = "Role for Terraform to deploy infrastructure with least privilege"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        # Only allow assumption from specific CI/CD service account
        AWS = "arn:aws:iam::${var.cicd_account_id}:role/github-actions-role"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "sts:ExternalId" = var.terraform_external_id
        }
        IpAddress = {
          "aws:SourceIp" = var.allowed_cidr_blocks  # Restrict by source IP
        }
      }
    }]
  })
  
  # Permission boundary to prevent privilege escalation
  permissions_boundary = aws_iam_policy.terraform_boundary.arn
  
  # Maximum session duration (1 hour for deployments)
  max_session_duration = 3600
  
  tags = merge(
    local.common_tags,
    {
      Name    = "${var.environment}-terraform-deployer"
      Purpose = "TerraformDeployment"
    }
  )
}

# Permission Boundary (Hard Limits)
resource "aws_iam_policy" "terraform_boundary" {
  name        = "${var.environment}-terraform-boundary"
  description = "Permission boundary for Terraform deployer"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowedServices"
        Effect = "Allow"
        Action = [
          "ec2:*",
          "rds:*",
          "s3:*",
          "dynamodb:*",
          "lambda:*",
          "cloudwatch:*",
          "logs:*",
          "elasticloadbalancing:*",
          "autoscaling:*",
          "iam:Get*",
          "iam:List*",
          "iam:PassRole",
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyDangerousActions"
        Effect = "Deny"
        Action = [
          # Prevent IAM privilege escalation
          "iam:CreateUser",
          "iam:CreateAccessKey",
          "iam:PutUserPolicy",
          "iam:AttachUserPolicy",
          "iam:CreatePolicyVersion",
          "iam:SetDefaultPolicyVersion",
          "iam:UpdateAssumeRolePolicy",
          # Prevent organizational changes
          "organizations:*",
          "account:*",
          # Prevent billing access
          "aws-portal:*",
          "budgets:*",
          # Prevent security service modifications
          "guardduty:DeleteDetector",
          "securityhub:DisableSecurityHub",
          "config:DeleteConfigurationRecorder"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyRegionRestriction"
        Effect = "Deny"
        Action = "*"
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:RequestedRegion" = var.allowed_regions
          }
          # Exempt global services
          ForAllValues:StringNotEquals = {
            "aws:Service" = [
              "iam",
              "route53",
              "cloudfront",
              "organizations",
              "support"
            ]
          }
        }
      }
    ]
  })
  
  tags = local.common_tags
}

# Granular Policy for Specific Resources (Scoped Permissions)
resource "aws_iam_policy" "ec2_deployment" {
  name        = "${var.environment}-ec2-deployment"
  description = "Scoped permissions for EC2 deployments only"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2InstanceManagement"
        Effect = "Allow"
        Action = [
          "ec2:RunInstances",
          "ec2:TerminateInstances",
          "ec2:StartInstances",
          "ec2:StopInstances",
          "ec2:RebootInstances",
          "ec2:ModifyInstanceAttribute"
        ]
        Resource = "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:instance/*"
        Condition = {
          StringEquals = {
            # Only instances tagged with Environment
            "aws:ResourceTag/Environment" = var.environment
          }
        }
      },
      {
        Sid    = "EC2NetworkConfiguration"
        Effect = "Allow"
        Action = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress"
        ]
        Resource = "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:security-group/*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/ManagedBy" = "Terraform"
          }
        }
      },
      {
        Sid    = "EC2ReadPermissions"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "ec2:Get*"
        ]
        Resource = "*"
      },
      {
        Sid    = "PassRoleToEC2"
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.environment}-ec2-*"
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "ec2.amazonaws.com"
          }
        }
      }
    ]
  })
  
  tags = local.common_tags
}

# S3 State Management Policy (Restricted)
resource "aws_iam_policy" "state_management" {
  name        = "${var.environment}-state-management"
  description = "Permissions for Terraform state management in S3"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "StateFileAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = [
          "arn:aws:s3:::${var.state_bucket_name}/${var.environment}/*"
        ]
        Condition = {
          StringEquals = {
            # Enforce encryption
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid    = "StateBucketList"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketVersioning",
          "s3:GetBucketLocation"
        ]
        Resource = "arn:aws:s3:::${var.state_bucket_name}"
      },
      {
        Sid    = "StateLockAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ]
        Resource = "arn:aws:dynamodb:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/${var.lock_table_name}"
      },
      {
        Sid    = "KMSForStateEncryption"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = var.state_kms_key_arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${var.aws_region}.amazonaws.com"
          }
        }
      }
    ]
  })
  
  tags = local.common_tags
}

# Attach Policies to Terraform Deployer Role
resource "aws_iam_role_policy_attachment" "deployer_ec2" {
  role       = aws_iam_role.terraform_deployer.name
  policy_arn = aws_iam_policy.ec2_deployment.arn
}

resource "aws_iam_role_policy_attachment" "deployer_state" {
  role       = aws_iam_role.terraform_deployer.name
  policy_arn = aws_iam_policy.state_management.arn
}

# Session Tags for Fine-Grained Access Control
resource "aws_iam_role" "application_role" {
  name = "${var.environment}-application-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
  
  tags = local.common_tags
}

resource "aws_iam_policy" "application_s3_access" {
  name = "${var.environment}-application-s3-access"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "S3AccessByTeam"
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:PutObject"
      ]
      # Use session tags for dynamic access control
      Resource = "arn:aws:s3:::${var.data_bucket}/$${aws:PrincipalTag/Team}/*"
    }]
  })
}

# IAM Access Analyzer for Unused Permissions
resource "aws_accessanalyzer_analyzer" "main" {
  analyzer_name = "${var.environment}-access-analyzer"
  type          = "ACCOUNT"
  
  tags = merge(
    local.common_tags,
    {
      Purpose = "UnusedAccessAnalysis"
    }
  )
}

# CloudWatch Alarm for IAM Changes
resource "aws_cloudwatch_event_rule" "iam_changes" {
  name        = "${var.environment}-iam-changes"
  description = "Capture IAM policy and role changes"
  
  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "PutRolePolicy",
        "PutUserPolicy",
        "AttachRolePolicy",
        "AttachUserPolicy",
        "CreateAccessKey",
        "CreateUser",
        "CreateRole"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "iam_changes_sns" {
  rule      = aws_cloudwatch_event_rule.iam_changes.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.security_alerts.arn
}
```


### Least Privilege Implementation Checklist

| Control | Implementation | Impact |
| :-- | :-- | :-- |
| **Permission Boundaries** | Prevent privilege escalation | Blocks unauthorized IAM changes |
| **Resource-Level Permissions** | Restrict actions to specific ARNs | Prevents cross-environment access |
| **Condition Keys** | Enforce encryption, tags, regions | Ensures compliance requirements |
| **Service Control Policies** | Organization-wide guardrails | Prevents account-level violations |
| **Session Duration Limits** | 1-hour max for deployments | Reduces credential exposure window |
| **IP Restrictions** | Whitelist CI/CD IPs only | Prevents unauthorized access |
| **External ID** | Required for role assumption | Prevents confused deputy attacks |
| **Tag-Based Access** | Dynamic permissions via tags | Automatic access control |

## AWS Secrets Manager Integration

### Secure Secret Management Lifecycle

```hcl
# secrets/secrets-manager.tf

# Generate Random Password (Never in State)
resource "random_password" "db_master" {
  length  = 32
  special = true
  
  # Override special characters for database compatibility
  override_special = "!#$%&*()-_=+[]{}<>:?"
  
  lifecycle {
    # Changing this recreates password - use with caution
    create_before_destroy = true
  }
}

# Secrets Manager Secret
resource "aws_secretsmanager_secret" "database_password" {
  name_prefix             = "${var.environment}-database-password-"
  description             = "RDS master password for ${var.environment}"
  recovery_window_in_days = 30  # Allows recovery if accidentally deleted
  
  # KMS Encryption
  kms_key_id = aws_kms_key.secrets.arn
  
  # Automatic Rotation Configuration
  rotation_lambda_arn = aws_lambda_function.secret_rotation.arn
  rotation_rules {
    automatically_after_days = 30
  }
  
  tags = merge(
    local.common_tags,
    {
      Name        = "${var.environment}-database-password"
      Compliance  = "PCI-DSS"
      DataClass   = "Confidential"
      AutoRotate  = "true"
    }
  )
}

# Store Secret Value
resource "aws_secretsmanager_secret_version" "database_password" {
  secret_id = aws_secretsmanager_secret.database_password.id
  
  # Store as JSON for structured data
  secret_string = jsonencode({
    username = "dbadmin"
    password = random_password.db_master.result
    engine   = "postgres"
    host     = aws_db_instance.main.endpoint
    port     = 5432
    dbname   = aws_db_instance.main.db_name
  })
  
  lifecycle {
    ignore_changes = [
      secret_string,  # Rotation updates this
    ]
  }
}

# KMS Key for Secrets Encryption
resource "aws_kms_key" "secrets" {
  description             = "KMS key for Secrets Manager encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  # Key policy for Secrets Manager access
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Secrets Manager"
        Effect = "Allow"
        Principal = {
          Service = "secretsmanager.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${var.aws_region}.amazonaws.com"
          }
        }
      },
      {
        Sid    = "Allow Application Access"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.application.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${var.aws_region}.amazonaws.com"
          }
        }
      }
    ]
  })
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-secrets-kms-key"
    }
  )
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${var.environment}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

# Lambda Function for Secret Rotation
resource "aws_lambda_function" "secret_rotation" {
  filename      = "secret_rotation.zip"
  function_name = "${var.environment}-secret-rotation"
  role          = aws_iam_role.secret_rotation.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.11"
  timeout       = 300
  
  environment {
    variables = {
      SECRETS_MANAGER_ENDPOINT = "https://secretsmanager.${var.aws_region}.amazonaws.com"
    }
  }
  
  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda_rotation.id]
  }
  
  tags = local.common_tags
}

# IAM Role for Secret Rotation Lambda
resource "aws_iam_role" "secret_rotation" {
  name = "${var.environment}-secret-rotation-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
  
  tags = local.common_tags
}

resource "aws_iam_role_policy" "secret_rotation" {
  name = "${var.environment}-secret-rotation-policy"
  role = aws_iam_role.secret_rotation.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecretsManagerAccess"
        Effect = "Allow"
        Action = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecretVersionStage"
        ]
        Resource = aws_secretsmanager_secret.database_password.arn
      },
      {
        Sid    = "RDSPasswordUpdate"
        Effect = "Allow"
        Action = [
          "rds:ModifyDBInstance",
          "rds:DescribeDBInstances"
        ]
        Resource = aws_db_instance.main.arn
      },
      {
        Sid    = "KMSDecryption"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.secrets.arn
      },
      {
        Sid    = "VPCNetworking"
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface"
        ]
        Resource = "*"
      }
    ]
  })
}

# Grant Secrets Manager Permission to Invoke Lambda
resource "aws_lambda_permission" "secrets_manager" {
  statement_id  = "AllowExecutionFromSecretsManager"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.secret_rotation.function_name
  principal     = "secretsmanager.amazonaws.com"
}

# Application IAM Policy for Secret Access
resource "aws_iam_policy" "application_secrets_access" {
  name        = "${var.environment}-application-secrets-access"
  description = "Allow application to read secrets"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GetSpecificSecrets"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          aws_secretsmanager_secret.database_password.arn,
          "${aws_secretsmanager_secret.api_keys.arn}*"  # Allow versions
        ]
      },
      {
        Sid    = "DecryptSecrets"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.secrets.arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${var.aws_region}.amazonaws.com"
          }
        }
      }
    ]
  })
  
  tags = local.common_tags
}

# CloudWatch Alarm for Secret Access
resource "aws_cloudwatch_metric_alarm" "unauthorized_secret_access" {
  alarm_name          = "${var.environment}-unauthorized-secret-access"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "AccessDeniedCount"
  namespace           = "AWS/SecretsManager"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "Multiple unauthorized secret access attempts"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  
  dimensions = {
    SecretId = aws_secretsmanager_secret.database_password.id
  }
  
  tags = local.common_tags
}

# Resource Policy for Cross-Account Access (if needed)
resource "aws_secretsmanager_secret_policy" "cross_account" {
  count = var.enable_cross_account_access ? 1 : 0
  
  secret_arn = aws_secretsmanager_secret.database_password.arn
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowTrustedAccountAccess"
      Effect = "Allow"
      Principal = {
        AWS = var.trusted_account_arns
      }
      Action = [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ]
      Resource = "*"
      Condition = {
        StringEquals = {
          "secretsmanager:VersionStage" = "AWSCURRENT"
        }
      }
    }]
  })
}
```


### Secret Rotation Lambda (Python)

```python
# secret_rotation.py

import json
import boto3
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

secretsmanager = boto3.client('secretsmanager')
rds = boto3.client('rds')

def lambda_handler(event, context):
    """
    Rotate RDS master password in Secrets Manager
    """
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']
    
    # Get secret metadata
    metadata = secretsmanager.describe_secret(SecretId=arn)
    
    if not metadata['RotationEnabled']:
        logger.error(f"Secret {arn} is not enabled for rotation")
        raise ValueError("Secret is not enabled for rotation")
    
    # Get versions
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        logger.error(f"Secret version {token} has no stage for rotation")
        raise ValueError("Secret version has no stage for rotation")
    
    if "AWSCURRENT" in versions[token]:
        logger.info(f"Secret version {token} already set as AWSCURRENT")
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error(f"Secret version {token} not set as AWSPENDING for rotation")
        raise ValueError("Secret version not set as AWSPENDING")
    
    # Execute rotation step
    if step == "createSecret":
        create_secret(secretsmanager, arn, token)
    elif step == "setSecret":
        set_secret(secretsmanager, rds, arn, token)
    elif step == "testSecret":
        test_secret(secretsmanager, arn, token)
    elif step == "finishSecret":
        finish_secret(secretsmanager, arn, token)
    else:
        raise ValueError("Invalid step parameter")

def create_secret(service_client, arn, token):
    """Generate new password and store as AWSPENDING"""
    # Get current secret
    current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")
    
    # Generate new password
    passwd = service_client.get_random_password(
        ExcludeCharacters='/@"\'\\'
    )
    
    # Store new password as pending
    current_dict['password'] = passwd['RandomPassword']
    
    service_client.put_secret_value(
        SecretId=arn,
        ClientRequestToken=token,
        SecretString=json.dumps(current_dict),
        VersionStages=['AWSPENDING']
    )
    
    logger.info("createSecret: Successfully created new secret")

def set_secret(service_client, rds_client, arn, token):
    """Update RDS master password"""
    pending_dict = get_secret_dict(service_client, arn, "AWSPENDING", token)
    
    # Modify RDS instance password
    rds_client.modify_db_instance(
        DBInstanceIdentifier=pending_dict['dbname'],
        MasterUserPassword=pending_dict['password'],
        ApplyImmediately=True
    )
    
    logger.info("setSecret: Successfully set password in RDS")

def test_secret(service_client, arn, token):
    """Test new password works"""
    import psycopg2
    
    pending_dict = get_secret_dict(service_client, arn, "AWSPENDING", token)
    
    # Test connection with new password
    try:
        conn = psycopg2.connect(
            host=pending_dict['host'],
            user=pending_dict['username'],
            password=pending_dict['password'],
            dbname=pending_dict['dbname'],
            connect_timeout=5
        )
        conn.close()
        logger.info("testSecret: Successfully validated new password")
    except Exception as e:
        logger.error(f"testSecret: Failed to connect with new password: {e}")
        raise

def finish_secret(service_client, arn, token):
    """Finalize rotation by updating version stages"""
    metadata = service_client.describe_secret(SecretId=arn)
    current_version = None
    
    for version, stages in metadata["VersionIdsToStages"].items():
        if "AWSCURRENT" in stages:
            if version == token:
                logger.info("finishSecret: Version already marked as AWSCURRENT")
                return
            current_version = version
            break
    
    # Move AWSCURRENT stage to new version
    service_client.update_secret_version_stage(
        SecretId=arn,
        VersionStage="AWSCURRENT",
        MoveToVersionId=token,
        RemoveFromVersionId=current_version
    )
    
    logger.info("finishSecret: Successfully finalized rotation")

def get_secret_dict(service_client, arn, stage, token=None):
    """Retrieve secret value as dictionary"""
    required_fields = ['username', 'password', 'engine', 'host', 'port', 'dbname']
    
    if token:
        secret = service_client.get_secret_value(
            SecretId=arn,
            VersionId=token,
            VersionStage=stage
        )
    else:
        secret = service_client.get_secret_value(
            SecretId=arn,
            VersionStage=stage
        )
    
    secret_dict = json.loads(secret['SecretString'])
    
    # Validate required fields
    for field in required_fields:
        if field not in secret_dict:
            raise KeyError(f"{field} key is missing from secret JSON")
    
    return secret_dict
```


## Ephemeral Values for Managed Resources (Terraform 1.11+)

### Using Ephemeral Resources and Write-Only Arguments

Terraform 1.11 introduced ephemeral values that never persist in state files, providing secure secret handling.

```hcl
# ephemeral/ephemeral-secrets.tf

terraform {
  required_version = ">= 1.11.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

# Ephemeral Random Password (Never in State)
ephemeral "random_password" "db_password" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# Store Ephemeral Password in Secrets Manager with Write-Only Argument
resource "aws_secretsmanager_secret" "database" {
  name_prefix             = "${var.environment}-db-password-"
  recovery_window_in_days = 7
  kms_key_id              = aws_kms_key.secrets.arn
  
  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "database" {
  secret_id = aws_secretsmanager_secret.database.id
  
  # write_only argument - value never stored in state
  secret_string_wo = jsonencode({
    username = "dbadmin"
    password = ephemeral.random_password.db_password.result
    engine   = "postgres"
  })
  
  # Version tracking for write-only values
  secret_string_wo_version = 1
  
  lifecycle {
    # Prevent accidental updates
    ignore_changes = [secret_string_wo]
  }
}

# Retrieve Secret Ephemerally When Needed
ephemeral "aws_secretsmanager_secret_version" "database" {
  secret_id = aws_secretsmanager_secret.database.id
  
  depends_on = [aws_secretsmanager_secret_version.database]
}

# Use Ephemeral Secret in RDS (State-Safe)
resource "aws_db_instance" "main" {
  identifier = "${var.environment}-postgres"
  
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.micro"
  
  allocated_storage = 20
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
  
  # Username from ephemeral secret
  username = jsondecode(ephemeral.aws_secretsmanager_secret_version.database.secret_string).username
  
  # Password from ephemeral secret - never persisted to state
  password = jsondecode(ephemeral.aws_secretsmanager_secret_version.database.secret_string).password
  
  # Mark password as sensitive
  lifecycle {
    ignore_changes = [password]
  }
  
  tags = local.common_tags
}

# Ephemeral OAuth Token from External System
ephemeral "external" "oauth_token" {
  program = ["bash", "-c", <<-EOT
    curl -s -X POST https://auth.example.com/token \
      -H "Content-Type: application/json" \
      -d '{"client_id":"'$CLIENT_ID'","client_secret":"'$CLIENT_SECRET'"}' \
      | jq -r '{token: .access_token}'
  EOT
  ]
  
  query = {
    CLIENT_ID     = var.oauth_client_id
    CLIENT_SECRET = var.oauth_client_secret
  }
}

# Use Ephemeral Token for API Configuration
resource "aws_api_gateway_rest_api" "main" {
  name        = "${var.environment}-api"
  description = "API Gateway with ephemeral authentication"
  
  # Token used during creation, never stored
  body = templatefile("${path.module}/openapi.yaml", {
    auth_token = ephemeral.external.oauth_token.result.token
  })
  
  tags = local.common_tags
}

# Ephemeral SSH Key for EC2 Instance
ephemeral "tls_private_key" "ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# Store Public Key in AWS (Private Key Never in State)
resource "aws_key_pair" "deployer" {
  key_name   = "${var.environment}-deployer-key"
  public_key = ephemeral.tls_private_key.ssh.public_key_openssh
  
  tags = local.common_tags
}

# Save Private Key to Secrets Manager (Not State)
resource "aws_secretsmanager_secret_version" "ssh_private_key" {
  secret_id = aws_secretsmanager_secret.ssh_key.id
  
  # Write-only: Private key never in state
  secret_string_wo = ephemeral.tls_private_key.ssh.private_key_pem
  secret_string_wo_version = 1
}

# Ephemeral Database Connection
ephemeral "postgresql_connection" "app" {
  host     = aws_db_instance.main.endpoint
  username = jsondecode(ephemeral.aws_secretsmanager_secret_version.database.secret_string).username
  password = jsondecode(ephemeral.aws_secretsmanager_secret_version.database.secret_string).password
  database = "myapp"
  sslmode  = "require"
}

# Create Database User with Ephemeral Connection
resource "postgresql_role" "app_user" {
  # Connection credentials never persist in state
  connection_host     = ephemeral.postgresql_connection.app.host
  connection_user     = ephemeral.postgresql_connection.app.username
  connection_password = ephemeral.postgresql_connection.app.password
  
  name     = "app_user"
  login    = true
  password = random_password.app_user_password.result
}

# Pattern: Generate → Store → Retrieve → Use
# 1. Generate ephemeral secret
ephemeral "random_password" "api_key" {
  length  = 64
  special = false
}

# 2. Store with write-only (persisted securely)
resource "aws_secretsmanager_secret_version" "api_key" {
  secret_id            = aws_secretsmanager_secret.api_key.id
  secret_string_wo     = ephemeral.random_password.api_key.result
  secret_string_wo_version = 1
}

# 3. Retrieve ephemerally when needed
ephemeral "aws_secretsmanager_secret_version" "api_key" {
  secret_id  = aws_secretsmanager_secret.api_key.id
  depends_on = [aws_secretsmanager_secret_version.api_key]
}

# 4. Use in resource configuration
resource "aws_api_gateway_api_key" "application" {
  name  = "${var.environment}-application-key"
  value = ephemeral.aws_secretsmanager_secret_version.api_key.secret_string
}
```


### Ephemeral Values Best Practices

| Practice | Benefit | Example |
| :-- | :-- | :-- |
| **Generate ephemeral passwords** | Never in state or logs | `ephemeral "random_password"` |
| **Use write-only arguments** | Persist without state exposure | `secret_string_wo = ephemeral.random_password.result` |
| **Retrieve ephemerally** | Access secrets at runtime only | `ephemeral "aws_secretsmanager_secret_version"` |
| **Chain ephemeral resources** | End-to-end secure flow | Generate → Store → Retrieve → Use |
| **Mark lifecycle ignore_changes** | Prevent accidental updates | `ignore_changes = [password]` |
| **Use for temporary connections** | Database, API, SSH connections | `ephemeral "postgresql_connection"` |

## Keeping Secrets Out of State Files

### State File Security Patterns

```hcl
# state-security/secure-outputs.tf

# ❌ BAD: Sensitive output (appears in state plaintext)
output "database_password_bad" {
  value = aws_db_instance.main.password
  # Password visible in:
  # - terraform.tfstate
  # - terraform output
  # - CI/CD logs
}

# ✅ GOOD: Sensitive output (hidden but still in state)
output "database_password_better" {
  value     = aws_db_instance.main.password
  sensitive = true
  # Hidden from CLI/logs but STILL in state file
}

# ✅ BEST: Reference to secret (not the secret itself)
output "database_password_secret_arn" {
  value       = aws_secretsmanager_secret.database_password.arn
  description = "ARN of secret containing database password"
  # Application retrieves secret at runtime
}

# Pattern: Store Secrets, Reference ARNs
resource "aws_ssm_parameter" "db_connection_string" {
  name  = "/${var.environment}/database/connection_string"
  type  = "SecureString"
  value = "postgresql://${aws_db_instance.main.username}:PLACEHOLDER@${aws_db_instance.main.endpoint}/${aws_db_instance.main.db_name}"
  
  # KMS encryption for SSM Parameter
  key_id = aws_kms_key.ssm.id
  
  lifecycle {
    ignore_changes = [value]  # Don't update after creation
  }
  
  tags = local.common_tags
}

# Update SSM Parameter with actual password (outside Terraform)
resource "null_resource" "update_ssm_parameter" {
  triggers = {
    secret_version = aws_secretsmanager_secret_version.database_password.version_id
  }
  
  provisioner "local-exec" {
    command = <<-EOT
      aws ssm put-parameter \
        --name "${aws_ssm_parameter.db_connection_string.name}" \
        --value "postgresql://${aws_db_instance.main.username}:$(aws secretsmanager get-secret-value --secret-id ${aws_secretsmanager_secret.database_password.id} --query SecretString --output text | jq -r '.password')@${aws_db_instance.main.endpoint}/${aws_db_instance.main.db_name}" \
        --overwrite \
        --type SecureString \
        --key-id ${aws_kms_key.ssm.id}
    EOT
  }
}

# Use Data Source to Read (Not Store) Secrets
data "aws_secretsmanager_secret_version" "database" {
  secret_id = aws_secretsmanager_secret.database_password.id
}

# locals block for processing (sensitive = true)
locals {
  db_credentials = jsondecode(data.aws_secretsmanager_secret_version.database.secret_string)
  
  # Mark as sensitive
  db_username = sensitive(local.db_credentials.username)
  db_password = sensitive(local.db_credentials.password)
}

# Use Sensitive Variables
variable "api_key" {
  description = "API key for external service"
  type        = string
  sensitive   = true
  # Never logged, always redacted
}

# Prevent Secrets in Logs
resource "null_resource" "deploy_application" {
  provisioner "local-exec" {
    command = "deploy.sh"
    
    environment = {
      DB_HOST     = aws_db_instance.main.endpoint
      DB_NAME     = aws_db_instance.main.db_name
      SECRET_ARN  = aws_secretsmanager_secret.database_password.arn
      # Application fetches secret using SDK
      # Secret never passed as environment variable
    }
  }
}

# Terraform Cloud/Enterprise Variable Sets
# Store secrets in HCP Terraform, never in code
# Reference via:
# var.db_password (marked sensitive in workspace)
```


### State File Security Checklist

| Risk | Mitigation | Implementation |
| :-- | :-- | :-- |
| **Plaintext secrets in state** | Use Secrets Manager ARNs | Output ARNs, not values |
| **State file in VCS** | Never commit state | Add to `.gitignore` |
| **Unencrypted remote state** | Enable S3 SSE-KMS | `encrypt = true, kms_key_id = ...` |
| **Overly permissive state access** | IAM least privilege | Restrict S3/DynamoDB access |
| **Sensitive outputs visible** | Mark outputs sensitive | `sensitive = true` |
| **Secrets in logs** | Sensitive variables | `variable { sensitive = true }` |
| **State file backups** | Encrypt backups | S3 versioning with KMS |
| **Local state files** | Use remote state | S3 backend from day 1 |

## Remote State Encryption Configuration

### Secure S3 Backend Configuration

```hcl
# backend/s3-backend-setup.tf

# S3 Bucket for Terraform State
resource "aws_s3_bucket" "terraform_state" {
  bucket = "${var.organization}-terraform-state-${data.aws_caller_identity.current.account_id}"
  
  tags = merge(
    local.common_tags,
    {
      Name       = "Terraform State Bucket"
      Purpose    = "Infrastructure State Management"
      Compliance = "SOC2"
    }
  )
}

# Block ALL Public Access (Critical!)
resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable Versioning (Required for Recovery)
resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

# KMS Key for State Encryption
resource "aws_kms_key" "terraform_state" {
  description             = "KMS key for Terraform state encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow S3 to use the key"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow Terraform service account"
        Effect = "Allow"
        Principal = {
          AWS = var.terraform_deployer_role_arn
        }
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
  
  tags = merge(
    local.common_tags,
    {
      Name = "Terraform State Encryption Key"
    }
  )
}

resource "aws_kms_alias" "terraform_state" {
  name          = "alias/terraform-state"
  target_key_id = aws_kms_key.terraform_state.key_id
}

# Server-Side Encryption with KMS
resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.terraform_state.arn
    }
    bucket_key_enabled = true  # Reduces KMS costs
  }
}

# Lifecycle Policy for Old Versions
resource "aws_s3_bucket_lifecycle_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  rule {
    id     = "expire-old-versions"
    status = "Enabled"
    
    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }
    
    noncurrent_version_transition {
      noncurrent_days = 90
      storage_class   = "GLACIER"
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }
  
  rule {
    id     = "delete-incomplete-uploads"
    status = "Enabled"
    
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# S3 Bucket Policy (Defense in Depth)
resource "aws_s3_bucket_policy" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedObjectUploads"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.terraform_state.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid    = "DenyInsecureTransport"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.terraform_state.arn,
          "${aws_s3_bucket.terraform_state.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "AllowTerraformServiceAccount"
        Effect = "Allow"
        Principal = {
          AWS = var.terraform_deployer_role_arn
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.terraform_state.arn,
          "${aws_s3_bucket.terraform_state.arn}/*"
        ]
      }
    ]
  })
}

# DynamoDB Table for State Locking
resource "aws_dynamodb_table" "terraform_locks" {
  name         = "terraform-state-locks"
  billing_mode = "PAY_PER_REQUEST"  # Cost-effective for infrequent access
  hash_key     = "LockID"
  
  attribute {
    name = "LockID"
    type = "S"
  }
  
  # Enable encryption at rest
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.dynamodb_locks.arn
  }
  
  # Point-in-time recovery
  point_in_time_recovery {
    enabled = true
  }
  
  tags = merge(
    local.common_tags,
    {
      Name    = "Terraform State Locks"
      Purpose = "State Locking"
    }
  )
}

# KMS Key for DynamoDB Encryption
resource "aws_kms_key" "dynamodb_locks" {
  description             = "KMS key for DynamoDB state locks encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = merge(
    local.common_tags,
    {
      Name = "DynamoDB Locks Encryption Key"
    }
  )
}

# S3 Access Logging (Audit Trail)
resource "aws_s3_bucket" "state_access_logs" {
  bucket = "${var.organization}-terraform-state-logs-${data.aws_caller_identity.current.account_id}"
  
  tags = local.common_tags
}

resource "aws_s3_bucket_logging" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  target_bucket = aws_s3_bucket.state_access_logs.id
  target_prefix = "state-access-logs/"
}

# CloudTrail for State Bucket Access Monitoring
resource "aws_cloudtrail" "state_bucket_trail" {
  name                          = "${var.environment}-state-bucket-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = false
  is_multi_region_trail         = false
  
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.terraform_state.arn}/*"]
    }
  }
  
  tags = local.common_tags
}

# CloudWatch Alarm for Unusual State Access
resource "aws_cloudwatch_metric_alarm" "state_access_spike" {
  alarm_name          = "${var.environment}-unusual-state-access"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "NumberOfObjects"
  namespace           = "AWS/S3"
  period              = 300
  statistic           = "Sum"
  threshold           = 100  # Adjust based on normal activity
  alarm_description   = "Unusual number of state file accesses"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  
  dimensions = {
    BucketName = aws_s3_bucket.terraform_state.id
    FilterId   = "EntireBucket"
  }
  
  tags = local.common_tags
}
```


### Backend Configuration for Projects

```hcl
# terraform.tf (in each project)

terraform {
  required_version = ">= 1.11.0"
  
  backend "s3" {
    # Bucket configuration
    bucket = "myorg-terraform-state-123456789012"
    key    = "production/networking/terraform.tfstate"
    region = "us-east-1"
    
    # Encryption (REQUIRED)
    encrypt        = true
    kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
    
    # State Locking (REQUIRED for team environments)
    dynamodb_table = "terraform-state-locks"
    
    # Access Control
    acl            = "private"
    
    # IAM Role for Backend Access
    role_arn       = "arn:aws:iam::123456789012:role/terraform-state-access"
    
    # Workspace Configuration
    workspace_key_prefix = "workspaces"
    
    # Additional Security
    skip_credentials_validation = false
    skip_metadata_api_check     = false
    skip_region_validation      = false
    
    # Enable S3 bucket key (reduces KMS costs)
    bucket_key_enabled = true
  }
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# Alternative: Use Terragrunt for DRY backend config
# terragrunt.hcl
remote_state {
  backend = "s3"
  config = {
    encrypt        = true
    bucket         = "myorg-terraform-state-${get_aws_account_id()}"
    key            = "${path_relative_to_include()}/terraform.tfstate"
    region         = "us-east-1"
    kms_key_id     = "arn:aws:kms:us-east-1:${get_aws_account_id()}:alias/terraform-state"
    dynamodb_table = "terraform-state-locks"
  }
  generate = {
    path      = "backend.tf"
    if_exists = "overwrite"
  }
}

## Access Controls for S3 Remote State Storage

### Multi-Layer State Access Control

```hcl
# state-access/iam-policies.tf

# Read-Only Access for Developers
resource "aws_iam_policy" "state_read_only" {
  name        = "${var.environment}-terraform-state-read-only"
  description = "Read-only access to Terraform state files"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ListStateBucket"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketVersioning",
          "s3:GetBucketLocation"
        ]
        Resource = aws_s3_bucket.terraform_state.arn
        Condition = {
          StringLike = {
            # Restrict to specific environments
            "s3:prefix" = [
              "${var.environment}/*",
              "shared/*"
            ]
          }
        }
      },
      {
        Sid    = "ReadStateFiles"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion"
        ]
        Resource = [
          "${aws_s3_bucket.terraform_state.arn}/${var.environment}/*",
          "${aws_s3_bucket.terraform_state.arn}/shared/*"
        ]
      },
      {
        Sid    = "ViewStateLocks"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = aws_dynamodb_table.terraform_locks.arn
      },
      {
        Sid    = "DecryptStateFiles"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.terraform_state.arn
      }
    ]
  })
  
  tags = local.common_tags
}

# Write Access for CI/CD Pipelines
resource "aws_iam_policy" "state_write_cicd" {
  name        = "${var.environment}-terraform-state-write-cicd"
  description = "Write access to Terraform state for CI/CD pipelines"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ListStateBucket"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketVersioning"
        ]
        Resource = aws_s3_bucket.terraform_state.arn
      },
      {
        Sid    = "ReadWriteStateFiles"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"  # For workspace cleanup
        ]
        Resource = "${aws_s3_bucket.terraform_state.arn}/${var.environment}/*"
        Condition = {
          StringEquals = {
            # Enforce encryption
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid    = "ManageStateLocks"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ]
        Resource = aws_dynamodb_table.terraform_locks.arn
        Condition = {
          # Only allow locks for this environment
          ForAllValues:StringEquals = {
            "dynamodb:LeadingKeys" = [
              "${aws_s3_bucket.terraform_state.id}/${var.environment}/*"
            ]
          }
        }
      },
      {
        Sid    = "EncryptDecryptStateFiles"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.terraform_state.arn
      }
    ]
  })
  
  tags = local.common_tags
}

# Emergency Break-Glass Access (Audit Logged)
resource "aws_iam_policy" "state_admin" {
  name        = "${var.environment}-terraform-state-admin"
  description = "Full admin access to Terraform state (emergency only)"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "FullStateAccess"
        Effect = "Allow"
        Action = [
          "s3:*"
        ]
        Resource = [
          aws_s3_bucket.terraform_state.arn,
          "${aws_s3_bucket.terraform_state.arn}/*"
        ]
      },
      {
        Sid    = "FullLockAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:*"
        ]
        Resource = aws_dynamodb_table.terraform_locks.arn
      },
      {
        Sid    = "FullKMSAccess"
        Effect = "Allow"
        Action = [
          "kms:*"
        ]
        Resource = aws_kms_key.terraform_state.arn
      }
    ]
  })
  
  tags = local.common_tags
}

# Team-Based Access Control
resource "aws_iam_role" "team_infrastructure" {
  name        = "${var.environment}-team-infrastructure-terraform"
  description = "Terraform access for infrastructure team"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = var.infrastructure_team_arns
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "sts:ExternalId" = var.team_external_id
        }
        IpAddress = {
          "aws:SourceIp" = var.office_ip_ranges
        }
        Bool = {
          "aws:MultiFactorAuthPresent" = "true"  # Require MFA
        }
      }
    }]
  })
  
  max_session_duration = 3600  # 1 hour
  
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "team_infrastructure_write" {
  role       = aws_iam_role.team_infrastructure.name
  policy_arn = aws_iam_policy.state_write_cicd.arn
}

# Service Account for GitHub Actions
resource "aws_iam_role" "github_actions" {
  name        = "${var.environment}-github-actions-terraform"
  description = "Terraform access for GitHub Actions CI/CD"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          # Restrict to specific repos
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:*"
        }
      }
    }]
  })
  
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "github_actions_state" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.state_write_cicd.arn
}

# S3 Bucket Ownership Controls
resource "aws_s3_bucket_ownership_controls" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# S3 Object Lock (Immutable State Versions)
resource "aws_s3_bucket_object_lock_configuration" "terraform_state" {
  count = var.enable_state_immutability ? 1 : 0
  
  bucket = aws_s3_bucket.terraform_state.id
  
  rule {
    default_retention {
      mode = "GOVERNANCE"  # Can be overridden with special permissions
      days = 7
    }
  }
}

# EventBridge Rule for State Modifications
resource "aws_cloudwatch_event_rule" "state_modifications" {
  name        = "${var.environment}-terraform-state-modifications"
  description = "Capture all Terraform state modifications"
  
  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName = [
        "PutObject",
        "DeleteObject",
        "CopyObject"
      ]
      requestParameters = {
        bucketName = [aws_s3_bucket.terraform_state.id]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "state_modifications_sns" {
  rule      = aws_cloudwatch_event_rule.state_modifications.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.state_audit.arn
}

# SNS Topic for State Audit Trail
resource "aws_sns_topic" "state_audit" {
  name              = "${var.environment}-terraform-state-audit"
  kms_master_key_id = aws_kms_key.sns_audit.id
  
  tags = local.common_tags
}

resource "aws_sns_topic_subscription" "state_audit_email" {
  topic_arn = aws_sns_topic.state_audit.arn
  protocol  = "email"
  endpoint  = var.security_team_email
}

# Lambda Function for State Change Analysis
resource "aws_lambda_function" "state_change_analyzer" {
  filename      = "state_analyzer.zip"
  function_name = "${var.environment}-state-change-analyzer"
  role          = aws_iam_role.state_analyzer.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 60
  
  environment {
    variables = {
      SLACK_WEBHOOK_URL = var.slack_webhook_url
      SEVERITY_THRESHOLD = "high"
    }
  }
  
  tags = local.common_tags
}

resource "aws_lambda_permission" "state_analyzer_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.state_change_analyzer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.state_modifications.arn
}

resource "aws_cloudwatch_event_target" "state_modifications_lambda" {
  rule      = aws_cloudwatch_event_rule.state_modifications.name
  target_id = "AnalyzeStateChanges"
  arn       = aws_lambda_function.state_change_analyzer.arn
}

# Cross-Region Replication for Disaster Recovery
resource "aws_s3_bucket" "terraform_state_replica" {
  provider = aws.dr_region
  
  bucket = "${var.organization}-terraform-state-replica-${data.aws_caller_identity.current.account_id}"
  
  tags = merge(
    local.common_tags,
    {
      Name    = "Terraform State Replica"
      Purpose = "Disaster Recovery"
    }
  )
}

resource "aws_s3_bucket_versioning" "terraform_state_replica" {
  provider = aws.dr_region
  
  bucket = aws_s3_bucket.terraform_state_replica.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_iam_role" "replication" {
  name = "${var.environment}-terraform-state-replication"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "s3.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
  
  tags = local.common_tags
}

resource "aws_iam_role_policy" "replication" {
  name = "${var.environment}-terraform-state-replication-policy"
  role = aws_iam_role.replication.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.terraform_state.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl"
        ]
        Resource = "${aws_s3_bucket.terraform_state.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete"
        ]
        Resource = "${aws_s3_bucket.terraform_state_replica.arn}/*"
      }
    ]
  })
}

resource "aws_s3_bucket_replication_configuration" "terraform_state" {
  depends_on = [
    aws_s3_bucket_versioning.terraform_state,
    aws_s3_bucket_versioning.terraform_state_replica
  ]
  
  bucket = aws_s3_bucket.terraform_state.id
  role   = aws_iam_role.replication.arn
  
  rule {
    id     = "replicate-all-state"
    status = "Enabled"
    
    filter {}
    
    destination {
      bucket        = aws_s3_bucket.terraform_state_replica.arn
      storage_class = "STANDARD_IA"
    }
    
    delete_marker_replication {
      status = "Enabled"
    }
  }
}
```


### State Access Control Matrix

| Role | Read State | Write State | Lock State | Delete Objects | KMS Decrypt | KMS Encrypt |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| **Developer (Read-Only)** | ✅ Own env | ❌ | ❌ | ❌ | ✅ | ❌ |
| **CI/CD Pipeline** | ✅ Own env | ✅ Own env | ✅ | ❌ | ✅ | ✅ |
| **Infrastructure Team** | ✅ All envs | ✅ All envs | ✅ | ⚠️ With approval | ✅ | ✅ |
| **Security Team** | ✅ All envs | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Break-Glass Admin** | ✅ All | ✅ All | ✅ All | ✅ Audit logged | ✅ | ✅ |

## Continuous Infrastructure and Source Code Scanning

### Static Analysis with Multiple Tools

```hcl
# scanning/.pre-commit-config.yaml

# Pre-commit hooks for local scanning
repos:
  - repo: https://github.com/antonbabenko/pre-commit-terraform
    rev: v1.94.0
    hooks:
      - id: terraform_fmt
      - id: terraform_validate
      - id: terraform_docs
      - id: terraform_tflint
        args:
          - --args=--config=__GIT_WORKING_DIR__/.tflint.hcl
      - id: terraform_tfsec
        args:
          - --args=--config-file=__GIT_WORKING_DIR__/.tfsec.yml
      - id: terraform_checkov
        args:
          - --args=--config-file=__GIT_WORKING_DIR__/.checkov.yml
      
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: check-merge-conflict
      - id: detect-private-key
      - id: check-added-large-files
      - id: check-case-conflict
      - id: check-json
      - id: check-yaml
      - id: end-of-file-fixer
      - id: trailing-whitespace

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.5.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
```


### TFLint Configuration

```hcl
# .tflint.hcl

plugin "aws" {
  enabled = true
  version = "0.32.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

config {
  module = true
  force = false
}

# Security Rules
rule "aws_s3_bucket_public_access_block_enabled" {
  enabled = true
}

rule "aws_s3_bucket_versioning_enabled" {
  enabled = true
}

rule "aws_s3_bucket_encryption_enabled" {
  enabled = true
}

rule "aws_db_instance_storage_encrypted" {
  enabled = true
}

rule "aws_security_group_unrestricted_ingress" {
  enabled = true
}

rule "aws_iam_policy_too_permissive" {
  enabled = true
}

rule "terraform_deprecated_interpolation" {
  enabled = true
}

rule "terraform_documented_variables" {
  enabled = true
}

rule "terraform_naming_convention" {
  enabled = true
  format  = "snake_case"
}

rule "terraform_required_version" {
  enabled = true
}
```


### tfsec Configuration

```yaml
# .tfsec.yml

exclude:
  - AWS001  # S3 bucket encryption - handled by Checkov
  - AWS017  # ECR image scanning - not applicable

severity_overrides:
  AWS002: ERROR      # S3 bucket public access
  AWS018: CRITICAL   # Missing security group description
  AWS089: HIGH       # EC2 instance metadata service v1

minimum_severity: MEDIUM

custom_check_dir: .tfsec-custom/
```


### Checkov Configuration

```yaml
# .checkov.yml

framework:
  - terraform
  - secrets

skip-check:
  - CKV_AWS_18  # Ensure S3 bucket logging - not needed for all buckets
  - CKV_AWS_21  # Ensure S3 bucket versioning - selectively applied

check:
  - CKV_AWS_19  # Ensure S3 bucket encryption
  - CKV_AWS_20  # Ensure S3 bucket not public
  - CKV_AWS_23  # Ensure security groups do not allow 0.0.0.0/0 ingress
  - CKV_AWS_24  # Ensure security group descriptions
  - CKV_AWS_27  # Ensure all data in RDS is encrypted
  - CKV_AWS_61  # Ensure IAM password policy requires minimum length
  - CKV_AWS_79  # Ensure Instance Metadata Service v2 enabled

soft-fail: false
output: cli
compact: true
quiet: false

external-checks-dir:
  - ./custom-checks/
```


### GitHub Actions CI/CD Security Pipeline

```yaml
# .github/workflows/terraform-security.yml

name: Terraform Security Scanning

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'  # Weekly scan

jobs:
  tflint:
    name: TFLint
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      
      - name: Setup TFLint
        uses: terraform-linters/setup-tflint@v4
        with:
          tflint_version: v0.50.0
      
      - name: Init TFLint
        run: tflint --init
      
      - name: Run TFLint
        run: tflint --recursive --format=sarif > tflint.sarif
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: tflint.sarif
          category: tflint

  tfsec:
    name: tfsec
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      
      - name: Run tfsec
        uses: aquasecurity/tfsec-action@v1.0.3
        with:
          working_directory: .
          format: sarif
          sarif_file: tfsec.sarif
          soft_fail: false
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: tfsec.sarif
          category: tfsec

  checkov:
    name: Checkov
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      
      - name: Run Checkov
        uses: bridgecrewio/checkov-action@v12
        with:
          directory: .
          framework: terraform
          output_format: sarif
          output_file_path: checkov.sarif
          soft_fail: false
          download_external_modules: true
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: checkov.sarif
          category: checkov

  terrascan:
    name: Terrascan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      
      - name: Run Terrascan
        uses: tenable/terrascan-action@v1.5.0
        with:
          iac_type: terraform
          iac_dir: .
          policy_type: aws
          sarif_upload: true
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: terrascan.sarif
          category: terrascan

  snyk:
    name: Snyk IaC
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      
      - name: Run Snyk IaC
        uses: snyk/actions/iac@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          command: test
          args: --sarif-file-output=snyk.sarif
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: snyk.sarif
          category: snyk

  infracost:
    name: Infracost
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
      
      - name: Terraform Init
        run: terraform init
      
      - name: Run Infracost
        uses: infracost/actions/setup@v3
        with:
          api-key: ${{ secrets.INFRACOST_API_KEY }}
      
      - name: Generate Cost Estimate
        run: |
          infracost breakdown --path=. \
            --format=json \
            --out-file=infracost.json
      
      - name: Post Cost Comment
        if: github.event_name == 'pull_request'
        uses: infracost/actions/comment@v1
        with:
          path: infracost.json
          behavior: update

  secret-scanning:
    name: Secret Scanning
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: TruffleHog OSS
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: main
          head: HEAD
      
      - name: GitGuardian
        uses: GitGuardian/ggshield-action@v1
        env:
          GITGUARDIAN_API_KEY: ${{ secrets.GITGUARDIAN_API_KEY }}
        with:
          args: scan ci

  terraform-plan:
    name: Terraform Plan Security Check
    runs-on: ubuntu-latest
    needs: [tflint, tfsec, checkov, terrascan]
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.11.0
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1
      
      - name: Terraform Init
        run: terraform init
      
      - name: Terraform Plan
        run: terraform plan -out=tfplan
      
      - name: Convert Plan to JSON
        run: terraform show -json tfplan > tfplan.json
      
      - name: Scan Plan with OPA
        run: |
          docker run --rm -v $(pwd):/project openpolicyagent/opa:latest \
            eval -i /project/tfplan.json \
            -d /project/policies/ \
            "data.terraform.deny"

  security-summary:
    name: Security Summary
    runs-on: ubuntu-latest
    needs: [tflint, tfsec, checkov, terrascan, snyk, secret-scanning]
    if: always()
    steps:
      - name: Generate Security Report
        run: |
          echo "## Security Scan Results" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "| Tool | Status |" >> $GITHUB_STEP_SUMMARY
          echo "|------|--------|" >> $GITHUB_STEP_SUMMARY
          echo "| TFLint | ${{ needs.tflint.result }} |" >> $GITHUB_STEP_SUMMARY
          echo "| tfsec | ${{ needs.tfsec.result }} |" >> $GITHUB_STEP_SUMMARY
          echo "| Checkov | ${{ needs.checkov.result }} |" >> $GITHUB_STEP_SUMMARY
          echo "| Terrascan | ${{ needs.terrascan.result }} |" >> $GITHUB_STEP_SUMMARY
          echo "| Snyk | ${{ needs.snyk.result }} |" >> $GITHUB_STEP_SUMMARY
          echo "| Secret Scanning | ${{ needs.secret-scanning.result }} |" >> $GITHUB_STEP_SUMMARY
```


### Open Policy Agent (OPA) Policies

```rego
# policies/terraform.rego

package terraform

# Deny S3 buckets without encryption
deny[msg] {
  resource := input.planned_values.root_module.resources[_]
  resource.type == "aws_s3_bucket"
  not has_encryption(resource)
  
  msg := sprintf("S3 bucket '%s' must have encryption enabled", [resource.name])
}

has_encryption(resource) {
  input.configuration.root_module.resources[_].expressions.server_side_encryption_configuration
}

# Deny security groups with 0.0.0.0/0 ingress
deny[msg] {
  resource := input.planned_values.root_module.resources[_]
  resource.type == "aws_security_group"
  rule := resource.values.ingress[_]
  rule.cidr_blocks[_] == "0.0.0.0/0"
  
  msg := sprintf("Security group '%s' allows unrestricted ingress from 0.0.0.0/0", [resource.name])
}

# Deny RDS without encryption
deny[msg] {
  resource := input.planned_values.root_module.resources[_]
  resource.type == "aws_db_instance"
  not resource.values.storage_encrypted
  
  msg := sprintf("RDS instance '%s' must have storage encryption enabled", [resource.name])
}

# Deny IAM policies with overly permissive actions
deny[msg] {
  resource := input.planned_values.root_module.resources[_]
  resource.type == "aws_iam_policy"
  policy := json.unmarshal(resource.values.policy)
  statement := policy.Statement[_]
  statement.Effect == "Allow"
  statement.Action[_] == "*"
  
  msg := sprintf("IAM policy '%s' contains overly permissive wildcard action", [resource.name])
}

# Require tags on all resources
deny[msg] {
  resource := input.planned_values.root_module.resources[_]
  taggable_resources := ["aws_instance", "aws_s3_bucket", "aws_db_instance", "aws_lb"]
  resource.type == taggable_resources[_]
  not resource.values.tags.Environment
  
  msg := sprintf("Resource '%s' of type '%s' must have 'Environment' tag", [resource.name, resource.type])
}
```


## Static Analysis and Dynamic Scanning with AWS Services

### AWS Config Rules for Compliance

```hcl
# aws-security/config-rules.tf

# Enable AWS Config
resource "aws_config_configuration_recorder" "main" {
  name     = "${var.environment}-config-recorder"
  role_arn = aws_iam_role.config.arn
  
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${var.environment}-config-delivery"
  s3_bucket_name = aws_s3_bucket.config.id
  sns_topic_arn  = aws_sns_topic.config.arn
  
  snapshot_delivery_properties {
    delivery_frequency = "Six_Hours"
  }
  
  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  
  depends_on = [aws_config_delivery_channel.main]
}

# Managed Config Rules
resource "aws_config_config_rule" "s3_bucket_public_read_prohibited" {
  name = "s3-bucket-public-read-prohibited"
  
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
  
  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "s3_bucket_encryption_enabled" {
  name = "s3-bucket-server-side-encryption-enabled"
  
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }
  
  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "rds_storage_encrypted" {
  name = "rds-storage-encrypted"
  
  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }
  
  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "ec2_imdsv2_check" {
  name = "ec2-imdsv2-check"
  
  source {
    owner             = "AWS"
    source_identifier = "EC2_IMDSV2_CHECK"
  }
  
  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "iam_password_policy" {
  name = "iam-password-policy"
  
  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }
  
  input_parameters = jsonencode({
    RequireUppercaseCharacters = true
    RequireLowercaseCharacters = true
    RequireSymbols             = true
    RequireNumbers             = true
    MinimumPasswordLength      = 14
    PasswordReusePrevention    = 24
    MaxPasswordAge             = 90
  })
  
  depends_on = [aws_config_configuration_recorder.main]
}

# Custom Config Rule (Lambda-based)
resource "aws_config_config_rule" "terraform_managed_resources" {
  name        = "terraform-managed-resources"
  description = "Checks if resources are managed by Terraform"
  
  source {
    owner             = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.config_rule_terraform_check.arn
    
    source_detail {
      event_source = "aws.config"
      message_type = "ConfigurationItemChangeNotification"
    }
  }
  
  scope {
    compliance_resource_types = [
      "AWS::EC2::Instance",
      "AWS::RDS::DBInstance",
      "AWS::S3::Bucket"
    ]
  }
  
  depends_on = [
    aws_config_configuration_recorder.main,
    aws_lambda_permission.config_rule
  ]
}

resource "aws_lambda_function" "config_rule_terraform_check" {
  filename      = "config_rule.zip"
  function_name = "${var.environment}-config-terraform-check"
  role          = aws_iam_role.config_rule_lambda.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 60
  
  environment {
    variables = {
      REQUIRED_TAG_KEY = "ManagedBy"
      REQUIRED_TAG_VALUE = "Terraform"
    }
  }
  
  tags = local.common_tags
}

resource "aws_lambda_permission" "config_rule" {
  statement_id  = "AllowExecutionFromConfig"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.config_rule_terraform_check.function_name
  principal     = "config.amazonaws.com"
}

# AWS Security Hub
resource "aws_securityhub_account" "main" {}

resource "aws_securityhub_standards_subscription" "cis" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
}

resource "aws_securityhub_standards_subscription" "pci_dss" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/pci-dss/v/3.2.1"
}

# Amazon Inspector
resource "aws_inspector2_enabler" "main" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["EC2", "ECR", "LAMBDA"]
}

# GuardDuty
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  
  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }
  
  tags = local.common_tags
}

# EventBridge Rule for Security Hub Findings
resource "aws_cloudwatch_event_rule" "security_hub_findings" {
  name        = "${var.environment}-security-hub-findings"
  description = "Capture critical Security Hub findings"
  
  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["CRITICAL", "HIGH"]
        }
        Compliance = {
          Status = ["FAILED"]
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "security_hub_sns" {
  rule      = aws_cloudwatch_event_rule.security_hub_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.security_critical.arn
}

# Automated Remediation with Systems Manager
resource "aws_ssm_document" "remediate_s3_public_access" {
  name            = "${var.environment}-remediate-s3-public-access"
  document_type   = "Automation"
  document_format = "YAML"
  
  content = <<DOC
schemaVersion: '0.3'
description: Remediate S3 bucket public access
assumeRole: '${aws_iam_role.remediation.arn}'
parameters:
  BucketName:
    type: String
    description: Name of S3 bucket to remediate
mainSteps:
  - name: BlockPublicAccess
    action: 'aws:executeAwsApi'
    inputs:
      Service: s3
      Api: PutPublicAccessBlock
      Bucket: '{{ BucketName }}'
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        IgnorePublicAcls: true
        BlockPublicPolicy: true
        RestrictPublicBuckets: true
DOC
  
  tags = local.common_tags
}

# CloudWatch Events for Auto-Remediation
resource "aws_cloudwatch_event_rule" "s3_public_access_detected" {
  name        = "${var.environment}-s3-public-access-detected"
  description = "Trigger remediation when S3 bucket becomes public"
  
  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      configRuleName = [aws_config_config_rule.s3_bucket_public_read_prohibited.name]
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "remediate_s3_public" {
  rule     = aws_cloudwatch_event_rule.s3_public_access_detected.name
  arn      = "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:automation-definition/${aws_ssm_document.remediate_s3_public_access.name}:$DEFAULT"
  role_arn = aws_iam_role.eventbridge_ssm.arn
  
  run_command_targets {
    key    = "tag:Environment"
    values = [var.environment]
  }
}

## ⚠️ Common Security Pitfalls

### Pitfall 1: Secrets Hardcoded in Variables

**❌ PROBLEM:**

```hcl
# variables.tf
variable "database_password" {
  description = "Database master password"
  type        = string
  default     = "SuperSecret123!"  # HARDCODED!
}

# terraform.tfvars (COMMITTED TO GIT!)
database_password = "ProductionPassword456!"

# Problems:
# - Visible in Git history forever
# - Exposed in plan output
# - Stored in state file
# - Visible to anyone with repo access
```

**✅ SOLUTION:**

```hcl
# variables.tf
variable "database_password_secret_arn" {
  description = "ARN of Secrets Manager secret containing database password"
  type        = string
}

# Data source to retrieve secret
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = var.database_password_secret_arn
}

locals {
  db_password = jsondecode(data.aws_secretsmanager_secret_version.db_password.secret_string).password
}

# Use in resource
resource "aws_db_instance" "main" {
  password = local.db_password
  
  lifecycle {
    ignore_changes = [password]
  }
}

# Pass ARN (not secret) via environment variable or Terraform Cloud
# export TF_VAR_database_password_secret_arn="arn:aws:secretsmanager:..."
```


### Pitfall 2: State File in Version Control

**❌ PROBLEM:**

```bash
# .gitignore is missing or incomplete
git add .
git commit -m "Initial commit"
# terraform.tfstate committed with ALL secrets in plaintext!

# Once in Git history, secrets are PERMANENT
# Even after deletion, accessible via:
git log --all --full-history -- terraform.tfstate
```

**✅ SOLUTION:**

```bash
# .gitignore (ADD BEFORE FIRST COMMIT!)
**/.terraform/*
*.tfstate
*.tfstate.*
crash.log
crash.*.log
*.tfvars
*.tfvars.json
override.tf
override.tf.json
*_override.tf
*_override.tf.json
.terraformrc
terraform.rc

# Use remote state from day 1
# backend.tf
terraform {
  backend "s3" {
    bucket         = "myorg-terraform-state"
    key            = "production/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/..."
    dynamodb_table = "terraform-locks"
  }
}

# If already committed state file:
# 1. Rotate ALL secrets immediately
# 2. Use git-filter-repo to remove from history
pip install git-filter-repo
git filter-repo --path terraform.tfstate --invert-paths
# 3. Force push (coordinate with team!)
git push --force --all
```


### Pitfall 3: Overly Permissive IAM Policies

**❌ PROBLEM:**

```hcl
# Terraform deployer with admin access
resource "aws_iam_role_policy_attachment" "terraform_admin" {
  role       = aws_iam_role.terraform.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
  # Can delete production database
  # Can modify billing
  # Can create users with admin access
  # Privilege escalation possible
}
```

**✅ SOLUTION:**

```hcl
# Scoped permissions with permission boundary
resource "aws_iam_policy" "terraform_deployment" {
  name = "TerraformDeployment"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowSpecificServices"
        Effect   = "Allow"
        Action   = [
          "ec2:*",
          "rds:*",
          "s3:*",
          "elasticloadbalancing:*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = ["us-east-1", "us-west-2"]
          }
        }
      },
      {
        Sid    = "DenyDangerousActions"
        Effect = "Deny"
        Action = [
          "iam:CreateUser",
          "iam:DeleteUser",
          "iam:AttachUserPolicy",
          "rds:DeleteDBInstance",
          "s3:DeleteBucket"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "terraform" {
  name                 = "TerraformDeployer"
  permissions_boundary = aws_iam_policy.permission_boundary.arn
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${var.cicd_account}:role/GithubActions"
      }
      Action = "sts:AssumeRole"
      Condition = {
        Bool = {
          "aws:MultiFactorAuthPresent" = "true"
        }
      }
    }]
  })
}
```


### Pitfall 4: Not Using Sensitive Attribute

**❌ PROBLEM:**

```hcl
output "database_connection_string" {
  value = "postgresql://${aws_db_instance.main.username}:${aws_db_instance.main.password}@${aws_db_instance.main.endpoint}"
  # Password visible in:
  # - terraform output command
  # - CI/CD logs
  # - Terraform Cloud UI
}

# Console output:
# database_connection_string = "postgresql://admin:MyPassword123@db.amazonaws.com"
```

**✅ SOLUTION:**

```hcl
# Mark output as sensitive
output "database_connection_string" {
  value = "postgresql://${aws_db_instance.main.username}:${aws_db_instance.main.password}@${aws_db_instance.main.endpoint}"
  sensitive = true
  # Output shows: database_connection_string = <sensitive>
}

# Better: Output secret ARN instead
output "database_secret_arn" {
  value       = aws_secretsmanager_secret.database.arn
  description = "ARN of secret containing database connection info"
  # Application retrieves at runtime
}

# Mark variables as sensitive
variable "api_key" {
  type      = string
  sensitive = true
  # Never logged or displayed
}

# Mark locals as sensitive
locals {
  admin_password = sensitive(random_password.admin.result)
}
```


### Pitfall 5: Unencrypted Remote State

**❌ PROBLEM:**

```hcl
terraform {
  backend "s3" {
    bucket = "my-terraform-state"
    key    = "production/terraform.tfstate"
    region = "us-east-1"
    # No encryption!
    # No KMS key!
    # State readable by anyone with S3 access
  }
}
```

**✅ SOLUTION:**

```hcl
terraform {
  backend "s3" {
    bucket         = "my-terraform-state"
    key            = "production/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true  # Enable SSE
    kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
    dynamodb_table = "terraform-locks"
    
    # Additional security
    acl            = "private"
    
    # Use IAM role instead of access keys
    role_arn = "arn:aws:iam::123456789012:role/TerraformStateAccess"
    
    # Skip credential validation for assumed roles
    skip_credentials_validation = false
    skip_metadata_api_check     = false
    skip_region_validation      = false
  }
}

# Ensure S3 bucket has encryption enabled
resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = "my-terraform-state"
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.state.arn
    }
    bucket_key_enabled = true
  }
}
```


### Pitfall 6: Missing Security Scanning in CI/CD

**❌ PROBLEM:**

```yaml
# .github/workflows/deploy.yml
name: Deploy Infrastructure

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Terraform Apply
        run: terraform apply -auto-approve
        # No security scanning!
        # Misconfigurations deployed directly to production!
```

**✅ SOLUTION:**

```yaml
# .github/workflows/deploy.yml
name: Deploy Infrastructure

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      # Multiple security tools
      - name: Run tfsec
        uses: aquasecurity/tfsec-action@v1.0.3
        with:
          soft_fail: false
      
      - name: Run Checkov
        uses: bridgecrewio/checkov-action@v12
        with:
          soft_fail: false
      
      - name: Secret Scanning
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: main
          head: HEAD
  
  terraform-plan:
    needs: security-scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Terraform Plan
        run: terraform plan -out=tfplan
      
      - name: Scan Plan with OPA
        run: |
          docker run --rm -v $(pwd):/project \
            openpolicyagent/opa:latest eval \
            -i /project/tfplan.json \
            -d /project/policies/ \
            "data.terraform.deny"
  
  deploy:
    needs: terraform-plan
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
      - name: Terraform Apply
        run: terraform apply tfplan
```


### Pitfall 7: No Audit Trail for Infrastructure Changes

**❌ PROBLEM:**

```hcl
# Infrastructure changes with no tracking
# Who made the change?
# When was it made?
# What was changed?
# Why was it changed?

# No CloudTrail
# No state access logs
# No change notifications
```

**✅ SOLUTION:**

```hcl
# Enable CloudTrail for all API calls
resource "aws_cloudtrail" "main" {
  name                          = "${var.environment}-audit-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
  
  insight_selector {
    insight_type = "ApiCallRateInsight"
  }
  
  tags = local.common_tags
}

# S3 bucket access logging for state
resource "aws_s3_bucket_logging" "state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  target_bucket = aws_s3_bucket.state_logs.id
  target_prefix = "state-access-logs/"
}

# EventBridge rule for state changes
resource "aws_cloudwatch_event_rule" "state_changes" {
  name = "${var.environment}-terraform-state-changes"
  
  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["PutObject", "DeleteObject"]
      requestParameters = {
        bucketName = [aws_s3_bucket.terraform_state.id]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "state_changes_sns" {
  rule      = aws_cloudwatch_event_rule.state_changes.name
  target_id = "NotifySecurityTeam"
  arn       = aws_sns_topic.security_audit.arn
  
  input_transformer {
    input_paths = {
      user      = "$.detail.userIdentity.principalId"
      time      = "$.time"
      bucket    = "$.detail.requestParameters.bucketName"
      key       = "$.detail.requestParameters.key"
      eventName = "$.detail.eventName"
    }
    input_template = <<EOF
"Terraform state change detected:
User: <user>
Action: <eventName>
Bucket: <bucket>
Key: <key>
Time: <time>"
EOF
  }
}

# Store metadata about changes
resource "null_resource" "change_metadata" {
  triggers = {
    timestamp = timestamp()
  }
  
  provisioner "local-exec" {
    command = <<-EOT
      aws s3api put-object-tagging \
        --bucket ${aws_s3_bucket.terraform_state.id} \
        --key ${var.environment}/terraform.tfstate \
        --tagging 'TagSet=[
          {Key=LastModifiedBy,Value=${var.deployer_name}},
          {Key=ChangeTicket,Value=${var.change_ticket}},
          {Key=DeploymentPipeline,Value=${var.ci_cd_run_id}}
        ]'
    EOT
  }
}
```


### Pitfall 8: Not Rotating Secrets

**❌ PROBLEM:**

```hcl
# Database password created once, never rotated
resource "random_password" "db_password" {
  length  = 32
  special = true
}

resource "aws_db_instance" "main" {
  password = random_password.db_password.result
}

# Password never changes
# If compromised, remains valid indefinitely
# No rotation policy
```

**✅ SOLUTION:**

```hcl
# Secrets Manager with automatic rotation
resource "aws_secretsmanager_secret" "database" {
  name_prefix = "${var.environment}-db-password-"
  
  # Enable automatic rotation
  rotation_lambda_arn = aws_lambda_function.rotate_secret.arn
  rotation_rules {
    automatically_after_days = 30
  }
  
  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "database" {
  secret_id     = aws_secretsmanager_secret.database.id
  secret_string = jsonencode({
    username = "dbadmin"
    password = random_password.db_password.result
  })
  
  lifecycle {
    ignore_changes = [secret_string]  # Rotation updates this
  }
}

# Lambda function for rotation (see earlier section)
resource "aws_lambda_function" "rotate_secret" {
  filename      = "rotate_secret.zip"
  function_name = "${var.environment}-rotate-db-secret"
  role          = aws_iam_role.rotation.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.11"
  timeout       = 300
  
  tags = local.common_tags
}

# CloudWatch alarm for failed rotations
resource "aws_cloudwatch_metric_alarm" "rotation_failed" {
  alarm_name          = "${var.environment}-secret-rotation-failed"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Secret rotation Lambda function failed"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  
  dimensions = {
    FunctionName = aws_lambda_function.rotate_secret.function_name
  }
}
```


### Pitfall 9: No Security Baseline Enforcement

**❌ PROBLEM:**

```hcl
# Every developer implements security differently
# No consistent security standards
# Some resources encrypted, others not
# Inconsistent tagging
# No policy enforcement
```

**✅ SOLUTION:**

```hcl
# Service Control Policy (Organization Level)
resource "aws_organizations_policy" "security_baseline" {
  name        = "SecurityBaseline"
  description = "Enforce security baseline across all accounts"
  type        = "SERVICE_CONTROL_POLICY"
  
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedS3"
        Effect = "Deny"
        Action = "s3:PutObject"
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = ["AES256", "aws:kms"]
          }
        }
      },
      {
        Sid    = "DenyUnencryptedRDS"
        Effect = "Deny"
        Action = "rds:CreateDBInstance"
        Resource = "*"
        Condition = {
          Bool = {
            "rds:StorageEncrypted" = "false"
          }
        }
      },
      {
        Sid    = "RequireIMDSv2"
        Effect = "Deny"
        Action = "ec2:RunInstances"
        Resource = "arn:aws:ec2:*:*:instance/*"
        Condition = {
          StringNotEquals = {
            "ec2:MetadataHttpTokens" = "required"
          }
        }
      },
      {
        Sid    = "RequireTags"
        Effect = "Deny"
        Action = [
          "ec2:RunInstances",
          "rds:CreateDBInstance",
          "s3:CreateBucket"
        ]
        Resource = "*"
        Condition = {
          Null = {
            "aws:RequestTag/Environment" = "true"
          }
        }
      }
    ]
  })
}

# Terraform validation with custom checks
# custom-checks/encryption.rego
package terraform

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket"
  not has_encryption_config(resource)
  
  msg := sprintf("S3 bucket %s must have encryption configuration", [resource.address])
}

has_encryption_config(resource) {
  resource.change.after.server_side_encryption_configuration
}

# Pre-commit hook to enforce checks
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: terraform-security-baseline
        name: Terraform Security Baseline
        entry: bash -c 'terraform plan -out=tfplan && terraform show -json tfplan | conftest test --policy custom-checks -'
        language: system
        pass_filenames: false
```


### Pitfall 10: Ephemeral Values Not Used for Secrets

**❌ PROBLEM:**

```hcl
# Using traditional approach (secrets in state)
resource "random_password" "api_key" {
  length  = 32
  special = false
}

resource "aws_api_gateway_api_key" "main" {
  name  = "production-key"
  value = random_password.api_key.result
  # Password stored in state file!
}

# State file contains:
# "random_password.api_key": {
#   "result": "abc123xyz789..."
# }
```

**✅ SOLUTION:**

```hcl
# Terraform 1.11+ ephemeral values
ephemeral "random_password" "api_key" {
  length  = 32
  special = false
}

# Store in Secrets Manager with write-only
resource "aws_secretsmanager_secret_version" "api_key" {
  secret_id            = aws_secretsmanager_secret.api_key.id
  secret_string_wo     = ephemeral.random_password.api_key.result
  secret_string_wo_version = 1
  # Never stored in state!
}

# Retrieve ephemerally when needed
ephemeral "aws_secretsmanager_secret_version" "api_key" {
  secret_id  = aws_secretsmanager_secret.api_key.id
  depends_on = [aws_secretsmanager_secret_version.api_key]
}

# Use ephemeral value
resource "aws_api_gateway_api_key" "main" {
  name  = "production-key"
  value = ephemeral.aws_secretsmanager_secret_version.api_key.secret_string
  # Value exists only during apply, never persisted
}
```


## 💡 Expert Security Tips from the Field

1. **"Use AWS Systems Manager Session Manager instead of SSH keys"** - No keys to manage, full audit trail in CloudTrail, no bastion hosts needed. Works with IMDSv2 and eliminates port 22 exposure.
2. **"Enable S3 Block Public Access at account level"** - Even if bucket policy allows public access, account-level block overrides it. Prevents accidental public exposure across all buckets.
3. **"Use aws:PrincipalOrgID in policies for cross-account access"** - Automatically allows all accounts in your organization without maintaining list of account IDs. Updates automatically when accounts added/removed.
4. **"Implement state file versioning with lifecycle rules"** - Keep 90 days of versions in Standard, transition older to Glacier. Allows recovery from any point without excessive S3 costs.
5. **"Use Terraform Cloud/Enterprise for centralized state management"** - Built-in encryption, access controls, audit logs, state versioning, and remote execution. Eliminates need to manage S3/DynamoDB backend.
6. **"Enable AWS Config aggregator for multi-account compliance"** - Single pane of glass for compliance across all accounts. Automatically discovers non-compliant resources organization-wide.
7. **"Use IAM permission boundaries for delegated admin"** - Junior engineers can create roles but cannot exceed boundary. Prevents privilege escalation while enabling self-service.
8. **"Implement break-glass procedures for emergency access"** - MFA-protected admin role that triggers PagerDuty alert when used. Only for production outages, every use audited.
9. **"Use AWS Secrets Manager rotation for RDS, Redshift, DocumentDB"** - AWS provides Lambda functions for automatic rotation. No custom code needed, works out of the box.
10. **"Enable S3 Object Lock for state files in regulated industries"** - Immutable state versions for 7 days prevents tampering. Required for FINRA, HIPAA, SEC compliance.
11. **"Use KMS key policies, not IAM policies alone"** - KMS key policy is ultimate authority. IAM policy can grant access but key policy must also allow. Defense in depth.
12. **"Implement sentinel policies in Terraform Cloud"** - Policy as code that runs before apply. Can enforce security standards, cost limits, and organizational policies automatically.
13. **"Use AWS Control Tower for multi-account governance"** - Pre-configured guardrails, account factory, centralized logging. Sets up secure baseline automatically across organization.
14. **"Enable GuardDuty malware protection for EBS volumes"** - Scans EC2 instance volumes for malware when GuardDuty detects suspicious behavior. Automatic threat detection and response.
15. **"Use AWS Security Hub for centralized security posture"** - Aggregates findings from GuardDuty, Inspector, Macie, Config, IAM Access Analyzer. Single dashboard for all security issues.
16. **"Implement Infrastructure as Code scanning in IDE"** - VS Code extensions for Checkov, tfsec run as you type. Catch security issues before commit, not after deployment.
17. **"Use ephemeral resources for database connections"** - Connection credentials never in state. Retrieve from Secrets Manager ephemerally, use, and discard. Zero-trust approach.
18. **"Enable AWS CloudTrail Insights for anomaly detection"** - ML-powered detection of unusual API activity. Automatically identifies potential security incidents based on historical patterns.
19. **"Use AWS Organizations SCPs to deny region access"** - Prevent resources from being created in non-approved regions. Ensures data sovereignty and reduces attack surface.
20. **"Implement least privilege with IAM Access Analyzer"** - Continuously analyzes IAM policies, identifies unused permissions. Automatically generates least-privilege policies based on actual usage.

## 🎯 Practical Security Exercises

### Exercise 1: Implement Secure Remote State

**Difficulty:** Beginner
**Time:** 30 minutes
**Objective:** Set up encrypted S3 backend with DynamoDB locking

**Steps:**

1. Create secure state infrastructure:
```bash
mkdir secure-state-setup
cd secure-state-setup
```

2. Use the S3 backend setup code from earlier in this chapter
3. Deploy state infrastructure:
```bash
terraform init
terraform apply
```

4. Migrate existing local state:
```bash
# In project directory
terraform init -migrate-state
# Confirm migration
```

5. Verify encryption:
```bash
aws s3api head-object \
  --bucket myorg-terraform-state \
  --key production/terraform.tfstate

# Should show:
# "ServerSideEncryption": "aws:kms"
```

**Validation:**

- State file encrypted in S3 with KMS
- DynamoDB table exists for locking
- S3 versioning enabled
- Public access blocked
- Access logging enabled

**Challenge:** Set up cross-region replication for disaster recovery.

### Exercise 2: Implement Ephemeral Secrets

**Difficulty:** Intermediate
**Time:** 45 minutes
**Objective:** Convert traditional secrets to ephemeral values (Terraform 1.11+)

**Prerequisites:**

- Terraform 1.11.0 or later
- AWS account with Secrets Manager access

**Steps:**

1. Create project with traditional secrets:
```hcl
# Before (secrets in state)
resource "random_password" "db" {
  length = 32
}

resource "aws_db_instance" "main" {
  password = random_password.db.result
}
```

2. Refactor to ephemeral:
```hcl
# After (secrets never in state)
ephemeral "random_password" "db" {
  length = 32
}

resource "aws_secretsmanager_secret_version" "db" {
  secret_id            = aws_secretsmanager_secret.db.id
  secret_string_wo     = ephemeral.random_password.db.result
  secret_string_wo_version = 1
}

ephemeral "aws_secretsmanager_secret_version" "db" {
  secret_id  = aws_secretsmanager_secret.db.id
  depends_on = [aws_secretsmanager_secret_version.db]
}

resource "aws_db_instance" "main" {
  password = jsondecode(ephemeral.aws_secretsmanager_secret_version.db.secret_string).password
}
```

3. Apply and verify:
```bash
terraform apply
grep -i password terraform.tfstate  # Should find nothing
```

**Validation:**

- No passwords in state file
- Secrets stored in Secrets Manager
- Database connects successfully
- Terraform plan shows no changes

**Challenge:** Implement automatic secret rotation with Lambda.

### Exercise 3: Set Up Security Scanning Pipeline

**Difficulty:** Intermediate
**Time:** 60 minutes
**Objective:** Implement multi-tool security scanning in CI/CD

**Steps:**

1. Install pre-commit hooks:
```bash
pip install pre-commit
pre-commit install
```

2. Configure scanning tools (use earlier .pre-commit-config.yaml)
3. Set up GitHub Actions workflow (use earlier security pipeline YAML)
4. Create intentional security issues:
```hcl
# Trigger security violations
resource "aws_s3_bucket" "bad" {
  bucket = "intentionally-public"
  # No encryption
  # No public access block
}

resource "aws_security_group" "bad" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Open to world
  }
}
```

5. Commit and observe failures:
```bash
git add .
git commit -m "Test security scanning"
# Pre-commit hooks should fail
```

6. Fix issues:
```hcl
resource "aws_s3_bucket" "good" {
  bucket = "secure-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "good" {
  bucket = aws_s3_bucket.good.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "good" {
  bucket = aws_s3_bucket.good.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

**Validation:**

- All security scanners pass
- No secrets detected
- Encryption enforced
- Public access blocked

**Challenge:** Add custom OPA policies for organization-specific rules.

### Exercise 4: Implement Least Privilege IAM

**Difficulty:** Advanced
**Time:** 50 minutes
**Objective:** Create scoped IAM policies with permission boundaries

**Steps:**

1. Analyze current permissions:
```bash
# Use IAM Access Analyzer
aws accessanalyzer list-analyzers
aws accessanalyzer list-findings --analyzer-arn <arn>
```

2. Create least-privilege policy:
```hcl
# Use IAM policy examples from earlier in chapter
```

3. Test with IAM Policy Simulator:
```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:role/TerraformDeployer \
  --action-names ec2:TerminateInstances rds:DeleteDBInstance \
  --resource-arns "*"
```

4. Implement permission boundary:
```hcl
# Add permission boundary to prevent escalation
resource "aws_iam_role" "terraform" {
  name                 = "TerraformDeployer"
  permissions_boundary = aws_iam_policy.boundary.arn
}
```

5. Verify restrictions:
```bash
# Attempt to create admin user (should fail)
aws iam create-user --user-name admin-user \
  --role-session-name TerraformTest
# Should return AccessDenied
```

**Validation:**

- Can perform required operations
- Cannot perform dangerous operations
- Permission boundary prevents escalation
- IAM Access Analyzer shows no unused permissions

**Challenge:** Implement dynamic IAM policies using session tags.

### Exercise 5: Enable AWS Security Services

**Difficulty:** Advanced
**Time:** 45 minutes
**Objective:** Deploy Security Hub, GuardDuty, Config, and Inspector

**Steps:**

1. Use AWS security service configurations from earlier in chapter
2. Enable services:
```bash
terraform apply
```

3. Configure aggregation:
```hcl
# Security Hub aggregation across regions
resource "aws_securityhub_finding_aggregator" "main" {
  linking_mode = "ALL_REGIONS"
}
```

4. Create remediation automation:
```hcl
# Use SSM automation document from earlier
```

5. Test security findings:
```bash
# Create intentional violation
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxx \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Wait for Security Hub finding
aws securityhub get-findings \
  --filters '{"ResourceId":[{"Value":"sg-xxxxx","Comparison":"EQUALS"}]}'
```

**Validation:**

- All security services enabled
- Findings appearing in Security Hub
- Auto-remediation triggered
- Notifications sent to SNS

**Challenge:** Implement custom Lambda function for advanced remediation logic.

## Key Security Takeaways

- Principle of least privilege must be implemented at every layer: IAM policies with permission boundaries prevent privilege escalation, resource-level conditions restrict actions to specific ARNs, and Service Control Policies provide organization-wide guardrails that cannot be bypassed
- Ephemeral values in Terraform 1.11+ fundamentally change secret management by ensuring sensitive data never persists in state files, plan outputs, or logs while maintaining full functionality through runtime-only access patterns
- Remote state encryption with S3 SSE-KMS, DynamoDB state locking, S3 versioning, and cross-region replication provides defense-in-depth for infrastructure state that often contains sensitive connection strings and resource identifiers
- Multi-tool security scanning with tfsec, Checkov, Terrascan, and Snyk in CI/CD pipelines catches 95% of common misconfigurations before deployment, preventing security incidents that cost millions to remediate in production
- AWS-native security services (Security Hub, GuardDuty, Config, Inspector) provide continuous monitoring and automated remediation with zero infrastructure overhead, detecting threats and compliance violations in real-time
- Secrets Manager automatic rotation with Lambda functions eliminates the most common attack vector (compromised static credentials) by ensuring all passwords, keys, and tokens rotate every 30 days without manual intervention
- Audit trails through CloudTrail, S3 access logs, state modification notifications, and EventBridge rules create comprehensive forensic capabilities that satisfy SOC2, PCI-DSS, and HIPAA compliance requirements


## What's Next

With security fundamentals mastered, you're ready to build reusable, maintainable infrastructure components. In **Chapter 7: Terraform Modules**, you'll learn module design patterns, versioning strategies, private registry implementation, composition patterns for complex architectures, testing methodologies, and upgrade strategies for production modules. Security practices from this chapter become embedded in modules, creating secure-by-default infrastructure that scales across teams and projects.

## Additional Resources

**Official Documentation:**

- [Terraform Security Best Practices](https://developer.hashicorp.com/terraform/language/manage-sensitive-data) - HashiCorp security guidelines
- [AWS Security Best Practices](https://aws.amazon.com/security/best-practices/) - AWS security baseline
- [Terraform Ephemeral Values](https://developer.hashicorp.com/terraform/language/manage-sensitive-data/write-only) - Write-only arguments guide

**Security Scanning Tools:**

- [Checkov Documentation](https://www.checkov.io/documentation.html) - Policy-as-code scanner
- [tfsec](https://github.com/aquasecurity/tfsec) - Static analysis for Terraform
- [Terrascan](https://github.com/tenable/terrascan) - IaC vulnerability scanner
- [Snyk IaC](https://snyk.io/product/infrastructure-as-code-security/) - Developer-first security

**AWS Security Services:**

- [AWS Security Hub](https://docs.aws.amazon.com/securityhub/) - Centralized security management
- [Amazon GuardDuty](https://docs.aws.amazon.com/guardduty/) - Threat detection service
- [AWS Config](https://docs.aws.amazon.com/config/) - Resource compliance monitoring
- [Amazon Inspector](https://docs.aws.amazon.com/inspector/) - Vulnerability management

**Secrets Management:**

- [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/) - Secrets lifecycle management
- [HashiCorp Vault](https://www.vaultproject.io/) - Enterprise secrets management
- [AWS Systems Manager Parameter Store](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html) - Configuration data store

**Policy as Code:**

- [Open Policy Agent](https://www.openpolicyagent.org/) - Policy engine for cloud-native
- [Sentinel](https://www.hashicorp.com/sentinel) - HashiCorp policy framework
- [AWS Config Rules](https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config.html) - AWS-native compliance

**Compliance Frameworks:**

- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services) - Security hardening
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/) - Security best practices
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) - Enterprise security standards

***

**Security is not a feature—it's a requirement.** Every line of Terraform code creates either a secure resource or a potential vulnerability. Use ephemeral values for secrets, scan with multiple tools, implement least privilege, encrypt everything at rest and in transit, and automate compliance monitoring. The time to fix a security vulnerability is during development, not after a breach. Build security into your infrastructure from the first terraform init, not as an afterthought.



