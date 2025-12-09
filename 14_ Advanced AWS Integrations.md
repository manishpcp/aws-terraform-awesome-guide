# Chapter 14: Advanced AWS Integrations

## Introduction

Basic Terraform usage creates individual AWS resources—a VPC here, an EC2 instance there, an S3 bucket somewhere else—but production systems require orchestrated integrations where resources communicate through events, secrets flow securely between services, containers deploy automatically, and workflows chain across multiple AWS services. Teams hitting this integration wall discover that provisioning infrastructure is the easy part; the challenge is wiring everything together so Lambda functions respond to EventBridge events, ECS tasks pull secrets from Secrets Manager, Step Functions orchestrate multi-step workflows, and Parameter Store provides configuration across hundreds of resources. Without systematic integration patterns, teams build brittle architectures with hardcoded ARNs, manual secret management, and resource coupling that makes changes risky.

Advanced AWS integrations transform infrastructure from isolated resources into cohesive systems. EventBridge rules automatically trigger Lambda functions when S3 objects arrive, passing event metadata through customizable patterns. Secrets Manager rotation workflows use Lambda to automatically update database credentials every 30 days, propagating changes to all connected applications without downtime. ECS Fargate tasks pull container images from ECR, inject secrets as environment variables, register with Application Load Balancers, and scale based on CloudWatch metrics—all configured through Terraform. Step Functions orchestrate multi-stage workflows combining Lambda, ECS, Glue, and SageMaker into reliable state machines that handle retries, error handling, and parallel execution.

This chapter covers production-grade patterns for integrating AWS services through Terraform. You'll learn EventBridge event-driven architectures connecting 20+ services through rules and targets, containerized Lambda deployments packaging functions with custom dependencies in Docker images pushed to ECR, ECS Fargate orchestration running stateless microservices behind load balancers, Systems Manager Parameter Store hierarchical configuration management, Secrets Manager automated credential rotation protecting production databases, and Step Functions workflow orchestration coordinating multi-service business processes. Whether you're building microservices architectures, serverless applications, or data processing pipelines, these patterns will help you compose AWS services into reliable, maintainable systems.

## EventBridge Event-Driven Architecture

### EventBridge Fundamentals

EventBridge enables event-driven architectures where services communicate asynchronously through events rather than tight coupling.

**Key Concepts:**


| Component | Description | Use Case |
| :-- | :-- | :-- |
| **Event Bus** | Central hub receiving and routing events | Separate buses per environment (dev/prod) |
| **Event Rule** | Pattern matching filter selecting events | "Process only S3 PUT events from bucket X" |
| **Event Target** | Destination receiving matched events | Lambda, SQS, SNS, Step Functions, ECS Task |
| **Event Pattern** | JSON filter defining which events to process | Match on source, detail type, specific fields |
| **Schedule Expression** | Cron/rate expression for time-based triggers | Run Lambda every 5 minutes |

### Basic EventBridge Architecture

**S3 Upload → EventBridge → Lambda Processing:**

```hcl
# eventbridge-s3-lambda.tf
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
  region = "us-east-1"
  
  default_tags {
    tags = {
      Project     = "eventbridge-integration"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# variables.tf
variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "document-processor"
}

# S3 bucket for uploads
resource "aws_s3_bucket" "uploads" {
  bucket = "${var.project_name}-uploads-${data.aws_caller_identity.current.account_id}"
}

# Enable EventBridge notifications on S3 bucket
resource "aws_s3_bucket_notification" "uploads_notification" {
  bucket      = aws_s3_bucket.uploads.id
  eventbridge = true
}

# Custom event bus (optional - can use default)
resource "aws_cloudwatch_event_bus" "application" {
  name = "${var.project_name}-event-bus"
}

# EventBridge rule matching S3 PutObject events
resource "aws_cloudwatch_event_rule" "s3_upload" {
  name           = "${var.project_name}-s3-upload-rule"
  description    = "Trigger Lambda on S3 object upload"
  event_bus_name = aws_cloudwatch_event_bus.application.name
  
  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["Object Created"]
    detail = {
      bucket = {
        name = [aws_s3_bucket.uploads.id]
      }
      object = {
        key = [{
          prefix = "documents/"  # Only process files in documents/ folder
        }]
      }
    }
  })
}

# Lambda function to process uploads
resource "aws_lambda_function" "processor" {
  filename         = "processor.zip"
  function_name    = "${var.project_name}-processor"
  role             = aws_iam_role.lambda_processor.arn
  handler          = "index.handler"
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = 512
  source_code_hash = filebase64sha256("processor.zip")
  
  environment {
    variables = {
      BUCKET_NAME = aws_s3_bucket.uploads.id
      ENVIRONMENT = var.environment
    }
  }
}

# IAM role for Lambda
resource "aws_iam_role" "lambda_processor" {
  name = "${var.project_name}-lambda-processor-role"
  
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

# Lambda CloudWatch Logs permissions
resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_processor.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Lambda S3 read permissions
resource "aws_iam_role_policy" "lambda_s3_read" {
  name = "s3-read-policy"
  role = aws_iam_role.lambda_processor.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion"
        ]
        Resource = "${aws_s3_bucket.uploads.arn}/*"
      }
    ]
  })
}

# EventBridge target: Lambda function
resource "aws_cloudwatch_event_target" "lambda" {
  rule           = aws_cloudwatch_event_rule.s3_upload.name
  event_bus_name = aws_cloudwatch_event_bus.application.name
  target_id      = "ProcessorLambda"
  arn            = aws_lambda_function.processor.arn
  
  retry_policy {
    maximum_retry_attempts = 3
    maximum_event_age      = 3600  # 1 hour
  }
  
  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

# Lambda permission for EventBridge
resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_upload.arn
}

# Dead letter queue for failed invocations
resource "aws_sqs_queue" "dlq" {
  name                      = "${var.project_name}-dlq"
  message_retention_seconds = 1209600  # 14 days
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

# outputs.tf
output "upload_bucket_name" {
  description = "S3 bucket name for uploads"
  value       = aws_s3_bucket.uploads.id
}

output "event_bus_name" {
  description = "EventBridge event bus name"
  value       = aws_cloudwatch_event_bus.application.name
}

output "lambda_function_name" {
  description = "Lambda processor function name"
  value       = aws_lambda_function.processor.function_name
}
```

**Lambda function (processor/index.py):**

```python
import json
import boto3
import os

s3 = boto3.client('s3')

def handler(event, context):
    """Process S3 upload events from EventBridge"""
    
    print(f"Received event: {json.dumps(event)}")
    
    # Extract S3 bucket and key from EventBridge event
    detail = event['detail']
    bucket_name = detail['bucket']['name']
    object_key = detail['object']['key']
    
    print(f"Processing file: s3://{bucket_name}/{object_key}")
    
    try:
        # Get object metadata
        response = s3.head_object(Bucket=bucket_name, Key=object_key)
        file_size = response['ContentLength']
        content_type = response.get('ContentType', 'unknown')
        
        print(f"File size: {file_size} bytes")
        print(f"Content type: {content_type}")
        
        # Download and process file
        obj = s3.get_object(Bucket=bucket_name, Key=object_key)
        content = obj['Body'].read()
        
        # Your processing logic here
        # Example: Count lines in text file
        if content_type.startswith('text/'):
            lines = content.decode('utf-8').split('\n')
            line_count = len(lines)
            print(f"File has {line_count} lines")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'File processed successfully',
                'file': object_key,
                'size': file_size
            })
        }
        
    except Exception as e:
        print(f"Error processing file: {str(e)}")
        raise
```

**Testing:**

```bash
# Deploy infrastructure
terraform init
terraform apply

# Upload test file
aws s3 cp test-document.txt s3://$(terraform output -raw upload_bucket_name)/documents/test-document.txt

# Check Lambda logs
aws logs tail /aws/lambda/$(terraform output -raw lambda_function_name) --follow

# Output:
# Received event: {"source": "aws.s3", "detail-type": "Object Created", ...}
# Processing file: s3://document-processor-uploads-123456789012/documents/test-document.txt
# File size: 1024 bytes
# Content type: text/plain
# File has 42 lines
```


### Multi-Target EventBridge Pattern

Route events to multiple targets (Lambda, SQS, SNS):

```hcl
# multi-target-eventbridge.tf

# EventBridge rule for critical events
resource "aws_cloudwatch_event_rule" "critical_events" {
  name        = "critical-system-events"
  description = "Route critical events to multiple destinations"
  
  event_pattern = jsonencode({
    source      = ["custom.application"]
    detail-type = ["Critical Error", "System Failure"]
    detail = {
      severity = ["CRITICAL", "HIGH"]
    }
  })
}

# Target 1: Lambda for immediate processing
resource "aws_cloudwatch_event_target" "lambda_immediate" {
  rule      = aws_cloudwatch_event_rule.critical_events.name
  target_id = "ImmediateLambda"
  arn       = aws_lambda_function.immediate_handler.arn
}

# Target 2: SQS for async processing
resource "aws_cloudwatch_event_target" "sqs_async" {
  rule      = aws_cloudwatch_event_rule.critical_events.name
  target_id = "AsyncQueue"
  arn       = aws_sqs_queue.async_processing.arn
}

# Target 3: SNS for alerts
resource "aws_cloudwatch_event_target" "sns_alerts" {
  rule      = aws_cloudwatch_event_rule.critical_events.name
  target_id = "AlertTopic"
  arn       = aws_sns_topic.alerts.arn
  
  input_transformer {
    input_paths = {
      severity = "$.detail.severity"
      message  = "$.detail.message"
      source   = "$.source"
    }
    
    input_template = <<EOF
{
  "alert": "Critical Event Detected",
  "severity": <severity>,
  "message": <message>,
  "source": <source>,
  "timestamp": "$.time"
}
EOF
  }
}

# Target 4: CloudWatch Logs for audit trail
resource "aws_cloudwatch_event_target" "cloudwatch_logs" {
  rule      = aws_cloudwatch_event_rule.critical_events.name
  target_id = "AuditLogs"
  arn       = aws_cloudwatch_log_group.event_audit.arn
}

# Lambda for immediate handling
resource "aws_lambda_function" "immediate_handler" {
  filename      = "immediate_handler.zip"
  function_name = "critical-event-immediate-handler"
  role          = aws_iam_role.lambda_immediate.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 30
}

# SQS queue for async processing
resource "aws_sqs_queue" "async_processing" {
  name                       = "critical-events-async-queue"
  visibility_timeout_seconds = 300
  message_retention_seconds  = 1209600  # 14 days
}

# SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "critical-event-alerts"
}

# SNS email subscription
resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# CloudWatch log group for audit
resource "aws_cloudwatch_log_group" "event_audit" {
  name              = "/aws/events/critical-audit"
  retention_in_days = 90
}

# IAM permissions for EventBridge to invoke targets
resource "aws_sqs_queue_policy" "eventbridge_sqs" {
  queue_url = aws_sqs_queue.async_processing.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.async_processing.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.critical_events.arn
          }
        }
      }
    ]
  })
}

resource "aws_sns_topic_policy" "eventbridge_sns" {
  arn = aws_sns_topic.alerts.arn
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}
```


### Scheduled EventBridge Rules

```hcl
# scheduled-tasks.tf

# Run Lambda every 5 minutes
resource "aws_cloudwatch_event_rule" "every_five_minutes" {
  name                = "every-five-minutes"
  description         = "Trigger every 5 minutes"
  schedule_expression = "rate(5 minutes)"
}

resource "aws_cloudwatch_event_target" "health_check" {
  rule      = aws_cloudwatch_event_rule.every_five_minutes.name
  target_id = "HealthCheckLambda"
  arn       = aws_lambda_function.health_check.arn
}

# Run Lambda at specific time (daily at 2 AM UTC)
resource "aws_cloudwatch_event_rule" "daily_report" {
  name                = "daily-report-generation"
  description         = "Generate daily report at 2 AM UTC"
  schedule_expression = "cron(0 2 * * ? *)"  # Minute Hour Day Month DayOfWeek Year
}

resource "aws_cloudwatch_event_target" "report_generator" {
  rule      = aws_cloudwatch_event_rule.daily_report.name
  target_id = "ReportGenerator"
  arn       = aws_lambda_function.report_generator.arn
  
  input = jsonencode({
    report_type = "daily"
    format      = "pdf"
    recipients  = ["team@example.com"]
  })
}

# Complex cron: Every Monday at 9 AM EST (14:00 UTC)
resource "aws_cloudwatch_event_rule" "weekly_backup" {
  name                = "weekly-monday-backup"
  description         = "Trigger backup every Monday at 9 AM EST"
  schedule_expression = "cron(0 14 ? * MON *)"
}

# Run ECS task on schedule
resource "aws_cloudwatch_event_target" "scheduled_ecs_task" {
  rule      = aws_cloudwatch_event_rule.daily_report.name
  target_id = "ETLTask"
  arn       = aws_ecs_cluster.main.arn
  role_arn  = aws_iam_role.ecs_events.arn
  
  ecs_target {
    task_definition_arn = aws_ecs_task_definition.etl.arn
    task_count          = 1
    launch_type         = "FARGATE"
    
    network_configuration {
      subnets          = data.aws_subnets.private.ids
      security_groups  = [aws_security_group.ecs_task.id]
      assign_public_ip = false
    }
  }
}
```


## Containerized Lambda Functions with ECR

### Lambda Container Image Deployment

Deploy Lambda functions as Docker containers for custom dependencies and larger packages.

**Directory structure:**

```
lambda-container/
├── terraform/
│   ├── main.tf
│   ├── variables.tf
│   └── outputs.tf
├── src/
│   ├── app.py
│   ├── requirements.txt
│   └── Dockerfile
└── .github/
    └── workflows/
        └── deploy.yml
```

**Terraform configuration:**

```hcl
# terraform/main.tf
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

# ECR repository for Lambda container images
resource "aws_ecr_repository" "lambda" {
  name                 = var.function_name
  image_tag_mutability = "MUTABLE"
  
  image_scanning_configuration {
    scan_on_push = true
  }
  
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr.arn
  }
}

# ECR lifecycle policy (keep last 10 images)
resource "aws_ecr_lifecycle_policy" "lambda" {
  repository = aws_ecr_repository.lambda.name
  
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 10 images"
        selection = {
          tagStatus     = "any"
          countType     = "imageCountMoreThan"
          countNumber   = 10
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

# KMS key for ECR encryption
resource "aws_kms_key" "ecr" {
  description             = "KMS key for ECR repository encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_kms_alias" "ecr" {
  name          = "alias/${var.function_name}-ecr"
  target_key_id = aws_kms_key.ecr.key_id
}

# Lambda function using container image
resource "aws_lambda_function" "containerized" {
  function_name = var.function_name
  role          = aws_iam_role.lambda.arn
  package_type  = "Image"  # Container image instead of ZIP
  image_uri     = "${aws_ecr_repository.lambda.repository_url}:${var.image_tag}"
  timeout       = 60
  memory_size   = 1024
  
  environment {
    variables = {
      ENVIRONMENT  = var.environment
      LOG_LEVEL    = "INFO"
      REGION       = var.aws_region
    }
  }
  
  # Dead letter queue for failed invocations
  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }
  
  # VPC configuration (if needed)
  dynamic "vpc_config" {
    for_each = var.enable_vpc ?  : []
    content {
      subnet_ids         = var.subnet_ids
      security_group_ids = [aws_security_group.lambda[^0].id]
    }
  }
  
  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic,
    aws_cloudwatch_log_group.lambda
  ]
}

# CloudWatch log group
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = 14
  kms_key_id        = aws_kms_key.lambda_logs.arn
}

# KMS key for CloudWatch Logs
resource "aws_kms_key" "lambda_logs" {
  description             = "KMS key for Lambda CloudWatch Logs"
  deletion_window_in_days = 7
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
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.aws_region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:CreateGrant",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.function_name}"
          }
        }
      }
    ]
  })
}

# IAM role for Lambda
resource "aws_iam_role" "lambda" {
  name = "${var.function_name}-role"
  
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

# Basic Lambda execution permissions
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# VPC access (if needed)
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  count      = var.enable_vpc ? 1 : 0
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# SQS dead letter queue
resource "aws_sqs_queue" "lambda_dlq" {
  name                      = "${var.function_name}-dlq"
  message_retention_seconds = 1209600  # 14 days
  kms_master_key_id         = "alias/aws/sqs"
}

# SQS DLQ permissions for Lambda
resource "aws_lambda_permission" "sqs_dlq" {
  statement_id  = "AllowSQSDLQ"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.containerized.function_name
  principal     = "sqs.amazonaws.com"
  source_arn    = aws_sqs_queue.lambda_dlq.arn
}

# Data source
data "aws_caller_identity" "current" {}

# variables.tf
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "function_name" {
  description = "Lambda function name"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "image_tag" {
  description = "Docker image tag to deploy"
  type        = string
  default     = "latest"
}

variable "enable_vpc" {
  description = "Enable VPC configuration for Lambda"
  type        = bool
  default     = false
}

variable "subnet_ids" {
  description = "Subnet IDs for Lambda VPC configuration"
  type        = list(string)
  default     = []
}

# outputs.tf
output "lambda_function_arn" {
  description = "ARN of Lambda function"
  value       = aws_lambda_function.containerized.arn
}

output "lambda_function_name" {
  description = "Name of Lambda function"
  value       = aws_lambda_function.containerized.function_name
}

output "ecr_repository_url" {
  description = "ECR repository URL"
  value       = aws_ecr_repository.lambda.repository_url
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.lambda.name
}
```

**Dockerfile:**

```dockerfile
# src/Dockerfile
FROM public.ecr.aws/lambda/python:3.11

# Copy requirements and install dependencies
COPY requirements.txt ${LAMBDA_TASK_ROOT}/
RUN pip install --no-cache-dir -r requirements.txt

# Copy function code
COPY app.py ${LAMBDA_TASK_ROOT}/

# Set handler
CMD ["app.handler"]
```

**Lambda function code:**

```python
# src/app.py
import json
import os
import boto3
from datetime import datetime

# Example with additional dependencies
import requests
import pandas as pd

def handler(event, context):
    """
    Lambda function handler with custom dependencies
    """
    
    print(f"Function invoked at {datetime.utcnow().isoformat()}")
    print(f"Event: {json.dumps(event)}")
    
    environment = os.environ.get('ENVIRONMENT', 'unknown')
    region = os.environ.get('REGION', 'us-east-1')
    
    # Example: Process data with pandas
    if 'data' in event:
        df = pd.DataFrame(event['data'])
        summary = df.describe().to_dict()
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Data processed successfully',
                'environment': environment,
                'region': region,
                'summary': summary
            })
        }
    
    # Example: Make HTTP request
    if 'url' in event:
        response = requests.get(event['url'])
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'HTTP request successful',
                'status_code': response.status_code,
                'content_length': len(response.content)
            })
        }
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Function executed successfully',
            'environment': environment
        })
    }
```

**Requirements file:**

```
# src/requirements.txt
requests==2.31.0
pandas==2.1.4
numpy==1.26.2
boto3==1.34.0
```

**CI/CD Deployment (GitHub Actions):**

```yaml
# .github/workflows/deploy.yml
name: Deploy Lambda Container

on:
  push:
    branches: [main]

env:
  AWS_REGION: us-east-1
  FUNCTION_NAME: data-processor

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    permissions:
      id-token: write
      contents: read
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: ${{ env.AWS_REGION }}
      
      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v2
      
      - name: Build, tag, and push image to Amazon ECR
        working-directory: ./src
        env:
          ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
          IMAGE_TAG: ${{ github.sha }}
        run: |
          docker build -t $ECR_REGISTRY/$FUNCTION_NAME:$IMAGE_TAG .
          docker tag $ECR_REGISTRY/$FUNCTION_NAME:$IMAGE_TAG $ECR_REGISTRY/$FUNCTION_NAME:latest
          docker push $ECR_REGISTRY/$FUNCTION_NAME:$IMAGE_TAG
          docker push $ECR_REGISTRY/$FUNCTION_NAME:latest
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.11.0
      
      - name: Terraform Init
        working-directory: ./terraform
        run: terraform init
      
      - name: Terraform Apply
        working-directory: ./terraform
        env:
          TF_VAR_function_name: ${{ env.FUNCTION_NAME }}
          TF_VAR_image_tag: ${{ github.sha }}
        run: terraform apply -auto-approve
```

**Testing:**

```bash
# Build and push image locally
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account-id>.dkr.ecr.us-east-1.amazonaws.com

cd src
docker build -t data-processor:test .
docker tag data-processor:test <account-id>.dkr.ecr.us-east-1.amazonaws.com/data-processor:test
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/data-processor:test

# Deploy with Terraform
cd ../terraform
terraform apply -var="image_tag=test"

# Invoke Lambda
aws lambda invoke \
  --function-name data-processor \
  --payload '{"data": [{"a": 1, "b": 2}, {"a": 3, "b": 4}]}' \
  response.json

cat response.json
# {"statusCode": 200, "body": "{\"message\": \"Data processed successfully\", ...}"}

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
