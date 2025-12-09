# Appendix C: AWS Service Coverage Matrix

## Introduction

This appendix provides a comprehensive reference matrix of AWS services with Terraform resource support status, common use cases, and practical examples. As of December 2025, the Terraform AWS Provider supports over 1,200 resources and 600 data sources covering the majority of AWS services. This matrix helps you quickly determine whether a specific AWS service can be managed via Terraform and identifies the corresponding resource types.

***

## Coverage Legend

| Symbol | Meaning | Description |
| :-- | :-- | :-- |
| ✅ | Full Support | Complete resource and data source coverage |
| 🟨 | Partial Support | Core features supported, some limitations |
| 🔄 | Beta/Preview | Available but may have breaking changes |
| ❌ | Not Supported | Not yet available in AWS provider |
| 🔜 | Planned | On provider roadmap |


***

## Compute Services

| AWS Service | Support | Resource Type | Common Use Cases | Example |
| :-- | :-- | :-- | :-- | :-- |
| **Amazon EC2** | ✅ | `aws_instance` | Virtual servers, application hosting | General compute workloads |
| EC2 Auto Scaling | ✅ | `aws_autoscaling_group` | Dynamic capacity management | Web tier scaling |
| EC2 Launch Templates | ✅ | `aws_launch_template` | Instance configuration templates | ASG definitions |
| Elastic Load Balancing (ALB) | ✅ | `aws_lb` | HTTP/HTTPS load balancing | Application layer 7 routing |
| Elastic Load Balancing (NLB) | ✅ | `aws_lb` (type=network) | TCP/UDP load balancing | High-performance routing |
| Classic Load Balancer | ✅ | `aws_elb` | Legacy load balancing | Legacy applications |
| **AWS Lambda** | ✅ | `aws_lambda_function` | Serverless compute | Event-driven processing |
| Lambda Layers | ✅ | `aws_lambda_layer_version` | Shared code libraries | Dependency management |
| **Amazon ECS** | ✅ | `aws_ecs_cluster` | Container orchestration | Docker workloads |
| ECS Task Definitions | ✅ | `aws_ecs_task_definition` | Container specifications | Application definitions |
| ECS Services | ✅ | `aws_ecs_service` | Long-running containers | Microservices |
| **Amazon EKS** | ✅ | `aws_eks_cluster` | Managed Kubernetes | Cloud-native applications |
| EKS Node Groups | ✅ | `aws_eks_node_group` | Worker nodes | Kubernetes compute |
| EKS Add-ons | ✅ | `aws_eks_addon` | Cluster extensions | VPC CNI, CoreDNS |
| **AWS Batch** | ✅ | `aws_batch_job_definition` | Batch processing | Data pipelines |
| **AWS Fargate** | ✅ | Via ECS/EKS | Serverless containers | No server management |
| **Elastic Beanstalk** | ✅ | `aws_elastic_beanstalk_application` | PaaS deployments | Quick application hosting |
| **AWS Lightsail** | 🟨 | `aws_lightsail_instance` | Simple VPS | Small projects |

**Example: EC2 with Auto Scaling**

```hcl
resource "aws_launch_template" "app" {
  name_prefix   = "app-"
  image_id      = "ami-12345678"
  instance_type = "t3.micro"
}

resource "aws_autoscaling_group" "app" {
  name                = "app-asg"
  vpc_zone_identifier = [aws_subnet.private.id]
  min_size            = 2
  max_size            = 10
  desired_capacity    = 3
  
  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }
}
```


***

## Storage Services

| AWS Service | Support | Resource Type | Common Use Cases | Example |
| :-- | :-- | :-- | :-- | :-- |
| **Amazon S3** | ✅ | `aws_s3_bucket` | Object storage | Static assets, backups |
| S3 Bucket Policies | ✅ | `aws_s3_bucket_policy` | Access control | Public/private access |
| S3 Lifecycle | ✅ | `aws_s3_bucket_lifecycle_configuration` | Cost optimization | Archive old data |
| S3 Replication | ✅ | `aws_s3_bucket_replication_configuration` | Cross-region backup | Disaster recovery |
| S3 Glacier | ✅ | `aws_glacier_vault` | Long-term archive | Compliance storage |
| **Amazon EBS** | ✅ | `aws_ebs_volume` | Block storage | EC2 persistent disks |
| EBS Snapshots | ✅ | `aws_ebs_snapshot` | Volume backups | Point-in-time recovery |
| **Amazon EFS** | ✅ | `aws_efs_file_system` | Shared file storage | Multi-instance access |
| **AWS Storage Gateway** | ✅ | `aws_storagegateway_gateway` | Hybrid storage | On-premises integration |
| **AWS Backup** | ✅ | `aws_backup_plan` | Centralized backup | Automated backups |
| **Amazon FSx** | ✅ | `aws_fsx_windows_file_system` | Managed file systems | Windows workloads |
| FSx for Lustre | ✅ | `aws_fsx_lustre_file_system` | High-performance computing | ML/analytics |

**Example: S3 with Lifecycle Policy**

```hcl
resource "aws_s3_bucket" "data" {
  bucket = "my-app-data-bucket"
}

resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  
  rule {
    id     = "archive-old-data"
    status = "Enabled"
    
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    
    expiration {
      days = 365
    }
  }
}
```


***

## Database Services

| AWS Service | Support | Resource Type | Common Use Cases | Example |
| :-- | :-- | :-- | :-- | :-- |
| **Amazon RDS** | ✅ | `aws_db_instance` | Managed relational DB | MySQL, PostgreSQL |
| RDS Aurora | ✅ | `aws_rds_cluster` | High-performance DB | Enterprise workloads |
| RDS Proxy | ✅ | `aws_db_proxy` | Connection pooling | Lambda connections |
| RDS Snapshots | ✅ | `aws_db_snapshot` | Database backups | Point-in-time recovery |
| **Amazon DynamoDB** | ✅ | `aws_dynamodb_table` | NoSQL database | High-scale key-value |
| DynamoDB Global Tables | ✅ | `aws_dynamodb_table` (replica) | Multi-region replication | Global applications |
| **Amazon ElastiCache** | ✅ | `aws_elasticache_cluster` | In-memory cache | Redis, Memcached |
| ElastiCache Redis | ✅ | `aws_elasticache_replication_group` | Redis with replication | Session storage |
| **Amazon DocumentDB** | ✅ | `aws_docdb_cluster` | MongoDB-compatible | Document database |
| **Amazon Neptune** | ✅ | `aws_neptune_cluster` | Graph database | Relationship queries |
| **Amazon Redshift** | ✅ | `aws_redshift_cluster` | Data warehouse | Analytics workloads |
| **Amazon Timestream** | ✅ | `aws_timestreamwrite_database` | Time-series database | IoT, metrics |
| **Amazon QLDB** | ✅ | `aws_qldb_ledger` | Ledger database | Immutable records |
| **AWS Database Migration Service** | ✅ | `aws_dms_replication_instance` | Database migration | Cloud migrations |

**Example: RDS with Multi-AZ**

```hcl
resource "aws_db_instance" "main" {
  identifier           = "myapp-db"
  engine               = "postgres"
  engine_version       = "15.4"
  instance_class       = "db.t3.medium"
  allocated_storage    = 100
  storage_encrypted    = true
  multi_az             = true
  
  db_name  = "appdb"
  username = "admin"
  password = var.db_password
  
  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"
}
```


***

## Networking \& Content Delivery

| AWS Service | Support | Resource Type | Common Use Cases | Example |
| :-- | :-- | :-- | :-- | :-- |
| **Amazon VPC** | ✅ | `aws_vpc` | Virtual network | Network isolation |
| VPC Subnets | ✅ | `aws_subnet` | Network segments | Public/private tiers |
| VPC Internet Gateway | ✅ | `aws_internet_gateway` | Internet access | Public connectivity |
| VPC NAT Gateway | ✅ | `aws_nat_gateway` | Outbound internet | Private subnet internet |
| VPC Peering | ✅ | `aws_vpc_peering_connection` | VPC-to-VPC | Cross-VPC communication |
| VPC Transit Gateway | ✅ | `aws_ec2_transit_gateway` | Hub-and-spoke networking | Multi-VPC architecture |
| **AWS Direct Connect** | ✅ | `aws_dx_connection` | Dedicated connectivity | On-premises link |
| **Amazon Route 53** | ✅ | `aws_route53_zone` | DNS service | Domain management |
| Route 53 Health Checks | ✅ | `aws_route53_health_check` | Endpoint monitoring | Failover routing |
| **Amazon CloudFront** | ✅ | `aws_cloudfront_distribution` | CDN | Content delivery |
| **AWS Global Accelerator** | ✅ | `aws_globalaccelerator_accelerator` | Global routing | Multi-region apps |
| **Elastic IP** | ✅ | `aws_eip` | Static IP addresses | Persistent IPs |
| **VPC Endpoints** | ✅ | `aws_vpc_endpoint` | Private AWS service access | S3, DynamoDB private |
| **AWS PrivateLink** | ✅ | `aws_vpc_endpoint_service` | Private connectivity | Service exposure |
| **AWS VPN** | ✅ | `aws_vpn_connection` | Site-to-site VPN | Hybrid connectivity |
| **AWS App Mesh** | ✅ | `aws_appmesh_mesh` | Service mesh | Microservices networking |

**Example: VPC with Public and Private Subnets**

```hcl
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.11.0/24"
  availability_zone = "us-east-1a"
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id
}
```


***

## Security, Identity \& Compliance

| AWS Service | Support | Resource Type | Common Use Cases | Example |
| :-- | :-- | :-- | :-- | :-- |
| **AWS IAM** | ✅ | `aws_iam_role` | Identity management | Access control |
| IAM Policies | ✅ | `aws_iam_policy` | Permissions | Fine-grained access |
| IAM Groups | ✅ | `aws_iam_group` | User collections | Team permissions |
| IAM OIDC Provider | ✅ | `aws_iam_openid_connect_provider` | Federated identity | GitHub Actions auth |
| **AWS IAM Identity Center** | ✅ | `aws_ssoadmin_permission_set` | SSO management | Centralized access |
| **AWS Organizations** | ✅ | `aws_organizations_organization` | Multi-account management | Enterprise governance |
| Service Control Policies | ✅ | `aws_organizations_policy` | Account guardrails | Compliance enforcement |
| **AWS KMS** | ✅ | `aws_kms_key` | Encryption keys | Data encryption |
| KMS Aliases | ✅ | `aws_kms_alias` | Key naming | User-friendly references |
| **AWS Secrets Manager** | ✅ | `aws_secretsmanager_secret` | Secret storage | Credentials management |
| **AWS Systems Manager** | ✅ | `aws_ssm_parameter` | Configuration storage | Application config |
| Parameter Store | ✅ | `aws_ssm_parameter` | Centralized parameters | Environment variables |
| **AWS Certificate Manager** | ✅ | `aws_acm_certificate` | SSL/TLS certificates | HTTPS encryption |
| **AWS WAF** | ✅ | `aws_wafv2_web_acl` | Web application firewall | DDoS protection |
| **AWS Shield** | 🟨 | Limited | DDoS protection | Enterprise protection |
| **AWS Security Hub** | ✅ | `aws_securityhub_account` | Security posture | Compliance dashboard |
| **Amazon GuardDuty** | ✅ | `aws_guardduty_detector` | Threat detection | Security monitoring |
| **AWS Config** | ✅ | `aws_config_configuration_recorder` | Compliance tracking | Resource auditing |
| **AWS CloudTrail** | ✅ | `aws_cloudtrail` | API audit logging | Activity tracking |
| **AWS Firewall Manager** | ✅ | `aws_fms_policy` | Centralized firewall | Multi-account security |

**Example: IAM Role for Lambda**

```hcl
resource "aws_iam_role" "lambda_exec" {
  name = "lambda-execution-role"
  
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
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
```


***

## Developer Tools \& CI/CD

| AWS Service | Support | Resource Type | Common Use Cases | Example |
| :-- | :-- | :-- | :-- | :-- |
| **AWS CodeCommit** | ✅ | `aws_codecommit_repository` | Git repositories | Source control |
| **AWS CodeBuild** | ✅ | `aws_codebuild_project` | Build automation | CI pipelines |
| **AWS CodeDeploy** | ✅ | `aws_codedeploy_app` | Deployment automation | Application releases |
| **AWS CodePipeline** | ✅ | `aws_codepipeline` | CI/CD orchestration | End-to-end pipelines |
| **AWS CodeArtifact** | ✅ | `aws_codeartifact_repository` | Artifact repository | Package management |
| **Amazon ECR** | ✅ | `aws_ecr_repository` | Container registry | Docker images |
| **AWS Cloud9** | 🟨 | `aws_cloud9_environment_ec2` | Cloud IDE | Development environment |

**Example: CodePipeline with S3 Source**

```hcl
resource "aws_codepipeline" "app" {
  name     = "app-pipeline"
  role_arn = aws_iam_role.pipeline.arn
  
  artifact_store {
    location = aws_s3_bucket.artifacts.bucket
    type     = "S3"
  }
  
  stage {
    name = "Source"
    
    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "S3"
      version          = "1"
      output_artifacts = ["source_output"]
      
      configuration = {
        S3Bucket    = aws_s3_bucket.source.bucket
        S3ObjectKey = "source.zip"
      }
    }
  }
  
  stage {
    name = "Build"
    
    action {
      name             = "Build"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["source_output"]
      output_artifacts = ["build_output"]
      
      configuration = {
        ProjectName = aws_codebuild_project.app.name
      }
    }
  }
}
```


***

## Management \& Governance

| AWS Service | Support | Resource Type | Common Use Cases | Example |
| :-- | :-- | :-- | :-- | :-- |
| **AWS CloudWatch** | ✅ | `aws_cloudwatch_log_group` | Monitoring \& logging | Application logs |
| CloudWatch Alarms | ✅ | `aws_cloudwatch_metric_alarm` | Alerting | Threshold notifications |
| CloudWatch Dashboards | ✅ | `aws_cloudwatch_dashboard` | Visualization | Metrics dashboards |
| **AWS CloudFormation** | 🟨 | `aws_cloudformation_stack` | IaC orchestration | Hybrid deployments |
| **AWS Service Catalog** | ✅ | `aws_servicecatalog_portfolio` | Product catalog | Self-service provisioning |
| **AWS Control Tower** | 🟨 | Limited | Multi-account setup | Landing zone |
| **AWS Resource Groups** | ✅ | `aws_resourcegroups_group` | Resource organization | Tag-based grouping |
| **AWS Cost Explorer** | ❌ | Via API only | Cost analysis | Budget monitoring |
| **AWS Budgets** | ✅ | `aws_budgets_budget` | Cost control | Spending alerts |
| **AWS Trusted Advisor** | ❌ | Via API only | Best practices | Optimization recommendations |

**Example: CloudWatch Alarm**

```hcl
resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  alarm_name          = "high-cpu-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Alert when CPU exceeds 80%"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  
  dimensions = {
    InstanceId = aws_instance.web.id
  }
}
```


***

## Analytics \& Big Data

| AWS Service | Support | Resource Type | Common Use Cases | Example |
| :-- | :-- | :-- | :-- | :-- |
| **Amazon Athena** | ✅ | `aws_athena_workgroup` | SQL queries on S3 | Data lake analytics |
| **AWS Glue** | ✅ | `aws_glue_catalog_database` | ETL service | Data transformation |
| Glue Crawlers | ✅ | `aws_glue_crawler` | Schema discovery | Automatic cataloging |
| **Amazon EMR** | ✅ | `aws_emr_cluster` | Big data processing | Hadoop, Spark |
| **Amazon Kinesis** | ✅ | `aws_kinesis_stream` | Real-time streaming | Event processing |
| Kinesis Firehose | ✅ | `aws_kinesis_firehose_delivery_stream` | Stream delivery | S3, Redshift ingestion |
| **AWS Data Pipeline** | ✅ | `aws_datapipeline_pipeline` | Data workflows | Scheduled ETL |
| **Amazon QuickSight** | 🟨 | `aws_quicksight_user` | Business intelligence | Data visualization |
| **AWS Lake Formation** | ✅ | `aws_lakeformation_permissions` | Data lake security | Centralized governance |

**Example: Kinesis Stream with Firehose**

```hcl
resource "aws_kinesis_stream" "events" {
  name             = "app-events-stream"
  shard_count      = 1
  retention_period = 24
}

resource "aws_kinesis_firehose_delivery_stream" "s3" {
  name        = "events-to-s3"
  destination = "extended_s3"
  
  kinesis_source_configuration {
    kinesis_stream_arn = aws_kinesis_stream.events.arn
    role_arn           = aws_iam_role.firehose.arn
  }
  
  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose.arn
    bucket_arn = aws_s3_bucket.data.arn
    prefix     = "events/"
  }
}
```


***

## Machine Learning \& AI

| AWS Service | Support | Resource Type | Common Use Cases | Example |
| :-- | :-- | :-- | :-- | :-- |
| **Amazon SageMaker** | ✅ | `aws_sagemaker_notebook_instance` | ML platform | Model development |
| SageMaker Endpoints | ✅ | `aws_sagemaker_endpoint` | Model serving | Inference hosting |
| SageMaker Models | ✅ | `aws_sagemaker_model` | ML models | Model packaging |
| **Amazon Comprehend** | 🟨 | Limited | NLP service | Text analysis |
| **Amazon Rekognition** | ❌ | Via API only | Image/video analysis | Computer vision |
| **Amazon Polly** | ❌ | Via API only | Text-to-speech | Voice synthesis |
| **Amazon Transcribe** | 🟨 | `aws_transcribe_language_model` | Speech-to-text | Audio transcription |
| **AWS DeepRacer** | ❌ | Not applicable | Reinforcement learning | Educational ML |

**Example: SageMaker Notebook**

```hcl
resource "aws_sagemaker_notebook_instance" "ml_dev" {
  name          = "ml-development"
  instance_type = "ml.t3.medium"
  role_arn      = aws_iam_role.sagemaker.arn
  
  tags = {
    Environment = "development"
  }
}
```


***

## Application Integration

| AWS Service | Support | Resource Type | Common Use Cases | Example |
| :-- | :-- | :-- | :-- | :-- |
| **Amazon SQS** | ✅ | `aws_sqs_queue` | Message queuing | Asynchronous processing |
| **Amazon SNS** | ✅ | `aws_sns_topic` | Pub/sub messaging | Fan-out notifications |
| **Amazon EventBridge** | ✅ | `aws_cloudwatch_event_rule` | Event bus | Event-driven architecture |
| **AWS Step Functions** | ✅ | `aws_sfn_state_machine` | Workflow orchestration | Complex workflows |
| **Amazon MQ** | ✅ | `aws_mq_broker` | Message broker | ActiveMQ, RabbitMQ |
| **Amazon API Gateway** | ✅ | `aws_api_gateway_rest_api` | API management | REST APIs |
| API Gateway v2 (HTTP) | ✅ | `aws_apigatewayv2_api` | HTTP APIs | Low-latency APIs |
| **AWS AppSync** | ✅ | `aws_appsync_graphql_api` | GraphQL APIs | Real-time data |

**Example: SQS with SNS Subscription**

```hcl
resource "aws_sns_topic" "alerts" {
  name = "app-alerts"
}

resource "aws_sqs_queue" "processor" {
  name                      = "alert-processor"
  message_retention_seconds = 86400
}

resource "aws_sns_topic_subscription" "queue" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.processor.arn
}
```


***

## IoT \& Edge

| AWS Service | Support | Resource Type | Common Use Cases | Example |
| :-- | :-- | :-- | :-- | :-- |
| **AWS IoT Core** | ✅ | `aws_iot_thing` | IoT messaging | Device communication |
| IoT Rules | ✅ | `aws_iot_topic_rule` | Message routing | Data ingestion |
| **AWS IoT Greengrass** | ✅ | `aws_greengrass_group` | Edge computing | Local device processing |
| **AWS IoT Analytics** | ✅ | `aws_iotanalytics_channel` | IoT data analysis | Time-series analytics |


***

## Service Coverage Summary

### By Category Support Level

| Category | Full Support | Partial Support | Total Services |
| :-- | :-- | :-- | :-- |
| Compute | 15 | 2 | 17 |
| Storage | 10 | 0 | 10 |
| Database | 13 | 0 | 13 |
| Networking | 18 | 0 | 18 |
| Security | 17 | 1 | 18 |
| Developer Tools | 6 | 1 | 7 |
| Analytics | 8 | 1 | 9 |
| Machine Learning | 3 | 3 | 6 |
| Application Integration | 8 | 0 | 8 |

### Overall Coverage: ~85% of commonly used AWS services


***

## Finding Resource Documentation

### Official Provider Documentation

All resources documented at:

```
https://registry.terraform.io/providers/hashicorp/aws/latest/docs
```


### Quick Lookup Pattern

```bash
# Search for specific service resources
terraform providers schema -json | jq '.provider_schemas."registry.terraform.io/hashicorp/aws".resource_schemas | keys | .[] | select(contains("rds"))'

# Output:
# aws_rds_cluster
# aws_rds_cluster_endpoint
# aws_db_instance
# aws_db_parameter_group
# ...
```


### Resource Naming Convention

Most AWS resources follow pattern:

```
aws_<service>_<resource_type>

Examples:
aws_ec2_instance          → EC2 Instance
aws_s3_bucket            → S3 Bucket
aws_lambda_function      → Lambda Function
aws_dynamodb_table       → DynamoDB Table
aws_ecs_cluster          → ECS Cluster
```


***

## Requesting New Resources

If a service isn't supported:

1. **Check provider roadmap**: [AWS Provider GitHub Issues](https://github.com/hashicorp/terraform-provider-aws/issues)
2. **Search existing requests**: Look for feature requests
3. **Open new issue**: Use template for resource requests
4. **Contribute**: Provider accepts community contributions

**Example Feature Request:**

```markdown
### Service Name
AWS Service XYZ

### Use Case
Describe why this resource is needed

### AWS API Reference
Link to AWS documentation

### Terraform Configuration Example
Show desired Terraform syntax
```


***

This coverage matrix provides a comprehensive reference for determining Terraform support for AWS services as of December 2025. For the most up-to-date information, always consult the official Terraform AWS Provider documentation at registry.terraform.io. New resources are added regularly as AWS releases new services and features.

