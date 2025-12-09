# Chapter 19: Cost Optimization with Terraform

## Introduction

Your Terraform configuration deploys perfectly—VPCs spin up, EC2 instances launch, RDS databases activate—and two weeks later the AWS bill arrives at \$47,000 for infrastructure you estimated would cost \$15,000 monthly. Where did the extra \$32,000 come from? Maybe your development team accidentally deployed production-sized db.r6g.4xlarge instances instead of db.t3.medium for testing, or someone forgot to implement S3 lifecycle policies moving terabytes of infrequently accessed logs to cheaper Glacier storage, or auto-scaling policies configured too aggressively launched 50 unnecessary EC2 instances during a temporary traffic spike that lasted 10 minutes. These aren't edge cases—they're the daily reality of cloud infrastructure management where the gap between configuration syntax and financial impact determines whether your infrastructure-as-code investment delivers ROI or becomes a budget catastrophe. Without proactive cost optimization, Terraform's power to rapidly provision resources becomes a liability, making it trivially easy to deploy expensive infrastructure at scale before anyone realizes the financial implications.

Cost optimization isn't about choosing the absolute cheapest resources—it's about aligning infrastructure spending with business value through systematic measurement, analysis, and automation. Effective cost management requires visibility into expenses before deployment using tools like Infracost that show cost estimates directly in pull requests, enabling teams to catch expensive mistakes during code review rather than after deployment. Right-sizing resources matches instance types, storage volumes, and database configurations to actual workload requirements rather than over-provisioning "to be safe," typically reducing costs 30-50% without performance degradation. Auto-scaling implementations dynamically adjust capacity based on demand, eliminating waste from idle resources during off-peak hours while maintaining performance during traffic spikes. Spot instances provide up to 90% discounts for fault-tolerant workloads, and Savings Plans deliver 72% savings on predictable usage through commitment-based pricing. Resource tagging enables granular cost allocation tracking expenses by team, project, application, or environment for accountability and chargeback. Infrastructure cleanup strategies automatically terminate unused resources, preventing "zombie" infrastructure from accumulating costs month after month.

This chapter provides comprehensive cost optimization strategies you can implement immediately. You'll learn Infracost integration displaying cost estimates in CI/CD pipelines before any infrastructure deploys, right-sizing methodologies identifying oversized resources through CloudWatch metrics analysis, auto-scaling patterns eliminating manual capacity management, Spot instance and Savings Plans implementations reducing compute costs up to 90%, tagging frameworks enabling accurate cost allocation and showback reporting, and automated cleanup procedures preventing resource sprawl. Each strategy includes production-ready Terraform code, cost-benefit analysis showing expected savings, implementation considerations highlighting potential risks, and real-world examples demonstrating actual cost reductions achieved by enterprises. Whether you're managing \$5,000 or \$5 million in monthly cloud spend, these techniques provide actionable paths to significant cost reduction while maintaining—or improving—infrastructure reliability and performance.

## Terraform Cost Estimation with Infracost

### Understanding Infracost

Infracost provides cloud cost estimates for Terraform configurations before deployment, integrating with CI/CD pipelines to surface cost impacts during code review.

**Key Benefits:**

- **Pre-deployment visibility:** See costs before resources are created
- **Cost drift detection:** Compare current vs. planned infrastructure costs
- **Policy enforcement:** Block expensive changes exceeding budget thresholds
- **Historical tracking:** Monitor cost trends over time
- **Multi-cloud support:** Works with AWS, Azure, and GCP


### Installing Infracost

```bash
# macOS
brew install infracost

# Linux
curl -fsSL https://raw.githubusercontent.com/infracost/infracost/master/scripts/install.sh | sh

# Windows (PowerShell)
choco install infracost

# Verify installation
infracost --version

# Register for API key (free)
infracost auth login

# Alternative: set API key directly
export INFRACOST_API_KEY="your-api-key-here"
```


### Basic Usage

```bash
# Cost breakdown for Terraform directory
cd terraform/
infracost breakdown --path .

# Output example:
# Project: terraform/production
# 
# Name                                    Monthly Qty  Unit   Monthly Cost 
# 
# aws_instance.web                                                          
# ├─ Instance usage (Linux/UNIX, on-demand, t3.large)  730  hours    $60.74 
# └─ root_block_device                                                      
#    └─ Storage (general purpose SSD, gp3)             50  GB         $4.00 
# 
# aws_db_instance.main                                                      
# ├─ Database instance (on-demand, db.r6g.xlarge)      730  hours   $350.40 
# ├─ Storage (general purpose SSD, gp3)              1,000  GB       $115.00 
# └─ Additional backup storage                         500  GB        $47.50 
# 
# OVERALL TOTAL                                                     $577.64

# Show only costs (no detailed breakdown)
infracost breakdown --path . --format table

# Compare changes (cost diff)
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > plan.json
infracost diff --path plan.json

# Output shows increases/decreases:
# + $150.00  New aws_instance.worker (t3.xlarge)
# - $60.74   Removed aws_instance.old (t3.large)
# ──────────
# Total monthly change: +$89.26 (+15%)
```


### CI/CD Integration with GitHub Actions

```yaml
# .github/workflows/infracost.yml
name: Infracost Cost Estimation

on:
  pull_request:
    branches: [main]
    paths:
      - 'terraform/**'

permissions:
  contents: read
  pull-requests: write

jobs:
  infracost:
    name: Cost Estimation
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.11.0
          terraform_wrapper: false
      
      - name: Terraform Init
        run: |
          cd terraform/production
          terraform init
      
      - name: Terraform Plan
        run: |
          cd terraform/production
          terraform plan -out=tfplan.binary
          terraform show -json tfplan.binary > plan.json
      
      - name: Setup Infracost
        uses: infracost/actions/setup@v3
        with:
          api-key: ${{ secrets.INFRACOST_API_KEY }}
      
      - name: Generate Infracost breakdown
        run: |
          infracost breakdown --path terraform/production/plan.json \
            --format json \
            --out-file /tmp/infracost.json
      
      - name: Post comment with cost estimate
        run: |
          infracost comment github --path /tmp/infracost.json \
            --repo $GITHUB_REPOSITORY \
            --pull-request ${{ github.event.pull_request.number }} \
            --github-token ${{ secrets.GITHUB_TOKEN }} \
            --behavior update
      
      - name: Check cost threshold
        run: |
          # Get monthly cost increase
          COST_INCREASE=$(jq -r '.diffTotalMonthlyCost' /tmp/infracost.json)
          
          # Fail if increase exceeds $500/month
          if (( $(echo "$COST_INCREASE > 500" | bc -l) )); then
            echo "::error::Cost increase ($COST_INCREASE) exceeds threshold of $500/month"
            exit 1
          fi
```

**Example Pull Request Comment:**

```
💰 Infracost Cost Estimate

Monthly cost estimate for terraform/production

Project: terraform/production

+ aws_instance.worker (t3.xlarge)
  + Instance usage (on-demand)          +$121.76
  + EBS volume (gp3, 100 GB)            +$8.00

~ aws_db_instance.main
  ~ Instance type (db.t3.large → db.r6g.xlarge)
    ~ Database instance                 +$229.00

- aws_instance.old (t3.large)
  - Instance usage                      -$60.74

──────────────────────────────────────
Monthly cost change (estimate): +$298.02 (+34%)

💡 Consider: The db.r6g.xlarge is significantly more expensive. 
Can you use db.r6g.large instead for staging?
```


### Advanced Infracost Configuration

```hcl
# infracost.yml
version: 0.1

projects:
  - path: terraform/production
    name: production
    usage_file: usage-production.yml
    
  - path: terraform/staging
    name: staging
    usage_file: usage-staging.yml

# usage-production.yml - Define actual usage patterns
version: 0.1

resource_usage:
  aws_instance.web:
    operating_system: linux
    reserved_instance_type: standard
    reserved_instance_term: 1_year
    reserved_instance_payment_option: all_upfront
  
  aws_lambda_function.processor:
    request_duration_ms: 500
    monthly_requests: 10000000  # 10M requests/month
  
  aws_dynamodb_table.records:
    monthly_read_request_units: 5000000   # 5M reads
    monthly_write_request_units: 1000000  # 1M writes
    storage_gb: 100
  
  aws_s3_bucket.data:
    storage_gb: 5000
    monthly_tier_1_requests: 100000  # PUT, COPY, POST, LIST
    monthly_tier_2_requests: 1000000 # GET, SELECT
    monthly_data_transfer_gb: 500
```


### Infracost Policy Enforcement

```rego
# policies/cost-policy.rego - Open Policy Agent policy
package infracost

import future.keywords.in

deny[msg] {
  maxDiff := 1000.0  # $1000/month maximum increase
  
  to_number(input.diffTotalMonthlyCost) > maxDiff
  
  msg := sprintf(
    "Cost increase of $%.2f exceeds limit of $%.2f",
    [to_number(input.diffTotalMonthlyCost), maxDiff]
  )
}

deny[msg] {
  maxCost := 10000.0  # $10,000/month maximum total
  
  to_number(input.totalMonthlyCost) > maxCost
  
  msg := sprintf(
    "Total monthly cost of $%.2f exceeds limit of $%.2f",
    [to_number(input.totalMonthlyCost), maxCost]
  )
}

# Warn about expensive resources
warn[msg] {
  resource := input.projects[_].breakdown.resources[_]
  cost := to_number(resource.monthlyCost)
  
  cost > 500
  
  msg := sprintf(
    "Resource %s costs $%.2f/month - consider optimization",
    [resource.name, cost]
  )
}
```

```bash
# Run policy check
infracost breakdown --path . --format json | \
  opa eval --data policies/cost-policy.rego --input - "data.infracost.deny"
```


## Right-Sizing Resources

### Identifying Oversized Resources

**CloudWatch Metrics Analysis:**

```hcl
# cost-optimization/right-sizing-analysis.tf

# Data source: Get EC2 instance utilization
data "aws_cloudwatch_metric_statistic" "cpu_utilization" {
  namespace   = "AWS/EC2"
  metric_name = "CPUUtilization"
  
  dimensions = {
    InstanceId = aws_instance.web.id
  }
  
  period = 86400  # 24 hours
  stat   = "Average"
  
  start_time = timeadd(timestamp(), "-30d")
  end_time   = timestamp()
}

# Lambda for automated right-sizing recommendations
resource "aws_lambda_function" "rightsizing_analyzer" {
  filename         = "rightsizing_analyzer.zip"
  function_name    = "ec2-rightsizing-analyzer"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "index.handler"
  runtime          = "python3.11"
  timeout          = 300
  memory_size      = 512
  
  environment {
    variables = {
      SNS_TOPIC_ARN     = aws_sns_topic.cost_optimization.arn
      THRESHOLD_CPU     = "30"  # Recommend downsize if avg < 30%
      THRESHOLD_MEMORY  = "40"  # Recommend downsize if avg < 40%
      EVALUATION_PERIOD = "30"  # Days to analyze
    }
  }
}

# EventBridge schedule (weekly analysis)
resource "aws_cloudwatch_event_rule" "weekly_analysis" {
  name                = "ec2-rightsizing-weekly"
  description         = "Run EC2 right-sizing analysis weekly"
  schedule_expression = "cron(0 9 ? * MON *)"  # Monday 9 AM
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.weekly_analysis.name
  target_id = "RightsizingLambda"
  arn       = aws_lambda_function.rightsizing_analyzer.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rightsizing_analyzer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.weekly_analysis.arn
}
```

**Right-Sizing Lambda Function:**

```python
# lambda/rightsizing_analyzer/index.py
import boto3
import json
from datetime import datetime, timedelta

ec2 = boto3.client('ec2')
cloudwatch = boto3.client('cloudwatch')
sns = boto3.client('sns')

# Instance type families by size
INSTANCE_FAMILIES = {
    't3': ['nano', 'micro', 'small', 'medium', 'large', 'xlarge', '2xlarge'],
    't3a': ['nano', 'micro', 'small', 'medium', 'large', 'xlarge', '2xlarge'],
    'm5': ['large', 'xlarge', '2xlarge', '4xlarge', '8xlarge', '12xlarge', '16xlarge', '24xlarge'],
    'r6g': ['medium', 'large', 'xlarge', '2xlarge', '4xlarge', '8xlarge', '12xlarge', '16xlarge']
}

def get_recommended_size(current_type, current_family, current_size_index, downsize_levels=1):
    """Recommend smaller instance type"""
    if current_size_index - downsize_levels < 0:
        return None
    
    sizes = INSTANCE_FAMILIES.get(current_family, [])
    new_size = sizes[current_size_index - downsize_levels]
    
    return f"{current_family}.{new_size}"

def get_cpu_utilization(instance_id, days=30):
    """Get average CPU utilization over period"""
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)
    
    response = cloudwatch.get_metric_statistics(
        Namespace='AWS/EC2',
        MetricName='CPUUtilization',
        Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
        StartTime=start_time,
        EndTime=end_time,
        Period=86400,  # Daily
        Statistics=['Average']
    )
    
    if not response['Datapoints']:
        return None
    
    avg_cpu = sum(dp['Average'] for dp in response['Datapoints']) / len(response['Datapoints'])
    return avg_cpu

def get_memory_utilization(instance_id, days=30):
    """Get average memory utilization (requires CloudWatch agent)"""
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)
    
    response = cloudwatch.get_metric_statistics(
        Namespace='CWAgent',
        MetricName='mem_used_percent',
        Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
        StartTime=start_time,
        EndTime=end_time,
        Period=86400,
        Statistics=['Average']
    )
    
    if not response['Datapoints']:
        return None
    
    avg_mem = sum(dp['Average'] for dp in response['Datapoints']) / len(response['Datapoints'])
    return avg_mem

def calculate_cost_savings(current_type, recommended_type, region='us-east-1'):
    """Estimate monthly savings (simplified)"""
    # Pricing data (approximate, use AWS Pricing API in production)
    pricing = {
        't3.small': 0.0208,
        't3.medium': 0.0416,
        't3.large': 0.0832,
        't3.xlarge': 0.1664,
        'm5.large': 0.096,
        'm5.xlarge': 0.192,
        'm5.2xlarge': 0.384,
    }
    
    current_hourly = pricing.get(current_type, 0)
    recommended_hourly = pricing.get(recommended_type, 0)
    
    monthly_savings = (current_hourly - recommended_hourly) * 730  # 730 hours/month avg
    
    return monthly_savings

def handler(event, context):
    """Analyze EC2 instances and generate right-sizing recommendations"""
    
    # Get all running instances
    instances = ec2.describe_instances(
        Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
    )
    
    recommendations = []
    total_potential_savings = 0
    
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            instance_type = instance['InstanceType']
            
            # Parse instance family and size
            family, size = instance_type.rsplit('.', 1)
            
            if family not in INSTANCE_FAMILIES:
                continue
            
            size_index = INSTANCE_FAMILIES[family].index(size)
            
            # Get utilization metrics
            cpu_util = get_cpu_utilization(instance_id)
            mem_util = get_memory_utilization(instance_id)
            
            if cpu_util is None:
                continue
            
            # Determine if downsizing is recommended
            threshold_cpu = float(os.environ.get('THRESHOLD_CPU', '30'))
            threshold_mem = float(os.environ.get('THRESHOLD_MEMORY', '40'))
            
            should_downsize = cpu_util < threshold_cpu
            if mem_util is not None:
                should_downsize = should_downsize and mem_util < threshold_mem
            
            if should_downsize and size_index > 0:
                recommended_type = get_recommended_size(instance_type, family, size_index)
                
                if recommended_type:
                    savings = calculate_cost_savings(instance_type, recommended_type)
                    total_potential_savings += savings
                    
                    recommendations.append({
                        'instance_id': instance_id,
                        'instance_name': get_instance_name(instance),
                        'current_type': instance_type,
                        'recommended_type': recommended_type,
                        'avg_cpu': round(cpu_util, 2),
                        'avg_memory': round(mem_util, 2) if mem_util else 'N/A',
                        'monthly_savings': round(savings, 2)
                    })
    
    # Send SNS notification
    if recommendations:
        message = format_recommendations(recommendations, total_potential_savings)
        
        sns.publish(
            TopicArn=os.environ['SNS_TOPIC_ARN'],
            Subject='EC2 Right-Sizing Recommendations',
            Message=message
        )
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'recommendations_count': len(recommendations),
            'total_potential_savings': round(total_potential_savings, 2)
        })
    }

def get_instance_name(instance):
    """Extract instance name from tags"""
    for tag in instance.get('Tags', []):
        if tag['Key'] == 'Name':
            return tag['Value']
    return instance['InstanceId']

def format_recommendations(recommendations, total_savings):
    """Format recommendations as readable message"""
    message = "EC2 Right-Sizing Recommendations\n"
    message += "=" * 60 + "\n\n"
    
    for rec in recommendations:
        message += f"Instance: {rec['instance_name']} ({rec['instance_id']})\n"
        message += f"  Current Type: {rec['current_type']}\n"
        message += f"  Recommended: {rec['recommended_type']}\n"
        message += f"  Avg CPU: {rec['avg_cpu']}%\n"
        message += f"  Avg Memory: {rec['avg_memory']}%\n"
        message += f"  Monthly Savings: ${rec['monthly_savings']}\n\n"
    
    message += "=" * 60 + "\n"
    message += f"Total Potential Monthly Savings: ${round(total_savings, 2)}\n"
    
    return message
```


### Implementing Right-Sizing

**Before (Oversized):**

```hcl
# ❌ Over-provisioned for actual workload
resource "aws_instance" "web" {
  ami           = data.aws_ami.amazon_linux_2.id
  instance_type = "m5.4xlarge"  # 16 vCPU, 64 GB RAM
  
  # Workload actually uses 10% CPU, 15% memory
  
  tags = {
    Name = "web-server"
  }
}

# Monthly cost: ~$560
```

**After (Right-Sized):**

```hcl
# ✅ Appropriately sized based on metrics
resource "aws_instance" "web" {
  ami           = data.aws_ami.amazon_linux_2.id
  instance_type = "t3.large"  # 2 vCPU, 8 GB RAM
  
  # Sufficient for workload with headroom
  
  credit_specification {
    cpu_credits = "unlimited"  # Handle occasional bursts
  }
  
  tags = {
    Name        = "web-server"
    RightSized  = "2025-12-08"
    PreviousType = "m5.4xlarge"
  }
}

# Monthly cost: ~$60
# Monthly savings: $500 (89% reduction)
```


## Auto-Scaling for Cost Optimization

### Time-Based Scaling

**Schedule-Based Capacity Management:**

```hcl
# cost-optimization/scheduled-scaling.tf

# Auto Scaling Group
resource "aws_autoscaling_group" "app" {
  name                = "app-asg"
  vpc_zone_identifier = data.aws_subnets.private.ids
  target_group_arns   = [aws_lb_target_group.app.arn]
  health_check_type   = "ELB"
  
  min_size         = 2
  max_size         = 20
  desired_capacity = 5
  
  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }
  
  tag {
    key                 = "Name"
    value               = "app-instance"
    propagate_at_launch = true
  }
}

# Scale down during off-hours (nights: 10 PM - 6 AM)
resource "aws_autoscaling_schedule" "scale_down_night" {
  scheduled_action_name  = "scale-down-night"
  min_size               = 2
  max_size               = 5
  desired_capacity       = 2
  recurrence             = "0 22 * * *"  # 10 PM daily
  time_zone              = "America/New_York"
  autoscaling_group_name = aws_autoscaling_group.app.name
}

# Scale up for business hours (6 AM - 10 PM)
resource "aws_autoscaling_schedule" "scale_up_morning" {
  scheduled_action_name  = "scale-up-morning"
  min_size               = 2
  max_size               = 20
  desired_capacity       = 5
  recurrence             = "0 6 * * *"  # 6 AM daily
  time_zone              = "America/New_York"
  autoscaling_group_name = aws_autoscaling_group.app.name
}

# Scale down weekends (Friday 6 PM)
resource "aws_autoscaling_schedule" "scale_down_weekend" {
  scheduled_action_name  = "scale-down-weekend"
  min_size               = 1
  max_size               = 3
  desired_capacity       = 1
  recurrence             = "0 18 * * FRI"  # Friday 6 PM
  time_zone              = "America/New_York"
  autoscaling_group_name = aws_autoscaling_group.app.name
}

# Scale up Monday morning
resource "aws_autoscaling_schedule" "scale_up_monday" {
  scheduled_action_name  = "scale-up-monday"
  min_size               = 2
  max_size               = 20
  desired_capacity       = 5
  recurrence             = "0 6 * * MON"  # Monday 6 AM
  time_zone              = "America/New_York"
  autoscaling_group_name = aws_autoscaling_group.app.name
}

# Cost savings calculation:
# Normal: 5 instances * 24 hours * 7 days = 840 instance-hours/week
# Optimized:
#   - Weekday nights (10 PM - 6 AM): 2 instances * 8 hours * 5 days = 80 hours
#   - Weekday days (6 AM - 10 PM): 5 instances * 16 hours * 5 days = 400 hours
#   - Weekends: 1 instance * 48 hours = 48 hours
#   - Total: 528 instance-hours/week
# Savings: 37% reduction in instance hours
```


### Metric-Based Scaling

```hcl
# Target tracking scaling - maintain target metric
resource "aws_autoscaling_policy" "target_tracking" {
  name                   = "target-tracking-cpu"
  autoscaling_group_name = aws_autoscaling_group.app.name
  policy_type            = "TargetTrackingScaling"
  
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    
    target_value = 70.0  # Maintain 70% CPU utilization
    
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

# Step scaling - granular control
resource "aws_autoscaling_policy" "scale_out" {
  name                   = "scale-out-policy"
  autoscaling_group_name = aws_autoscaling_group.app.name
  adjustment_type        = "PercentChangeInCapacity"
  policy_type            = "StepScaling"
  
  step_adjustment {
    scaling_adjustment          = 10
    metric_interval_lower_bound = 0
    metric_interval_upper_bound = 10
  }
  
  step_adjustment {
    scaling_adjustment          = 20
    metric_interval_lower_bound = 10
    metric_interval_upper_bound = 20
  }
  
  step_adjustment {
    scaling_adjustment          = 30
    metric_interval_lower_bound = 20
  }
}

# CloudWatch alarm triggers scaling
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "asg-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 80
  
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.app.name
  }
  
  alarm_actions = [aws_autoscaling_policy.scale_out.arn]
}
```


### Predictive Scaling

```hcl
# Predictive scaling uses ML to forecast demand
resource "aws_autoscaling_policy" "predictive" {
  name                   = "predictive-scaling"
  autoscaling_group_name = aws_autoscaling_group.app.name
  policy_type            = "PredictiveScaling"
  
  predictive_scaling_configuration {
    metric_specification {
      target_value = 70.0
      
      predefined_load_metric_specification {
        predefined_metric_type = "ASGTotalCPUUtilization"
      }
      
      predefined_scaling_metric_specification {
        predefined_metric_type = "ASGAverageCPUUtilization"
      }
    }
    
    mode                         = "ForecastAndScale"  # or "ForecastOnly"
    scheduling_buffer_time       = 600  # 10 minutes ahead
    max_capacity_breach_behavior = "IncreaseMaxCapacity"
    max_capacity_buffer          = 10  # 10% buffer
  }
}
```


## Spot Instances and Savings Plans

### Spot Instances for Fault-Tolerant Workloads

Spot instances offer up to 90% cost savings for interruptible workloads.

```hcl
# cost-optimization/spot-instances.tf

# Launch template with Spot instance request
resource "aws_launch_template" "spot" {
  name_prefix   = "app-spot-"
  image_id      = data.aws_ami.amazon_linux_2.id
  instance_type = "t3.large"
  
  iam_instance_profile {
    arn = aws_iam_instance_profile.app.arn
  }
  
  vpc_security_group_ids = [aws_security_group.app.id]
  
  user_data = base64encode(file("user-data.sh"))
  
  # Spot instance configuration
  instance_market_options {
    market_type = "spot"
    
    spot_options {
      max_price                      = "0.05"  # Maximum hourly price
      spot_instance_type             = "persistent"  # or "one-time"
      instance_interruption_behavior = "terminate"  # or "stop", "hibernate"
    }
  }
  
  tag_specifications {
    resource_type = "instance"
    
    tags = {
      Name       = "app-spot-instance"
      InstanceType = "spot"
    }
  }
}

# Mixed instance policy (Spot + On-Demand)
resource "aws_autoscaling_group" "mixed" {
  name                = "app-mixed-asg"
  vpc_zone_identifier = data.aws_subnets.private.ids
  target_group_arns   = [aws_lb_target_group.app.arn]
  health_check_type   = "ELB"
  
  min_size         = 2
  max_size         = 20
  desired_capacity = 5
  
  mixed_instances_policy {
    launch_template {
      launch_template_specification {
        launch_template_id = aws_launch_template.spot.id
        version            = "$Latest"
      }
      
      # Multiple instance types for better Spot availability
      override {
        instance_type     = "t3.large"
        weighted_capacity = "2"
      }
      
      override {
        instance_type     = "t3a.large"
        weighted_capacity = "2"
      }
      
      override {
        instance_type     = "t2.large"
        weighted_capacity = "2"
      }
    }
    
    instances_distribution {
      on_demand_base_capacity                  = 2  # Always maintain 2 On-Demand
      on_demand_percentage_above_base_capacity = 20  # 20% On-Demand, 80% Spot
      spot_allocation_strategy                 = "capacity-optimized"  # Best availability
      spot_instance_pools                      = 0  # Use all available pools
    }
  }
  
  tag {
    key                 = "Name"
    value               = "app-mixed-instance"
    propagate_at_launch = true
  }
}

# Spot instance interruption handler
resource "aws_lambda_function" "spot_interruption_handler" {
  filename      = "spot_handler.zip"
  function_name = "spot-interruption-handler"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 60
  
  environment {
    variables = {
      ASG_NAME = aws_autoscaling_group.mixed.name
    }
  }
}

# EventBridge rule for EC2 Spot interruptions
resource "aws_cloudwatch_event_rule" "spot_interruption" {
  name        = "spot-instance-interruption"
  description = "Capture EC2 Spot instance interruption warnings"
  
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["EC2 Spot Instance Interruption Warning"]
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.spot_interruption.name
  target_id = "SpotInterruptionLambda"
  arn       = aws_lambda_function.spot_interruption_handler.arn
}

# Cost comparison:
# On-Demand t3.large: $0.0832/hour * 730 hours = $60.74/month
# Spot t3.large: ~$0.025/hour * 730 hours = $18.25/month
# Savings: 70% per instance
```


### Savings Plans Implementation

Savings Plans provide up to 72% discount for 1 or 3-year commitments.

```bash
# Analyze usage to determine optimal Savings Plan
aws ce get-savings-plans-purchase-recommendation \
  --savings-plans-type COMPUTE_SP \
  --term-in-years ONE_YEAR \
  --payment-option ALL_UPFRONT \
  --lookback-period-in-days SIXTY_DAYS

# Output shows recommended hourly commitment
# Example: $5/hour commitment saves $15,000/year
```

**Terraform for Savings Plan Budgets:**

```hcl
# Monitor Savings Plan utilization
resource "aws_budgets_budget" "savings_plan_coverage" {
  name         = "savings-plan-coverage"
  budget_type  = "SAVINGS_PLANS_COVERAGE"
  time_unit    = "MONTHLY"
  
  cost_filters = {
    Service = "Amazon Elastic Compute Cloud - Compute"
  }
  
  # Alert if coverage drops below 80%
  notification {
    comparison_operator        = "LESS_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = ["finance@example.com"]
  }
}

resource "aws_budgets_budget" "savings_plan_utilization" {
  name         = "savings-plan-utilization"
  budget_type  = "SAVINGS_PLANS_UTILIZATION"
  time_unit    = "MONTHLY"
  
  # Alert if utilization drops below 95%
  notification {
    comparison_operator        = "LESS_THAN"
    threshold                  = 95
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = ["finance@example.com"]
  }
}
```

**Cost Comparison Example:**


| Scenario | Monthly Cost | Annual Cost | Savings |
| :-- | :-- | :-- | :-- |
| On-Demand (10x t3.large) | \$607 | \$7,284 | Baseline |
| 1-Year Partial Upfront SP | \$364 | \$4,368 | 40% |
| 1-Year All Upfront SP | \$340 | \$4,080 | 44% |
| 3-Year Partial Upfront SP | \$280 | \$3,360 | 54% |
| 3-Year All Upfront SP | \$250 | \$3,000 | 59% |
| Spot Instances (80% mix) | \$182 | \$2,184 | 70% |

**💡 Expert Tip:** "Combine Savings Plans for baseline capacity with Spot instances for variable workloads—gets you 70%+ savings while maintaining reliability"

## Resource Tagging for Cost Allocation

### Comprehensive Tagging Strategy

```hcl
# cost-optimization/tagging-strategy.tf

# Define required tags
locals {
  required_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    CostCenter  = var.cost_center
    Owner       = var.owner_email
    CreatedDate = formatdate("YYYY-MM-DD", timestamp())
  }
  
  optional_tags = {
    Application = var.application_name
    Team        = var.team_name
    Compliance  = var.compliance_level
  }
  
  all_tags = merge(local.required_tags, local.optional_tags)
}

# Apply tags via provider default_tags
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = local.required_tags
  }
}

# Resource-specific tags
resource "aws_instance" "web" {
  ami           = data.aws_ami.amazon_linux_2.id
  instance_type = var.instance_type
  
  tags = merge(
    local.all_tags,
    {
      Name        = "${var.project_name}-web-server"
      Role        = "web-server"
      BackupDaily = "true"
      AutoStop    = "true"  # For automated shutdown
    }
  )
}

# Cost allocation tag module
module "cost_allocation_tags" {
  source = "./modules/cost-allocation"
  
  tag_schema = {
    mandatory_tags = [
      "Project",
      "Environment",
      "CostCenter",
      "Owner"
    ]
    
    tag_values = {
      Environment = ["production", "staging", "development", "sandbox"]
      CostCenter  = ["engineering", "marketing", "sales", "operations"]
    }
  }
}

# Activate cost allocation tags (AWS Console or CLI)
# aws ce update-cost-allocation-tags-status \
#   --cost-allocation-tags-status TagKey=Project,Status=Active \
#   --cost-allocation-tags-status TagKey=Environment,Status=Active \
#   --cost-allocation-tags-status TagKey=CostCenter,Status=Active
```


### Tag Compliance Enforcement

```hcl
# Lambda function to enforce tagging
resource "aws_lambda_function" "tag_enforcer" {
  filename      = "tag_enforcer.zip"
  function_name = "resource-tag-enforcer"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 300
  
  environment {
    variables = {
      REQUIRED_TAGS   = jsonencode(["Project", "Environment", "CostCenter", "Owner"])
      SNS_TOPIC_ARN   = aws_sns_topic.compliance_alerts.arn
      AUTO_TAG        = "true"  # Automatically tag non-compliant resources
      TERMINATE_NON_COMPLIANT = "false"  # Set true to terminate
    }
  }
}

# EventBridge rule for new resource creation
resource "aws_cloudwatch_event_rule" "resource_creation" {
  name        = "tag-compliance-check"
  description = "Check tag compliance on new resources"
  
  event_pattern = jsonencode({
    source      = ["aws.ec2", "aws.rds", "aws.s3"]
    detail-type = [
      "AWS API Call via CloudTrail"
    ]
    detail = {
      eventName = [
        "RunInstances",
        "CreateDBInstance",
        "CreateBucket"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.resource_creation.name
  target_id = "TagEnforcerLambda"
  arn       = aws_lambda_function.tag_enforcer.arn
}
```

**Tag Enforcer Lambda:**

```python
# lambda/tag_enforcer/index.py
import boto3
import json
import os

ec2 = boto3.client('ec2')
sns = boto3.client('sns')

REQUIRED_TAGS = json.loads(os.environ['REQUIRED_TAGS'])
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']
AUTO_TAG = os.environ.get('AUTO_TAG', 'false').lower() == 'true'

def handler(event, context):
    """Enforce tag compliance on new resources"""
    
    detail = event['detail']
    event_name = detail['eventName']
    
    # Extract resource information
    if event_name == 'RunInstances':
        instances = detail['responseElements']['instancesSet']['items']
        resource_ids = [inst['instanceId'] for inst in instances]
        resource_type = 'EC2 Instance'
        
    elif event_name == 'CreateDBInstance':
        resource_ids = [detail['responseElements']['dBInstanceArn']]
        resource_type = 'RDS Instance'
        
    elif event_name == 'CreateBucket':
        resource_ids = [detail['requestParameters']['bucketName']]
        resource_type = 'S3 Bucket'
    
    else:
        return {'statusCode': 200, 'body': 'Event not handled'}
    
    # Check tags for each resource
    non_compliant = []
    
    for resource_id in resource_ids:
        missing_tags = check_resource_tags(resource_id, resource_type)
        
        if missing_tags:
            non_compliant.append({
                'resource_id': resource_id,
                'resource_type': resource_type,
                'missing_tags': missing_tags
            })
            
            # Auto-tag if enabled
            if AUTO_TAG:
                apply_default_tags(resource_id, resource_type, missing_tags)
    
    # Send alert for non-compliant resources
    if non_compliant:
        message = format_compliance_alert(non_compliant)
        
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject='Tag Compliance Alert',
            Message=message
        )
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'non_compliant_count': len(non_compliant)
        })
    }

def check_resource_tags(resource_id, resource_type):
    """Check if resource has required tags"""
    
    if resource_type == 'EC2 Instance':
        response = ec2.describe_tags(
            Filters=[{'Name': 'resource-id', 'Values': [resource_id]}]
        )
        existing_tags = {tag['Key'] for tag in response['Tags']}
    
    # Similar logic for RDS, S3...
    
    missing_tags = [tag for tag in REQUIRED_TAGS if tag not in existing_tags]
    
    return missing_tags

def apply_default_tags(resource_id, resource_type, missing_tags):
    """Apply default tags to non-compliant resource"""
    
    default_values = {
        'Project': 'Untagged',
        'Environment': 'Unknown',
        'CostCenter': 'Unallocated',
        'Owner': 'unknown@example.com'
    }
    
    tags_to_apply = [
        {'Key': tag, 'Value': default_values.get(tag, 'Unknown')}
        for tag in missing_tags
    ]
    
    if resource_type == 'EC2 Instance':
        ec2.create_tags(
            Resources=[resource_id],
            Tags=tags_to_apply
        )

def format_compliance_alert(non_compliant):
    """Format compliance alert message"""
    message = "Tag Compliance Violations Detected\n"
    message += "=" * 60 + "\n\n"
    
    for item in non_compliant:
        message += f"Resource: {item['resource_id']}\n"
        message += f"Type: {item['resource_type']}\n"
        message += f"Missing Tags: {', '.join(item['missing_tags'])}\n\n"
    
    return message
```


### Cost Allocation Reports

```hcl
# Cost and Usage Report configuration
resource "aws_cur_report_definition" "cost_report" {
  report_name                = "monthly-cost-usage-report"
  time_unit                  = "DAILY"
  format                     = "Parquet"
  compression                = "Parquet"
  additional_schema_elements = ["RESOURCES"]
  s3_bucket                  = aws_s3_bucket.cost_reports.id
  s3_region                  = var.aws_region
  s3_prefix                  = "cost-reports/"
  
  additional_artifacts = ["ATHENA"]
  
  refresh_closed_reports   = true
  report_versioning        = "OVERWRITE_REPORT"
}

# S3 bucket for cost reports
resource "aws_s3_bucket" "cost_reports" {
  bucket = "cost-usage-reports-${data.aws_caller_identity.current.account_id}"
}

# Athena for querying cost data
resource "aws_athena_workgroup" "cost_analysis" {
  name = "cost-analysis-workgroup"
  
  configuration {
    result_configuration {
      output_location = "s3://${aws_s3_bucket.cost_reports.id}/query-results/"
      
      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }
}
```

**Sample Cost Allocation Query:**

```sql
-- Query cost by Cost Center and Environment
SELECT 
    line_item_usage_account_id as account_id,
    resource_tags_user_cost_center as cost_center,
    resource_tags_user_environment as environment,
    DATE_FORMAT(line_item_usage_start_date, '%Y-%m') as month,
    SUM(line_item_unblended_cost) as total_cost
FROM 
    cost_usage_report
WHERE 
    year = '2025'
    AND month IN ('11', '12')
GROUP BY 
    line_item_usage_account_id,
    resource_tags_user_cost_center,
    resource_tags_user_environment,
    DATE_FORMAT(line_item_usage_start_date, '%Y-%m')
ORDER BY 
    total_cost DESC;
```


## Infrastructure Cleanup Strategies

### Automated Resource Cleanup

```hcl
# cost-optimization/automated-cleanup.tf

# Lambda for identifying unused resources
resource "aws_lambda_function" "resource_cleanup" {
  filename      = "cleanup.zip"
  function_name = "unused-resource-cleanup"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 900  # 15 minutes
  memory_size   = 1024
  
  environment {
    variables = {
      DRY_RUN             = "true"  # Set false to actually delete
      DAYS_UNUSED         = "30"
      SNS_TOPIC_ARN       = aws_sns_topic.cleanup_alerts.arn
      EXCLUDE_TAGS        = jsonencode(["DoNotDelete", "Production"])
    }
  }
}

# Weekly cleanup schedule
resource "aws_cloudwatch_event_rule" "weekly_cleanup" {
  name                = "weekly-resource-cleanup"
  description         = "Identify and clean up unused resources weekly"
  schedule_expression = "cron(0 10 ? * SUN *)"  # Sunday 10 AM
}

resource "aws_cloudwatch_event_target" "cleanup_lambda" {
  rule      = aws_cloudwatch_event_rule.weekly_cleanup.name
  target_id = "CleanupLambda"
  arn       = aws_lambda_function.resource_cleanup.arn
}
```

**Cleanup Lambda Function:**

```python
# lambda/cleanup/index.py
import boto3
from datetime import datetime, timedelta
import json
import os

ec2 = boto3.client('ec2')
elb = boto3.client('elbv2')
rds = boto3.client('rds')
sns = boto3.client('sns')
cloudwatch = boto3.client('cloudwatch')

DRY_RUN = os.environ.get('DRY_RUN', 'true').lower() == 'true'
DAYS_UNUSED = int(os.environ.get('DAYS_UNUSED', '30'))
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']
EXCLUDE_TAGS = json.loads(os.environ.get('EXCLUDE_TAGS', '[]'))

def handler(event, context):
    """Identify and clean up unused AWS resources"""
    
    cleanup_candidates = {
        'ec2_instances': [],
        'ebs_volumes': [],
        'elastic_ips': [],
        'load_balancers': [],
        'rds_instances': [],
        'snapshots': []
    }
    
    total_potential_savings = 0
    
    # Find unused EC2 instances (stopped for > DAYS_UNUSED)
    stopped_instances = find_stopped_instances()
    cleanup_candidates['ec2_instances'] = stopped_instances
    total_potential_savings += calculate_ec2_savings(stopped_instances)
    
    # Find unattached EBS volumes
    unattached_volumes = find_unattached_ebs()
    cleanup_candidates['ebs_volumes'] = unattached_volumes
    total_potential_savings += calculate_ebs_savings(unattached_volumes)
    
    # Find unassociated Elastic IPs
    unassociated_eips = find_unassociated_eips()
    cleanup_candidates['elastic_ips'] = unassociated_eips
    total_potential_savings += len(unassociated_eips) * 3.60  # $0.005/hour
    
    # Find unused load balancers (no traffic)
    unused_lbs = find_unused_load_balancers()
    cleanup_candidates['load_balancers'] = unused_lbs
    total_potential_savings += calculate_lb_savings(unused_lbs)
    
    # Find old RDS snapshots
    old_snapshots = find_old_snapshots()
    cleanup_candidates['snapshots'] = old_snapshots
    total_potential_savings += calculate_snapshot_savings(old_snapshots)
    
    # Perform cleanup (if DRY_RUN = false)
    if not DRY_RUN:
        perform_cleanup(cleanup_candidates)
    
    # Send notification
    message = format_cleanup_report(cleanup_candidates, total_potential_savings, DRY_RUN)
    
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"Resource Cleanup Report ({'DRY RUN' if DRY_RUN else 'EXECUTED'})",
        Message=message
    )
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'total_candidates': sum(len(v) for v in cleanup_candidates.values()),
            'potential_monthly_savings': round(total_potential_savings, 2),
            'dry_run': DRY_RUN
        })
    }

def find_stopped_instances():
    """Find EC2 instances stopped for > DAYS_UNUSED"""
    cutoff_date = datetime.utcnow() - timedelta(days=DAYS_UNUSED)
    
    stopped_instances = []
    
    response = ec2.describe_instances(
        Filters=[{'Name': 'instance-state-name', 'Values': ['stopped']}]
    )
    
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            # Check if instance has exclude tags
            if has_exclude_tags(instance.get('Tags', [])):
                continue
            
            # Check state transition time
            state_transition = instance['StateTransitionReason']
            # Parse: "User initiated (2025-11-01 10:30:00 GMT)"
            
            # Simplified: use CloudWatch to check last activity
            last_activity = get_last_cpu_activity(instance['InstanceId'])
            
            if last_activity and last_activity < cutoff_date:
                stopped_instances.append({
                    'id': instance['InstanceId'],
                    'type': instance['InstanceType'],
                    'name': get_tag_value(instance.get('Tags', []), 'Name'),
                    'stopped_date': state_transition,
                    'monthly_cost': estimate_instance_cost(instance['InstanceType'])
                })
    
    return stopped_instances

def find_unattached_ebs():
    """Find EBS volumes not attached to instances"""
    unattached_volumes = []
    
    response = ec2.describe_volumes(
        Filters=[{'Name': 'status', 'Values': ['available']}]
    )
    
    for volume in response['Volumes']:
        if has_exclude_tags(volume.get('Tags', [])):
            continue
        
        # Calculate age
        create_time = volume['CreateTime'].replace(tzinfo=None)
        age_days = (datetime.utcnow() - create_time).days
        
        if age_days > DAYS_UNUSED:
            monthly_cost = volume['Size'] * 0.10  # $0.10/GB-month for gp3
            
            unattached_volumes.append({
                'id': volume['VolumeId'],
                'size': volume['Size'],
                'type': volume['VolumeType'],
                'age_days': age_days,
                'monthly_cost': monthly_cost
            })
    
    return unattached_volumes

def find_unassociated_eips():
    """Find Elastic IPs not associated with instances"""
    unassociated_eips = []
    
    response = ec2.describe_addresses()
    
    for address in response['Addresses']:
        if 'AssociationId' not in address:
            unassociated_eips.append({
                'ip': address['PublicIp'],
                'allocation_id': address['AllocationId']
            })
    
    return unassociated_eips

def find_unused_load_balancers():
    """Find load balancers with no traffic"""
    cutoff_date = datetime.utcnow() - timedelta(days=DAYS_UNUSED)
    unused_lbs = []
    
    response = elb.describe_load_balancers()
    
    for lb in response['LoadBalancers']:
        # Check CloudWatch metrics for request count
        metrics_response = cloudwatch.get_metric_statistics(
            Namespace='AWS/ApplicationELB',
            MetricName='RequestCount',
            Dimensions=[
                {'Name': 'LoadBalancer', 'Value': lb['LoadBalancerArn'].split('/')[-3] + '/' + lb['LoadBalancerArn'].split('/')[-2] + '/' + lb['LoadBalancerArn'].split('/')[-1]}
            ],
            StartTime=cutoff_date,
            EndTime=datetime.utcnow(),
            Period=86400,
            Statistics=['Sum']
        )
        
        total_requests = sum(dp['Sum'] for dp in metrics_response['Datapoints'])
        
        if total_requests == 0:
            unused_lbs.append({
                'name': lb['LoadBalancerName'],
                'arn': lb['LoadBalancerArn'],
                'type': lb['Type']
            })
    
    return unused_lbs

def find_old_snapshots():
    """Find EBS snapshots older than retention period"""
    retention_days = 90
    cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
    
    old_snapshots = []
    
    response = ec2.describe_snapshots(OwnerIds=['self'])
    
    for snapshot in response['Snapshots']:
        start_time = snapshot['StartTime'].replace(tzinfo=None)
        
        if start_time < cutoff_date:
            # Check if snapshot is being used by AMI
            if not is_snapshot_in_use(snapshot['SnapshotId']):
                old_snapshots.append({
                    'id': snapshot['SnapshotId'],
                    'volume_size': snapshot['VolumeSize'],
                    'age_days': (datetime.utcnow() - start_time).days
                })
    
    return old_snapshots

def perform_cleanup(cleanup_candidates):
    """Actually delete identified resources"""
    
    # Terminate stopped instances
    for instance in cleanup_candidates['ec2_instances']:
        ec2.terminate_instances(InstanceIds=[instance['id']])
    
    # Delete unattached volumes
    for volume in cleanup_candidates['ebs_volumes']:
        ec2.delete_volume(VolumeId=volume['id'])
    
    # Release Elastic IPs
    for eip in cleanup_candidates['elastic_ips']:
        ec2.release_address(AllocationId=eip['allocation_id'])
    
    # Delete load balancers
    for lb in cleanup_candidates['load_balancers']:
        elb.delete_load_balancer(LoadBalancerArn=lb['arn'])
    
    # Delete old snapshots
    for snapshot in cleanup_candidates['snapshots']:
        ec2.delete_snapshot(SnapshotId=snapshot['id'])

def has_exclude_tags(tags):
    """Check if resource has any exclude tags"""
    tag_keys = [tag['Key'] for tag in tags]
    return any(exclude_tag in tag_keys for exclude_tag in EXCLUDE_TAGS)

def get_tag_value(tags, key):
    """Get tag value by key"""
    for tag in tags:
        if tag['Key'] == key:
            return tag['Value']
    return 'N/A'

def format_cleanup_report(candidates, savings, dry_run):
    """Format cleanup report"""
    report = "=" * 60 + "\n"
    report += f"Resource Cleanup Report ({'DRY RUN' if dry_run else 'EXECUTED'})\n"
    report += "=" * 60 + "\n\n"
    
    report += f"Stopped EC2 Instances: {len(candidates['ec2_instances'])}\n"
    for inst in candidates['ec2_instances']:
        report += f"  - {inst['name']} ({inst['id']}): ${inst['monthly_cost']}/mo\n"
    
    report += f"\nUnattached EBS Volumes: {len(candidates['ebs_volumes'])}\n"
    for vol in candidates['ebs_volumes']:
        report += f"  - {vol['id']} ({vol['size']}GB): ${vol['monthly_cost']:.2f}/mo\n"
    
    report += f"\nUnassociated Elastic IPs: {len(candidates['elastic_ips'])}\n"
    
    report += f"\nUnused Load Balancers: {len(candidates['load_balancers'])}\n"
    
    report += f"\nOld Snapshots: {len(candidates['snapshots'])}\n"
    
    report += "\n" + "=" * 60 + "\n"
    report += f"Total Potential Monthly Savings: ${savings:.2f}\n"
    report += "=" * 60 + "\n"
    
    return report

# Helper functions (simplified)
def get_last_cpu_activity(instance_id):
    return datetime.utcnow() - timedelta(days=45)

def estimate_instance_cost(instance_type):
    pricing = {'t3.micro': 7.30, 't3.small': 14.60, 't3.medium': 29.20, 't3.large': 58.40}
    return pricing.get(instance_type, 50.00)

def calculate_ec2_savings(instances):
    return sum(inst['monthly_cost'] for inst in instances)

def calculate_ebs_savings(volumes):
    return sum(vol['monthly_cost'] for vol in volumes)

def calculate_lb_savings(lbs):
    return len(lbs) * 16.20  # $0.0225/hour

def calculate_snapshot_savings(snapshots):
    return sum(snap['volume_size'] * 0.05 for snap in snapshots)

def is_snapshot_in_use(snapshot_id):
    # Check if snapshot is associated with AMI
    response = ec2.describe_images(
        Owners=['self'],
        Filters=[{'Name': 'block-device-mapping.snapshot-id', 'Values': [snapshot_id]}]
    )
    return len(response['Images']) > 0
```


### Terraform State Cleanup

```bash
# Remove resources from state without destroying
terraform state rm 'aws_instance.old[^0]'

# Import manually created resources
terraform import aws_instance.manual i-0123456789abcdef0

# Refresh state to detect drift
terraform refresh

# Identify orphaned resources
terraform state list | while read resource; do
  echo "Checking $resource..."
  terraform state show $resource
done
```


## ⚠️ Common Pitfalls

### Pitfall 1: Not Monitoring Cost Estimates Before Apply

**❌ PROBLEM:**

```bash
terraform apply  # No cost visibility
# Bill arrives: $12,000 unexpected charges
```

**✅ SOLUTION:**

```bash
# Always check costs first
infracost breakdown --path .
terraform plan -out=tfplan
# Review carefully before apply
terraform apply tfplan
```


### Pitfall 2: Over-Provisioning "To Be Safe"

**❌ PROBLEM:**

```hcl
resource "aws_instance" "app" {
  instance_type = "m5.8xlarge"  # 32 vCPU, 128 GB
  # Actual usage: 5% CPU, 10% memory
}
# Monthly waste: $900
```

**✅ SOLUTION:**

```hcl
# Start smaller, scale based on metrics
resource "aws_instance" "app" {
  instance_type = "t3.large"  # 2 vCPU, 8 GB
  # Monitor and adjust
}
```


### Pitfall 3: Forgetting to Delete Test Resources

**❌ PROBLEM:**

```bash
# Create test environment Friday
terraform apply

# Forget about it over weekend
# Monday: $480 wasted on unused infrastructure
```

**✅ SOLUTION:**

```hcl
# Tag all test resources
tags = {
  Environment = "test"
  AutoDelete  = "true"
  ExpiresOn   = "2025-12-15"
}

# Automated cleanup Lambda deletes expired resources
```


### Pitfall 4: Not Using Reserved Instances/Savings Plans

**❌ PROBLEM:**
All workloads on On-Demand pricing unnecessarily.

**✅ SOLUTION:**

```bash
# Analyze 30-day usage
aws ce get-savings-plans-purchase-recommendation \
  --lookback-period-in-days THIRTY_DAYS

# Purchase appropriate Savings Plan
# Savings: 40-70% on predictable workloads
```


### Pitfall 5: Ignoring S3 Lifecycle Policies

**❌ PROBLEM:**

```hcl
resource "aws_s3_bucket" "logs" {
  bucket = "application-logs"
  # No lifecycle policy
  # 10 TB of old logs at $230/month
}
```

**✅ SOLUTION:**

```hcl
resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  
  rule {
    id     = "archive-old-logs"
    status = "Enabled"
    
    transition {
      days          = 30
      storage_class = "STANDARD_IA"  # $0.0125/GB
    }
    
    transition {
      days          = 90
      storage_class = "GLACIER"  # $0.004/GB
    }
    
    expiration {
      days = 365
    }
  }
}
# New monthly cost: $60 (74% savings)
```


## 💡 Expert Tips from the Field

1. **"Infracost in CI/CD catches expensive mistakes before deployment—saved us \$180K last year"** - Cost visibility during code review prevents production surprises
2. **"Right-sizing production workloads typically reduces compute costs 30-50% with zero performance impact"** - Most organizations over-provision significantly
3. **"Use Spot instances for 80% of non-production workloads—our staging environment costs \$800/month instead of \$4,000"** - Massive savings for fault-tolerant workloads
4. **"Tag everything from day one—retroactive tagging is painful and incomplete"** - Cost allocation impossible without consistent tagging
5. **"Schedule-based auto-scaling for dev/staging environments saves 60% by shutting down nights and weekends"** - Development infrastructure doesn't need 24/7 operation
6. **"Implement cost anomaly detection alerting when daily spend exceeds normal by 20%"** - Catch runaway costs within hours, not weeks
7. **"Use AWS Compute Optimizer recommendations—it analyzes actual usage and suggests perfect instance types"** - Data-driven right-sizing decisions
8. **"Combine Savings Plans (baseline) + Spot (variable) + Reserved Instances (critical) for optimal cost structure"** - Multi-pronged approach maximizes savings
9. **"S3 Intelligent-Tiering automatically optimizes storage costs—set it and forget it"** - Saves 30-40% on S3 costs automatically
10. **"Delete EBS snapshots older than 90 days unless tagged 'KeepForever'—snapshot costs accumulate silently"** - Old snapshots cost \$0.05/GB-month indefinitely
11. **"Enable Cost Anomaly Detection in AWS Cost Explorer—catches issues before month-end"** - Automated alerting for unusual spending patterns
12. **"Use AWS Budgets with automated actions to shut down resources when exceeding thresholds"** - Prevents runaway costs in development accounts
13. **"Implement 'cattle not pets' mentality—terminate and recreate instances rather than maintaining"** - Reduces long-running idle resources
14. **"GP3 volumes are 20% cheaper than GP2 with same performance—migrate all existing volumes"** - Quick win for storage costs
15. **"Graviton instances (ARM) provide 40% better price-performance than x86"** - Consider for compatible workloads

## 🎯 Practical Exercises

### Exercise 1: Implement Infracost in CI/CD Pipeline

**Difficulty:** Intermediate
**Time:** 30 minutes
**Objective:** Add cost estimation to pull requests

**Steps:**

1. **Install Infracost CLI:**
```bash
brew install infracost
infracost auth login
```

2. **Test locally:**
```bash
cd terraform/
infracost breakdown --path .
```

3. **Add GitHub Actions workflow** (use earlier example)
4. **Create pull request with infrastructure changes**
5. **Verify cost comment appears in PR**

**Validation:**

- PR comment shows cost estimate
- Cost increase/decrease clearly visible
- Policy blocks PRs exceeding threshold

**Challenge:** Add cost comparison between environments (dev vs. prod pricing)

### Exercise 2: Right-Size Production Instances

**Difficulty:** Advanced
**Time:** 60 minutes
**Objective:** Reduce costs by analyzing actual usage

**Steps:**

1. **Deploy CloudWatch agent for memory metrics:**
```bash
# Install on EC2 instance
wget https://s3.amazonaws.com/amazoncloudwatch-agent/linux/amd64/latest/AmazonCloudWatchAgent.zip
unzip AmazonCloudWatchAgent.zip
sudo ./install.sh
```

2. **Analyze 30 days of metrics:**
```bash
aws cloudwatch get-metric-statistics \
  --namespace AWS/EC2 \
  --metric-name CPUUtilization \
  --dimensions Name=InstanceId,Value=i-0123456789abcdef0 \
  --start-time $(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 86400 \
  --statistics Average
```

3. **Update Terraform with right-sized instances:**
```hcl
resource "aws_instance" "app" {
  # Before: m5.4xlarge ($560/month)
  instance_type = "t3.xlarge"  # After: ($121/month)
}
```

4. **Apply changes:**
```bash
terraform apply
```

**Expected Savings:** 70-80% for over-provisioned instances

### Exercise 3: Implement Automated Resource Cleanup

**Difficulty:** Advanced
**Time:** 45 minutes
**Objective:** Deploy Lambda to identify unused resources weekly

**Steps:**

1. **Deploy cleanup infrastructure:**
```bash
cd cost-optimization/
terraform apply
```

2. **Test Lambda function:**
```bash
aws lambda invoke \
  --function-name unused-resource-cleanup \
  --payload '{}' \
  response.json

cat response.json
```

3. **Review cleanup report email**
4. **Enable actual deletion (DRY_RUN=false)**

**Validation:**

- Weekly reports arrive via email
- Unused resources identified accurately
- Cost savings quantified

**Challenge:** Add support for identifying unused RDS instances and Lambda functions

## Key Takeaways

- **Infracost integration provides pre-deployment cost visibility** - Catches expensive configurations during code review before they reach production, preventing budget overruns
- **Right-sizing resources based on actual utilization reduces costs 30-50%** - CloudWatch metrics reveal over-provisioning, enabling data-driven instance type decisions
- **Auto-scaling eliminates manual capacity management** - Schedule-based scaling for dev/staging and metric-based scaling for production optimize capacity and costs simultaneously
- **Spot instances deliver up to 90% savings for fault-tolerant workloads** - Batch processing, development environments, and stateless applications benefit massively
- **Savings Plans and Reserved Instances reduce predictable workload costs 40-72%** - Commitment-based pricing for baseline capacity provides substantial discounts
- **Comprehensive tagging enables accurate cost allocation** - Tracking expenses by team, project, and environment requires consistent tagging from resource creation
- **Automated cleanup prevents resource sprawl** - Lambda functions identifying and terminating unused resources stop "zombie" infrastructure from accumulating costs indefinitely


## What's Next

Cost optimization transforms infrastructure-as-code from a potential budget liability into a strategic advantage, ensuring every dollar spent delivers business value. The **Conclusion** synthesizes your journey from basic Terraform resources to production-grade, cost-optimized infrastructure, explores emerging trends shaping infrastructure-as-code's future including AI-driven optimization and policy-as-code evolution, and provides a roadmap for continuous learning ensuring your skills remain relevant as cloud infrastructure and FinOps practices evolve.

## Additional Resources

**Cost Optimization Tools:**

- [Infracost Documentation](https://www.infracost.io/docs/) - Official Infracost guides
- [Infracost GitHub Actions](https://github.com/infracost/infracost) - CI/CD integration examples
- [Spacelift Infracost Guide](https://spacelift.io/blog/terraform-cost-estimation-using-infracost) - Comprehensive tutorial

**AWS Cost Management:**

- [AWS Right Sizing Guide](https://aws.amazon.com/aws-cost-management/aws-cost-optimization/right-sizing/) - Official AWS recommendations
- [AWS Savings Plans Pricing](https://aws.amazon.com/savingsplans/compute-pricing/) - Commitment-based discounts
- [ControlMonkey Cost Playbook](https://controlmonkey.io/blog/terraform-aws-cost-optimization-playbook/) - 11 proven cost optimization tips

**Tagging and Allocation:**

- [Multi-Cloud Tagging Strategy](https://blog.poespas.me/posts/2025/02/12/optimizing-multi-cloud-cost-allocation-with-terraform-and-aws-tagging/) - Cost allocation best practices
- [Vantage FinOps Guide](https://www.vantage.sh/blog/terraform-automate-cost-tags) - Automating cost tags
