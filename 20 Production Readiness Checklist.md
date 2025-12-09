# Chapter 20: Production Readiness Checklist

## Introduction

Production deployments succeed or fail long before `terraform apply` runs—success depends on the rigor of your checklists, standards, and review processes, not on any single command. A small misconfiguration such as an open security group, missing backup policy, or incorrectly tagged resource can translate into outages, data loss, or uncontrolled cost growth once deployed at scale. Production readiness is therefore a discipline: a repeatable set of validations, documentation practices, naming standards, and operational processes that every change must pass before it reaches live environments.

This chapter provides a practical, opinionated production readiness checklist tailored to Terraform and AWS, covering pre-deployment validation, formatting and validation standards, consistent naming conventions, documentation expectations, disaster recovery planning, change management workflows, and prompt remediation procedures. You can adapt it into your own “go/no-go” gate for production, integrate it with CI/CD, and enforce it via policy-as-code and automation. The goal is that no change reaches production without passing the same rigorous, auditable set of checks every single time.

***

## Pre-Deployment Validation Checklist

A structured pre-deployment checklist reduces human error and ensures every change is reviewed from correctness, security, reliability, and cost perspectives.

### Core Terraform Validation

- `terraform fmt` passes on all files.
- `terraform validate` and `terraform plan` complete without errors.
- Plan is reviewed by at least one peer (four-eyes principle) for correctness, security, and blast radius.
- Plan output is stored (artifact) for audit and rollback analysis.


### Environment and Safety Checks

- Change is being applied to the correct environment and AWS account (e.g., using dedicated profiles and clear environment variables).
- Remote backend (S3 + DynamoDB) is configured with locking, encryption, and versioning.
- State drift was checked with either `terraform plan -refresh-only` or a separate drift detection workflow.
- Any manual state manipulations (`terraform state mv` / `rm` / `import`) are documented and reviewed.


### Security and Compliance Checks

- No security groups allow `0.0.0.0/0` on sensitive ports (SSH, RDP, DB ports) except where explicitly justified and documented.
- KMS encryption is enabled for state, EBS, RDS, S3, and backups where required.
- IAM roles follow least privilege; wildcard (`*`) actions/resources are justified and approved.
- Guardrails (Sentinel/OPA, AWS Config, SCPs) are green for the change set.


### Availability and Reliability Checks

- Multi-AZ is configured for critical databases and load balancers.
- Health checks and alarms are in place for application endpoints and critical metrics.
- Auto-scaling policies are configured and tested where applicable.
- Runbooks exist for scaling, failover, and restoration for the components being changed.


### Cost and Tagging Checks

- Cost impact is estimated (e.g., via cost estimation tooling or manual calculation) and under agreed thresholds or explicitly approved.
- Mandatory tags (Environment, Project, CostCenter, Owner, etc.) are present on all resources.
- Lifecycle policies are configured for S3, snapshots, and logs to avoid unbounded growth.

***

## Formatting and Validation Standards

Formal standards ensure code is readable, maintainable, and enforceable via automation.

### Terraform Formatting

- `terraform fmt -recursive` is enforced via pre-commit hooks and CI.
- Use 2 spaces for indentation, no tabs.
- One resource/module per logical block with clear, consistent ordering: `resource` block, `depends_on`, `lifecycle`, then arguments.


### Validation and Linting

- `terraform validate` is mandatory in CI for all modules and root stacks.
- Optional but recommended: static analysis using tools such as `tflint`, `tfsec`, or Checkov to catch security and style issues.
- Validation failures block merges to main and production deployment branches.


### Module and File Organization

- Standard files per root module: `main.tf`, `variables.tf`, `outputs.tf`, `providers.tf`, `backend.tf`, `locals.tf`, `versions.tf`.
- Modules live under `modules/` with the same structure, plus `README.md` describing inputs/outputs and usage.
- Environment-specific configuration lives in separate folders (`envs/dev`, `envs/stage`, `envs/prod`) or separate workspaces, not conditionals for fundamentally different topologies.

***

## Consistent Naming Conventions

Consistent naming reduces cognitive load, eases debugging, and helps cost allocation and security reviews.

### General Naming Rules

- Use lowercase with underscores or hyphens (`my_app_api`, `my-app-api`); avoid camelCase in resource names.
- Include environment and region where helpful (e.g., `myapp-prod-us-east-1-vpc`).
- Avoid embedding account IDs in names unless specifically needed.
- Use descriptive, role-based names (`app_web_asg`, `app_db_primary`, `shared_network_transit_gateway`).


### Terraform Resource Names

```
- Resource names: `<layer>_<component>_<role>` (e.g., `network_vpc_main`, `app_alb_public`, `data_rds_primary`).  
```

- Variable names are nouns describing intent, not implementation (`max_capacity`, `db_backup_retention_days`, `enable_waf`).
- Output names indicate what is exposed and why (`alb_dns_name`, `vpc_id`, `db_reader_endpoint`).


### AWS Resource Naming

- S3 buckets: `org-project-env-purpose[-region]` (e.g., `acme-logs-prod-central-us-east-1`).
- IAM roles: `project-env-role-name` (e.g., `billing-prod-terraform-execution`).
- Security groups: `project-env-role-sg` (e.g., `myapp-prod-alb-sg`).
- RDS identifiers: `project-env-role-db` (e.g., `myapp-prod-primary-db`).

***

## Documentation Requirements

Treat infrastructure like an application: production-ready code is always accompanied by clear, current documentation.

### Mandatory Documentation Artifacts

- **Architecture diagrams** for each major system: VPC layout, multi-account relationships, DR topology, and data flows.
- **Module README**: usage examples, inputs/outputs, assumptions, and constraints.
- **Runbooks**: operational procedures for common scenarios (deploy, rollback, failover, capacity increase).
- **Onboarding guide**: how new engineers can set up environment, run `terraform plan`, and safely contribute.


### Documentation Currency and Ownership

- Documentation is updated as part of every change, not as an afterthought.
- Each module/system has an explicit owner (team or individual) responsible for keeping docs accurate.
- “Last reviewed” dates on key documents (e.g., DR runbook, security posture) with a scheduled review cadence.


### Code and Change History

- Each Terraform change references a ticket/issue ID (e.g., in commit messages or PR titles) for traceability.
- Significant changes (new services, DR model change, major cost shift) are recorded in a `CHANGELOG.md` per system.

***

## Disaster Recovery Planning

Production readiness demands documented, tested disaster recovery (DR) strategies that match business RTO and RPO.

### DR Strategy Definition

- For each application, DR strategy is explicitly defined: backup/restore, pilot light, warm standby, or active-active.
- RTO (Recovery Time Objective) and RPO (Recovery Point Objective) are agreed with business stakeholders and documented.
- Critical dependencies (RDS, S3, queues, DNS, identity) are mapped and included in DR plans.


### DR Implementation Requirements

- Automated backups configured for databases and critical state; retention periods match compliance needs.
- Cross-region replication configured where required (e.g., S3 CRR, DynamoDB global tables, read replicas).
- Terraform code supports recreation of infrastructure in DR region with minimal manual steps (parameterized region, DR toggles).


### DR Testing and Validation

- DR tests are scheduled at least annually (ideally quarterly) with clear, scripted scenarios.
- Each DR test yields a report: what was tested, what worked, what failed, and what was improved.
- Failover and failback procedures are documented as executable runbooks with step-by-step commands and validation steps.

***

## Change Management Processes

Change management ensures production changes are controlled, auditable, and reversible.

### Change Workflow

- All infrastructure changes flow through Git-based workflows (no “console first” changes in production).
- Branch protection rules enforce PR reviews, status checks (linting, tests, plans), and required approvals.
- Changes to high-risk components (networking, IAM, state backends, DR) require elevated approvals or CAB review.


### Environment Promotion

- Changes move from dev → staging → production with automated or semi-automated promotions (same code, different vars).
- Production is never a one-off fork of staging; differences are expressed via variables, workspaces, or environment overlays.
- Blue/green or canary patterns are preferred for impactful changes where feasible (e.g., new ALB, new RDS, new EKS nodegroup).


### Auditability and Governance

- Every production apply is associated with a ticket/change record and stored plan/apply logs.
- State file changes are logged with who, when, and what changed (e.g., using Terraform Cloud, Atlantis, Spacelift, or custom tooling).
- Policy-as-code (Sentinel/OPA) enforces organizational rules: required tags, blocked regions, size limits, encryption requirements.

***

## Prompt Remediation Procedures

Even with strong checklists, incidents will happen. Production readiness includes how quickly and reliably you can detect and remediate issues.

### Detection and Alerting

- Alerts configured for availability (HTTP 5xx, latency), capacity (CPU, memory, disk, queue depth), and security (unusual access patterns).
- Cost anomaly alerts configured to detect unexpected spend spikes.
- Dashboards exist for each major system combining infrastructure and application metrics.


### Standard Remediation Playbooks

- **Rollback:** documented process for reverting to previous Terraform version (e.g., re-applying last known good commit and state).
- **Hotfix:** small, targeted changes that can be safely fast-tracked under an emergency change procedure.
- **Scale-out:** known procedures for temporarily increasing capacity to stabilize a system before deeper fixes.


### Escalation and Communication

- Clear on-call rota and escalation paths for infrastructure incidents.
- Defined communication templates: what to say to stakeholders, how often to update, and where (Slack/Teams/status page).
- Blameless postmortem process focusing on systemic improvements, not individual blame.

***

## Production Readiness Checklist (Summary)

Use this checklist as a practical “go/no-go” gate before any Terraform-driven production change:

- **Validation \& Safety**
    - [ ] `terraform fmt`, `validate`, `plan` all pass; plan reviewed and stored.
    - [ ] Correct environment/account verified; remote state configured with locking and encryption.
    - [ ] Security controls (IAM, SGs, encryption) meet organizational standards.
- **Reliability \& DR**
    - [ ] Health checks, alarms, and logs in place for all critical paths.
    - [ ] DR strategy (backup/restore or multi-region) defined and implemented; RTO/RPO documented.
- **Cost \& Tagging**
    - [ ] Cost impact understood and within approved thresholds; estimates available to reviewers.
    - [ ] Mandatory tags applied for cost allocation and governance on all new resources.
- **Standards \& Documentation**
    - [ ] Naming conventions followed consistently across Terraform and AWS resources.
    - [ ] Architecture diagrams, module READMEs, and runbooks updated to reflect this change.
- **Process \& Remediation**
    - [ ] Change is tracked via ticket/issue; approvals recorded.
    - [ ] Rollback plan and remediation playbooks are documented and understood by on-call engineers.


## What’s Next

With a robust production readiness checklist in place, you can move from ad-hoc deployments to repeatable, auditable, and safe production operations. The Conclusion will synthesize all preceding chapters—architecture, modules, state, security, cost optimization, and production readiness—into a cohesive operating model for Terraform on AWS, and outline how to evolve your platform with advanced patterns such as policy-as-code, platform engineering, and AI-assisted infrastructure workflows.

