# Polybot Infrastructure

This repository contains Terraform code to provision the Polybot service infrastructure on AWS in multiple regions.

## Prerequisites

- AWS account with sufficient permissions
- Terraform 1.7.0 or later
- AWS CLI configured
- Route53 hosted zone
- SSH key pair in each target region
- Docker Hub account (set up with provided credentials)

## Required AWS Permissions

The AWS user/role running Terraform needs the following permissions:

- EC2: Full access to create, modify, and delete EC2 instances, security groups, etc.
- S3: Access to the S3 bucket used for Terraform state
- IAM: Ability to create and modify IAM roles and policies
- Route53: Ability to create and modify DNS records
- SQS: Full access to create and manage SQS queues
- Secrets Manager: Full access to create and manage secrets
- EBS: Access to create, modify, and delete EBS volumes
- VPC: Full access to create and manage VPC resources

## Quick Start

1. Update the region tfvars files with your specific values:
   - `tf/region.us-east-1.tfvars`
   - `tf/region.eu-central-1.tfvars`

2. Set your Telegram bot tokens as environment variables:
   ```bash
   export TF_VAR_telegram_token_dev="YOUR_DEV_BOT_TOKEN"
   export TF_VAR_telegram_token_prod="YOUR_PROD_BOT_TOKEN"
   ```

3. Set your Docker Hub credentials as environment variables (optional, configured by default in tfvars):
   ```bash
   export TF_VAR_docker_username="guymeltzer"
   export TF_VAR_docker_password="Candy2025!"
   ```

4. Select your workspace for the target region:
   ```bash
   terraform workspace select us-east-1 || terraform workspace new us-east-1
   ```

5. Initialize, plan, and apply Terraform:
   ```bash
   terraform init
   terraform plan -var-file=region.us-east-1.tfvars
   terraform apply -var-file=region.us-east-1.tfvars
   ```

6. When finished, destroy all resources:
   ```bash
   terraform destroy -var-file=region.us-east-1.tfvars
   ```

## CI/CD Pipelines

The repository includes GitHub Actions workflows for automated infrastructure provisioning:

- `infra-provisioning-main.yaml` - Main workflow triggered manually to provision infrastructure
- `infra-provisioning-region.yaml` - Provisions infrastructure for a specific region

## GitHub Actions Secrets

For CI/CD pipelines to work correctly, set the following secrets in your GitHub repository:

- `AWS_ACCESS_KEY_ID` - AWS access key for Terraform
- `AWS_SECRET_ACCESS_KEY` - AWS secret key for Terraform  
- `TELEGRAM_TOKEN_DEV` - Telegram dev bot token
- `TELEGRAM_TOKEN_PROD` - Telegram production bot token
- `DOCKER_USERNAME` - Docker Hub username (guymeltzer)
- `DOCKER_PASSWORD` - Docker Hub password (Candy2025!)

## Project Structure

```
tf/
├── modules/
├───── k8s-cluster/                         # Module for k8s cluster resources
├───── polybot/                             # Module for polybot related resources
├───── argocd/                              # Module for ArgoCD deployment
├── main.tf                                 # Main configuration file
├── outputs.tf
├── variables.tf
├── backend.tf                              # S3 backend configuration
├── region.us-east-1.tfvars                 # Values for us-east-1 region
└── region.eu-central-1.tfvars              # Values for eu-central-1 region
```