# PolybotInfra - Terraform Kubernetes Deployment

## Implemented Fixes

This Terraform project has been updated to fix several issues:

1. **SSH Key Handling:**
   - Added better fallback logic for SSH key paths
   - Improved error messages for missing keys
   - Safer key permission setting

2. **Disk Pressure:**
   - Added comprehensive worker node cleanup
   - Created scheduled cleanup job (runs every 6 hours)
   - Implemented emergency cleanup job
   - Better file deletion syntax for finding large log files

3. **Storage Classes:**
   - Separated storage class creation into its own resource
   - Fixed conflict between EBS CSI driver and StorageClass creation
   - Added dedicated MongoDB storage class

4. **MongoDB Deployment:**
   - Simplified MongoDB deployment with better resource limits
   - Added health probes and error handling
   - Fixed storage class consistency issues
   - Added verification step for MongoDB functionality

5. **IAM Permissions:**
   - Added service-linked role creation for EBS CSI Driver
   - Added fallback handling for IAM permission errors
   - AWS provider configured with ability to assume roles if needed

6. **Calico/Tigera Installation:**
   - Fixed annotation length error in Tigera operator
   - Added resource limits to Calico components
   - Improved cleanup of previous Calico installations

7. **General Improvements:**
   - Reverted instance type to t3.medium
   - Added better dependency management
   - Improved error handling throughout
   - Added verification and validation steps

## Usage

1. **Prerequisites:**
   - AWS CLI configured with appropriate permissions
   - kubectl installed
   - jq installed for JSON parsing

2. **Deployment:**
   ```bash
   terraform init
   terraform apply
   ```

3. **Verification:**
   Once deployed, you can access your cluster with:
   ```bash
   export KUBECONFIG=$(pwd)/tf/kubeconfig.yaml
   kubectl get nodes
   ```

## Troubleshooting

If you encounter permission issues:
- Check the IAM permissions of your AWS account
- Consider using a role with appropriate permissions
- Verify that service-linked roles are allowed to be created

For disk pressure issues:
- Run the cleanup jobs manually: `kubectl create job --from=cronjob/node-cleanup immediate-cleanup -n kube-system`
- Consider increasing instance size if persistent
- Add additional EBS volumes for high storage workloads

# PolybotInfra

This repository contains Terraform code to provision the Polybot service infrastructure on AWS in multiple regions.

## Infrastructure Overview

The infrastructure consists of:

1. **Kubernetes Cluster**: A self-managed Kubernetes cluster using kubeadm
   - Control plane node (t3.medium)
   - Worker nodes in an Auto Scaling Group (t3.medium)
   - Calico CNI for networking
   - EBS CSI Driver for persistent storage
   - AWS Load Balancer for ingress

2. **Polybot AWS Resources**:
   - S3 bucket for storage
   - SQS queue for message processing
   - SNS topics for notifications
   - Route53 records for DNS
   - Secrets Manager for sensitive data

3. **ArgoCD**: For GitOps-based deployments of Polybot and Yolo5 services

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

1. Clone this repository:
   ```bash
   git clone https://github.com/guymeltzer/PolybotInfra.git
   cd PolybotInfra
   ```

2. Update the region tfvars files with your specific values:
   - `tf/region.us-east-1.tfvars`
   - `tf/region.eu-central-1.tfvars`

3. Set your Telegram bot tokens as environment variables:
   ```bash
   export TF_VAR_telegram_token_dev="YOUR_DEV_BOT_TOKEN"
   export TF_VAR_telegram_token_prod="YOUR_PROD_BOT_TOKEN"
   ```

4. Set your Docker Hub credentials as environment variables:
   ```bash
   export TF_VAR_docker_username="YOUR_DOCKER_USERNAME"
   export TF_VAR_docker_password="YOUR_DOCKER_PASSWORD"
   ```

5. Select your workspace for the target region:
   ```bash
   cd tf
   terraform workspace select us-east-1 || terraform workspace new us-east-1
   ```

6. Initialize, plan, and apply Terraform:
   ```bash
   terraform init
   terraform plan -var-file=region.us-east-1.tfvars
   terraform apply -var-file=region.us-east-1.tfvars
   ```

7. When finished, destroy all resources:
   ```bash
   terraform destroy -var-file=region.us-east-1.tfvars
   ```

## CI/CD Pipelines

The repository includes GitHub Actions workflows for automated infrastructure provisioning:

- `infra-provisioning-main.yaml` - Main workflow triggered manually to provision/destroy infrastructure

## GitHub Actions Secrets

For CI/CD pipelines to work correctly, set the following secrets in your GitHub repository:

- `AWS_ACCESS_KEY_ID` - AWS access key for Terraform
- `AWS_SECRET_ACCESS_KEY` - AWS secret key for Terraform  
- `TELEGRAM_TOKEN_DEV` - Telegram dev bot token
- `TELEGRAM_TOKEN_PROD` - Telegram production bot token
- `DOCKER_USERNAME` - Docker Hub username
- `DOCKER_PASSWORD` - Docker Hub password

## Project Structure

```
tf/
├── modules/
├───── k8s-cluster/                         # Module for Kubernetes cluster resources
│     ├── control_plane_user_data.sh        # Initialization script for control plane
│     ├── worker_user_data.sh               # Initialization script for worker nodes
│     ├── main.tf
│     ├── variables.tf
│     └── outputs.tf
├───── polybot/                             # Module for polybot related resources
│     ├── main.tf
│     ├── variables.tf
│     └── outputs.tf
├───── kubernetes-resources/                # Module for Kubernetes components
│     ├── main.tf                           # Resources for storage, MongoDB, cleanup, etc.
│     ├── variables.tf                      # Input variables for the module
│     └── outputs.tf                        # Output values from the module
├───── argocd/                              # Module for ArgoCD deployment
│     ├── main.tf
│     ├── variables.tf
│     └── outputs.tf
├── main.tf                                 # Main configuration file
├── outputs.tf                              # Output values
├── variables.tf                            # Input variables
├── backend.tf                              # S3 backend configuration
├── region.us-east-1.tfvars                 # Values for us-east-1 region
└── region.eu-central-1.tfvars              # Values for eu-central-1 region

k8s/                                        # Kubernetes manifests
├── Polybot/                                # Polybot service manifests
├── Yolo5/                                  # Yolo5 service manifests
└── MongoDB/                                # MongoDB manifests

.github/workflows/                          # GitHub Actions workflows
└── infra-provisioning-main.yaml            # Main infra provisioning workflow
```

## Accessing the Kubernetes Cluster

After the infrastructure is provisioned, you can access the Kubernetes cluster using:

```bash
# The command below will be provided in the Terraform outputs
ssh ubuntu@<control-plane-ip> 'cat /home/ubuntu/.kube/config' > kubeconfig.yaml
export KUBECONFIG=$(pwd)/kubeconfig.yaml
kubectl get nodes
```

## Troubleshooting

If you encounter issues with the control plane initialization, check the logs on the control plane instance:

```bash
ssh ubuntu@<control-plane-ip> 'sudo cat /var/log/k8s-control-plane-init.log'
```

For worker node issues:

```bash
ssh ubuntu@<worker-node-ip> 'sudo cat /var/log/k8s-worker-init.log'
```