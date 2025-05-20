# PolybotInfra Terraform Deployment

## Prerequisites
- AWS CLI configured
- Terraform installed
- Access to AWS account with required permissions
- SSH key pair for access to EC2 instances

## Deployment Instructions

### 1. Create or update terraform.tfvars
Ensure your terraform.tfvars file contains all required variables:

```
region = "us-east-1"
vpc_id = "vpc-xxxxxxxx"
subnet_ids = ["subnet-xxxxxxxx", "subnet-yyyyyyyy"]
route53_zone_id = "Zxxxxxxxxxxxxxxx"
key_name = "your-ssh-key"
control_plane_ami = "ami-xxxxxxxxx"
worker_ami = "ami-xxxxxxxxx"
telegram_token_dev = "your-telegram-token-dev"
telegram_token_prod = "your-telegram-token-prod"
aws_access_key_id = "your-aws-access-key"
aws_secret_access_key = "your-aws-secret-key"
docker_username = "your-docker-username"
docker_password = "your-docker-password"
git_repo_url = "https://github.com/your-org/your-repo.git"
```

### 2. Run Terraform

```
terraform init
terraform apply
```

The infrastructure deployment includes automatic initialization of required files and configurations. A valid kubeconfig will be created automatically as part of the Terraform workflow.

## Troubleshooting

### kubeconfig parse error
If you get an error like:
```
Error: Provider configuration: cannot load Kubernetes client config
```

This should be automatically handled by the `terraform_data.init_environment` resource. If issues persist, you can manually create a kubeconfig with the included script:

```
chmod +x ./create_kubeconfig.sh
./create_kubeconfig.sh
```

### AWS Resource Provisioning
The infrastructure creates:
1. EC2 instances for Kubernetes control plane and worker nodes
2. Security groups and IAM roles
3. Load balancer and Route53 records
4. Kubernetes namespaces and resources

### Kubernetes Resources
After the cluster is provisioned:
1. AWS EBS CSI driver is installed
2. ArgoCD is deployed
3. Development and production namespaces are created
4. Polybot application resources are provisioned

## Clean Up

To destroy all resources:

```
terraform destroy
``` 