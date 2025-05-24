region            = "eu-central-1"

# Ubuntu 22.04 LTS AMIs for eu-central-1 
control_plane_ami = "ami-04e601abe3e1a910f"
worker_ami        = "ami-04e601abe3e1a910f"

# EC2 instance types
control_plane_instance_type = "t3.medium"
instance_type               = "t3.medium"

# Worker node scaling
min_worker_nodes     = 2
max_worker_nodes     = 5
desired_worker_nodes = 2

# Network configuration
pod_cidr = "10.244.0.0/16"  # Flannel default

# Route53 zone ID (replace with your actual zone ID)
route53_zone_id = "ZXXXXXXXXXX"

key_name          = "polybot-key"            # SSH key for instance access
vpc_id            = ""                       # Leave empty to create a new VPC

# Telegram tokens should be set via environment variables
# export TF_VAR_telegram_token_dev="YOUR_DEV_BOT_TOKEN"
# export TF_VAR_telegram_token_prod="YOUR_PROD_BOT_TOKEN"

# AWS Credentials used by Polybot (optional, can be set via environment variables)
# export TF_VAR_aws_access_key_id="YOUR_AWS_ACCESS_KEY"
# export TF_VAR_aws_secret_access_key="YOUR_AWS_SECRET_KEY"

# Docker Hub credentials for pulling images (optional, can be set via environment variables)
# export TF_VAR_docker_username="YOUR_DOCKER_USERNAME"
# export TF_VAR_docker_password="YOUR_DOCKER_PASSWORD"

# Hardcoded values for Docker Hub credentials (use environment variables in production)
docker_username = "guymeltzer"
docker_password = "Candy2025!"