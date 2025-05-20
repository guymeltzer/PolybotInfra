region           = "us-east-1"
control_plane_ami = "ami-052edda5de5f8e53b"  # Ubuntu 24.04 LTS
worker_ami        = "ami-052edda5de5f8e53b"  # Ubuntu 24.04 LTS
route53_zone_id   = "Z1234567890"            # Replace with your actual Route53 zone ID
key_name          = "guy-key-pair"           # Replace with your SSH key name in this region
vpc_id            = ""                       # Leave empty to create a new VPC
subnet_ids        = []                       # Leave empty to create new subnets
git_repo_url      = "https://github.com/guymeltzer/PolybotInfra.git"
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
docker_username   = "guymeltzer"
docker_password   = "Candy2025!"

