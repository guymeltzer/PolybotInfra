region           = "us-east-1"
control_plane_ami = "ami-07d9b9ddc6cd8dd30"  # Ubuntu 20.04 LTS (update regularly)
worker_ami        = "ami-07d9b9ddc6cd8dd30"  # Ubuntu 20.04 LTS (update regularly)
route53_zone_id   = "Z02842682SGSPDJQMJGFT"    # Update with the actual Route53 zone ID
vpc_id            = ""  # Will be created by terraform
subnet_ids        = []  # Will be created by terraform
key_name          = "polybot-key"  # Replace with your SSH key name
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
