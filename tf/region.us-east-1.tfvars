region           = "us-east-1"
control_plane_ami = "ami-084568db4383264d4"  # Ubuntu AMI in us-east-1
worker_ami        = "ami-084568db4383264d4"  # Ubuntu AMI in us-east-1
route53_zone_id   = "Z02842682SGSPDJQMJGFT"  # Your actual Route53 zone ID
key_name          = ""                       # Set to empty to create instances without SSH key
vpc_id            = ""                       # Leave empty to create a new VPC
subnet_ids        = []                       # Leave empty to create new subnets
git_repo_url      = "https://github.com/guymeltzer/PolybotInfra.git"

# Telegram token values (replace with your actual tokens)
telegram_token_dev  = "YOUR_DEV_TELEGRAM_TOKEN"
telegram_token_prod = "YOUR_PROD_TELEGRAM_TOKEN"

# Docker Hub credentials
docker_username   = "guymeltzer"  # Your Docker Hub username
docker_password   = "Candy2025!"  # Your Docker Hub password

# These variables should be set via environment variables for security
# export TF_VAR_telegram_token_dev="YOUR_DEV_BOT_TOKEN"
# export TF_VAR_telegram_token_prod="YOUR_PROD_BOT_TOKEN"
# export TF_VAR_aws_access_key_id="YOUR_AWS_ACCESS_KEY"
# export TF_VAR_aws_secret_access_key="YOUR_AWS_SECRET_KEY"
# export TF_VAR_docker_username="YOUR_DOCKER_USERNAME"
# export TF_VAR_docker_password="YOUR_DOCKER_PASSWORD"

# These credentials should NEVER be hardcoded in production
# For development/testing only

