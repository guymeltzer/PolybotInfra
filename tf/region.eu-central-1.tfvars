region           = "eu-central-1"
control_plane_ami = "ami-0ec7f9846da6b0f61"  # Ubuntu 20.04 LTS (update regularly)
worker_ami        = "ami-0ec7f9846da6b0f61"  # Ubuntu 20.04 LTS (update regularly)
route53_zone_id   = "Z02842682SGSPDJQMJGFT"    # Update with the actual Route53 zone ID
vpc_id            = ""  # Will be created by terraform
subnet_ids        = []  # Will be created by terraform
key_name          = "polybot-key"  # Replace with your SSH key name
git_repo_url      = "https://github.com/guymeltzer/PolybotInfra.git"
# Telegram tokens should be set via environment variables
# export TF_VAR_telegram_token_dev="YOUR_DEV_BOT_TOKEN"
# export TF_VAR_telegram_token_prod="YOUR_PROD_BOT_TOKEN"