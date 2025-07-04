region            = "us-east-1"

# Ubuntu 22.04 LTS AMIs for us-east-1
control_plane_ami = "ami-0574da719dca65348"
worker_ami        = "ami-0574da719dca65348"

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
route53_zone_id = "Z02842682SGSPDJQMJGFT"

# SSL domain configuration  
domain_name = "guy-polybot.devops-int-college.com"

key_name                   = "polybot-key"           # SSH key for instance access
ssh_private_key_file_path  = "~/.ssh/polybot-key.pem" 
vpc_id                     = ""                      # Leave empty to create a new VPC
subnet_ids                 = []                      # Leave empty to create new subnets
git_repo_url               = "https://github.com/guymeltzer/PolybotInfra.git"

# REQUIRED: Telegram bot token (get from @BotFather on Telegram)
telegram_token = "YOUR_TELEGRAM_BOT_TOKEN_HERE"

# REQUIRED: Docker Hub credentials for pulling private images
docker_username = "guymeltzer"
docker_password = "Candy2025!"

# OPTIONAL: AWS credentials (if not provided, uses your current aws configure settings)
# aws_access_key_id = "YOUR_AWS_ACCESS_KEY"
# aws_secret_access_key = "YOUR_AWS_SECRET_KEY"

# NOTE: The following are AUTO-GENERATED by Terraform:
# - S3 bucket (polybot-storage-XXXX)
# - SQS queue (polybot-processing-queue)  
# - MongoDB URI (in-cluster MongoDB)
# - Application URLs (based on load balancer)

# Legacy variable names for backward compatibility (will be ignored with warnings)
root_key_name                  = "polybot-key"
root_ssh_private_key_file_path = "~/.ssh/polybot-key.pem"
