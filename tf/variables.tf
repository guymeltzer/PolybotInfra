variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "ID of the VPC where resources will be created. If not provided, a new VPC will be created."
  type        = string
  default     = ""
}

variable "subnet_ids" {
  description = "List of subnet IDs for the Kubernetes cluster. If not provided, new subnets will be created."
  type        = list(string)
  default     = []
}

variable "route53_zone_id" {
  description = "Route53 zone ID for DNS records"
  type        = string
}

variable "key_name" {
  description = "SSH key name for EC2 instances"
  type        = string
  default     = ""
  sensitive   = true
}

variable "control_plane_ami" {
  description = "AMI ID for control plane nodes"
  type        = string
}

variable "worker_ami" {
  description = "AMI ID for worker nodes"
  type        = string
}

variable "git_repo_url" {
  description = "URL of the Git repository containing the application manifests"
  type        = string
  default     = "https://github.com/guymeltzer/PolybotInfra.git"
}

variable "environment" {
  description = "Environment (dev or prod)"
  type        = string
  default     = "prod"
  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "Environment must be either 'dev' or 'prod'."
  }
}

variable "telegram_token_dev" {
  description = "Telegram bot token for development environment"
  type        = string
  sensitive   = true
  default     = ""
}

variable "telegram_token_prod" {
  description = "Telegram bot token for production environment"
  type        = string
  sensitive   = true
  default     = ""
}

variable "telegram_token" {
  description = "Telegram bot token for Polybot (required - get this from @BotFather on Telegram)"
  type        = string
  sensitive   = true
}

variable "sqs_queue_url" {
  description = "SQS queue URL for Polybot (auto-generated if not provided)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "s3_bucket_name" {
  description = "S3 bucket name for Polybot (auto-generated if not provided)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "telegram_app_url" {
  description = "Telegram app URL for Polybot (auto-generated if not provided)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "aws_access_key_id" {
  description = "AWS access key ID for Polybot (uses current AWS credentials if not provided)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "aws_secret_access_key" {
  description = "AWS secret access key for Polybot (uses current AWS credentials if not provided)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "mongo_collection" {
  description = "MongoDB collection name for Polybot"
  type        = string
  default     = "polybot"
}

variable "mongo_db" {
  description = "MongoDB database name for Polybot"
  type        = string
  default     = "polybot"
}

variable "mongo_uri" {
  description = "MongoDB URI for Polybot (auto-generated for in-cluster MongoDB if not provided)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "polybot_url" {
  description = "Polybot application URL (auto-generated if not provided)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "docker_username" {
  description = "Docker registry username (required for pulling private images)"
  type        = string
  sensitive   = true
}

variable "docker_password" {
  description = "Docker registry password (required for pulling private images)"
  type        = string
  sensitive   = true
}

variable "control_plane_instance_type" {
  description = "EC2 instance type for the Kubernetes control plane"
  type        = string
  default     = "t3.medium"
}

variable "instance_type" {
  description = "EC2 instance type for the Kubernetes worker nodes"
  type        = string
  default     = "t3.medium"
}

variable "min_worker_nodes" {
  description = "Minimum number of worker nodes in the auto-scaling group"
  type        = number
  default     = 2
}

variable "max_worker_nodes" {
  description = "Maximum number of worker nodes in the auto-scaling group"
  type        = number
  default     = 5
}

variable "desired_worker_nodes" {
  description = "Desired number of worker nodes in the auto-scaling group"
  type        = number
  default     = 2
}

variable "ssh_public_key" {
  description = "SSH public key to use for the instances (will be generated if not provided)"
  type        = string
  default     = ""
}

variable "skip_api_verification" {
  description = "Skip API server verification (true/false)"
  type        = bool
  default     = false
}

variable "skip_token_verification" {
  description = "Skip join token verification (true/false)"
  type        = bool
  default     = false
}

variable "verification_max_attempts" {
  description = "Maximum number of attempts for control plane verification"
  type        = number
  default     = 20
}

variable "verification_wait_seconds" {
  description = "Seconds to wait between verification attempts"
  type        = number
  default     = 30
}

variable "allow_worker_registration" {
  description = "Allow workers to register with the cluster"
  type        = bool
  default     = true
}

variable "pod_cidr" {
  description = "CIDR block for Kubernetes pod network"
  type        = string
  default     = "10.244.0.0/16"
}

# Additional variables for cluster configuration
variable "cluster_name" {
  description = "Name of the Kubernetes cluster"
  type        = string
  default     = "guy-cluster"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "subnet_cidrs" {
  description = "List of subnet CIDR blocks"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "ami_id" {
  description = "AMI ID for EC2 instances (for backwards compatibility)"
  type        = string
  default     = ""
}

variable "worker_instance_type" {
  description = "Instance type for worker nodes"
  type        = string
  default     = "t3.medium"
}

variable "worker_node_count" {
  description = "Number of worker nodes (for backwards compatibility)"
  type        = number
  default     = 2
}

variable "rebuild_workers" {
  description = "Flag to trigger rebuild of worker nodes"
  type        = bool
  default     = false
}

variable "rebuild_control_plane" {
  description = "Flag to trigger rebuild of the control plane instance"
  type        = bool
  default     = false
}

variable "addons" {
  description = "List of URLs to Kubernetes add-on manifests to apply"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = {}
}

variable "ssh_private_key_file_path" {
  description = "Local path to the SSH private key file (e.g., '~/.ssh/polybot-key.pem')."
  type        = string
  default     = null # Or you can provide a default, but since it's in your .tfvars, null or no default is fine.
                     # If you want to make it strictly required from the .tfvars, remove the default.
}

variable "root_key_name" {
  description = "Root SSH key name for EC2 instances"
  type        = string
  default     = ""
  sensitive   = true
}

variable "root_ssh_private_key_file_path" {
  description = "Path to the root SSH private key file"
  type        = string
  default     = ""
  sensitive   = true
}

variable "root_ssh_public_key" {
  description = "Root SSH public key content"
  type        = string
  default     = ""
  sensitive   = true
}