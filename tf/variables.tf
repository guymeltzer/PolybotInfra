variable "region" {
  description = "AWS region"
  type        = string
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

variable "aws_access_key_id" {
  description = "AWS Access Key ID to use in the Polybot application"
  type        = string
  sensitive   = true
  default     = ""
}

variable "aws_secret_access_key" {
  description = "AWS Secret Access Key to use in the Polybot application"
  type        = string
  sensitive   = true
  default     = ""
}

variable "docker_username" {
  description = "Docker Hub username for pulling private images"
  type        = string
  sensitive   = true
  default     = ""
}

variable "docker_password" {
  description = "Docker Hub password for pulling private images"
  type        = string
  sensitive   = true
  default     = ""
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