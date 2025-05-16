variable "region" {
  description = "AWS region"
  type        = string
}

variable "vpc_id" {
  description = "ID of the VPC where resources will be created"
  type        = string
  default     = ""
}

variable "subnet_ids" {
  description = "List of subnet IDs for the Kubernetes cluster"
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