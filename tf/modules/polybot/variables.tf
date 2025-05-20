variable "region" {
  description = "AWS region"
  type        = string
}

variable "route53_zone_id" {
  description = "Route53 zone ID for DNS records"
  type        = string
}

variable "alb_dns_name" {
  description = "DNS name of the application load balancer"
  type        = string
}

variable "alb_zone_id" {
  description = "Zone ID of the application load balancer"
  type        = string
}

variable "environment" {
  description = "Environment (dev or prod)"
  type        = string
  default     = "dev"
  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "Environment must be either 'dev' or 'prod'."
  }
}

variable "telegram_token" {
  description = "Telegram bot token"
  type        = string
  sensitive   = true
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
