variable "region" {
  description = "AWS region"
  type        = string
}

variable "route53_zone_id" {
  description = "Route53 zone ID for DNS records"
  type        = string
}

variable "alb_dns_name" {
  description = "DNS name of the ALB"
  type        = string
}

variable "alb_zone_id" {
  description = "Zone ID of the ALB"
  type        = string
}

variable "environment" {
  description = "Environment (dev or prod)"
  type        = string
  default     = "prod"
}

variable "telegram_token" {
  description = "Telegram bot token"
  type        = string
  sensitive   = true
  default     = ""
}
