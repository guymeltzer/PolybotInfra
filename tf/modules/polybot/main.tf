locals {
  name_prefix = "guy-polybot-${var.environment}"
  domain_name = var.environment == "prod" ? "polybot.${var.region}.devops-int-college.com" : "dev-polybot.${var.region}.devops-int-college.com"
}

# S3 bucket for storing polybot data
resource "aws_s3_bucket" "polybot_bucket" {
  bucket = "${local.name_prefix}-bucket-${var.region}"
  
  tags = {
    Name        = "${local.name_prefix}-bucket"
    Environment = var.environment
  }
}

# S3 bucket ACL
resource "aws_s3_bucket_ownership_controls" "polybot_bucket_ownership" {
  bucket = aws_s3_bucket.polybot_bucket.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "polybot_bucket_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.polybot_bucket_ownership]
  bucket     = aws_s3_bucket.polybot_bucket.id
  acl        = "private"
}

# SQS queue for polybot messages
resource "aws_sqs_queue" "polybot_queue" {
  name                      = "${local.name_prefix}-queue"
  delay_seconds             = 0
  max_message_size          = 262144
  message_retention_seconds = 86400
  visibility_timeout_seconds = 30
  
  tags = {
    Name        = "${local.name_prefix}-queue"
    Environment = var.environment
  }
}

# Store Telegram token in AWS Secrets Manager
resource "aws_secretsmanager_secret" "telegram_token" {
  name        = "guy-polybot-${var.environment}-telegram-token"
  description = "Telegram Bot Token for Polybot ${var.environment} environment"
  recovery_window_in_days = 0  # Allow immediate reuse
  
  tags = {
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "telegram_token_value" {
  secret_id     = aws_secretsmanager_secret.telegram_token.id
  secret_string = var.telegram_token != "" ? var.telegram_token : "placeholder-token-please-update"
}

# Store Docker Hub credentials in AWS Secrets Manager
resource "aws_secretsmanager_secret" "docker_credentials" {
  name        = "guy-polybot-${var.environment}-docker-credentials"
  description = "Docker Hub credentials for Polybot ${var.environment} environment"
  recovery_window_in_days = 0  # Allow immediate reuse
  
  tags = {
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "docker_credentials_value" {
  secret_id = aws_secretsmanager_secret.docker_credentials.id
  secret_string = jsonencode({
    username = var.docker_username
    password = var.docker_password
  })
}

# SNS topic for lifecycle events
resource "aws_sns_topic" "lifecycle_topic" {
  name = "${local.name_prefix}-lifecycle-topic"
  
  tags = {
    Name        = "${local.name_prefix}-lifecycle-topic"
    Environment = var.environment
  }
}

# Route53 record for the polybot service
# Commented out until Route53 zone is properly set up
/*
resource "aws_route53_record" "polybot_record" {
  zone_id = var.route53_zone_id
  name    = local.domain_name
  type    = "A"
  
  alias {
    name                   = var.alb_dns_name
    zone_id                = var.alb_zone_id
    evaluate_target_health = true
  }
}
*/

resource "aws_secretsmanager_secret" "polybot_secrets" {
  name        = "${local.name_prefix}-secrets-${var.region}"
  description = "Various Polybot configuration secrets for ${var.environment} environment"
  recovery_window_in_days = 0  # Allow immediate reuse
  force_overwrite_replica_secret = true
  
  tags = {
    Name        = "${local.name_prefix}-secrets"
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "polybot_secrets_version" {
  secret_id     = aws_secretsmanager_secret.polybot_secrets.id
  secret_string = jsonencode({
    telegram_token  = var.telegram_token
    aws_access_key  = var.aws_access_key_id
    aws_secret_key  = var.aws_secret_access_key
    database_url    = "mongodb://polybot-mongodb.${var.environment}.svc.cluster.local:27017/polybot"
    redis_host      = "polybot-redis.${var.environment}.svc.cluster.local"
    queue_url       = aws_sqs_queue.polybot_queue.url
    bucket_name     = aws_s3_bucket.polybot_bucket.bucket
    docker_username = var.docker_username
    docker_password = var.docker_password
  })
}
