# Auto-generated AWS resources for Polybot application
# This file creates AWS resources during terraform apply and uses existing credentials

# Get current AWS caller identity to use existing credentials
data "aws_caller_identity" "current" {}

# Create S3 bucket for Polybot
resource "aws_s3_bucket" "polybot_storage" {
  bucket = "polybot-storage-${random_id.bucket_suffix.hex}"

  tags = {
    Environment = "production"
    Application = "polybot"
    ManagedBy   = "terraform"
  }
}

# Random suffix for unique bucket name
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# Configure S3 bucket settings
resource "aws_s3_bucket_versioning" "polybot_storage" {
  bucket = aws_s3_bucket.polybot_storage.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "polybot_storage" {
  bucket = aws_s3_bucket.polybot_storage.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Create SQS queue for Polybot
resource "aws_sqs_queue" "polybot_queue" {
  name                      = "polybot-processing-queue"
  delay_seconds             = 0
  max_message_size          = 262144
  message_retention_seconds = 1209600
  receive_wait_time_seconds = 10

  tags = {
    Environment = "production"
    Application = "polybot"
    ManagedBy   = "terraform"
  }
}

# Auto-generated values using existing credentials and created resources
locals {
  generated_secrets = {
    # Use existing telegram token (user provides this)
    telegram_token         = var.telegram_token
    # Use current AWS credentials (from aws configure or IAM role)
    aws_access_key_id      = var.aws_access_key_id != "" ? var.aws_access_key_id : ""
    aws_secret_access_key  = var.aws_secret_access_key != "" ? var.aws_secret_access_key : ""
    # Use auto-generated AWS resources
    sqs_queue_url          = aws_sqs_queue.polybot_queue.url
    s3_bucket_name         = aws_s3_bucket.polybot_storage.bucket
    # Generate application URLs
    telegram_app_url       = "https://${try(module.k8s-cluster.alb_dns_name, "localhost")}/webhook"
    mongo_uri              = "mongodb://mongodb.default.svc.cluster.local:27017/polybot"
    polybot_url            = "https://${try(module.k8s-cluster.alb_dns_name, "localhost")}"
    # Use configured values
    mongo_collection       = var.mongo_collection
    mongo_db               = var.mongo_db
    docker_username        = var.docker_username
    docker_password        = var.docker_password
  }
}

# Output the generated values for reference
output "generated_secrets_info" {
  description = "Information about auto-generated AWS resources"
  value = {
    account_id        = data.aws_caller_identity.current.account_id
    s3_bucket_name    = aws_s3_bucket.polybot_storage.bucket
    sqs_queue_url     = aws_sqs_queue.polybot_queue.url
    telegram_app_url  = local.generated_secrets.telegram_app_url
    polybot_url       = local.generated_secrets.polybot_url
    mongo_uri         = local.generated_secrets.mongo_uri
  }
  sensitive = true
} 