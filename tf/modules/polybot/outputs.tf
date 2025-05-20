output "s3_bucket_name" {
  description = "Name of the S3 bucket created for Polybot"
  value       = aws_s3_bucket.polybot_bucket.bucket
}

output "s3_bucket_arn" {
  description = "ARN of the S3 bucket created for Polybot"
  value       = aws_s3_bucket.polybot_bucket.arn
}

output "sqs_queue_url" {
  description = "URL of the SQS queue created for Polybot"
  value       = aws_sqs_queue.polybot_queue.url
}

output "sqs_queue_arn" {
  description = "ARN of the SQS queue created for Polybot"
  value       = aws_sqs_queue.polybot_queue.arn
}

output "domain_name" {
  description = "Domain name for the Polybot service"
  value       = aws_route53_record.polybot_record.name
}

output "telegram_token_secret_arn" {
  description = "ARN of the Secrets Manager secret containing the Telegram token"
  value       = aws_secretsmanager_secret.telegram_token.arn
}

output "docker_credentials_secret_arn" {
  description = "ARN of the Secrets Manager secret containing the Docker Hub credentials"
  value       = aws_secretsmanager_secret.docker_credentials.arn
}

output "secrets_manager_arn" {
  description = "ARN of the Polybot Secrets Manager secret"
  value       = aws_secretsmanager_secret.polybot_secrets.arn
}

output "lambda_function_arn" {
  description = "ARN of the Polybot Lambda function"
  value       = aws_lambda_function.scaling_lambda.arn
}

output "sns_topic_arn" {
  description = "ARN of the Polybot lifecycle SNS topic"
  value       = aws_sns_topic.lifecycle_topic.arn
}
