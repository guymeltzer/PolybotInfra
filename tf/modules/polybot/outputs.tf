output "s3_bucket_name" {
  description = "Name of the Polybot S3 bucket"
  value       = aws_s3_bucket.polybot_bucket.bucket
}

output "s3_bucket_arn" {
  description = "ARN of the Polybot S3 bucket"
  value       = aws_s3_bucket.polybot_bucket.arn
}

output "sqs_queue_url" {
  description = "URL of the Polybot SQS queue"
  value       = aws_sqs_queue.polybot_queue.url
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
