resource "aws_s3_bucket" "polybot_bucket" {
  bucket = "guy-polybot-bucket-${var.environment}-${var.region}"
  
  tags = {
    Name = "PolybotBucket"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_versioning" "bucket_versioning" {
  bucket = aws_s3_bucket.polybot_bucket.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bucket_encryption" {
  bucket = aws_s3_bucket.polybot_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_sqs_queue" "polybot_queue" {
  name = "guy-polybot-queue-${var.environment}"
  
  # SQS settings
  visibility_timeout_seconds = 30
  message_retention_seconds = 345600 # 4 days
  max_message_size = 262144 # 256 KB
  
  tags = {
    Name = "PolybotQueue"
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret" "polybot_secrets" {
  name = "polybot-secrets-${var.environment}-${var.region}"
  recovery_window_in_days = 0  # Set to 0 for immediate deletion in dev/test

  tags = {
    Name = "PolybotSecrets"
    Environment = var.environment
  }
}

# Secret version that stores all Polybot credentials
resource "aws_secretsmanager_secret_version" "polybot_secret_version" {
  secret_id     = aws_secretsmanager_secret.polybot_secrets.id
  secret_string = jsonencode({
    telegram_token = var.telegram_token,
    s3_bucket_name = aws_s3_bucket.polybot_bucket.bucket,
    sqs_queue_url = aws_sqs_queue.polybot_queue.url,
    telegram_app_url = "https://guy-polybot-${var.environment}.devops-int-college.com",
    aws_access_key_id = var.aws_access_key_id,
    aws_secret_access_key = var.aws_secret_access_key,
    mongo_collection = "image_collection",
    mongo_db = "config",
    mongo_uri = "mongodb://mongodb-0.mongodb.mongodb.svc.cluster.local:27017,mongodb-1.mongodb.mongodb.svc.cluster.local:27017,mongodb-2.mongodb.mongodb.svc.cluster.local:27017/?replicaSet=rs0",
    polybot_url = "https://polybot-service:31024/results"
  })
}

# Docker Hub credentials
resource "aws_secretsmanager_secret" "docker_hub_credentials" {
  name = "docker-hub-credentials-${var.environment}"
  recovery_window_in_days = 0  # Set to 0 for immediate deletion in dev/test

  tags = {
    Name = "DockerHubCredentials"
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "docker_hub_credentials_version" {
  secret_id     = aws_secretsmanager_secret.docker_hub_credentials.id
  secret_string = jsonencode({
    username = var.docker_username,
    password = var.docker_password
  })
}

resource "aws_lambda_function" "scaling_lambda" {
  function_name = "guy-polybot-scaling-function-${var.environment}"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 60
  
  # Inline function code for simplicity - for real use, deploy from S3
  filename      = "${path.module}/lambda_package.zip"
  
  environment {
    variables = {
      ASG_NAME = "guy-polybot-asg"
      REGION   = var.region
      ENV      = var.environment
    }
  }
  
  tags = {
    Name = "PolybotScalingLambda"
    Environment = var.environment
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_policy
  ]
}

# Create dummy lambda zip file if it doesn't exist
resource "null_resource" "lambda_package" {
  triggers = {
    lambda_package_exists = "create"
  }

  provisioner "local-exec" {
    command = <<-EOT
      mkdir -p ${path.module}
      echo 'def handler(event, context):
          # Simple placeholder lambda function
          print("Polybot scaling lambda executed")
          return {"statusCode": 200}
      ' > /tmp/index.py
      cd /tmp
      zip -r lambda_package.zip index.py
      mv lambda_package.zip ${path.module}/
    EOT
  }
}

resource "aws_iam_role" "lambda_role" {
  name = "lambda_execution_role_${var.environment}_${var.region}"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
  
  tags = {
    Name = "PolybotLambdaRole"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "lambda_policy" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Add autoscaling permissions for the lambda
resource "aws_iam_policy" "lambda_asg_policy" {
  name        = "lambda_asg_policy_${var.environment}_${var.region}"
  description = "Allow Lambda to manage ASG"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "autoscaling:DescribeAutoScalingGroups",
        "autoscaling:UpdateAutoScalingGroup",
        "autoscaling:SetDesiredCapacity"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_asg_policy_attach" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_asg_policy.arn
}

resource "aws_sns_topic" "lifecycle_topic" {
  name = "guy-lifecycle-topic-${var.environment}-${var.region}"
  
  tags = {
    Name = "PolybotLifecycleTopic"
    Environment = var.environment
  }
}

resource "aws_route53_record" "polybot_record" {
  zone_id = var.route53_zone_id
  name    = "guy-polybot-${var.environment}.devops-int-college.com"
  type    = "A"
  
  alias {
    name                   = var.alb_dns_name
    zone_id                = var.alb_zone_id
    evaluate_target_health = true
  }
}
