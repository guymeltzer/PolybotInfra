#!/bin/bash
# Script to apply secrets to Kubernetes cluster

# Exit on any error
set -e

# Check for required environment variables
if [ -z "$AWS_REGION" ]; then
  echo "Error: AWS_REGION environment variable is required"
  exit 1
fi

# Fetch secrets from AWS Secrets Manager
echo "Fetching secrets from AWS Secrets Manager..."
# Load all secrets from Polybot Secrets
SECRET_JSON=$(aws secretsmanager get-secret-value --secret-id polybot-secrets-prod-$AWS_REGION --query SecretString --output text)

TELEGRAM_TOKEN=$(echo $SECRET_JSON | jq -r '.telegram_token')
S3_BUCKET_NAME=$(echo $SECRET_JSON | jq -r '.s3_bucket_name')
SQS_QUEUE_URL=$(echo $SECRET_JSON | jq -r '.sqs_queue_url')
TELEGRAM_APP_URL=$(echo $SECRET_JSON | jq -r '.telegram_app_url')
AWS_ACCESS_KEY_ID=$(echo $SECRET_JSON | jq -r '.aws_access_key_id')
AWS_SECRET_ACCESS_KEY=$(echo $SECRET_JSON | jq -r '.aws_secret_access_key')
MONGO_COLLECTION=$(echo $SECRET_JSON | jq -r '.mongo_collection')
MONGO_DB=$(echo $SECRET_JSON | jq -r '.mongo_db')
MONGO_URI=$(echo $SECRET_JSON | jq -r '.mongo_uri')
POLYBOT_URL=$(echo $SECRET_JSON | jq -r '.polybot_url')

# Get Docker Hub credentials
DOCKER_SECRETS=$(aws secretsmanager get-secret-value --secret-id docker-hub-credentials-prod --query SecretString --output text)
DOCKER_USERNAME=$(echo $DOCKER_SECRETS | jq -r '.username')
DOCKER_PASSWORD=$(echo $DOCKER_SECRETS | jq -r '.password')

# If Docker credentials are not available from AWS Secrets Manager, use hardcoded values
if [ -z "$DOCKER_USERNAME" ] || [ -z "$DOCKER_PASSWORD" ]; then
  echo "Docker Hub credentials not found in AWS Secrets Manager, using hardcoded values"
  DOCKER_USERNAME="guymeltzer"
  DOCKER_PASSWORD="Candy2025!"
fi

# Create base64 encoded auth for Docker
BASE64_ENCODED_DOCKER_USERNAME_PASSWORD=$(echo -n "$DOCKER_USERNAME:$DOCKER_PASSWORD" | base64)

# Get AWS account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Apply Polybot secrets
echo "Applying Polybot secrets..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: polybot-secrets
  namespace: prod
type: Opaque
stringData:
  telegram_token: "$TELEGRAM_TOKEN"
  s3_bucket_name: "$S3_BUCKET_NAME"
  sqs_queue_url: "$SQS_QUEUE_URL"
  telegram_app_url: "$TELEGRAM_APP_URL"
  aws_access_key_id: "$AWS_ACCESS_KEY_ID"
  aws_secret_access_key: "$AWS_SECRET_ACCESS_KEY"
  mongo_collection: "$MONGO_COLLECTION"
  mongo_db: "$MONGO_DB"
  mongo_uri: "$MONGO_URI"
  polybot_url: "$POLYBOT_URL"
EOF

# Apply ConfigMap
echo "Applying Polybot ConfigMap..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: polybot-config
  namespace: prod
data:
  sqs_queue_url: "$SQS_QUEUE_URL"
  s3_bucket: "$S3_BUCKET_NAME"
EOF

# Apply Docker registry credentials
echo "Applying Docker registry credentials..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: docker-registry-credentials
  namespace: prod
type: kubernetes.io/dockerconfigjson
stringData:
  .dockerconfigjson: |
    {
      "auths": {
        "https://index.docker.io/v1/": {
          "username": "$DOCKER_USERNAME",
          "password": "$DOCKER_PASSWORD",
          "auth": "$BASE64_ENCODED_DOCKER_USERNAME_PASSWORD"
        }
      }
    }
EOF

# Also create secrets for dev namespace
echo "Applying Polybot secrets for dev namespace..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: polybot-secrets
  namespace: dev
type: Opaque
stringData:
  telegram_token: "$TELEGRAM_TOKEN"
  s3_bucket_name: "$S3_BUCKET_NAME"
  sqs_queue_url: "$SQS_QUEUE_URL"
  telegram_app_url: "$TELEGRAM_APP_URL"
  aws_access_key_id: "$AWS_ACCESS_KEY_ID"
  aws_secret_access_key: "$AWS_SECRET_ACCESS_KEY"
  mongo_collection: "$MONGO_COLLECTION"
  mongo_db: "$MONGO_DB"
  mongo_uri: "$MONGO_URI"
  polybot_url: "$POLYBOT_URL"
EOF

# Apply Docker registry credentials for dev namespace
echo "Applying Docker registry credentials for dev namespace..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: docker-registry-credentials
  namespace: dev
type: kubernetes.io/dockerconfigjson
stringData:
  .dockerconfigjson: |
    {
      "auths": {
        "https://index.docker.io/v1/": {
          "username": "$DOCKER_USERNAME",
          "password": "$DOCKER_PASSWORD",
          "auth": "$BASE64_ENCODED_DOCKER_USERNAME_PASSWORD"
        }
      }
    }
EOF

echo "All secrets applied successfully!" 