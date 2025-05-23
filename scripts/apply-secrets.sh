#!/bin/bash
# Script to apply secrets to Kubernetes cluster

# Exit on any error
set -e

# Check for required environment variables
if [ -z "$AWS_REGION" ]; then
  echo "Error: AWS_REGION environment variable is required"
  exit 1
fi

if [ -z "$ENVIRONMENT" ]; then
  echo "Warning: ENVIRONMENT not specified, defaulting to 'prod'"
  ENVIRONMENT="prod"
fi

# Validate environment
if [[ "$ENVIRONMENT" != "dev" && "$ENVIRONMENT" != "prod" ]]; then
  echo "Error: ENVIRONMENT must be either 'dev' or 'prod'"
  exit 1
fi

echo "Applying secrets for $ENVIRONMENT environment in $AWS_REGION region"

# Fetch secrets from AWS Secrets Manager
echo "Fetching secrets from AWS Secrets Manager..."
# Load environment-specific secrets
SECRET_ID="polybot-secrets-${ENVIRONMENT}-${AWS_REGION}"
echo "Fetching secrets from $SECRET_ID"

if ! SECRET_JSON=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ID" --query SecretString --output text); then
  echo "Error: Failed to fetch secrets from AWS Secrets Manager using secret ID: $SECRET_ID"
  exit 1
fi

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

# Get Docker Hub credentials from secrets manager
DOCKER_SECRET_ID="docker-hub-credentials-${ENVIRONMENT}"
echo "Fetching Docker credentials from $DOCKER_SECRET_ID"

if ! DOCKER_SECRETS=$(aws secretsmanager get-secret-value --secret-id "$DOCKER_SECRET_ID" --query SecretString --output text); then
  echo "Error: Failed to fetch Docker credentials from AWS Secrets Manager"
  echo "Please ensure Docker credentials are stored in AWS Secrets Manager with ID: $DOCKER_SECRET_ID"
  exit 1
fi

DOCKER_USERNAME=$(echo $DOCKER_SECRETS | jq -r '.username')
DOCKER_PASSWORD=$(echo $DOCKER_SECRETS | jq -r '.password')

# Verify all required values are retrieved
for VAR_NAME in TELEGRAM_TOKEN S3_BUCKET_NAME SQS_QUEUE_URL TELEGRAM_APP_URL AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY MONGO_COLLECTION MONGO_DB MONGO_URI POLYBOT_URL DOCKER_USERNAME DOCKER_PASSWORD; do
  VAR_VALUE=$(eval echo \$$VAR_NAME)
  if [ -z "$VAR_VALUE" ]; then
    echo "Error: $VAR_NAME is empty or not found in AWS Secrets Manager"
    exit 1
  fi
done

# Create base64 encoded auth for Docker
BASE64_ENCODED_DOCKER_AUTH=$(echo -n "$DOCKER_USERNAME:$DOCKER_PASSWORD" | base64)

# Apply Polybot secrets to the specified namespace
echo "Applying Polybot secrets to $ENVIRONMENT namespace..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: polybot-secrets
  namespace: $ENVIRONMENT
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

# Apply ConfigMap to the specified namespace
echo "Applying Polybot ConfigMap to $ENVIRONMENT namespace..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: polybot-config
  namespace: $ENVIRONMENT
data:
  sqs_queue_url: "$SQS_QUEUE_URL"
  s3_bucket: "$S3_BUCKET_NAME"
EOF

# Apply Docker registry credentials to the specified namespace
echo "Applying Docker registry credentials to $ENVIRONMENT namespace..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: docker-registry-credentials
  namespace: $ENVIRONMENT
type: kubernetes.io/dockerconfigjson
stringData:
  .dockerconfigjson: |
    {
      "auths": {
        "https://index.docker.io/v1/": {
          "username": "$DOCKER_USERNAME",
          "password": "$DOCKER_PASSWORD",
          "auth": "$BASE64_ENCODED_DOCKER_AUTH"
        }
      }
    }
EOF

echo "All secrets applied successfully to $ENVIRONMENT namespace!" 