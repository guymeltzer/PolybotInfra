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
TELEGRAM_TOKEN=$(aws secretsmanager get-secret-value --secret-id polybot-secrets-prod-$AWS_REGION --query SecretString --output text | jq -r '.telegram_token')

# Get Docker Hub credentials
DOCKER_USERNAME=$(aws secretsmanager get-secret-value --secret-id docker-hub-credentials --query SecretString --output text | jq -r '.username')
DOCKER_PASSWORD=$(aws secretsmanager get-secret-value --secret-id docker-hub-credentials --query SecretString --output text | jq -r '.password')

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
  sqs_queue_url: "https://sqs.$AWS_REGION.amazonaws.com/$AWS_ACCOUNT_ID/guy-polybot-queue-prod"
  s3_bucket: "guy-polybot-bucket-prod-$AWS_REGION"
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

echo "All secrets applied successfully!" 