#!/bin/bash

# Exit on error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}AWS Secrets Verification Script${NC}"
echo -e "${YELLOW}=============================${NC}"
echo ""

# List of secret prefixes to check
DEV_PREFIXES=(
  "guy-polybot-dev-telegram-token"
  "guy-polybot-dev-docker-credentials" 
  "guy-polybot-dev-secrets"
)

PROD_PREFIXES=(
  "guy-polybot-prod-telegram-token"
  "guy-polybot-prod-docker-credentials"
  "guy-polybot-prod-secrets"
)

# Region parameter
REGION="${1:-us-east-1}"
echo -e "Using AWS region: ${GREEN}$REGION${NC}"

# Check if the AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not installed${NC}"
    exit 1
fi

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: jq is not installed${NC}"
    exit 1
fi

# Function to check and delete secret if requested
check_secret() {
    local prefix=$1
    echo -e "\nChecking for secrets with prefix: ${YELLOW}$prefix${NC}"
    
    # Get all secrets matching prefix
    set +e  # Temporarily disable exit on error for AWS command
    SECRETS=$(aws secretsmanager list-secrets \
        --region $REGION \
        --filters Key=name,Values=$prefix \
        --query "SecretList[*].{Name:Name,ARN:ARN,DeletionDate:DeletedDate}" \
        --output json 2>/dev/null)
    AWS_EXIT_CODE=$?
    set -e  # Re-enable exit on error
    
    if [ $AWS_EXIT_CODE -ne 0 ]; then
        echo -e "${RED}Error fetching secrets${NC}"
        return 1
    fi
    
    # Check if the output is valid JSON
    set +e  # Disable exit on error for jq check
    COUNT=$(echo $SECRETS | jq -e '. | length' 2>/dev/null)
    JQ_EXIT_CODE=$?
    set -e  # Re-enable exit on error
    
    if [ $JQ_EXIT_CODE -ne 0 ]; then
        echo -e "${RED}Error: Invalid JSON response from AWS${NC}"
        echo -e "${YELLOW}Raw response:${NC}"
        echo "$SECRETS"
        return 1
    fi
    
    if [ "$COUNT" -eq 0 ]; then
        echo -e "${GREEN}No secrets found with prefix: $prefix${NC}"
        return 0
    fi
    
    echo -e "${YELLOW}Found $COUNT secrets:${NC}"
    echo "$SECRETS" | jq -r '.[] | "Name: \(.Name), Deletion Date: \(.DeletionDate)"' || {
        echo -e "${RED}Error formatting secret list${NC}"
        return 1
    }
    
    # Ask to force delete
    set +e  # Disable exit on error for user input
    echo -e "${YELLOW}Do you want to force delete these secrets? (y/n)${NC}"
    read -r CONFIRM
    set -e  # Re-enable exit on error
    
    if [[ $CONFIRM != "y" && $CONFIRM != "Y" ]]; then
        echo -e "${RED}Skipping deletion${NC}"
        return 0
    fi
    
    # Proceed with deletion
    set +e  # Disable exit on error for deletion loop
    for SECRET_NAME in $(echo "$SECRETS" | jq -r '.[].Name'); do
        echo -e "Deleting ${YELLOW}$SECRET_NAME${NC}..."
        aws secretsmanager delete-secret \
            --region $REGION \
            --secret-id "$SECRET_NAME" \
            --force-delete-without-recovery
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Successfully deleted $SECRET_NAME${NC}"
        else
            echo -e "${RED}Failed to delete $SECRET_NAME${NC}"
        fi
    done
    set -e  # Re-enable exit on error
}

# Check all dev secrets
echo -e "\n${YELLOW}Checking DEV environment secrets...${NC}"
for prefix in "${DEV_PREFIXES[@]}"; do
    check_secret "$prefix" || echo -e "${RED}Failed to process prefix: $prefix${NC}"
done

# Check all prod secrets
echo -e "\n${YELLOW}Checking PROD environment secrets...${NC}"
for prefix in "${PROD_PREFIXES[@]}"; do
    check_secret "$prefix" || echo -e "${RED}Failed to process prefix: $prefix${NC}"
done

echo -e "\n${GREEN}Secret verification complete${NC}" 