#!/bin/bash

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

# Function to check and delete secret if requested
check_secret() {
    local prefix=$1
    echo -e "\nChecking for secrets with prefix: ${YELLOW}$prefix${NC}"
    
    # Get all secrets matching prefix
    SECRETS=$(aws secretsmanager list-secrets \
        --region $REGION \
        --filters Key=name,Values=$prefix \
        --query "SecretList[*].{Name:Name,ARN:ARN,DeletionDate:DeletedDate}" \
        --output json 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error fetching secrets${NC}"
        return 1
    fi
    
    COUNT=$(echo $SECRETS | jq '. | length')
    if [ "$COUNT" -eq 0 ]; then
        echo -e "${GREEN}No secrets found with prefix: $prefix${NC}"
        return 0
    fi
    
    echo -e "${YELLOW}Found $COUNT secrets:${NC}"
    echo "$SECRETS" | jq -r '.[] | "Name: \(.Name), Deletion Date: \(.DeletionDate)"'
    
    # Ask to force delete
    echo -e "${YELLOW}Do you want to force delete these secrets? (y/n)${NC}"
    read -r CONFIRM
    
    if [[ $CONFIRM != "y" && $CONFIRM != "Y" ]]; then
        echo -e "${RED}Skipping deletion${NC}"
        return 0
    fi
    
    # Proceed with deletion
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
}

# Check all dev secrets
echo -e "\n${YELLOW}Checking DEV environment secrets...${NC}"
for prefix in "${DEV_PREFIXES[@]}"; do
    check_secret "$prefix"
done

# Check all prod secrets
echo -e "\n${YELLOW}Checking PROD environment secrets...${NC}"
for prefix in "${PROD_PREFIXES[@]}"; do
    check_secret "$prefix"
done

echo -e "\n${GREEN}Secret verification complete${NC}" 