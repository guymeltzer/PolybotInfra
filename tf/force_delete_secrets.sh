#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}AWS Secrets Manager - Force Delete Utility${NC}"
echo -e "${YELLOW}==========================================${NC}"
echo ""

# Verify AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo -e "${RED}AWS CLI is not installed. Please install it first.${NC}"
    exit 1
fi

# Check if a region was specified
REGION="${1:-us-east-1}"
echo -e "Using AWS region: ${GREEN}$REGION${NC}"

# Get list of secrets scheduled for deletion
echo -e "\n${YELLOW}Fetching secrets scheduled for deletion...${NC}"
SECRETS=$(aws secretsmanager list-secrets --region $REGION --filter "Key=description,Values=scheduled for deletion" --query "SecretList[*].{Name:Name,ARN:ARN,DeletionDate:DeletedDate}" --output json)

if [ -z "$SECRETS" ] || [ "$SECRETS" == "[]" ]; then
    echo -e "${GREEN}No secrets found that are scheduled for deletion.${NC}"
    exit 0
fi

echo -e "\n${YELLOW}Found secrets scheduled for deletion:${NC}"
echo "$SECRETS" | jq -r '.[] | "Name: \(.Name), Deletion Date: \(.DeletionDate)"'

echo -e "\n${YELLOW}Do you want to force delete these secrets? (y/n)${NC}"
read -r CONFIRM

if [[ $CONFIRM != "y" && $CONFIRM != "Y" ]]; then
    echo -e "${RED}Operation cancelled.${NC}"
    exit 0
fi

echo -e "\n${YELLOW}Forcing deletion of secrets...${NC}"
for SECRET_NAME in $(echo "$SECRETS" | jq -r '.[].Name'); do
    echo -e "Deleting ${YELLOW}$SECRET_NAME${NC}..."
    aws secretsmanager delete-secret --secret-id "$SECRET_NAME" --force-delete-without-recovery --region $REGION
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Successfully deleted $SECRET_NAME${NC}"
    else
        echo -e "${RED}Failed to delete $SECRET_NAME${NC}"
    fi
done

echo -e "\n${GREEN}Operation complete.${NC}" 