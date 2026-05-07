#!/bin/bash

# Test script to check framework status without DynamoDB
# Set your AWS credentials before running this script

echo "Testing Framework Status Script..."
echo "=================================="

# Check if AWS credentials are set
if [[ -z "$AWS_ACCESS_KEY_ID" ]]; then
    echo "❌ AWS credentials not found!"
    echo ""
    echo "Please set your AWS credentials first:"
    echo "export AWS_ACCESS_KEY_ID=your_access_key"
    echo "export AWS_SECRET_ACCESS_KEY=your_secret_key"
    echo "export AWS_SESSION_TOKEN=your_session_token  # if using SSO"
    echo "export AWS_DEFAULT_REGION=eu-west-1  # or your preferred region"
    echo ""
    echo "Then run this script again."
    exit 1
fi

# Set test variables
export custname="TestCustomer"
export custregion="${AWS_DEFAULT_REGION:-eu-west-1}"
export today=$(date +"%Y-%m-%d")
export AWS_RETRY_MODE="standard"
export AWS_MAX_ATTEMPTS=10

echo "Using test configuration:"
echo "Customer Name: $custname"
echo "Region: $custregion"
echo "Date: $today"
echo ""

# Test the framework status module
echo "Running compliance framework status check..."
./modules/compliance-framework-status.sh

echo ""
echo "Test completed!"
