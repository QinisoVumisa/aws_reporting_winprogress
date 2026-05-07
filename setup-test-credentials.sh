#!/bin/bash

# Quick credentials setup for testing
# This script helps you set up AWS credentials for testing without DynamoDB

echo "AWS Credentials Setup for Testing"
echo "=================================="

echo ""
echo "Choose your authentication method:"
echo "1) AWS SSO credentials (temporary)"
echo "2) AWS Profile"
echo "3) Manual credential entry"
echo ""
read -p "Select option (1-3): " auth_method

case $auth_method in
    1)
        echo ""
        echo "Please paste your AWS SSO credentials below:"
        echo "(You can get these from AWS console -> Command line or programmatic access)"
        echo ""
        
        read -p "AWS_ACCESS_KEY_ID: " access_key
        read -p "AWS_SECRET_ACCESS_KEY: " secret_key
        read -p "AWS_SESSION_TOKEN: " session_token
        read -p "AWS_DEFAULT_REGION [eu-west-1]: " region
        region=${region:="eu-west-1"}
        
        export AWS_ACCESS_KEY_ID="$access_key"
        export AWS_SECRET_ACCESS_KEY="$secret_key"
        export AWS_SESSION_TOKEN="$session_token"
        export AWS_DEFAULT_REGION="$region"
        
        echo ""
        echo "✅ Credentials set! You can now run:"
        echo "./test-framework-status.sh"
        echo "or"
        echo "./test-report.sh"
        ;;
    2)
        read -p "Enter AWS Profile name: " profile_name
        read -p "AWS_DEFAULT_REGION [eu-west-1]: " region
        region=${region:="eu-west-1"}
        
        export AWS_PROFILE="$profile_name"
        export AWS_DEFAULT_REGION="$region"
        
        echo ""
        echo "✅ Profile set! You can now run:"
        echo "./test-framework-status.sh"
        echo "or"
        echo "./test-report.sh"
        ;;
    3)
        read -p "AWS_ACCESS_KEY_ID: " access_key
        read -p "AWS_SECRET_ACCESS_KEY: " secret_key
        read -p "AWS_DEFAULT_REGION [eu-west-1]: " region
        region=${region:="eu-west-1"}
        
        export AWS_ACCESS_KEY_ID="$access_key"
        export AWS_SECRET_ACCESS_KEY="$secret_key"
        export AWS_DEFAULT_REGION="$region"
        
        echo ""
        echo "✅ Credentials set! You can now run:"
        echo "./test-framework-status.sh"
        echo "or"  
        echo "./test-report.sh"
        ;;
    *)
        echo "Invalid option. Please run the script again."
        exit 1
        ;;
esac

echo ""
echo "Testing AWS connection..."
aws sts get-caller-identity --output table

if [ $? -eq 0 ]; then
    echo ""
    echo "🎉 AWS connection successful!"
    echo ""
    echo "Available test scripts:"
    echo "- ./test-framework-status.sh  (Quick framework check)"
    echo "- ./test-report.sh           (Full report test)"
else
    echo ""
    echo "❌ AWS connection failed. Please check your credentials."
fi
