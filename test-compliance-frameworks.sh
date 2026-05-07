#!/bin/bash

# Test script for compliance frameworks without Python/email dependencies
# Set your AWS credentials before running this script

echo "Testing Enhanced Compliance Framework Reporting..."
echo "================================================="

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

# Test the enhanced compliance modules
echo "1. Testing framework status detection..."
./modules/compliance-framework-status.sh

echo ""
echo "2. Testing enhanced compliance matrix..."
./modules/compliance-matrix.sh

echo ""
echo "3. Testing enhanced critical and high controls..."
./modules/compliance-critical-high-controls.sh

echo ""
echo "4. Testing enhanced compliance scoring..."
./modules/compliance-scores.sh

echo ""
echo "5. Testing enhanced top 5 failing resources..."
./modules/compliance-top5failingresources.sh

echo ""
echo "✅ Enhanced compliance framework testing completed!"
echo ""
echo "Summary of what was tested:"
echo "- Framework detection (CIS v1.4.0, CIS v3.0.0, PCI DSS v4.0.1)"
echo "- Enhanced compliance matrix with specific versions"
echo "- Top 5 critical and high failing controls per framework"
echo "- Enhanced compliance scoring per framework version"
echo "- Enhanced top 5 failing resources with version-specific data"
