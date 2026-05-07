#!/bin/bash

# Test version of report.sh that bypasses DynamoDB
# Set your AWS credentials before running this script

echo "AWS Security Report - Test Mode (No DynamoDB)"
echo "=============================================="

today=$(date +"%Y-%m-%d")

# Check if AWS credentials are already set
if [[ -z "$AWS_ACCESS_KEY_ID" ]]; then
    echo "❌ AWS credentials not found!"
    echo ""
    echo "Please set your AWS credentials first:"
    echo ""
    echo "For temporary credentials (SSO):"
    echo "export AWS_ACCESS_KEY_ID=your_access_key"
    echo "export AWS_SECRET_ACCESS_KEY=your_secret_key"
    echo "export AWS_SESSION_TOKEN=your_session_token"
    echo ""
    echo "For profile-based credentials:"
    echo "export AWS_PROFILE=your_profile_name"
    echo ""
    echo "export AWS_DEFAULT_REGION=eu-west-1  # or your preferred region"
    echo ""
    echo "Then run this script again."
    exit 1
fi

# Get customer name if not set
if [[ -z "$custname" ]]; then
    echo "Enter customer name for testing:"
    read custname
    if [[ -z "$custname" ]]; then 
        echo "Using default test customer name: TestCustomer"
        custname="TestCustomer"
    fi
fi

# Get region if not set
if [[ -z "$custregion" ]]; then
    echo "Enter security hub aggregate region [eu-west-1]:"
    read custregion
    custregion=${custregion:="eu-west-1"}
fi

# Set environment variables
export AWS_DEFAULT_REGION=$custregion
export AWS_RETRY_MODE="standard"
export AWS_MAX_ATTEMPTS=10
export custname=$custname
export today=$today

thismonth=$(date +%Y-%m)

echo ""
echo "Test Configuration:"
echo "=================="
echo "Customer Name: $custname"
echo "Region: $AWS_DEFAULT_REGION"
echo "Date: $today"
echo "Month: $thismonth"
echo ""

# Create output directory
mkdir -p ./OUTPUT/$thismonth/

echo "Testing Framework Status..."
echo "=========================="
./modules/compliance-framework-status.sh

echo ""
echo "Testing Critical/High Controls..."
echo "================================"
./modules/compliance-critical-high-controls.sh | head -50

echo ""
echo "Test completed! Check ./OUTPUT/$thismonth/ for any generated files."
