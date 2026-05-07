#!/bin/bash

echo "Setting up AWS Reports scripts for WSL..."
echo "========================================="

# Check if we're in WSL
if [[ ! -f /proc/version ]] || ! grep -q Microsoft /proc/version; then
    echo "❌ This script should be run in WSL (Windows Subsystem for Linux)"
    exit 1
fi

# Check if dos2unix is installed
if ! command -v dos2unix &> /dev/null; then
    echo "Installing dos2unix..."
    sudo apt-get update && sudo apt-get install -y dos2unix
fi

# Convert line endings
echo "Converting Windows line endings to Unix format..."
dos2unix *.sh 2>/dev/null || true
dos2unix modules/*.sh 2>/dev/null || true

# Make scripts executable
echo "Making scripts executable..."
chmod +x *.sh
chmod +x modules/*.sh

echo "✅ Setup complete!"
echo ""
echo "Now you can run:"
echo "  ./test-framework-status.sh"
echo ""
echo "Make sure to set your AWS credentials first:"
echo "  export AWS_ACCESS_KEY_ID=your_access_key"
echo "  export AWS_SECRET_ACCESS_KEY=your_secret_key"
echo "  export AWS_SESSION_TOKEN=your_session_token"
echo "  export AWS_DEFAULT_REGION=eu-west-1"
