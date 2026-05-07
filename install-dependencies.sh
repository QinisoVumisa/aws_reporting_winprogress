
echo "Installing missing dependencies for AWS Reports..."
echo "================================================="

# Update package list
echo "Updating package list..."
sudo apt-get update

# Install dos2unix if not already installed
if ! command -v dos2unix &> /dev/null; then
    echo "Installing dos2unix..."
    sudo apt-get install -y dos2unix
fi

# Install python3-pip if not already installed
if ! command -v pip3 &> /dev/null; then
    echo "Installing python3-pip..."
    sudo apt-get install -y python3-pip
fi

# Install python-docx for Word document generation
echo "Installing python-docx module..."
pip3 install python-docx

# Install mutt for email functionality (optional)
echo "Installing mutt for email functionality..."
sudo apt-get install -y mutt

# Install jq for JSON parsing (should already be installed)
if ! command -v jq &> /dev/null; then
    echo "Installing jq..."
    sudo apt-get install -y jq
fi

echo ""
echo "✅ Dependencies installation completed!"
echo ""
echo "Note: If you don't need email functionality, you can ignore mutt installation."
echo "The reports will still generate without it."
