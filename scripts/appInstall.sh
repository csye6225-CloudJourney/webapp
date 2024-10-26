#!/bin/bash
set -e

# Create the application directory if it doesn't exist
sudo mkdir -p /home/csye6225/app/build_output

# Move main.py to the application directory (if it was transferred)
if [[ -f /tmp/main.py ]]; then
    sudo mv /tmp/main.py /home/csye6225/app/main.py
else
    echo "Warning: /tmp/main.py not found, skipping application setup."
    exit 1
fi

# Set proper ownership for the application directory and files
sudo chown -R csye6225:csye6225 /home/csye6225/app

# Install Python dependencies using apt based on requirements-apt.txt
if [[ -f /tmp/requirements-apt.txt ]]; then
    xargs -a /tmp/requirements-apt.txt sudo apt-get install -y
else
    echo "requirements-apt.txt not found, skipping dependency installation."
    exit 1
fi

echo "App installation completed successfully."