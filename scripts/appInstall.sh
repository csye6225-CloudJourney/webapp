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

# Create the .env file for environment variables
cat << EOF | sudo tee /home/csye6225/app/.env
DB_USER=webapp_user
DB_PASSWORD=webapp_password
DB_HOST=localhost
DB_PORT=5432
DB_NAME=webapp_db
EOF

# Set permissions for the .env file
sudo chown csye6225:csye6225 /home/csye6225/app/.env
sudo chmod 600 /home/csye6225/app/.env

# Install Python dependencies using the requirements.txt file
if [[ -f /tmp/requirements.txt ]]; then
    xargs -a /tmp/requirements.txt sudo apt-get install -y
else
    echo "requirements.txt not found, skipping dependency installation."
    exit 1
fi

echo "App installation completed successfully."