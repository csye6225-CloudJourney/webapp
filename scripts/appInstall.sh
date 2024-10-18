#!/bin/bash
set -e

# Create the build_output directory if it doesn't exist
sudo mkdir -p /home/csye6225/app/build_output

# If there's an app binary tarball to move and extract, do it.
if [[ -f /tmp/app_binary.tar.gz ]]; then
    # Move the app binary tarball to the application directory
    sudo mv /tmp/app_binary.tar.gz /home/csye6225/app/app_binary.tar.gz
    
    # Change to the app directory and extract the tarball
    cd /home/csye6225/app || { echo 'Failed to change directory'; exit 1; }
    sudo tar -xzf app_binary.tar.gz
    
    # Clean up by removing the tarball
    sudo rm app_binary.tar.gz
else
    echo "Warning: /tmp/app_binary.tar.gz not found, skipping app extraction step."
fi

# Set proper ownership for the extracted files or existing files
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

# Install Python dependencies using apt
sudo apt-get update

# Install necessary Python packages via apt
sudo apt-get install -y python3-flask python3-sqlalchemy python3-psycopg2 python3-bcrypt

echo "App installation completed successfully."