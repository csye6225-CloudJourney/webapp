#!/bin/bash
set -e

# Move and extract application binary
sudo mv /tmp/app_binary.tar.gz /home/csye6225/app/app_binary.tar.gz
cd /home/csye6225/app || { echo 'Failed to change directory'; exit 1; }
sudo tar -xzf app_binary.tar.gz
sudo rm app_binary.tar.gz
sudo chown -R csye6225:csye6225 /home/csye6225/app

# Create .env file for environment variables
cat << EOF | sudo tee /home/csye6225/app/.env
DB_USER=webapp_user
DB_PASSWORD=webapp_password
DB_HOST=localhost
DB_PORT=5432
DB_NAME=webapp_db
EOF

sudo chown csye6225:csye6225 /home/csye6225/app/.env
sudo chmod 600 /home/csye6225/app/.env

# Install Python dependencies
sudo -H pip3 install -r /home/csye6225/app/requirements.txt