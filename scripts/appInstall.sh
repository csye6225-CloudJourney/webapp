#!/bin/bash
set -e

# Move and extract application binary
mv /tmp/app_binary.tar.gz /home/csye6225/app/app_binary.tar.gz
cd /home/csye6225/app || { echo 'Failed to change directory'; exit 1; }
tar -xzf app_binary.tar.gz
rm app_binary.tar.gz
chown -R csye6225:csye6225 /home/csye6225/app

# Create .env file for environment variables
cat << EOF | tee /home/csye6225/app/.env
DB_USER=webapp_user
DB_PASSWORD=webapp_password
DB_HOST=localhost
DB_PORT=5432
DB_NAME=webapp_db
EOF

chown csye6225:csye6225 /home/csye6225/app/.env
chmod 600 /home/csye6225/app/.env

# Install Python dependencies
-H pip3 install -r /home/csye6225/app/requirements.txt