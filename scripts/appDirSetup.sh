#!/bin/bash
set -e

# Create non-login user if not exists
if ! id -u csye6225 >/dev/null 2>&1; then
  echo "Creating user csye6225"
  sudo useradd -m -s /usr/sbin/nologin csye6225
  if [[ $? -ne 0 ]]; then
    echo "Failed to create user csye6225"
    exit 1
  fi
else
  echo "User csye6225 already exists"
fi

# Setup application directory
echo "Creating application directory: /home/csye6225/app"
sudo mkdir -p /home/csye6225/app
sudo chown csye6225:csye6225 /home/csye6225/app
sudo chmod 755 /home/csye6225/app

# Verify directory creation
if sudo test -d /home/csye6225/app; then
  echo 'Directory /home/csye6225/app created successfully'
else
  echo 'Directory /home/csye6225/app not created'
  exit 1
fi