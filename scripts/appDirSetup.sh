#!/bin/bash
set -e

# Create non-login user if not exists
if ! id -u csye6225 >/dev/null 2>&1; then
  useradd -m -s /usr/sbin/nologin csye6225
fi

# Setup application directory
mkdir -p /home/csye6225/app
chown csye6225:csye6225 /home/csye6225/app
chmod 755 /home/csye6225/app

# Verify directory creation
if [[ ! -d /home/csye6225/app ]]; then
  echo 'Directory /home/csye6225/app not created'
  exit 1
fi