#!/bin/bash

set -e

# Extract the app binary (your tarball contains main.py and other files)
sudo tar -xzvf /tmp/app.tar.gz -C /opt/myapp/

# Move the extracted main.py to the correct directory (update paths if needed)
sudo cp /opt/myapp/main.py /opt/myapp/app

# Reload and enable the service (since the service file is already in place)
sudo systemctl daemon-reload
sudo systemctl enable webapp

# Set ownership for the directory
sudo chown -R webappA4:webappA4 /opt/myapp