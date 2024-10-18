#!/bin/bash
set -e

# Move service file and start the service
mv /tmp/webapp.service /etc/systemd/system/webapp.service
systemctl daemon-reload
systemctl enable webapp.service
systemctl start webapp.service