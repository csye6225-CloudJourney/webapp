#!/bin/bash
set -e

sudo apt-get update -y

# Download and install the CloudWatch Agent from Amazon S3
curl -O https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
sudo dpkg -i -E ./amazon-cloudwatch-agent.deb

# Clean up the downloaded .deb file
rm amazon-cloudwatch-agent.deb

# Update permissions to allow configuration file upload
sudo mv /tmp/cloudwatch-config.json /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
sudo chown cwagent:cwagent /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json