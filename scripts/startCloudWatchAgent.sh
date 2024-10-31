#!/bin/bash
set -e

# Start and enable the CloudWatch Agent with the custom config
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s
sudo systemctl enable amazon-cloudwatch-agent.service