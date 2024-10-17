#!/bin/bash
set -e

DIR="/opt/myapp"

# Create app directory and system user
sudo mkdir -p "${DIR}"
sudo useradd --system --shell /usr/sbin/nologin webappA4