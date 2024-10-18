#!/bin/bash
set -e

# Install necessary packages
sudo apt-get install -y python3-pip python3-dev libpq-dev postgresql postgresql-contrib

# Enable and start PostgreSQL
sudo systemctl enable postgresql
sudo systemctl start postgresql

# Setup PostgreSQL user and database
sudo -u postgres psql -c "CREATE USER webapp_user WITH PASSWORD 'webapp_password';"
sudo -u postgres psql -c "CREATE DATABASE webapp_db OWNER webapp_user;"