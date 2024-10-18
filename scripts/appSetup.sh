#!/bin/bash
set -e

# Install necessary packages
apt-get install -y python3-pip python3-dev libpq-dev postgresql postgresql-contrib

# Enable and start PostgreSQL
systemctl enable postgresql
systemctl start postgresql

# Setup PostgreSQL user and database
-u postgres psql -c "CREATE USER webapp_user WITH PASSWORD 'webapp_password';"
-u postgres psql -c "CREATE DATABASE webapp_db OWNER webapp_user;"