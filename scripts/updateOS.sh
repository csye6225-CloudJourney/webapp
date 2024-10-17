#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
export CHECKPOINT_DISABLE=1

set -e

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get -q -y upgrade
sudo apt-get clean