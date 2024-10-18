#!/bin/bash
set -e

export DEBIAN_FRONTEND=noninteractive
export CHECKPOINT_DISABLE=1

sudo apt-get update
sudo apt-get upgrade -y