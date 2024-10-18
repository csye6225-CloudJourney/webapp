#!/bin/bash
set -e

export DEBIAN_FRONTEND=noninteractive
export CHECKPOINT_DISABLE=1

apt-get update
apt-get upgrade -y