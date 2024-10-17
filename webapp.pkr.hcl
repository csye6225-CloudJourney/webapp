packer {
  required_version = ">= 1.7.0"
  required_plugins {
    amazon = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "instance_type" {
  type    = string
  default = "t2.small"
}

variable "ubuntu_ami" {
  type    = string
  default = "ami-0866a3c8686eaeeba" # Ubuntu 24.04 LTS
}

source "amazon-ebs" "webapp_source" {
  ami_name      = "webapp-{{timestamp}}"
  instance_type = var.instance_type
  region        = var.aws_region
  source_ami    = var.ubuntu_ami
  ssh_username  = "ubuntu"
}

build {
  name    = "webapp_build"
  sources = ["source.amazon-ebs.webapp_source"]

  provisioner "shell" {
    inline = [
      "export DEBIAN_FRONTEND=noninteractive", # Suppress debconf prompts
      "sudo apt-get update",
      "sudo apt-get upgrade -y",
      "sudo apt-get install -y python3-pip python3-dev libpq-dev postgresql postgresql-contrib", # Install PostgreSQL
      "sudo systemctl enable postgresql",                                                        # Enable PostgreSQL at boot
      "sudo systemctl start postgresql",                                                         # Start PostgreSQL service
      "sudo useradd -m -s /usr/sbin/nologin csye6225",                                           # Create non-login user
      "sudo mkdir -p /home/csye6225/app",
      "sudo chown csye6225:csye6225 /home/csye6225/app",
      "sudo chmod 755 /home/csye6225/app",
      "[[ -d /home/csye6225/app ]] || { echo 'Directory /home/csye6225/app not created'; exit 1; }" # Verify directory exists
    ]
  }

  provisioner "file" {
    source      = "build_output/app_binary.tar.gz"
    destination = "/tmp/app_binary.tar.gz"
  }

  provisioner "shell" {
    inline = [
      "sudo mv /tmp/app_binary.tar.gz /home/csye6225/app/app_binary.tar.gz",
      "cd /home/csye6225/app || { echo 'Failed to change to directory /home/csye6225/app'; exit 1; }",
      "sudo tar -xzf app_binary.tar.gz",
      "sudo rm app_binary.tar.gz",
      "sudo chown -R csye6225:csye6225 /home/csye6225/app"
    ]
  }

  provisioner "file" {
    source      = "webapp.service"
    destination = "/tmp/webapp.service"
  }

  provisioner "shell" {
    inline = [
      "sudo mv /tmp/webapp.service /etc/systemd/system/webapp.service",
      "sudo systemctl daemon-reload",
      "sudo systemctl enable webapp.service",
      "sudo systemctl start webapp.service"
    ]
  }

  post-processor "manifest" {
    output = "manifest.json"
  }
}