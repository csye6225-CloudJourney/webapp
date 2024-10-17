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
      "sudo apt-get update",
      "sudo apt-get upgrade -y",
      "sudo apt-get install -y python3-pip python3-dev libpq-dev postgresql postgresql-contrib",
      "sudo useradd -m -s /usr/sbin/nologin csye6225", # Create non-login user
      "sudo mkdir -p /home/csye6225/app",
      "sudo chown csye6225:csye6225 /home/csye6225/app",
      "sudo chmod 755 /home/csye6225/app"
    ]
  }

  provisioner "file" {
    source      = "build_output/app_binary.tar.gz"
    destination = "/home/csye6225/app/app_binary.tar.gz"
  }

  provisioner "shell" {
    inline = [
      "cd /home/csye6225/app",
      "sudo tar -xzf app_binary.tar.gz",
      "sudo rm app_binary.tar.gz",
      "sudo chown -R csye6225:csye6225 /home/csye6225/app" # Ensure proper ownership of app files
    ]
  }

  provisioner "file" {
    source      = "webapp.service"
    destination = "/home/csye6225/app/webapp.service"
  }

  provisioner "shell" {
    inline = [
      "sudo mv /home/csye6225/app/webapp.service /etc/systemd/system/webapp.service", # Move the service file to the correct location
      "sudo systemctl daemon-reload",                                                 # Reload systemd to recognize the new service
      "sudo systemctl enable webapp.service",                                         # Enable the service to start at boot
      "sudo systemctl start webapp.service"                                           # Start the service immediately
    ]
  }

  post-processor "manifest" {
    output = "manifest.json"
  }
}