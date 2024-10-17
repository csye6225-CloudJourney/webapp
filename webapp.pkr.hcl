packer {
  required_plugins {
    amazon = {
      source  = "github.com/hashicorp/amazon"
      version = ">= 1.0.0, < 2.0.0"
    }
  }
}

# Set default variables with overrides available
variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "source_ami" {
  type    = string
  default = "ami-0866a3c8686eaeeba"
}

variable "ssh_username" {
  type    = string
  default = "ubuntu"
}

variable "subnet_id" {
  type    = string
  default = "subnet-08d7b0eb57b1276f1"
}

# Define source block for amazon-ebs
source "amazon-ebs" "my-ami" {
  region          = var.aws_region
  ami_name        = "csye6224_webapp_${formatdate("YYYY_MM_DD", timestamp())}"
  ami_description = "AMI created for Assignment 4"
  instance_type   = "t2.small"
  source_ami      = var.source_ami
  ssh_username    = var.ssh_username
  subnet_id       = var.subnet_id

  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 8
    volume_type           = "gp2"
    delete_on_termination = true
  }

  ami_regions = ["us-east-1"]

  aws_polling {
    delay_seconds = 120
    max_attempts  = 50
  }
}

# Build block
build {
  sources = ["source.amazon-ebs.my-ami"]

  # OS update script provisioner
  provisioner "shell" {
    script = "scripts/updateOS.sh"
  }

  # Application directory setup
  provisioner "shell" {
    script = "scripts/appDirSetup.sh"
  }

  # Upload application binary
  provisioner "file" {
    source      = "app_binary.tar.gz"
    destination = "/tmp/app.tar.gz"
  }

  # Upload systemd service file to /tmp
  provisioner "file" {
    source      = "webapp.service"
    destination = "/tmp/webapp.service"
  }

  # Move systemd service file to the correct location with sudo
  provisioner "shell" {
    inline = [
      "sudo mv /tmp/webapp.service /etc/systemd/system/webapp.service",
      "sudo systemctl daemon-reload",
      "sudo systemctl enable webapp"
    ]
  }

  # App setup script
  provisioner "shell" {
    script = "scripts/appSetup.sh"
  }
}