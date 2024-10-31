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
    script = "scripts/updateOS.sh"
  }

  provisioner "shell" {
    script = "scripts/appDirSetup.sh"
  }

  provisioner "file" {
    source      = "requirements-apt.txt"
    destination = "/tmp/requirements-apt.txt"
  }

  provisioner "file" {
    source      = "main.py"
    destination = "/tmp/main.py"
  }

  provisioner "shell" {
    script = "scripts/appSetup.sh"
  }

  provisioner "shell" {
    script = "scripts/appInstall.sh"
  }

  provisioner "file" {
    source      = "webapp.service"
    destination = "/tmp/webapp.service"
  }

  provisioner "shell" {
    script = "scripts/setupService.sh"
  }

  provisioner "file" {
  source      = "config/cloudwatch-config.json"
  destination = "/tmp/cloudwatch-config.json"
  }

  provisioner "shell" {
    script = "scripts/installCloudWatchAgent.sh"
  }

  # Start the CloudWatch Agent using the new script
  provisioner "shell" {
    script = "scripts/startCloudWatchAgent.sh"
  }

  post-processor "manifest" {
    output = "manifest.json"
  }
}