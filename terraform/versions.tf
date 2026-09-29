terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
  }

  # Keep state out of the working tree. Example:
  # backend "s3" {
  #   bucket       = "my-terraform-state"
  #   key          = "phishing-detector/terraform.tfstate"
  #   region       = "us-east-1"
  #   encrypt      = true
  #   use_lockfile = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge({ Project = var.project_name, ManagedBy = "terraform" }, var.tags)
  }
}
