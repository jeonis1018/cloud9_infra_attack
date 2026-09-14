terraform {
  required_version = ">= 1.5.0"

  backend "s3" {
    bucket  = "cloud943-attack-tfstate"
    key     = "envs/security/terraform.tfstate"
    region  = "ap-northeast-2"
    profile = "cloud943"
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region              = "ap-northeast-2"
  profile             = var.aws_profile
  allowed_account_ids = ["896986966760"]
}
