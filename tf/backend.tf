terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    bucket         = "polybot-tfstate-bucket"
    key            = "polybot/terraform.tfstate"
    region         = "us-east-1"
  }
    required_version = ">= 1.7.0"
}
