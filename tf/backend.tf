terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    # Only include Kubernetes providers when NOT in destroy mode
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
      configuration_aliases = []
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
      configuration_aliases = []
    }
    kubectl = {
      source  = "gavinbunney/kubectl"
      version = "~> 1.14"
      configuration_aliases = []
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.9"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.4"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
  backend "s3" {
    bucket = "polybot-tfstate-bucket"
    key    = "polybot/terraform.tfstate"
    region = "us-east-1"
  }
  required_version = ">= 1.7.0"
}
