terraform {
  required_version = ">= 1.10, < 2.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.7"
    }
  }

  # Estado remoto en S3 con bloqueo nativo (S3 lockfile, Terraform >= 1.10).
  # Bucket, clave y región se pasan con -backend-config por entorno (env/<entorno>.s3.tfbackend).
  backend "s3" {
    use_lockfile = true
    encrypt      = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "aletheia"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
