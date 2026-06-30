terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
  }
  # archive_file is intentionally NOT used — it does not preserve the bootstrap
  # exec bit, which breaks the provided.al2023 runtime. build.sh zips instead.

  # Configure a remote backend per environment, e.g.:
  # backend "s3" { bucket = "..." key = "aws-oidc-warden/terraform.tfstate" region = "..." }
}
