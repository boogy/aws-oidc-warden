provider "aws" {
  region = var.region

  default_tags {
    tags = merge({ app = var.name_prefix }, var.tags)
  }
}
