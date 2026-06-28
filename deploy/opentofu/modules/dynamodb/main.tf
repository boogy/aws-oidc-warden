resource "aws_dynamodb_table" "cache" {
  name         = var.table_name
  billing_mode = var.billing_mode
  hash_key     = "Key"

  attribute {
    name = "Key"
    type = "S"
  }

  ttl {
    attribute_name = "TTL"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = var.point_in_time_recovery
  }

  tags = var.tags
}
