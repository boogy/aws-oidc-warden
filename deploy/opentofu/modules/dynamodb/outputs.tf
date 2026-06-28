output "table_name" {
  description = "Cache table name."
  value       = aws_dynamodb_table.cache.name
}

output "table_arn" {
  description = "Cache table ARN."
  value       = aws_dynamodb_table.cache.arn
}
