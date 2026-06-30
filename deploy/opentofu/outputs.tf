output "api_endpoint" {
  description = "POST this URL with {\"token\":\"...\",\"role\":\"...\"}."
  value       = module.apigateway.api_endpoint
}

output "lambda_function_name" {
  value = module.lambda.function_name
}

output "execution_role_arn" {
  value = module.iam.role_arn
}

output "config_bucket" {
  value = module.config_bucket.bucket_id
}

output "cache_table_name" {
  value = var.enable_dynamodb_cache ? module.dynamodb[0].table_name : null
}
