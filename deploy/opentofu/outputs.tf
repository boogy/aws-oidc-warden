output "api_endpoint" {
  description = "POST this URL with {\"token\":\"...\",\"role\":\"...\"}."
  value       = coalesce(one(module.apigateway[*].api_endpoint), one(module.apigateway_rest[*].api_endpoint))
}

output "waf_web_acl_arn" {
  description = "WAF web ACL ARN (rest + enable_waf only), or null."
  value       = var.enable_waf ? one(module.apigateway_rest[*].web_acl_arn) : null
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
