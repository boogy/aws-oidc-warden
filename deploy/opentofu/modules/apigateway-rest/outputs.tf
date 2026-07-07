output "api_id" {
  description = "REST API ID."
  value       = aws_api_gateway_rest_api.this.id
}

output "api_endpoint" {
  description = "Invoke URL for the verify route."
  value       = "${aws_api_gateway_stage.this.invoke_url}/verify"
}

output "web_acl_arn" {
  description = "WAF web ACL ARN, or empty string when not provisioned."
  value       = var.enable_waf ? aws_wafv2_web_acl.this[0].arn : ""
}
