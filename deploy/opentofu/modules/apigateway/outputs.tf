output "api_id" {
  description = "HTTP API ID."
  value       = aws_apigatewayv2_api.this.id
}

# invoke_url ends with "/" for the $default stage; trim it so the path is
# "/verify", not "//verify" (HTTP APIs do not normalize double slashes).
locals {
  base_url = trimsuffix(aws_apigatewayv2_stage.this.invoke_url, "/")

  # A route_key is "<METHOD> <path>"; the URL needs only the path.
  open_path = length(var.jwt_authorizers) == 0 ? split(" ", var.route_key)[1] : null
}

output "api_endpoint" {
  description = "Invoke URL for the single open route (self mode), or null in apigw mode."
  value       = local.open_path != null ? "${local.base_url}${local.open_path}" : null
}

output "route_endpoints" {
  description = "Per-issuer invoke URLs (apigw mode), keyed by issuer name."
  value       = { for k, v in var.jwt_authorizers : k => "${local.base_url}${split(" ", v.route_key)[1]}" }
}

output "jwt_authorizer_ids" {
  description = "JWT Authorizer IDs keyed by issuer name; empty in self mode."
  value       = { for k, a in aws_apigatewayv2_authorizer.jwt : k => a.id }
}
