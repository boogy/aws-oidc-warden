output "api_id" {
  description = "HTTP API ID."
  value       = aws_apigatewayv2_api.this.id
}

output "api_endpoint" {
  description = "Invoke URL for the verify route."
  value       = "${aws_apigatewayv2_stage.this.invoke_url}/verify"
}

output "jwt_authorizer_id" {
  description = "JWT Authorizer ID, or empty string when not provisioned."
  value       = var.enable_jwt_authorizer ? aws_apigatewayv2_authorizer.jwt[0].id : ""
}
