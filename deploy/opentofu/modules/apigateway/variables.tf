variable "name" {
  type        = string
  description = "API name."
}

variable "lambda_invoke_arn" {
  type        = string
  description = "Lambda invoke ARN."
}

variable "lambda_function_name" {
  type        = string
  description = "Lambda function name (for the invoke permission)."
}

variable "route_key" {
  type        = string
  description = "HTTP API route key."
  default     = "POST /verify"
}

variable "stage_name" {
  type        = string
  description = "Stage name."
  default     = "$default"
}

variable "throttling_burst_limit" {
  type        = number
  description = "Per-route burst limit."
  default     = 50
}

variable "throttling_rate_limit" {
  type        = number
  description = "Per-route steady-state rate limit."
  default     = 100
}

variable "payload_format_version" {
  type        = string
  description = "Lambda payload format version: '1.0' for cmd/apigateway, '2.0' for cmd/apigatewayv2."
  default     = "1.0"
}

variable "jwt_authorizers" {
  description = <<-EOT
    JWT Authorizers to provision, keyed by short issuer name. Each entry gets
    its own authorizer and its own route pointing at the shared Lambda
    integration. Empty (the default) means self mode: one open route on
    var.route_key, with the Lambda doing full validation.
  EOT
  type = map(object({
    issuer    = string
    audiences = list(string)
    route_key = string
  }))
  default = {}
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to API Gateway resources."
  default     = {}
}
