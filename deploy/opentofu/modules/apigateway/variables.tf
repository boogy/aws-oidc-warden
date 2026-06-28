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

variable "enable_jwt_authorizer" {
  type        = bool
  description = "Provision an API Gateway JWT Authorizer (jwt_validation_mode = 'apigw'). Requires payload_format_version = '2.0'."
  default     = false
}

variable "jwt_authorizer_issuer" {
  type        = string
  description = "OIDC issuer URL for the JWT Authorizer."
  default     = "https://token.actions.githubusercontent.com"
}

variable "jwt_authorizer_audiences" {
  type        = list(string)
  description = "Accepted audiences for the JWT Authorizer."
  default     = ["sts.amazonaws.com"]
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to API Gateway resources."
  default     = {}
}
