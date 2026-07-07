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

variable "stage_name" {
  type        = string
  description = "Stage name (part of the invoke URL path)."
  default     = "v1"
}

variable "throttling_burst_limit" {
  type        = number
  description = "Stage-wide burst limit."
  default     = 50
}

variable "throttling_rate_limit" {
  type        = number
  description = "Stage-wide steady-state rate limit."
  default     = 100
}

variable "enable_waf" {
  type        = bool
  description = "Attach an AWS WAFv2 web ACL (rate limiting + managed rules + request-shape filtering) to the stage."
  default     = false
}

variable "waf_rate_limit" {
  type        = number
  description = "WAF rate-based rule: max requests per source IP per 5-minute window. AWS minimum is 10."
  default     = 300
}

variable "waf_common_rule_set" {
  type        = bool
  description = "Include AWSManagedRulesCommonRuleSet in the web ACL. Disable if it false-positives on JWT request bodies."
  default     = true
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to API Gateway and WAF resources."
  default     = {}
}
