variable "function_name" {
  type        = string
  description = "Lambda function name."
}

variable "role_arn" {
  type        = string
  description = "Execution role ARN."
}

variable "zip_path" {
  type        = string
  description = "Path to the prebuilt deployment zip (must contain an executable 'bootstrap')."
}

variable "architecture" {
  type        = string
  description = "Lambda architecture: arm64 or x86_64."
  default     = "arm64"
}

variable "memory_size" {
  type        = number
  description = "Memory (MB)."
  default     = 256
}

variable "timeout" {
  type        = number
  description = "Timeout (seconds)."
  default     = 15
}

variable "environment_variables" {
  type        = map(string)
  description = "Environment variables (AOW_* and LOG_LEVEL)."
  default     = {}
}

variable "log_retention_days" {
  type        = number
  description = "CloudWatch log retention (days)."
  default     = 14
}

variable "reserved_concurrency" {
  type        = number
  description = "Reserved concurrency; -1 leaves it unreserved."
  default     = -1
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to the function."
  default     = {}
}
