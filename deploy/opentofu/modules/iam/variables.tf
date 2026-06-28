variable "name_prefix" {
  type        = string
  description = "Prefix for the role and policy names."
}

variable "assumable_role_arns" {
  type        = list(string)
  description = "Role ARNs the Lambda may assume (sts:AssumeRole/sts:TagSession)."
  default     = []
}

variable "enable_iam_getrole" {
  type        = bool
  description = "Grant iam:GetRole and iam:ListRoleTags for tag-based authorization."
  default     = false
}

variable "cache_dynamodb_table_arn" {
  type        = string
  description = "DynamoDB cache table ARN, or null."
  default     = null
}

variable "cache_s3_bucket_arn" {
  type        = string
  description = "S3 cache bucket ARN, or null."
  default     = null
}

variable "config_bucket_arn" {
  type        = string
  description = "S3 config bucket ARN, or null."
  default     = null
}

variable "session_policy_bucket_arn" {
  type        = string
  description = "S3 session-policy bucket ARN, or null."
  default     = null
}

variable "log_bucket_arn" {
  type        = string
  description = "S3 audit-log bucket ARN, or null."
  default     = null
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to IAM resources."
  default     = {}
}
