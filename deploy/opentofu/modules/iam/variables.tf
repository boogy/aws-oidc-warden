variable "execution_role_arn" {
  type        = string
  description = "ARN of an externally managed execution role to attach this module's inline policy to. Null creates the role instead. Its trust policy and managed-policy attachments stay with whoever owns it."
  default     = null

  validation {
    condition     = var.execution_role_arn == null || can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+$", coalesce(var.execution_role_arn, "")))
    error_message = "execution_role_arn must be an IAM role ARN (arn:aws:iam::<account>:role/<name>)."
  }
}

variable "role_name" {
  type        = string
  description = "Lambda execution IAM role name. Used only when execution_role_arn is null."
}

variable "name_prefix" {
  type        = string
  description = "Prefix for the inline policy name."
}

variable "assumable_role_arns" {
  type        = list(string)
  description = "Role ARNs the Lambda may assume (sts:AssumeRole/sts:TagSession)."
  default     = []
}

variable "enable_iam_getrole" {
  type        = bool
  description = "Grant iam:GetRole for tag-based authorization (reads role tags from the GetRole response)."
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
