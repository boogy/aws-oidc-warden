variable "region" {
  description = "AWS region to deploy into."
  type        = string
}

variable "name_prefix" {
  description = "Prefix for all resource names."
  type        = string
  default     = "aws-oidc-warden"
}

variable "tags" {
  description = "Additional tags applied to all resources."
  type        = map(string)
  default     = {}
}

# ---- Application config (rendered into config.yaml) ----
# This stack renders a single GitHub Actions issuer entry into the v2
# `issuers[]` list. For multi-issuer or non-GitHub providers, manage
# config.yaml yourself and point AOW_S3_CONFIG_BUCKET/PATH at it.
variable "issuer" {
  type        = string
  description = "OIDC issuer URL (rendered as issuers[0].issuer, provider github)."
  default     = "https://token.actions.githubusercontent.com"
}

variable "audiences" {
  type        = list(string)
  description = "Accepted token audiences (rendered as issuers[0].audiences)."
  default     = ["sts.amazonaws.com"]
}

variable "role_session_name" {
  type        = string
  description = "STS role session name."
  default     = "aws-oidc-warden"
}

variable "role_mappings" {
  description = <<-EOT
    Subject-to-role mappings (v2 schema, rendered verbatim into config.yaml).
    `subject` is an auto-anchored regex matched against the canonical subject
    (for GitHub: the `repository` claim, "owner/repo"). `conditions` are
    auto-anchored regexes against raw verified claims, AND-ed together.
  EOT
  type = list(object({
    subject             = string
    roles               = list(string)
    session_policy      = optional(string)
    session_policy_file = optional(string)
    conditions = optional(object({
      branch        = optional(string)
      ref           = optional(string)
      ref_type      = optional(string)
      event_name    = optional(string)
      workflow_ref  = optional(string)
      environment   = optional(string)
      actor_matches = optional(list(string))
    }))
  }))
  default = []
}

variable "tag_auth" {
  description = "Tag-based authorization settings. Set enabled=true to use."
  type = object({
    enabled                 = optional(bool, false)
    tag_prefix              = optional(string, "aow/")
    default_org             = optional(string)
    transitive_session_tags = optional(bool, false)
  })
  default = { enabled = false }
}

variable "cross_account" {
  description = "Cross-account policy gate. enabled=false hard-denies all cross-account operations. When true, the Lambda assumes target roles in member accounts directly (one hop, no spoke); the spoke role (spoke_role_name) is used only as a tag-read broker (iam:GetRole) when tag_auth is enabled against cross-account targets. external_id applies only to that hub->spoke tag-read hop, never to direct role assumption."
  type = object({
    enabled                = optional(bool, false)
    spoke_role_name        = optional(string, "aow-spoke")
    external_id            = optional(string)
    spoke_session_duration = optional(string, "15m")
    allowed_accounts       = optional(list(string), [])
  })
  default = { enabled = false }
}

# ---- Lambda sizing ----
variable "lambda_memory_size" {
  type        = number
  description = "Lambda memory (MB)."
  default     = 256
}

variable "lambda_timeout" {
  type        = number
  description = "Lambda timeout (seconds)."
  default     = 15
}

variable "lambda_architecture" {
  type        = string
  description = "Lambda architecture: arm64 or x86_64."
  default     = "arm64"
}

variable "log_retention_days" {
  type        = number
  description = "CloudWatch log retention (days)."
  default     = 14
}

variable "log_level" {
  type        = string
  description = "Lambda LOG_LEVEL (debug/info/warn/error)."
  default     = "info"
}

# ---- Feature toggles ----
variable "enable_dynamodb_cache" {
  type        = bool
  description = "Provision a DynamoDB JWKS cache and set cache.type=dynamodb."
  default     = false
}

variable "enable_s3_cache" {
  type        = bool
  description = "Provision an S3 JWKS cache and set cache.type=s3."
  default     = false
}

variable "cache_ttl" {
  type        = string
  description = "JWKS cache TTL."
  default     = "1h"
}

variable "enable_s3_logs" {
  type        = bool
  description = "Provision an audit-log bucket and enable log_to_s3."
  default     = false
}

variable "enable_session_policy_bucket" {
  type        = bool
  description = "Provision an S3 bucket for session policy files."
  default     = false
}

variable "assumable_role_arns" {
  type        = list(string)
  description = <<-EOT
    Role ARNs the Lambda may assume directly (sts:AssumeRole/sts:TagSession),
    including target roles in member accounts under cross_account.enabled
    (direct hub -> target, one hop). Prefer least-privilege per-account
    patterns, e.g. "arn:aws:iam::<member-account-id>:role/<prefix>*", over
    "arn:aws:iam::*:role/*". Only include the spoke role pattern (e.g.
    "arn:aws:iam::*:role/aow-spoke") when using cross-account tag_auth, since
    the spoke is a tag-read broker (iam:GetRole), not an assume target.
    (sts:GetCallerIdentity needs no explicit permission.)
  EOT
  default     = []
}

variable "bucket_suffix" {
  type        = string
  description = "Suffix appended to S3 bucket names for global uniqueness. Empty = use the account ID."
  default     = ""
}

variable "force_destroy_buckets" {
  type        = bool
  description = "Allow tofu destroy to delete non-empty buckets."
  default     = false
}

# ---- JWT Validation Mode ----
variable "jwt_validation_mode" {
  type        = string
  description = <<-EOT
    JWT validation mode: 'self' (default, apigateway binary) or 'apigw'
    (delegate to the provisioned API GW JWT Authorizer, apigatewayv2 binary).
    'alb' mode is not supported by this stack: it requires the `alb` Lambda
    binary behind an Application Load Balancer, which this module does not
    provision.
  EOT
  default     = "self"
  validation {
    condition     = contains(["self", "apigw"], var.jwt_validation_mode)
    error_message = "jwt_validation_mode must be 'self' or 'apigw' ('alb' needs the alb binary + an ALB, not provisioned here)."
  }
}

variable "jwt_authorizer_issuer" {
  type        = string
  description = "OIDC issuer URL for the API Gateway JWT Authorizer. Only used when jwt_validation_mode = 'apigw'. Defaults to var.issuer — set only to diverge from it."
  default     = null
}

variable "jwt_authorizer_audiences" {
  type        = list(string)
  description = "Accepted audiences for the API Gateway JWT Authorizer. Only used when jwt_validation_mode = 'apigw'. Defaults to var.audiences — set only to diverge from them."
  default     = null
}
