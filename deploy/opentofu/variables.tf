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
# By default this stack renders a single GitHub Actions issuer entry into the
# v2 `issuers[]` list. For multiple issuers or non-GitHub providers, set
# var.issuers instead — the module renders its config.yaml too, no hand
# management needed.
variable "issuer" {
  type        = string
  description = "OIDC issuer URL (rendered as a single github issuers[] entry). Mutually exclusive with var.issuers. Null uses the GitHub Actions default."
  default     = null
}

variable "audiences" {
  type        = list(string)
  description = "Accepted token audiences for var.issuer. Mutually exclusive with var.issuers."
  default     = null
}

variable "issuers" {
  description = <<-EOT
    Trusted issuers keyed by short name. Drives the rendered app config
    `issuers[]` and, in apigw mode, one JWT Authorizer + one route per entry.
    Leave unset to use the singular `issuer`/`audiences` shorthand, which
    renders a single GitHub Actions issuer (today's behavior).

    `provider` and `session_tags` are required per entry on purpose: inheriting
    GitHub's defaults for a non-GitHub issuer fails later with a confusing
    claim-mapping error instead of at plan time.

    `route_key` ("<METHOD> <path>", e.g. "POST /github") is required in apigw
    mode and must be omitted in self mode, which serves one route on
    var.route_key.
  EOT
  type = map(object({
    issuer          = string
    audiences       = list(string)
    provider        = string
    session_tags    = map(string)
    route_key       = optional(string)
    claim_mappings  = optional(map(string))
    required_claims = optional(list(string))
    jwks_uri        = optional(string)
  }))
  default = null

  validation {
    condition     = var.issuers == null ? true : alltrue([for k, v in var.issuers : contains(["github", "generic"], v.provider)])
    error_message = "Each issuer's provider must be \"github\" or \"generic\"."
  }

  validation {
    condition     = var.issuers == null ? true : alltrue([for k, v in var.issuers : v.audiences != null && length(v.audiences) > 0])
    error_message = "Each issuer must declare at least one audience."
  }

  validation {
    condition     = var.issuers == null ? true : alltrue([for k, v in var.issuers : v.route_key == null || length(split(" ", v.route_key)) == 2])
    error_message = "route_key must be \"<METHOD> <path>\", e.g. \"POST /github\"."
  }

  validation {
    condition     = var.issuers == null ? true : alltrue([for k, v in var.issuers : v.provider != "generic" || try(v.claim_mappings["subject"], "") != ""])
    error_message = "Each \"generic\" issuer must set claim_mappings.subject — the service requires it at boot for non-github issuers."
  }
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

    `issuer` binds this mapping to one issuer's `issuer` URL (not its
    `var.issuers` map key) and is required once more than one issuer is
    configured, unless `var.default_issuer` is set — the service refuses to
    boot otherwise (internal/config/config.go). With a single issuer it is
    optional; that sole issuer applies regardless.

    `role_session_name` overrides the global `var.role_session_name` for
    roles granted by THIS mapping only, so CloudTrail names the requester
    instead of the service. STS accepts 2-64 characters from
    `[\w+=,.@-]` — note `/` is NOT in that set, so a GitHub "owner/repo"
    subject cannot be used verbatim. An invalid value fails the service at
    boot rather than being silently reshaped. A mapping whose `subject` is a
    regex matching many repositories gets ONE name for the whole set, not one
    per repository — per-repository names require per-repository mappings.
  EOT
  type = list(object({
    subject             = string
    issuer              = optional(string)
    roles               = list(string)
    session_policy      = optional(string)
    session_policy_file = optional(string)
    role_session_name   = optional(string)
    conditions = optional(object({
      ref                = optional(string)
      ref_type           = optional(string)
      event_name         = optional(string)
      workflow_ref       = optional(string)
      runner_environment = optional(string)
      environment        = optional(string)
      actor              = optional(list(string))
    }))
  }))
  default = []

  validation {
    condition     = alltrue([for m in var.role_mappings : m.roles != null && length(m.roles) > 0])
    error_message = "Each role_mappings entry needs at least one role — an empty roles list plans clean but the service refuses to boot (internal/config/config.go)."
  }
}

variable "default_issuer" {
  type        = string
  description = <<-EOT
    Issuer (the `issuer` URL, not a `var.issuers` map key) inherited by any
    role_mappings entry that omits its own `issuer`. Required when more than
    one issuer is configured and any mapping omits `issuer`; with a single
    issuer this is optional — that sole issuer applies regardless.
  EOT
  default     = null
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

variable "session_tags_transitive" {
  type        = bool
  description = <<-EOT
    RECOMMENDED: mark every session tag transitive so the requester's identity
    survives further role chaining by the target role and cannot be altered
    downstream.

    Without this, a session tag is dropped the moment the target role assumes
    another role, so any ABAC policy past that hop can no longer see who the
    original caller was.

    Defaults to false only for upgrade safety: transitive tags are immutable
    downstream, so enabling this breaks a target role that re-tags with the
    same keys while chaining. If yours does not (the common case), turn it on.
  EOT
  default     = false
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

# ---- Endpoint hardening ----
variable "route_key" {
  type        = string
  description = "Route key (\"<METHOD> <path>\") for the single verify route: self mode, and the apigw singular-issuer shorthand."
  default     = "POST /verify"
  # route_key = null in apigw shorthand mode drops the entry from
  # local.jwt_authorizers and steers this value toward the open route's
  # module input instead — an opaque, deep null-required-argument failure
  # rather than a clean one. nullable = false substitutes the default here
  # instead (an explicit null falls back to it, same as leaving the argument
  # unset), so an accidental null gets the safe default route_key rather
  # than a confusing error several modules downstream.
  nullable = false
  validation {
    condition     = length(split(" ", var.route_key)) == 2
    error_message = "route_key must be \"<METHOD> <path>\", e.g. \"POST /verify\"."
  }
}

variable "api_gateway_type" {
  type        = string
  description = <<-EOT
    API Gateway flavor: 'http' (HTTP API v2, default) or 'rest' (REST API v1).
    'http' supports the JWT Authorizer (jwt_validation_mode = 'apigw');
    'rest' supports AWS WAF attachment (enable_waf) for multi-issuer self
    mode. Both run the same Lambda: 'rest' and 'http'+self use the
    `apigateway` binary (v1 events; the HTTP API uses payload format 1.0),
    'http'+apigw uses the `apigatewayv2` binary.
  EOT
  default     = "http"
  validation {
    condition     = contains(["http", "rest"], var.api_gateway_type)
    error_message = "api_gateway_type must be 'http' or 'rest'."
  }
}

variable "enable_waf" {
  type        = bool
  description = <<-EOT
    Attach an AWS WAFv2 web ACL to the API stage: per-source-IP rate limiting
    (waf_rate_limit), AWSManagedRulesCommonRuleSet, and a request-shape rule
    that blocks anything other than POST /verify. Requires api_gateway_type =
    'rest' (AWS WAF cannot attach to HTTP APIs). No IP allowlisting — GitHub
    runner IP ranges are vast and dynamic.
  EOT
  default     = false
}

variable "waf_rate_limit" {
  type        = number
  description = "WAF rate-based rule: max requests per source IP per 5-minute window. Only used when enable_waf = true."
  default     = 300
}

variable "waf_common_rule_set" {
  type        = bool
  description = "Include AWSManagedRulesCommonRuleSet in the web ACL. Disable if it false-positives on JWT request bodies. Only used when enable_waf = true."
  default     = true
}

variable "throttling_burst_limit" {
  type        = number
  description = "API Gateway stage burst limit (concurrent request spikes)."
  default     = 50
}

variable "throttling_rate_limit" {
  type        = number
  description = "API Gateway stage steady-state rate limit (requests/second)."
  default     = 100
}

variable "lambda_reserved_concurrency" {
  type        = number
  description = "Reserved concurrent executions for the Lambda — caps the cost/blast radius of unauthenticated floods in self mode. -1 leaves it unreserved."
  default     = -1
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

variable "check_lambda_variant" {
  type        = bool
  description = <<-EOT
    Enforce that the packaged Lambda binary variant matches
    jwt_validation_mode (see modules/lambda's precondition). Leave this at
    the default true for every real deployment — it exists only so
    hardening.tftest.hcl, which plans multiple jwt_validation_mode values
    against one build/marker, can turn the check off for itself; a real
    deploy has exactly one mode and must not disable it.
  EOT
  default     = true
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
  description = <<-EOT
    Provision an audit-log bucket and enable log_to_s3. Implied by
    audit_required (default true), which needs a durable destination — set
    audit_required=false to opt out of both.
  EOT
  default     = false
}

variable "log_claim_values" {
  type        = bool
  description = <<-EOT
    Include claim VALUES in logs and audit records: the canonical subject, raw
    `sub`, audience, resolved session tags, and the per-issuer `claims` object
    (repository/ref/event_name/actor for GitHub). Without this an audit record
    names the decision and the role but not who made the request. Set false to
    keep identities out of the log stream; claim NAMES, decision, and reason
    are always recorded either way.
  EOT
  default     = true
}

variable "audit_required" {
  type        = bool
  description = <<-EOT
    Write each allow decision's audit record to S3 synchronously, BEFORE
    credentials are returned; a write failure denies the request (fail-closed).
    Implies enable_s3_logs, since the guarantee needs a bucket to write to.
    Set false for the best-effort batched trail, which in Lambda can lose
    buffered records at container reclaim (docs/LOGGING.md).
  EOT
  default     = true
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

# ---- Audit bucket retention ----
variable "audit_log_retention_days" {
  type        = number
  description = "Days audit objects are kept in the log bucket before expiring. Must be >= audit_log_object_lock_days when Object Lock is on, or locked versions outlive the rule and are never removed."
  default     = 90
}

variable "audit_log_object_lock_mode" {
  type        = string
  description = "S3 Object Lock mode for the audit bucket: \"GOVERNANCE\" (overridable by a principal with s3:BypassGovernanceRetention), \"COMPLIANCE\" (not overridable by anyone, including root), or null to leave Object Lock off. Can only be set when the bucket is first created."
  default     = null
}

variable "audit_log_object_lock_days" {
  type        = number
  description = "Days each audit object version is retained under audit_log_object_lock_mode. Ignored when Object Lock is off."
  default     = 365
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
  description = <<-EOT
    OIDC issuer URL for the API Gateway JWT Authorizer. Only used when
    jwt_validation_mode = 'apigw'. Must match var.issuer (or its GitHub
    Actions default) exactly — apigw mode requires the authorizer's
    verified `iss` to exist in the app config's issuers[], so a divergent
    value makes every request fail at runtime with ErrUnknownIssuer
    (rejected at plan time instead, by a precondition on aws_s3_object.config).
  EOT
  default     = null
}

variable "jwt_authorizer_audiences" {
  type        = list(string)
  description = <<-EOT
    Accepted audiences for the API Gateway JWT Authorizer. Only used when
    jwt_validation_mode = 'apigw'. Defaults to var.audiences; may diverge
    from it, but only in the safe direction — a token must satisfy both the
    authorizer's list (checked first, at the gateway) and the app config's
    ANY-match audiences check (checked again in the Lambda), so a narrower
    authorizer list can only narrow acceptance, never widen what the app
    config alone would accept.
  EOT
  default     = null
}
