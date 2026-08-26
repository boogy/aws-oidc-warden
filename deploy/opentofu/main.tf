data "aws_caller_identity" "current" {}

locals {
  cache_type = var.enable_dynamodb_cache ? "dynamodb" : (var.enable_s3_cache ? "s3" : "memory")

  # S3 bucket names are globally unique — suffix with the account ID (overridable
  # via var.bucket_suffix) so "aws-oidc-warden-config" does not collide.
  suffix = var.bucket_suffix != "" ? var.bucket_suffix : data.aws_caller_identity.current.account_id

  config_bucket_name         = "${var.name_prefix}-config-${local.suffix}"
  cache_bucket_name          = "${var.name_prefix}-cache-${local.suffix}"
  log_bucket_name            = "${var.name_prefix}-logs-${local.suffix}"
  session_policy_bucket_name = "${var.name_prefix}-session-policies-${local.suffix}"
  cache_table_name           = "${var.name_prefix}-cache"
  config_key                 = "config.yaml"

  # The singular issuer/audiences shorthand renders as one GitHub entry, and in
  # apigw mode keeps today's single route (var.route_key). Setting var.issuers
  # replaces the shorthand entirely — the two are mutually exclusive, enforced
  # by a precondition on aws_s3_object.config.
  issuers_shorthand = {
    github = {
      issuer          = coalesce(var.issuer, "https://token.actions.githubusercontent.com")
      audiences       = coalesce(var.audiences, ["sts.amazonaws.com"])
      provider        = "github"
      required_claims = ["repository"]
      claim_mappings  = null
      jwks_uri        = null
      route_key       = var.jwt_validation_mode == "apigw" ? var.route_key : null
      # Standard GitHub session-tag spec (STS tag key <- raw claim name).
      # NOTE: the `repo` tag carries the full "owner/repo" value in v2.
      session_tags = {
        repo       = "repository"
        repo-owner = "repository_owner"
        ref        = "ref"
        ref-type   = "ref_type"
        actor      = "actor"
        event-name = "event_name"
      }
    }
  }

  issuers_effective = var.issuers != null ? var.issuers : local.issuers_shorthand

  # Authorizers exist only in apigw mode; self mode gets one open route.
  # jwt_authorizer_audiences may diverge from the app config's audiences on
  # the shorthand path, but only in the safe direction: a token must satisfy
  # both the authorizer's list and the app config's ANY-match check, so a
  # narrower authorizer list can only narrow acceptance, never widen it.
  # jwt_authorizer_issuer may NOT diverge — apigw mode requires an exact
  # match between the authorizer-verified iss and issuers[].issuer
  # (internal/validator's resolveIssuerSpec), so a different
  # jwt_authorizer_issuer here would make every request fail at runtime with
  # ErrUnknownIssuer. A precondition on aws_s3_object.config rejects that
  # combination at plan time.
  # Entries missing route_key are filtered out rather than passed through:
  # the "requires route_key" precondition on aws_s3_object.config is what
  # rejects that misconfiguration (blocking apply), so this filter exists
  # only to keep a bad entry from reaching modules/apigateway's route_key
  # string interpolation, which has no null guard.
  jwt_authorizers = var.jwt_validation_mode == "apigw" ? {
    for k, v in local.issuers_effective : k => {
      issuer    = var.issuers == null ? coalesce(var.jwt_authorizer_issuer, v.issuer) : v.issuer
      audiences = var.issuers == null && var.jwt_authorizer_audiences != null ? var.jwt_authorizer_audiences : v.audiences
      route_key = v.route_key
    } if v.route_key != null
  } : {}

  # audit_required needs a durable S3 destination to write to — with no bucket
  # the service downgrades it to a no-op at boot (internal/config/config.go),
  # silently losing the fail-closed guarantee the flag is asking for. So it
  # provisions the log bucket on its own rather than requiring the operator to
  # remember a second toggle; enable_s3_logs stays meaningful for the
  # audit_required=false case (best-effort batched trail, still to S3).
  s3_logs_enabled = var.enable_s3_logs || var.audit_required

  # Rendered application configuration (v3 schema: issuers[] + role_mappings).
  # Every key is unconditional so both branches of every ternary share the
  # same type (avoids e.g. log_to_s3 coercing to the string "true"); disabled
  # features render explicit nulls/false, which the service treats as absent.
  app_config = {
    issuers = [for k in sort(keys(local.issuers_effective)) : {
      issuer          = local.issuers_effective[k].issuer
      provider        = local.issuers_effective[k].provider
      audiences       = local.issuers_effective[k].audiences
      required_claims = local.issuers_effective[k].required_claims
      claim_mappings  = local.issuers_effective[k].claim_mappings
      jwks_uri        = local.issuers_effective[k].jwks_uri
      session_tags    = local.issuers_effective[k].session_tags
    }]
    role_session_name = var.role_session_name
    default_issuer    = var.default_issuer
    role_mappings     = var.role_mappings
    cache = {
      type           = local.cache_type
      ttl            = var.cache_ttl
      dynamodb_table = var.enable_dynamodb_cache ? local.cache_table_name : null
      s3_bucket      = var.enable_s3_cache ? local.cache_bucket_name : null
      s3_prefix      = var.enable_s3_cache ? "jwks/" : null
    }
    audit_required          = var.audit_required
    log_claim_values        = var.log_claim_values
    log_to_s3               = local.s3_logs_enabled
    log_bucket              = local.s3_logs_enabled ? local.log_bucket_name : null
    log_prefix              = local.s3_logs_enabled ? "audit/" : null
    session_policy_bucket   = var.enable_session_policy_bucket ? local.session_policy_bucket_name : null
    session_tags_transitive = var.session_tags_transitive
    tag_auth                = var.tag_auth
    cross_account           = var.cross_account
    jwt_validation          = { mode = var.jwt_validation_mode }
  }

  rendered_config = templatefile("${path.module}/templates/config.yaml.tftpl", { cfg = local.app_config })

  # The drift precondition below compares local.app_config against a
  # yamldecode() of local.rendered_config. The template omits null
  # role_mappings fields entirely (rather than emitting `field: null`), so
  # local.app_config's role_mappings (which always carries every key, null or
  # not) are stripped of null-valued keys here to line up with what actually
  # comes back from yamldecode. session_policy is additionally exempt from
  # the comparison's trailing-whitespace sensitivity: the template's `|-`
  # block scalar strips all trailing newlines on decode, but a heredoc-sourced
  # policy always ends in one, so an unnormalized compare would report
  # spurious drift on semantically identical content. trimspace() (not
  # trimsuffix, which only strips a single newline) normalizes both sides;
  # every other field is still compared byte-for-byte.
  rendered_config_decoded = yamldecode(local.rendered_config)
  app_config_for_drift_check = merge(local.app_config, {
    role_mappings = [for m in local.app_config.role_mappings : {
      for k, v in merge(m, {
        session_policy = m.session_policy == null ? null : trimspace(m.session_policy)
        conditions = m.conditions == null ? null : (
          length([for ck, cv in m.conditions : ck if cv != null]) == 0 ? null :
          { for ck, cv in m.conditions : ck => cv if cv != null }
        )
      }) : k => v if v != null
    }]
  })
  rendered_config_decoded_for_drift_check = merge(local.rendered_config_decoded, {
    role_mappings = [for m in local.rendered_config_decoded.role_mappings : {
      for k, v in merge(m, {
        session_policy = try(trimspace(m.session_policy), null)
        conditions     = try(m.conditions, null) == null ? null : { for ck, cv in m.conditions : ck => cv if cv != null }
      }) : k => v if v != null
    }]
  })
}

# ---- Buckets ----
module "config_bucket" {
  source        = "./modules/s3"
  bucket_name   = local.config_bucket_name
  force_destroy = var.force_destroy_buckets
}

module "cache_bucket" {
  count         = var.enable_s3_cache ? 1 : 0
  source        = "./modules/s3"
  bucket_name   = local.cache_bucket_name
  force_destroy = var.force_destroy_buckets
}

# The audit bucket is the durable record of every credential the warden ever
# issued, so it is versioned by default: an overwrite or delete of an audit
# object leaves the previous version recoverable. Set
# audit_log_object_lock_mode to make that retention non-negotiable (see
# deploy/README.md — it can only be set when the bucket is created).
module "log_bucket" {
  count                      = local.s3_logs_enabled ? 1 : 0
  source                     = "./modules/s3"
  bucket_name                = local.log_bucket_name
  force_destroy              = var.force_destroy_buckets
  lifecycle_expiration_days  = var.audit_log_retention_days
  versioning_enabled         = true
  object_lock_mode           = var.audit_log_object_lock_mode
  object_lock_retention_days = var.audit_log_object_lock_days
}

module "session_policy_bucket" {
  count         = var.enable_session_policy_bucket ? 1 : 0
  source        = "./modules/s3"
  bucket_name   = local.session_policy_bucket_name
  force_destroy = var.force_destroy_buckets
}

# ---- Cache table ----
module "dynamodb" {
  count      = var.enable_dynamodb_cache ? 1 : 0
  source     = "./modules/dynamodb"
  table_name = local.cache_table_name
}

# ---- Rendered config object ----
resource "aws_s3_object" "config" {
  bucket       = module.config_bucket.bucket_id
  key          = local.config_key
  content      = local.rendered_config
  content_type = "application/x-yaml"

  lifecycle {
    precondition {
      condition     = !(var.enable_dynamodb_cache && var.enable_s3_cache)
      error_message = "enable_dynamodb_cache and enable_s3_cache are mutually exclusive."
    }
    precondition {
      condition     = !(var.jwt_validation_mode == "apigw" && var.api_gateway_type != "http")
      error_message = "jwt_validation_mode = 'apigw' requires api_gateway_type = 'http' — JWT Authorizers exist only on HTTP APIs (v2)."
    }
    precondition {
      condition     = !(var.enable_waf && var.api_gateway_type != "rest")
      error_message = "enable_waf requires api_gateway_type = 'rest' — AWS WAF cannot attach to HTTP APIs (v2)."
    }
    precondition {
      condition     = var.issuers == null || (var.issuer == null && var.audiences == null)
      error_message = "var.issuers and the singular var.issuer/var.audiences are mutually exclusive — pick one source of truth."
    }
    precondition {
      condition     = length(local.issuers_effective) > 0
      error_message = "At least one issuer is required — the service rejects a config with zero issuers at boot (internal/config/config.go). Set var.issuers to a non-empty map, or leave it null to use the var.issuer/var.audiences shorthand."
    }
    precondition {
      condition     = length(local.issuers_effective) <= 1 || var.default_issuer != null || alltrue([for m in var.role_mappings : m.issuer != null])
      error_message = "Multiple issuers are configured — every role_mappings entry needs its own issuer, or set var.default_issuer, or the service refuses to boot (internal/config/config.go)."
    }
    precondition {
      # Deliberately no "<= 1" short-circuit: with a single issuer, an
      # unrelated var.default_issuer is just as much a boot-time rejection
      # (internal/config/config.go:783) as with several — the short-circuit
      # above exists only for the "is one set at all" question, not this
      # "is it a real one" question.
      condition     = var.default_issuer == null || contains([for k, v in local.issuers_effective : v.issuer], var.default_issuer)
      error_message = "var.default_issuer (${coalesce(var.default_issuer, "null")}) is not one of the configured issuers — the service rejects it at boot (internal/config/config.go). Configured issuers come from var.issuers, or the var.issuer shorthand if var.issuers is unset."
    }
    precondition {
      # Same reasoning: no short-circuit on issuer count. A mapping's issuer
      # is checked against internal/config/config.go:797 regardless of how
      # many issuers are configured, including exactly one.
      condition     = alltrue([for m in var.role_mappings : m.issuer == null || contains([for k, v in local.issuers_effective : v.issuer], m.issuer)])
      error_message = "role_mappings issuer(s) not among the configured issuers: ${jsonencode(distinct([for m in var.role_mappings : m.issuer if m.issuer != null && !contains([for k, v in local.issuers_effective : v.issuer], m.issuer)]))} — the service rejects these at boot (internal/config/config.go). Configured issuers come from var.issuers, or the var.issuer shorthand if var.issuers is unset."
    }
    precondition {
      condition     = var.issuers == null || (var.jwt_authorizer_issuer == null && var.jwt_authorizer_audiences == null)
      error_message = "jwt_authorizer_issuer/jwt_authorizer_audiences apply only to the singular issuer shorthand; with var.issuers each entry's own issuer/audiences drive its authorizer."
    }
    precondition {
      condition     = var.jwt_validation_mode != "apigw" || var.jwt_authorizer_issuer == null || var.jwt_authorizer_issuer == local.issuers_shorthand.github.issuer
      error_message = "jwt_authorizer_issuer must match the app config's issuer (var.issuer, or its GitHub Actions default) — the JWT Authorizer's verified iss must exist in issuers[], or every apigw request fails at runtime with ErrUnknownIssuer. jwt_authorizer_audiences may still diverge (safe direction only)."
    }
    precondition {
      condition     = var.issuers == null || var.jwt_validation_mode != "apigw" || alltrue([for k, v in var.issuers : v.route_key != null])
      error_message = "jwt_validation_mode = 'apigw' requires every var.issuers entry to set route_key."
    }
    precondition {
      condition     = var.issuers == null || var.jwt_validation_mode == "apigw" || alltrue([for k, v in var.issuers : v.route_key == null])
      error_message = "route_key applies only to apigw mode; self mode serves one route on var.route_key."
    }
    precondition {
      condition     = var.issuers == null || var.jwt_validation_mode != "apigw" || length(distinct([for k, v in var.issuers : v.route_key])) == length(var.issuers)
      error_message = "Each var.issuers entry needs a distinct route_key."
    }
    precondition {
      condition     = var.jwt_validation_mode != "apigw" || length(local.issuers_effective) <= 10
      error_message = "API Gateway allows at most 10 JWT Authorizers per HTTP API; split across two APIs beyond that."
    }
    precondition {
      condition     = jsonencode(local.rendered_config_decoded_for_drift_check) == jsonencode(local.app_config_for_drift_check)
      error_message = "Rendered config.yaml does not round-trip to local.app_config — templates/config.yaml.tftpl has drifted from the config structure."
    }
  }
}

# ---- IAM ----
module "iam" {
  source              = "./modules/iam"
  name_prefix         = var.name_prefix
  assumable_role_arns = var.assumable_role_arns
  # iam:GetRole is only needed for tag-auth's hub-account tag reads; cross-account
  # assumes are direct and don't require it.
  enable_iam_getrole        = var.tag_auth.enabled
  cache_dynamodb_table_arn  = var.enable_dynamodb_cache ? module.dynamodb[0].table_arn : null
  cache_s3_bucket_arn       = var.enable_s3_cache ? module.cache_bucket[0].bucket_arn : null
  config_bucket_arn         = module.config_bucket.bucket_arn
  session_policy_bucket_arn = var.enable_session_policy_bucket ? module.session_policy_bucket[0].bucket_arn : null
  log_bucket_arn            = local.s3_logs_enabled ? module.log_bucket[0].bucket_arn : null
}

# ---- Lambda ----
module "lambda" {
  source               = "./modules/lambda"
  function_name        = var.name_prefix
  role_arn             = module.iam.role_arn
  zip_path             = "${path.module}/dist/function.zip"
  expected_variant     = var.jwt_validation_mode == "apigw" ? "apigatewayv2" : "apigateway"
  check_variant        = var.check_lambda_variant
  architecture         = var.lambda_architecture
  memory_size          = var.lambda_memory_size
  timeout              = var.lambda_timeout
  log_retention_days   = var.log_retention_days
  reserved_concurrency = var.lambda_reserved_concurrency
  environment_variables = {
    AOW_S3_CONFIG_BUCKET    = module.config_bucket.bucket_id
    AOW_S3_CONFIG_PATH      = local.config_key
    AOW_JWT_VALIDATION_MODE = var.jwt_validation_mode
    LOG_LEVEL               = var.log_level
  }

  depends_on = [aws_s3_object.config]
}

# ---- API Gateway ----
# Exactly one front-end is provisioned, selected by var.api_gateway_type:
# "http" (v2) supports the JWT Authorizer; "rest" (v1) supports WAF attachment.
module "apigateway" {
  count                = var.api_gateway_type == "http" ? 1 : 0
  source               = "./modules/apigateway"
  name                 = var.name_prefix
  lambda_invoke_arn    = module.lambda.invoke_arn
  lambda_function_name = module.lambda.function_name
  # "apigw" mode: v2 payload format + one JWT Authorizer and route per issuer,
  # so API GW validates the token before invoking Lambda (which then reads the
  # pre-validated claims and resolves the matching issuer spec).
  payload_format_version = var.jwt_validation_mode == "apigw" ? "2.0" : "1.0"
  jwt_authorizers        = local.jwt_authorizers
  route_key              = var.route_key
  throttling_burst_limit = var.throttling_burst_limit
  throttling_rate_limit  = var.throttling_rate_limit
}

module "apigateway_rest" {
  count                  = var.api_gateway_type == "rest" ? 1 : 0
  source                 = "./modules/apigateway-rest"
  name                   = var.name_prefix
  lambda_invoke_arn      = module.lambda.invoke_arn
  lambda_function_name   = module.lambda.function_name
  throttling_burst_limit = var.throttling_burst_limit
  throttling_rate_limit  = var.throttling_rate_limit
  enable_waf             = var.enable_waf
  waf_rate_limit         = var.waf_rate_limit
  waf_common_rule_set    = var.waf_common_rule_set
  tags                   = var.tags
}
