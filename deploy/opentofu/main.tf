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
  # jwt_authorizer_issuer/_audiences still override the authorizer on the
  # shorthand path, so an authorizer can validate against a different
  # issuer/audiences than the app config (documented escape hatch).
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

  # Rendered application configuration (v2 schema: issuers[] + role_mappings).
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
    log_to_s3             = var.enable_s3_logs
    log_bucket            = var.enable_s3_logs ? local.log_bucket_name : null
    log_prefix            = var.enable_s3_logs ? "audit/" : null
    session_policy_bucket = var.enable_session_policy_bucket ? local.session_policy_bucket_name : null
    tag_auth              = var.tag_auth
    cross_account         = var.cross_account
    jwt_validation        = { mode = var.jwt_validation_mode }
  }

  rendered_config = templatefile("${path.module}/templates/config.yaml.tftpl", { cfg = local.app_config })

  # The drift precondition below compares local.app_config against a
  # yamldecode() of local.rendered_config. session_policy is exempt from that
  # comparison's trailing-whitespace sensitivity: the template's `|-` block
  # scalar strips all trailing newlines on decode, but a heredoc-sourced
  # policy always ends in one, so an unnormalized compare would report
  # spurious drift on semantically identical content. trimspace() (not
  # trimsuffix, which only strips a single newline) normalizes both sides;
  # every other field is still compared byte-for-byte.
  rendered_config_decoded = yamldecode(local.rendered_config)
  app_config_for_drift_check = merge(local.app_config, {
    role_mappings = [for m in local.app_config.role_mappings : merge(m, {
      session_policy = m.session_policy == null ? null : trimspace(m.session_policy)
    })]
  })
  rendered_config_decoded_for_drift_check = merge(local.rendered_config_decoded, {
    role_mappings = [for m in local.rendered_config_decoded.role_mappings : merge(m, {
      session_policy = m.session_policy == null ? null : trimspace(m.session_policy)
    })]
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

module "log_bucket" {
  count                     = var.enable_s3_logs ? 1 : 0
  source                    = "./modules/s3"
  bucket_name               = local.log_bucket_name
  force_destroy             = var.force_destroy_buckets
  lifecycle_expiration_days = 90
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
      condition     = var.issuers == null || (var.jwt_authorizer_issuer == null && var.jwt_authorizer_audiences == null)
      error_message = "jwt_authorizer_issuer/jwt_authorizer_audiences apply only to the singular issuer shorthand; with var.issuers each entry's own issuer/audiences drive its authorizer."
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
  log_bucket_arn            = var.enable_s3_logs ? module.log_bucket[0].bucket_arn : null
}

# ---- Lambda ----
module "lambda" {
  source               = "./modules/lambda"
  function_name        = var.name_prefix
  role_arn             = module.iam.role_arn
  zip_path             = "${path.module}/dist/function.zip"
  architecture         = var.lambda_architecture
  memory_size          = var.lambda_memory_size
  timeout              = var.lambda_timeout
  log_retention_days   = var.log_retention_days
  reserved_concurrency = var.lambda_reserved_concurrency
  environment_variables = {
    AOW_S3_CONFIG_BUCKET = module.config_bucket.bucket_id
    AOW_S3_CONFIG_PATH   = local.config_key
    LOG_LEVEL            = var.log_level
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
