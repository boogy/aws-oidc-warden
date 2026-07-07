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

  # Rendered application configuration (v2 schema: issuers[] + role_mappings).
  # Unset optional object attributes render as YAML nulls, which the service
  # treats as absent.
  app_config = merge(
    {
      issuers = [
        {
          issuer          = var.issuer
          provider        = "github"
          audiences       = var.audiences
          required_claims = ["repository"]
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
      ]
      role_session_name = var.role_session_name
      cache = merge(
        { type = local.cache_type, ttl = var.cache_ttl },
        var.enable_dynamodb_cache ? { dynamodb_table = local.cache_table_name } : {},
        var.enable_s3_cache ? { s3_bucket = local.cache_bucket_name, s3_prefix = "jwks/" } : {},
      )
      role_mappings = var.role_mappings
    },
    var.enable_s3_logs ? { log_to_s3 = true, log_bucket = local.log_bucket_name, log_prefix = "audit/" } : {},
    var.enable_session_policy_bucket ? { session_policy_bucket = local.session_policy_bucket_name } : {},
    var.tag_auth.enabled ? { tag_auth = var.tag_auth } : {},
    var.cross_account.enabled ? { cross_account = var.cross_account } : {},
    # Render jwt_validation block only when not using the default "self" mode.
    var.jwt_validation_mode != "self" ? {
      jwt_validation = { mode = var.jwt_validation_mode }
    } : {},
  )
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
  content      = yamlencode(local.app_config)
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
  # "apigw" mode: use v2 payload format + provision a JWT Authorizer so API GW
  # validates the token before invoking Lambda (Lambda reads pre-validated claims).
  payload_format_version = var.jwt_validation_mode == "apigw" ? "2.0" : "1.0"
  enable_jwt_authorizer  = var.jwt_validation_mode == "apigw"
  # Authorizer follows the config issuer/audiences unless explicitly overridden,
  # so the two validation layers cannot drift apart in apigw mode.
  jwt_authorizer_issuer    = coalesce(var.jwt_authorizer_issuer, var.issuer)
  jwt_authorizer_audiences = var.jwt_authorizer_audiences != null ? var.jwt_authorizer_audiences : var.audiences
  throttling_burst_limit   = var.throttling_burst_limit
  throttling_rate_limit    = var.throttling_rate_limit
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
