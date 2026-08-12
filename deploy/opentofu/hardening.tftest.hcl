# Plan-time wiring tests for the endpoint-hardening variables. Runs with a
# mock AWS provider — no credentials needed: `tofu test`.

mock_provider "aws" {
  # The auto-generated mock value is a random string, which fails
  # aws_iam_role's JSON validation — return a minimal valid policy instead.
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::111122223333:role/mock-role"
    }
  }

  mock_resource "aws_apigatewayv2_api" {
    defaults = {
      execution_arn = "arn:aws:execute-api:eu-west-1:111122223333:mockapiv2"
    }
  }

  mock_resource "aws_api_gateway_rest_api" {
    defaults = {
      execution_arn = "arn:aws:execute-api:eu-west-1:111122223333:mockapiv1"
    }
  }

  mock_resource "aws_api_gateway_stage" {
    defaults = {
      arn = "arn:aws:apigateway:eu-west-1::/restapis/mockapiv1/stages/v1"
    }
  }

  mock_resource "aws_wafv2_web_acl" {
    defaults = {
      arn = "arn:aws:wafv2:eu-west-1:111122223333:regional/webacl/mock/00000000-0000-0000-0000-000000000000"
    }
  }
}

variables {
  region = "eu-west-1"
}

# (a) Defaults: HTTP API only, no REST/WAF resources.
run "defaults_http_api" {
  command = plan

  assert {
    condition     = length(module.apigateway) == 1 && length(module.apigateway_rest) == 0
    error_message = "Defaults must provision the HTTP API module only."
  }
}

# (b) REST + WAF: REST API module only; WAF web ACL provisioned.
run "rest_with_waf" {
  command = plan

  variables {
    api_gateway_type = "rest"
    enable_waf       = true
  }

  assert {
    condition     = length(module.apigateway) == 0 && length(module.apigateway_rest) == 1
    error_message = "api_gateway_type = 'rest' must provision the REST API module only."
  }

  assert {
    condition     = length(module.apigateway_rest[0].web_acl_arn) > 0
    error_message = "enable_waf must provision a WAF web ACL."
  }
}

# (c) Invalid combination: apigw JWT-authorizer mode on a REST API must fail
# the plan-time precondition.
run "apigw_mode_requires_http_api" {
  command = plan

  variables {
    api_gateway_type    = "rest"
    jwt_validation_mode = "apigw"
  }

  expect_failures = [aws_s3_object.config]
}

# (d) Invalid combination: WAF on an HTTP API must fail the precondition.
run "waf_requires_rest_api" {
  command = plan

  variables {
    api_gateway_type = "http"
    enable_waf       = true
  }

  expect_failures = [aws_s3_object.config]
}

# (e) Regression guard: multi-issuer self mode must remain deployable. Every
# var.issuers entry's route_key is null in self mode, so the distinct-route_key
# precondition must not fire, and self mode provisions zero JWT authorizers and
# zero per-issuer routes (the Lambda validates signatures itself).
run "self_mode_multi_issuer_plans" {
  command = plan

  variables {
    issuers = {
      github = {
        issuer       = "https://token.actions.githubusercontent.com"
        audiences    = ["sts.amazonaws.com"]
        provider     = "github"
        session_tags = { repo = "repository" }
      }
      other = {
        issuer         = "https://example.com"
        audiences      = ["sts.amazonaws.com"]
        provider       = "generic"
        session_tags   = { sub = "sub" }
        claim_mappings = { subject = "sub" }
      }
    }
  }

  assert {
    condition     = length(module.apigateway[0].jwt_authorizer_ids) == 0
    error_message = "Self mode must provision zero JWT authorizers, even with multiple var.issuers entries."
  }

  assert {
    condition     = length(module.apigateway[0].route_endpoints) == 0
    error_message = "Self mode must provision zero per-issuer routes, even with multiple var.issuers entries."
  }
}

# (f) Multi-issuer apigw mode: one authorizer and one route per issuer, each
# route paired with its own authorizer.
run "multi_issuer_apigw" {
  command = plan

  variables {
    api_gateway_type    = "http"
    jwt_validation_mode = "apigw"
    issuer              = null
    audiences           = null
    issuers = {
      github = {
        issuer       = "https://token.actions.githubusercontent.com"
        audiences    = ["sts.amazonaws.com"]
        provider     = "github"
        route_key    = "POST /github"
        session_tags = { repo = "repository" }
      }
      gitlab = {
        issuer         = "https://gitlab.com"
        audiences      = ["aws-oidc-warden"]
        provider       = "generic"
        route_key      = "POST /gitlab"
        claim_mappings = { subject = "project_path" }
        session_tags   = { project = "project_path" }
      }
    }
  }

  assert {
    condition     = length(module.apigateway[0].jwt_authorizer_ids) == 2
    error_message = "Each issuer must get its own JWT Authorizer."
  }

  assert {
    condition     = length(module.apigateway[0].route_endpoints) == 2
    error_message = "Each issuer must get its own route."
  }

  assert {
    condition     = endswith(module.apigateway[0].route_endpoints["gitlab"], "/gitlab")
    error_message = "Each route endpoint must use that issuer's route_key path."
  }

  assert {
    condition     = length(yamldecode(aws_s3_object.config.content).issuers) == 2
    error_message = "The rendered config must list both issuers."
  }

  assert {
    condition     = strcontains(aws_s3_object.config.content, "\nissuers:\n")
    error_message = "Rendered YAML keys must be unquoted."
  }
}

# (g) route_key is mandatory in apigw mode.
run "apigw_requires_route_key" {
  command = plan

  variables {
    jwt_validation_mode = "apigw"
    issuer              = null
    audiences           = null
    issuers = {
      github = {
        issuer       = "https://token.actions.githubusercontent.com"
        audiences    = ["sts.amazonaws.com"]
        provider     = "github"
        session_tags = { repo = "repository" }
      }
    }
  }

  expect_failures = [aws_s3_object.config]
}

# (h) route_key is meaningless in self mode and must be rejected, not ignored.
run "self_mode_rejects_route_key" {
  command = plan

  variables {
    jwt_validation_mode = "self"
    issuer              = null
    audiences           = null
    issuers = {
      github = {
        issuer       = "https://token.actions.githubusercontent.com"
        audiences    = ["sts.amazonaws.com"]
        provider     = "github"
        route_key    = "POST /github"
        session_tags = { repo = "repository" }
      }
    }
  }

  expect_failures = [aws_s3_object.config]
}

# (i) var.issuers and the singular shorthand are mutually exclusive.
run "issuers_excludes_shorthand" {
  command = plan

  variables {
    issuer    = "https://token.actions.githubusercontent.com"
    audiences = ["sts.amazonaws.com"]
    issuers = {
      github = {
        issuer       = "https://token.actions.githubusercontent.com"
        audiences    = ["sts.amazonaws.com"]
        provider     = "github"
        session_tags = { repo = "repository" }
      }
    }
  }

  expect_failures = [aws_s3_object.config]
}

# (j) Duplicate route keys would make the plan ambiguous.
run "duplicate_route_keys_rejected" {
  command = plan

  variables {
    jwt_validation_mode = "apigw"
    issuer              = null
    audiences           = null
    issuers = {
      a = {
        issuer         = "https://a.example.com"
        audiences      = ["aud"]
        provider       = "generic"
        route_key      = "POST /same"
        claim_mappings = { subject = "sub" }
        session_tags   = { x = "y" }
      }
      b = {
        issuer         = "https://b.example.com"
        audiences      = ["aud"]
        provider       = "generic"
        route_key      = "POST /same"
        claim_mappings = { subject = "sub" }
        session_tags   = { x = "y" }
      }
    }
  }

  expect_failures = [aws_s3_object.config]
}

# (k) Self mode (no var.issuers override) still produces exactly one open
# route and no authorizers.
run "self_mode_single_open_route" {
  command = plan

  assert {
    condition     = length(module.apigateway[0].jwt_authorizer_ids) == 0
    error_message = "Self mode must provision no JWT Authorizers."
  }

  assert {
    condition     = endswith(module.apigateway[0].api_endpoint, "/verify")
    error_message = "Self mode must serve the single verify route."
  }
}

# (l) Regression guard: a heredoc-sourced session_policy always ends in a
# newline, which the template's `|-` block scalar strips on decode. The drift
# precondition must tolerate that (session_policy trailing whitespace is the
# only exemption in the comparison) instead of failing the plan on
# semantically identical content.
run "session_policy_heredoc_trailing_newline" {
  command = plan

  variables {
    role_mappings = [
      {
        subject        = "myorg/myrepo"
        roles          = ["arn:aws:iam::111122223333:role/deploy"]
        session_policy = <<-EOT
          {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}
        EOT
      }
    ]
  }

  assert {
    condition     = length(yamldecode(aws_s3_object.config.content).role_mappings) == 1
    error_message = "The rendered config must include the heredoc-sourced role mapping despite its trailing-newline session_policy."
  }
}
