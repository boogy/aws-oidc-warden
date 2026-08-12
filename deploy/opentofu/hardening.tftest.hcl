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

  # This suite plans jwt_validation_mode = "self" and "apigw" against one
  # local dist/function.zip, so no single dist/variant marker value could
  # ever satisfy modules/lambda's variant-vs-mode precondition across every
  # run. Turn the check off here only — a real deployment leaves
  # var.check_lambda_variant at its default (true).
  check_lambda_variant = false
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

# (m) An empty var.issuers map satisfies every route_key precondition
# vacuously (alltrue([]) and 0 == 0 are both true), so nothing else stops a
# zero-issuer apigw deploy — which the service refuses to boot regardless.
run "apigw_rejects_empty_issuers" {
  command = plan

  variables {
    jwt_validation_mode = "apigw"
    issuer              = null
    audiences           = null
    issuers             = {}
  }

  expect_failures = [aws_s3_object.config]
}

# (n) An issuer with no session tags is an ordinary, valid config — it must
# not trip the config.yaml round-trip check. The template previously rendered
# an empty session_tags map as a bare key (decodes to null, not {}).
run "empty_session_tags_is_valid" {
  command = plan

  variables {
    issuers = {
      github = {
        issuer       = "https://token.actions.githubusercontent.com"
        audiences    = ["sts.amazonaws.com"]
        provider     = "github"
        session_tags = {}
      }
    }
  }

  assert {
    condition     = yamldecode(aws_s3_object.config.content).issuers[0].session_tags == {}
    error_message = "An issuer's session_tags must round-trip to an empty map, not null."
  }
}

# (o) Multi-issuer + role_mappings with no per-mapping issuer and no
# default_issuer must fail at plan time — the service refuses to boot this
# combination (internal/config/config.go), so it must never reach apply.
run "multi_issuer_role_mapping_requires_issuer_or_default" {
  command = plan

  variables {
    issuers = {
      github = {
        issuer       = "https://token.actions.githubusercontent.com"
        audiences    = ["sts.amazonaws.com"]
        provider     = "github"
        session_tags = { repo = "repository" }
      }
      gitlab = {
        issuer         = "https://gitlab.com"
        audiences      = ["aws-oidc-warden"]
        provider       = "generic"
        claim_mappings = { subject = "project_path" }
        session_tags   = { project = "project_path" }
      }
    }
    role_mappings = [
      {
        subject = "my-org/my-repo"
        roles   = ["arn:aws:iam::111122223333:role/deploy"]
      },
    ]
  }

  expect_failures = [aws_s3_object.config]
}

# (p) The same multi-issuer + role_mappings combination boots once each
# mapping either carries its own issuer or default_issuer is set — the
# combination CRITICAL #1 found broken (clean plan, dead cold start).
run "multi_issuer_role_mapping_boots_with_issuer" {
  command = plan

  variables {
    issuers = {
      github = {
        issuer       = "https://token.actions.githubusercontent.com"
        audiences    = ["sts.amazonaws.com"]
        provider     = "github"
        session_tags = { repo = "repository" }
      }
      gitlab = {
        issuer         = "https://gitlab.com"
        audiences      = ["aws-oidc-warden"]
        provider       = "generic"
        claim_mappings = { subject = "project_path" }
        session_tags   = { project = "project_path" }
      }
    }
    role_mappings = [
      {
        subject = "my-org/my-repo"
        issuer  = "https://token.actions.githubusercontent.com"
        roles   = ["arn:aws:iam::111122223333:role/deploy"]
      },
    ]
  }

  assert {
    condition     = yamldecode(aws_s3_object.config.content).role_mappings[0].issuer == "https://token.actions.githubusercontent.com"
    error_message = "The rendered role_mappings entry must carry its issuer."
  }
}

# (q) Same combination, satisfied via default_issuer instead of a per-mapping
# issuer — the precondition must accept either.
run "multi_issuer_role_mapping_boots_with_default_issuer" {
  command = plan

  variables {
    default_issuer = "https://gitlab.com"
    issuers = {
      github = {
        issuer       = "https://token.actions.githubusercontent.com"
        audiences    = ["sts.amazonaws.com"]
        provider     = "github"
        session_tags = { repo = "repository" }
      }
      gitlab = {
        issuer         = "https://gitlab.com"
        audiences      = ["aws-oidc-warden"]
        provider       = "generic"
        claim_mappings = { subject = "project_path" }
        session_tags   = { project = "project_path" }
      }
    }
    role_mappings = [
      {
        subject = "my-org/my-repo"
        roles   = ["arn:aws:iam::111122223333:role/deploy"]
      },
    ]
  }

  assert {
    condition     = yamldecode(aws_s3_object.config.content).default_issuer == "https://gitlab.com"
    error_message = "The rendered config must carry default_issuer."
  }
}

# (r) A subject with an escaped dot — ordinary regex authoring, e.g. matching a
# literal ".git" suffix — must not fail the plan. Before the fix, the
# unescaped "\." interpolated into a double-quoted YAML scalar broke
# yamldecode() in the drift precondition with "unknown escape character".
run "regex_backslash_dot_plans" {
  command = plan

  variables {
    role_mappings = [
      {
        subject = "myorg/myrepo\\.git"
        roles   = ["arn:aws:iam::111122223333:role/deploy"]
      },
    ]
  }

  assert {
    condition     = yamldecode(aws_s3_object.config.content).role_mappings[0].subject == "myorg/myrepo\\.git"
    error_message = "A subject containing an escaped dot must round-trip through config.yaml unchanged."
  }
}

# (s) A subject with "\b" (regex word boundary) must plan clean, and the
# subject must survive byte-exact. Before the fix, unescaped "\b" decodes as
# YAML's own backspace escape, so the drift precondition's yamldecode()
# mismatches the rendered value against the config object and fails the
# plan — same failure shape as (r), not a silent corruption.
run "regex_word_boundary_survives_roundtrip" {
  command = plan

  variables {
    role_mappings = [
      {
        subject = "^myorg/repo\\b.*x$"
        roles   = ["arn:aws:iam::111122223333:role/deploy"]
      },
    ]
  }

  assert {
    condition     = yamldecode(aws_s3_object.config.content).role_mappings[0].subject == "^myorg/repo\\b.*x$"
    error_message = "A subject containing \\b must round-trip as the literal backslash+b, not a YAML backspace control byte."
  }
}

# (t) A jwt_authorizer_issuer diverging from the app config's issuer must be
# rejected at plan time — apigw mode requires the authorizer's verified iss
# to exist in issuers[] (resolveIssuerSpec), so a divergent value would make
# every request fail at runtime with ErrUnknownIssuer.
run "jwt_authorizer_issuer_divergence_rejected" {
  command = plan

  variables {
    jwt_validation_mode   = "apigw"
    issuer                = "https://token.actions.githubusercontent.com"
    audiences             = ["sts.amazonaws.com"]
    jwt_authorizer_issuer = "https://example.com"
  }

  expect_failures = [aws_s3_object.config]
}

# (u) jwt_authorizer_audiences MAY diverge from the app config's audiences —
# only in the safe direction (narrower authorizer acceptance), so this must
# plan clean, unlike a diverging jwt_authorizer_issuer.
run "jwt_authorizer_audiences_divergence_allowed" {
  command = plan

  variables {
    jwt_validation_mode      = "apigw"
    issuer                   = "https://token.actions.githubusercontent.com"
    audiences                = ["sts.amazonaws.com", "extra-audience"]
    jwt_authorizer_audiences = ["sts.amazonaws.com"]
  }

  assert {
    condition     = length(module.apigateway[0].jwt_authorizer_ids) == 1
    error_message = "A narrower jwt_authorizer_audiences must still provision the authorizer."
  }
}

# (v) An empty roles list plans clean but the service refuses to boot
# (internal/config/config.go) — reject it at plan time via var.role_mappings'
# own validation instead.
run "role_mapping_requires_non_empty_roles" {
  command = plan

  variables {
    role_mappings = [{ subject = "myorg/myrepo", roles = [] }]
  }

  expect_failures = [var.role_mappings]
}

# (w) roles = null (as opposed to []) must hit the same validation message,
# not crash length() with an opaque "argument must not be null" before the
# message above is ever shown.
run "role_mapping_rejects_null_roles" {
  command = plan

  variables {
    role_mappings = [{ subject = "myorg/myrepo", roles = null }]
  }

  expect_failures = [var.role_mappings]
}

# (x) The same null-crash shape existed on var.issuers' audiences validation
# — fix it the same way.
run "issuer_rejects_null_audiences" {
  command = plan

  variables {
    issuers = {
      github = {
        issuer       = "https://token.actions.githubusercontent.com"
        audiences    = null
        provider     = "github"
        session_tags = { repo = "repository" }
      }
    }
  }

  expect_failures = [var.issuers]
}
