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
