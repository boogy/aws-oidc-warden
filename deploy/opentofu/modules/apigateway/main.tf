resource "aws_apigatewayv2_api" "this" {
  name          = var.name
  protocol_type = "HTTP"
  tags          = var.tags
}

resource "aws_apigatewayv2_integration" "this" {
  api_id                 = aws_apigatewayv2_api.this.id
  integration_type       = "AWS_PROXY"
  integration_uri        = var.lambda_invoke_arn
  integration_method     = "POST"
  payload_format_version = var.payload_format_version
}

# JWT Authorizers: one per configured issuer, provisioned only in apigw mode.
# API Gateway validates the JWT against the issuer's JWKS before invoking
# Lambda; claims arrive in event.requestContext.authorizer.jwt.claims (format
# 2.0). AWS allows at most 10 authorizers per HTTP API — the root module
# enforces that as a precondition.
resource "aws_apigatewayv2_authorizer" "jwt" {
  for_each = var.jwt_authorizers

  api_id           = aws_apigatewayv2_api.this.id
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  name             = "${var.name}-${each.key}"

  jwt_configuration {
    audience = each.value.audiences
    issuer   = each.value.issuer
  }
}

# apigw mode: one route per issuer, each pinned to that issuer's authorizer.
# A token presented to another issuer's route is rejected by API Gateway
# before the Lambda is invoked.
resource "aws_apigatewayv2_route" "jwt" {
  for_each = var.jwt_authorizers

  api_id    = aws_apigatewayv2_api.this.id
  route_key = each.value.route_key
  target    = "integrations/${aws_apigatewayv2_integration.this.id}"

  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.jwt[each.key].id
}

# self mode: a single open route — the Lambda validates signatures itself and
# is multi-issuer aware, so no per-issuer split is needed.
resource "aws_apigatewayv2_route" "open" {
  count = length(var.jwt_authorizers) == 0 ? 1 : 0

  api_id    = aws_apigatewayv2_api.this.id
  route_key = var.route_key
  target    = "integrations/${aws_apigatewayv2_integration.this.id}"

  authorization_type = "NONE"
}

# Existing self-mode deployments carry this route at the old address. apigw
# deployments need `tofu state mv` instead (see deploy/opentofu/README.md) —
# a moved block is static and cannot cover both target addresses.
moved {
  from = aws_apigatewayv2_route.this
  to   = aws_apigatewayv2_route.open[0]
}

resource "aws_apigatewayv2_stage" "this" {
  api_id      = aws_apigatewayv2_api.this.id
  name        = var.stage_name
  auto_deploy = true

  default_route_settings {
    throttling_burst_limit = var.throttling_burst_limit
    throttling_rate_limit  = var.throttling_rate_limit
  }

  tags = var.tags
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.this.execution_arn}/*/*"
}
