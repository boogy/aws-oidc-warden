locals {
  # build.sh writes the variant it packaged next to the zip (see its
  # comment). A missing marker means the zip predates this check — that
  # must not break an existing working deploy, so a missing marker is
  # treated as "unknown, assume compatible" rather than a mismatch.
  variant_marker_path = "${dirname(var.zip_path)}/variant"
  actual_variant      = fileexists(local.variant_marker_path) ? trimspace(file(local.variant_marker_path)) : null
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_lambda_function" "this" {
  function_name = var.function_name
  role          = var.role_arn
  runtime       = "provided.al2023"
  handler       = "bootstrap"
  architectures = [var.architecture]
  memory_size   = var.memory_size
  timeout       = var.timeout

  filename         = var.zip_path
  source_code_hash = fileexists(var.zip_path) ? filebase64sha256(var.zip_path) : null

  lifecycle {
    precondition {
      condition     = fileexists(var.zip_path)
      error_message = "Deployment zip not found (modules/lambda var.zip_path). Run deploy/opentofu/build.sh first — 'build.sh' for self mode, 'build.sh apigatewayv2' for apigw mode."
    }
    precondition {
      # var.check_variant defaults to true for every real deployment.
      # hardening.tftest.hcl sets the root var.check_lambda_variant (and so
      # this) to false: that suite plans multiple jwt_validation_mode values
      # against one build/marker, so a single expected_variant can never
      # match every run — the guard is structurally untestable there, not
      # weakened for a real deploy. (Manually verified instead: write
      # dist/variant with the wrong variant, plan in the mismatched mode,
      # observe this precondition's error.)
      condition     = !var.check_variant || local.actual_variant == null || local.actual_variant == var.expected_variant
      error_message = "Packaged Lambda binary variant (${coalesce(local.actual_variant, "unknown")}) does not match the variant jwt_validation_mode requires (${var.expected_variant}). Rebuild with 'deploy/opentofu/build.sh ${var.expected_variant}'."
    }
  }

  reserved_concurrent_executions = var.reserved_concurrency

  dynamic "environment" {
    for_each = length(var.environment_variables) > 0 ? [1] : []
    content {
      variables = var.environment_variables
    }
  }

  depends_on = [aws_cloudwatch_log_group.this]
  tags       = var.tags
}
