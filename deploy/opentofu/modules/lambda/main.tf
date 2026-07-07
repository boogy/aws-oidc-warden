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
