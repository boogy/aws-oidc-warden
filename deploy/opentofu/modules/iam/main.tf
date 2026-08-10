data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  name               = "${var.name_prefix}-exec"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "basic" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "perms" {
  dynamic "statement" {
    for_each = length(var.assumable_role_arns) > 0 ? [1] : []
    content {
      sid       = "AssumeTargetRoles"
      actions   = ["sts:AssumeRole", "sts:TagSession"]
      resources = var.assumable_role_arns
    }
  }

  dynamic "statement" {
    for_each = var.enable_iam_getrole ? [1] : []
    content {
      sid       = "ReadRoleTags"
      actions   = ["iam:GetRole", "iam:ListRoleTags"]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = var.cache_dynamodb_table_arn != null ? [1] : []
    content {
      sid       = "CacheDynamoDB"
      actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
      resources = [var.cache_dynamodb_table_arn]
    }
  }

  dynamic "statement" {
    for_each = var.cache_s3_bucket_arn != null ? [1] : []
    content {
      sid       = "CacheS3"
      actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
      resources = [var.cache_s3_bucket_arn, "${var.cache_s3_bucket_arn}/*"]
    }
  }

  dynamic "statement" {
    for_each = var.config_bucket_arn != null ? [1] : []
    content {
      sid       = "ReadConfig"
      actions   = ["s3:GetObject"]
      resources = ["${var.config_bucket_arn}/*"]
    }
  }

  dynamic "statement" {
    for_each = var.session_policy_bucket_arn != null ? [1] : []
    content {
      sid       = "ReadSessionPolicies"
      actions   = ["s3:GetObject"]
      resources = ["${var.session_policy_bucket_arn}/*"]
    }
  }

  dynamic "statement" {
    for_each = var.log_bucket_arn != null ? [1] : []
    content {
      sid       = "WriteAuditLogs"
      actions   = ["s3:PutObject"]
      resources = ["${var.log_bucket_arn}/*"]
    }
  }
}

locals {
  # Mirrors the statement conditions above. Derived from the variables rather
  # than from the document itself: the data source read is deferred to apply
  # whenever a bucket ARN comes from a resource created in the same run, which
  # makes every one of its attributes (including `statement`) unknown at plan.
  has_perms = (
    length(var.assumable_role_arns) > 0 ||
    var.enable_iam_getrole ||
    var.cache_dynamodb_table_arn != null ||
    var.cache_s3_bucket_arn != null ||
    var.config_bucket_arn != null ||
    var.session_policy_bucket_arn != null ||
    var.log_bucket_arn != null
  )
}

resource "aws_iam_role_policy" "this" {
  # Only attach when at least one statement exists.
  count  = local.has_perms ? 1 : 0
  name   = "${var.name_prefix}-perms"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.perms.json
}
