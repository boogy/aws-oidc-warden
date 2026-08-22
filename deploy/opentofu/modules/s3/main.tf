resource "aws_s3_bucket" "this" {
  bucket        = var.bucket_name
  force_destroy = var.force_destroy
  tags          = var.tags

  # Object Lock can only be turned on at creation time; enabling it later
  # requires an AWS Support request. Flipping this on an existing bucket
  # therefore forces a replacement rather than an in-place update.
  object_lock_enabled = var.object_lock_mode != null

  lifecycle {
    precondition {
      condition     = var.object_lock_mode == null || var.versioning_enabled
      error_message = "object_lock_mode requires versioning_enabled = true: S3 Object Lock retains object VERSIONS, and a suspended-versioning bucket has none to retain."
    }
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id

  versioning_configuration {
    status = var.versioning_enabled ? "Enabled" : "Suspended"
  }
}

# Retention lock for the audit trail. GOVERNANCE can be overridden by a
# principal holding s3:BypassGovernanceRetention (use it while tuning the
# retention window); COMPLIANCE cannot be overridden by anyone, including the
# root account, for the full retention period.
resource "aws_s3_bucket_object_lock_configuration" "this" {
  count  = var.object_lock_mode != null ? 1 : 0
  bucket = aws_s3_bucket.this.id

  rule {
    default_retention {
      mode = var.object_lock_mode
      days = var.object_lock_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  count  = var.lifecycle_expiration_days > 0 ? 1 : 0
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "expire-objects"
    status = "Enabled"

    filter {}

    expiration {
      days = var.lifecycle_expiration_days
    }

    # With versioning on, an expired object becomes a noncurrent version that
    # is otherwise kept (and billed) forever. Object Lock still governs how
    # long a version actually survives: a locked version is not deleted before
    # its retention expires, whatever this rule says.
    dynamic "noncurrent_version_expiration" {
      for_each = var.versioning_enabled ? [1] : []
      content {
        noncurrent_days = var.lifecycle_expiration_days
      }
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}
