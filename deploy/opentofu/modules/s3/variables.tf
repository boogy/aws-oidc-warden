variable "bucket_name" {
  description = "Globally-unique S3 bucket name."
  type        = string
}

variable "force_destroy" {
  description = "Allow deletion of a non-empty bucket."
  type        = bool
  default     = false
}

variable "versioning_enabled" {
  description = "Enable object versioning."
  type        = bool
  default     = false
}

variable "lifecycle_expiration_days" {
  description = "Expire objects after N days. 0 disables the rule."
  type        = number
  default     = 0
}

variable "object_lock_mode" {
  description = "S3 Object Lock default retention mode for new objects: \"GOVERNANCE\", \"COMPLIANCE\", or null to disable. Requires versioning_enabled, and can only be set when the bucket is created."
  type        = string
  default     = null

  validation {
    condition     = var.object_lock_mode == null || contains(["GOVERNANCE", "COMPLIANCE"], coalesce(var.object_lock_mode, "GOVERNANCE"))
    error_message = "object_lock_mode must be \"GOVERNANCE\", \"COMPLIANCE\", or null."
  }
}

variable "object_lock_retention_days" {
  description = "Days each new object version is retained under object_lock_mode. Ignored when object_lock_mode is null."
  type        = number
  default     = 365

  validation {
    condition     = var.object_lock_retention_days > 0
    error_message = "object_lock_retention_days must be greater than 0."
  }
}

variable "tags" {
  description = "Tags applied to the bucket."
  type        = map(string)
  default     = {}
}
