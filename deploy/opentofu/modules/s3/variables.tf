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

variable "tags" {
  description = "Tags applied to the bucket."
  type        = map(string)
  default     = {}
}
