variable "s3_bucket_arn" {
  description = "ARN of the project test S3 bucket that the EC2 role may access."
  type        = string

  validation {
    condition     = can(regex("^arn:(aws|aws-us-gov|aws-cn):s3:::[^/]+$", var.s3_bucket_arn))
    error_message = "s3_bucket_arn must be an S3 bucket ARN without an object suffix."
  }
}

variable "profile_bucket_arn" {
  description = "ARN of the profile-image S3 bucket the EC2 role may read/write. Null skips granting access."
  type        = string
  default     = null

  validation {
    condition     = var.profile_bucket_arn == null || can(regex("^arn:(aws|aws-us-gov|aws-cn):s3:::[^/]+$", var.profile_bucket_arn))
    error_message = "profile_bucket_arn must be null or an S3 bucket ARN without an object suffix."
  }
}

variable "enable_least_privilege" {
  description = "Use the reduced S3 read policy when true; use the intentionally broad, bucket-scoped lab policy when false."
  type        = bool
}

variable "name_prefix" {
  description = "Prefix used for IAM resource names."
  type        = string
  default     = "cloud9-infra-attack"

  validation {
    condition     = length(trimspace(var.name_prefix)) > 0
    error_message = "name_prefix must not be empty."
  }
}

variable "tags" {
  description = "Tags to apply to taggable IAM resources."
  type        = map(string)
  default     = {}
}
