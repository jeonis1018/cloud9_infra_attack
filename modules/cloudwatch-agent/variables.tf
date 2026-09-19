variable "account_id" {
  type    = string
  default = "896986966760"
  validation {
    condition     = var.account_id == "896986966760"
    error_message = "This configuration is restricted to the approved team AWS account."
  }
}

variable "region" {
  type    = string
  default = "ap-northeast-2"
  validation {
    condition     = var.region == "ap-northeast-2"
    error_message = "This configuration is restricted to ap-northeast-2."
  }
}

variable "block_seconds" {
  type    = number
  default = 600
  validation {
    condition     = var.block_seconds == floor(var.block_seconds) && var.block_seconds >= 180 && var.block_seconds <= 3600
    error_message = "block_seconds must be an integer between 180 and 3600."
  }
}

variable "allowlist_cidrs" {
  description = "Additional protected canonical CIDRs; the existing manual WAF allow sets are also read on every plan."
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([for cidr in var.allowlist_cidrs : try(
      "${cidrhost(cidr, 0)}/${split("/", cidr)[1]}" == lower(cidr), false
    )])
    error_message = "Use canonical CIDRs with no host bits set, for example 203.0.113.1/32."
  }
}


variable "enable_ingestion" {
  description = "Enable Agent/WAF subscriptions, the owned S3 notification and the detection event source after reviewing the deployment."
  type        = bool
  default     = false
}

variable "log_retention_days" {
  description = "Retention for the three new Lambda log groups only."
  type        = number
  default     = 14
  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365], var.log_retention_days)
    error_message = "Choose a supported CloudWatch Logs retention period."
  }
}

variable "permissions_boundary_arn" {
  description = "Optional IAM permissions boundary for the four new execution roles."
  type        = string
  default     = null
}

variable "iam_role_path" {
  type    = string
  default = "/"
}

variable "aws_cli_profile" {
  description = "AWS CLI profile matching the root AWS provider; null uses the shell credential chain. Used only for preserving shared S3 notifications."
  type        = string
  default     = null
  validation {
    condition     = var.aws_cli_profile == null ? true : length(trimspace(var.aws_cli_profile)) > 0
    error_message = "Use null for shell credentials, or a nonempty AWS CLI profile."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
