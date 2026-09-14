variable "aws_profile" {
  description = "AWS CLI profile for the security account (896986966760)."
  type        = string
}

variable "attack_environment" {
  description = "Attack stack whose Terraform state provides the protected S3 bucket."
  type        = string
  default     = "before"
  validation {
    condition     = contains(["before", "after"], var.attack_environment)
    error_message = "attack_environment must be before or after."
  }
}

variable "team_cidrs" {
  description = "Trusted source CIDRs for S3 read/list review rules and CloudTrail context."
  type        = list(string)
  default = [
    "162.120.184.59/32",
    "10.27.234.34/32",
    "119.204.55.139/32",
    "112.72.191.76/32",
    "172.30.1.59/32",
    "210.119.16.15/32",
    "211.177.210.10/32",
    "172.20.10.4/32",
    "210.119.237.103/32",
    "192.168.219.104/32",
    "121.156.245.211/32",
  ]
}

variable "permissions_boundary_arn" {
  description = "Optional permissions boundary required by the security account for new IAM roles."
  type        = string
  default     = null
}

