variable "vpc_id" {
  description = "ID of the VPC in which to create the EC2 security group."
  type        = string

  validation {
    condition     = length(trimspace(var.vpc_id)) > 0
    error_message = "vpc_id must not be empty."
  }
}

variable "private_subnet_ids" {
  description = "Private subnet IDs across which EC2 instances are distributed."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) > 0 && alltrue([for id in var.private_subnet_ids : length(trimspace(id)) > 0])
    error_message = "private_subnet_ids must contain at least one non-empty subnet ID."
  }
}

variable "instance_profile_name" {
  description = "Name of the IAM instance profile to attach to each EC2 instance."
  type        = string

  validation {
    condition     = length(trimspace(var.instance_profile_name)) > 0
    error_message = "instance_profile_name must not be empty."
  }
}

variable "enable_imdsv2" {
  description = "Require IMDSv2 tokens when true; permit IMDSv1 in the isolated before environment when false."
  type        = bool
}

variable "instance_type" {
  description = "EC2 instance type selected by the environment owner."
  type        = string

  validation {
    condition     = length(trimspace(var.instance_type)) > 0
    error_message = "instance_type must not be empty."
  }
}

variable "alb_security_group_id" {
  description = "Security group ID of the internet-facing ALB allowed to reach the application port."
  type        = string

  validation {
    condition     = length(trimspace(var.alb_security_group_id)) > 0
    error_message = "alb_security_group_id must not be empty."
  }
}

variable "app_port" {
  description = "TCP port exposed by the vulnerable web application."
  type        = number

  validation {
    condition     = var.app_port >= 1 && var.app_port <= 65535 && floor(var.app_port) == var.app_port
    error_message = "app_port must be an integer from 1 through 65535."
  }
}

variable "instance_count" {
  description = "Number of EC2 instances to create; instances are distributed across private_subnet_ids in order."
  type        = number

  validation {
    condition     = var.instance_count >= 1 && floor(var.instance_count) == var.instance_count
    error_message = "instance_count must be a positive integer."
  }
}

variable "ami_id" {
  description = "Optional AMI ID. When null, the latest official Amazon Linux 2023 x86_64 AMI is selected."
  type        = string
  default     = null

  validation {
    condition     = var.ami_id == null || can(regex("^ami-[0-9a-fA-F]+$", var.ami_id))
    error_message = "ami_id must be null or a valid AMI ID beginning with ami-."
  }
}

variable "user_data" {
  description = "Optional environment-provided bootstrap script for the web application."
  type        = string
  default     = null
  sensitive   = true
}

variable "name_prefix" {
  description = "Prefix used for EC2 resource names."
  type        = string
  default     = "cloud9-infra-attack"

  validation {
    condition     = length(trimspace(var.name_prefix)) > 0
    error_message = "name_prefix must not be empty."
  }
}

variable "tags" {
  description = "Tags to apply to EC2 resources."
  type        = map(string)
  default     = {}
}
