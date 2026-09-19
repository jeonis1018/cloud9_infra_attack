# New response resources are opt-in; existing before/after lab behavior is unchanged by default.
variable "enable_cloudwatch_agent_response" {
  description = "Deploy the cloudwatch-agent normalization, detection and response resources in this state only."
  type        = bool
  default     = false
}

variable "cloudwatch_agent_enable_ingestion" {
  description = "Start log/S3 delivery only after reviewing the created response resources and WAF rule."
  type        = bool
  default     = false
}

variable "cloudwatch_agent_allowlist_cidrs" {
  type    = list(string)
  default = []
}

variable "cloudwatch_agent_block_seconds" {
  type    = number
  default = 600
}

variable "cloudwatch_agent_permissions_boundary_arn" {
  type    = string
  default = null
}

module "cloudwatch_agent" {
  count  = var.enable_cloudwatch_agent_response ? 1 : 0
  source = "../../modules/cloudwatch-agent"

  enable_ingestion         = var.cloudwatch_agent_enable_ingestion
  allowlist_cidrs          = var.cloudwatch_agent_allowlist_cidrs
  block_seconds            = var.cloudwatch_agent_block_seconds
  permissions_boundary_arn = var.cloudwatch_agent_permissions_boundary_arn
  aws_cli_profile          = var.aws_profile

  tags = { Project = "cloudwatch-agent-response" }
}

output "cloudwatch_agent_response" {
  value = var.enable_cloudwatch_agent_response ? module.cloudwatch_agent[0].runtime_outputs : null
}
