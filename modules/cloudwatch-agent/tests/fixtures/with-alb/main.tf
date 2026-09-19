# Plan-only fixture for the same sibling-module wiring used by envs/after.
terraform {
  required_version = ">= 1.10, < 2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.60.0, < 7.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
  }
}

variable "enabled" {
  type    = bool
  default = false
}

module "cloudwatch_agent" {
  count  = var.enabled ? 1 : 0
  source = "../../.."

  enable_ingestion = true
}

module "alb_waf" {
  source = "../../../../alb-waf"

  vpc_id                            = "vpc-0123456789abcdef0"
  vpc_name                          = "WHS_VPC"
  public_subnet_ids                 = ["subnet-0123456789abcdef0", "subnet-0123456789abcdef1"]
  certificate_arn                   = "arn:aws:acm:ap-northeast-2:896986966760:certificate/e022050c-8d53-4fa5-b642-8698aef04f3f"
  cloudwatch_agent_response_ip_sets = var.enabled ? module.cloudwatch_agent[0].response_ip_sets : null
}

output "response_function_names" {
  value = var.enabled ? module.cloudwatch_agent[0].lambda_function_names : {}
}

output "response_ip_sets" {
  value = var.enabled ? module.cloudwatch_agent[0].response_ip_sets : null
}

output "alb_arn" {
  value = module.alb_waf.alb_arn
}
