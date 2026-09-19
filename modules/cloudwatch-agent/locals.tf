locals {
  tags = merge(var.tags, {
    ManagedBy = "terraform"
    Project   = "cloudwatch-agent-response"
  })
  bucket          = "cloud9-security-normalized-logs-896986966760-ap-northeast-2-an"
  input_prefix    = "waf/response/v1/"
  agent_prefix    = "cloudwatch-agent/v1"
  evidence_prefix = "evidence/cloudwatch-agent-response/v1/"
  waf_log_group   = "aws-waf-logs-cloud9-security"
  agent_log_group = "/aws/events/cloud9-security/cloudwatch-agent"
  agent_streams   = ["i-0b2b058d0c7e585ed/vuln-webapp", "i-07620a9c348f2071e/vuln-webapp"]
  web_acl_arn     = "arn:aws:wafv2:ap-northeast-2:896986966760:regional/webacl/WHS_VPC-WAF/0d04b6a4-be8a-4de8-b094-9c914efceb72"
  alb_arn         = "arn:aws:elasticloadbalancing:ap-northeast-2:896986966760:loadbalancer/app/WHS-ALB/d0ff76940805c393"
  state_machine   = "respond-cloudwatch-agent-logs"
  state_table     = "respond-cloudwatch-agent-logs-state"
  state_arn       = "arn:aws:states:${var.region}:${var.account_id}:stateMachine:${local.state_machine}"
  execution_arn   = "arn:aws:states:${var.region}:${var.account_id}:execution:${local.state_machine}:*"
  schedule        = "respond-cloudwatch-agent-logs-reconcile"
  schedule_arn    = "arn:aws:events:${var.region}:${var.account_id}:rule/${local.schedule}"
  block_rule      = "respond-cloudwatch-agent-logs-block"
  allowlist       = sort(distinct(concat(var.allowlist_cidrs, tolist(data.aws_wafv2_ip_set.manual_v4.addresses), tolist(data.aws_wafv2_ip_set.manual_v6.addresses))))

  functions = {
    normalizer = { name = "normalize-cloudwatch-agent-logs", handler = "normalizer.handler", timeout = 30 }
    detector   = { name = "detect-cloudwatch-agent-logs", handler = "pipeline.detect_handler", timeout = 30 }
    responder  = { name = "respond-cloudwatch-agent-logs", handler = "responder.handler", timeout = 60 }
  }
  common_environment = {
    EXPECTED_ACCOUNT  = var.account_id
    NORMALIZED_BUCKET = local.bucket
    NORMALIZED_PREFIX = local.input_prefix
    EVIDENCE_PREFIX   = local.evidence_prefix
    WAF_LOG_GROUP     = local.waf_log_group
    WEB_ACL_ARN       = local.web_acl_arn
    ALB_ARN           = local.alb_arn
    BLOCK_SECONDS     = tostring(var.block_seconds)
    ALLOWLIST_CIDRS   = join(",", local.allowlist)
    STATE_MACHINE_ARN = local.state_arn
  }
  function_environment = {
    normalizer = merge(local.common_environment, {
      AGENT_NORMALIZED_PREFIX = local.agent_prefix
      LOG_GROUP               = local.agent_log_group
      ALLOWED_LOG_STREAMS     = join(",", local.agent_streams)
    })
    detector = merge(local.common_environment, {
      DETECTION_QUEUE_ARN = aws_sqs_queue.detection.arn
    })
    responder = merge(local.common_environment, {
      STATE_TABLE   = aws_dynamodb_table.response.name
      IPV4_SET_ID   = aws_wafv2_ip_set.block["ipv4"].id
      IPV4_SET_NAME = aws_wafv2_ip_set.block["ipv4"].name
      IPV6_SET_ID   = aws_wafv2_ip_set.block["ipv6"].id
      IPV6_SET_NAME = aws_wafv2_ip_set.block["ipv6"].name
    })
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# IP sets must not depend on the Web ACL: alb-waf references these IP sets.
resource "terraform_data" "account_guard" {
  input = { account_id = var.account_id, region = var.region }
  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.current.account_id == var.account_id && data.aws_region.current.region == var.region
      error_message = "The inherited AWS provider must target the approved team account and region."
    }
  }
}

data "aws_s3_bucket" "existing" {
  bucket = local.bucket
}

data "aws_wafv2_web_acl" "existing" {
  resource_arn = local.alb_arn
  scope        = "REGIONAL"
}

data "aws_wafv2_ip_set" "manual_v4" {
  name  = "WHS-WAF-RuleSet_IPV4_Allow"
  scope = "REGIONAL"
}

data "aws_wafv2_ip_set" "manual_v6" {
  name  = "WHS-WAF-RuleSet_IPV6_Allow"
  scope = "REGIONAL"
}

resource "terraform_data" "identity_guard" {
  depends_on = [terraform_data.account_guard]
  input      = { account_id = var.account_id, region = var.region }
  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.current.account_id == var.account_id && data.aws_s3_bucket.existing.region == var.region
      error_message = "The account or existing bucket region differs from the approved team resources."
    }
    precondition {
      condition     = data.aws_wafv2_web_acl.existing.arn == local.web_acl_arn
      error_message = "The approved ALB is no longer attached to the expected existing Web ACL."
    }
    precondition {
      condition     = data.aws_wafv2_ip_set.manual_v4.id == "864beb1b-e691-4600-86d0-c33bc201a5f3" && data.aws_wafv2_ip_set.manual_v6.id == "b2125780-9c82-481c-8313-46fd987132d3"
      error_message = "An existing manual allowlist IP set changed identity."
    }
    precondition {
      condition     = length(local.allowlist) <= 256 && length(join(",", local.allowlist)) <= 2200
      error_message = "The combined allowlist exceeds the supported Lambda environment size."
    }
  }
}
