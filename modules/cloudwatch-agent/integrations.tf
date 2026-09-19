locals {
  integrations_script = abspath("${path.module}/scripts/integrations.py")
  notification_config = jsonencode({
    account_id      = var.account_id
    region          = var.region
    bucket          = local.bucket
    queue_arn       = aws_sqs_queue.detection.arn
    notification_id = "detect-cloudwatch-agent-logs"
    input_prefix    = local.input_prefix
    suffix          = ".jsonl"
  })
}

# The S3 bucket is shared. Change only our own notification entry, preserving
# existing queue/topic/Lambda/EventBridge entries. No Web ACL helper is invoked:
# the existing alb-waf module owns the inline response rule.
resource "terraform_data" "notification" {
  count = var.enable_ingestion ? 1 : 0
  input = {
    config_json = local.notification_config
    script_path = local.integrations_script
    profile     = var.aws_cli_profile
  }
  triggers_replace = [local.notification_config, var.aws_cli_profile, filesha256(local.integrations_script), filesha256("${path.module}/scripts/aws_cli.py")]

  provisioner "local-exec" {
    command = "python3 \"${self.input.script_path}\" attach-notification"
    environment = merge(
      { INTEGRATION_CONFIG = self.input.config_json },
      self.input.profile == null ? {} : { AWS_PROFILE = self.input.profile }
    )
  }
  provisioner "local-exec" {
    when    = destroy
    command = "python3 \"${self.input.script_path}\" detach-notification"
    environment = merge(
      { INTEGRATION_CONFIG = self.input.config_json },
      self.input.profile == null ? {} : { AWS_PROFILE = self.input.profile }
    )
  }
  depends_on = [aws_sqs_queue_policy.s3_delivery, aws_lambda_event_source_mapping.detection, aws_lambda_function_event_invoke_config.failures]
}

resource "aws_cloudwatch_log_subscription_filter" "agent" {
  count           = var.enable_ingestion ? 1 : 0
  name            = "normalize-cloudwatch-agent-logs"
  log_group_name  = local.agent_log_group
  filter_pattern  = ""
  destination_arn = aws_lambda_function.runtime["normalizer"].arn
  distribution    = "ByLogStream"
  depends_on      = [aws_lambda_permission.agent_logs, terraform_data.notification, aws_sfn_state_machine.response]
}

resource "aws_cloudwatch_log_subscription_filter" "waf" {
  count           = var.enable_ingestion ? 1 : 0
  name            = "normalize-cloudwatch-agent-logs-waf"
  log_group_name  = local.waf_log_group
  filter_pattern  = ""
  destination_arn = aws_lambda_function.runtime["normalizer"].arn
  distribution    = "ByLogStream"
  depends_on      = [aws_lambda_permission.waf_logs, terraform_data.notification, aws_sfn_state_machine.response]
}
