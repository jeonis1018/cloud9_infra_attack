output "runtime_outputs" {
  description = "Verification input; run terraform output -json runtime_outputs to save a plain JSON object."
  value = {
    StateMachineArn      = aws_sfn_state_machine.response.arn
    StateTableName       = aws_dynamodb_table.response.name
    InputBucket          = local.bucket
    InputPrefix          = local.input_prefix
    AgentInputPrefix     = "${local.agent_prefix}/"
    EvidencePrefix       = local.evidence_prefix
    BlockSeconds         = tostring(var.block_seconds)
    AllowlistCidrs       = join(",", local.allowlist)
    RuleName             = local.block_rule
    IPv4SetId            = aws_wafv2_ip_set.block["ipv4"].id
    IPv4SetName          = aws_wafv2_ip_set.block["ipv4"].name
    IPv4SetArn           = aws_wafv2_ip_set.block["ipv4"].arn
    IPv6SetId            = aws_wafv2_ip_set.block["ipv6"].id
    IPv6SetName          = aws_wafv2_ip_set.block["ipv6"].name
    IPv6SetArn           = aws_wafv2_ip_set.block["ipv6"].arn
    NormalizerArn        = aws_lambda_function.runtime["normalizer"].arn
    AgentNormalizerArn   = aws_lambda_function.runtime["normalizer"].arn
    DetectorArn          = aws_lambda_function.runtime["detector"].arn
    ResponderArn         = aws_lambda_function.runtime["responder"].arn
    AgentLogGroup        = local.agent_log_group
    WAFLogGroup          = local.waf_log_group
    DetectionQueueArn    = aws_sqs_queue.detection.arn
    DetectionQueueUrl    = aws_sqs_queue.detection.url
    DetectionDLQArn      = aws_sqs_queue.detection_dlq.arn
    DetectionDLQUrl      = aws_sqs_queue.detection_dlq.url
    AsyncFailureQueueArn = aws_sqs_queue.async_failures.arn
    AsyncFailureQueueUrl = aws_sqs_queue.async_failures.url
    RuntimeCodeSha256    = data.archive_file.runtime.output_base64sha256
  }
  depends_on = [aws_cloudwatch_log_subscription_filter.agent, aws_cloudwatch_log_subscription_filter.waf]
}


output "response_ip_sets" {
  description = "Pass into alb-waf.cloudwatch_agent_response_ip_sets. Only the owning alb-waf module writes the Web ACL rule."
  value = {
    ipv4_arn = aws_wafv2_ip_set.block["ipv4"].arn
    ipv6_arn = aws_wafv2_ip_set.block["ipv6"].arn
  }
}

output "lambda_function_names" {
  value = { for key, fn in aws_lambda_function.runtime : key => fn.function_name }
}

output "lambda_log_group_names" {
  value = { for key, group in aws_cloudwatch_log_group.runtime : key => group.name }
}
