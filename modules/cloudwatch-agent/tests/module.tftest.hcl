# Every run is plan-only and the AWS provider is mocked. No AWS API or
# local-exec integration helper runs during this suite.
mock_provider "aws" {
  override_during = plan

  mock_data "aws_caller_identity" {
    defaults = { account_id = "896986966760" }
  }
  mock_data "aws_region" {
    defaults = { region = "ap-northeast-2" }
  }
  mock_data "aws_s3_bucket" {
    defaults = { region = "ap-northeast-2", arn = "arn:aws:s3:::cloud9-security-normalized-logs-896986966760-ap-northeast-2-an" }
  }
  mock_data "aws_wafv2_web_acl" {
    defaults = { arn = "arn:aws:wafv2:ap-northeast-2:896986966760:regional/webacl/WHS_VPC-WAF/0d04b6a4-be8a-4de8-b094-9c914efceb72" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::896986966760:role/test-execution-role" }
  }
  mock_resource "aws_lambda_function" {
    defaults = { arn = "arn:aws:lambda:ap-northeast-2:896986966760:function:test-function" }
  }
  mock_resource "aws_sqs_queue" {
    defaults = { arn = "arn:aws:sqs:ap-northeast-2:896986966760:test-queue", url = "https://sqs.ap-northeast-2.amazonaws.com/896986966760/test-queue" }
  }
  mock_resource "aws_wafv2_ip_set" {
    defaults = { arn = "arn:aws:wafv2:ap-northeast-2:896986966760:regional/ipset/test-set/00000000-0000-0000-0000-000000000000" }
  }
  mock_resource "aws_dynamodb_table" {
    defaults = { arn = "arn:aws:dynamodb:ap-northeast-2:896986966760:table/respond-cloudwatch-agent-logs-state" }
  }
  mock_resource "aws_sfn_state_machine" {
    defaults = { arn = "arn:aws:states:ap-northeast-2:896986966760:stateMachine:respond-cloudwatch-agent-logs" }
  }
}

override_data {
  target = data.aws_wafv2_ip_set.manual_v4
  values = {
    id        = "864beb1b-e691-4600-86d0-c33bc201a5f3"
    addresses = ["203.0.113.4/32"]
  }
}

override_data {
  target = data.aws_wafv2_ip_set.manual_v6
  values = {
    id        = "b2125780-9c82-481c-8313-46fd987132d3"
    addresses = ["2001:db8::4/128"]
  }
}

run "default_deployment_has_no_intake" {
  command = plan

  assert {
    condition = (
      length(aws_lambda_function.runtime) == 3 &&
      length(aws_cloudwatch_log_group.runtime) == 3 &&
      aws_lambda_function.runtime["normalizer"].function_name == "normalize-cloudwatch-agent-logs" &&
      aws_lambda_function.runtime["detector"].function_name == "detect-cloudwatch-agent-logs" &&
      aws_lambda_function.runtime["responder"].function_name == "respond-cloudwatch-agent-logs" &&
      aws_lambda_function.runtime["responder"].reserved_concurrent_executions == 1 &&
      alltrue([for role, fn in aws_lambda_function.runtime :
        aws_cloudwatch_log_group.runtime[role].name == format("/aws/lambda/%s", fn.function_name) &&
        aws_cloudwatch_log_group.runtime[role].retention_in_days == 14 &&
        fn.source_code_hash == data.archive_file.runtime.output_base64sha256
      ])
    )
    error_message = "The default plan must deploy exactly three correctly packaged functions and their retained logs, with a serialized responder."
  }

  assert {
    condition = (
      aws_lambda_event_source_mapping.detection.enabled == false &&
      length(aws_cloudwatch_log_subscription_filter.agent) == 0 &&
      length(aws_cloudwatch_log_subscription_filter.waf) == 0 &&
      length(terraform_data.notification) == 0
    )
    error_message = "Initial deployment must not attach either source log group, modify bucket notifications or consume detection events."
  }
}

run "enabled_intake_runtime_and_permissions" {
  command = plan
  variables {
    enable_ingestion = true
    allowlist_cidrs  = ["203.0.113.4/32", "198.51.100.0/24"]
  }
  assert {
    condition = (
      length(aws_lambda_function.runtime) == 3 &&
      aws_lambda_function.runtime["responder"].reserved_concurrent_executions == 1 &&
      aws_lambda_function.runtime["normalizer"].reserved_concurrent_executions == -1 &&
      aws_lambda_function.runtime["detector"].reserved_concurrent_executions == -1
    )
    error_message = "The response IP sets must retain one serialized writer, with three total Lambda functions."
  }
  assert {
    condition = (
      aws_lambda_event_source_mapping.detection.enabled == true &&
      length(aws_cloudwatch_log_subscription_filter.agent) == 1 &&
      length(aws_cloudwatch_log_subscription_filter.waf) == 1 &&
      aws_lambda_function.runtime["normalizer"].handler == "normalizer.handler" &&
      aws_lambda_function.runtime["normalizer"].environment[0].variables.AGENT_NORMALIZED_PREFIX == "cloudwatch-agent/v1" &&
      aws_lambda_function.runtime["normalizer"].environment[0].variables.NORMALIZED_PREFIX == "waf/response/v1/" &&
      aws_cloudwatch_log_subscription_filter.agent[0].destination_arn == aws_cloudwatch_log_subscription_filter.waf[0].destination_arn &&
      aws_cloudwatch_log_subscription_filter.agent[0].log_group_name == "/aws/events/cloud9-security/cloudwatch-agent" &&
      aws_cloudwatch_log_subscription_filter.waf[0].log_group_name == "aws-waf-logs-cloud9-security"
    )
    error_message = "Both existing log groups must route to the shared normalizer with separate output prefixes."
  }
  assert {
    condition = (
      output.runtime_outputs.AllowlistCidrs == "198.51.100.0/24,2001:db8::4/128,203.0.113.4/32" &&
      output.runtime_outputs.BlockSeconds == "600" &&
      output.runtime_outputs.AgentNormalizerArn == output.runtime_outputs.NormalizerArn &&
      output.runtime_outputs.RuntimeCodeSha256 == data.archive_file.runtime.output_base64sha256
    )
    error_message = "The verifier must receive the exact code hash, block duration, and merged deduplicated protection snapshot."
  }
  assert {
    condition = alltrue([
      for role in ["normalizer", "detector"] : alltrue([
        for statement in jsondecode(aws_iam_role_policy.lambda[role].policy).Statement : alltrue([
          for action in statement.Action : !startswith(action, "wafv2:") && !startswith(action, "dynamodb:")
        ])
      ])
    ])
    error_message = "Normalization and detection must not be able to mutate response state or WAF."
  }
  assert {
    condition = (
      !strcontains(aws_iam_role_policy.lambda["responder"].policy, "wafv2:UpdateWebACL") &&
      contains(flatten([for statement in jsondecode(aws_iam_role_policy.lambda["responder"].policy).Statement : statement.Action]), "wafv2:UpdateIPSet") &&
      alltrue([for role in ["normalizer", "responder"] : contains(flatten([for statement in jsondecode(aws_iam_role_policy.lambda[role].policy).Statement : statement.Action]), "sqs:SendMessage")])
    )
    error_message = "Only owned IP sets may be changed and both asynchronous Lambda destinations require SendMessage permission."
  }
}

run "failure_and_expiry_paths" {
  command = plan
  assert {
    condition = (
      jsondecode(aws_sfn_state_machine.response.definition).States.Block.Catch[0].Next == "Failed" &&
      jsondecode(aws_sfn_state_machine.response.definition).States.Release.Catch[0].Next == "Failed" &&
      contains(jsondecode(aws_sfn_state_machine.response.definition).States.Block.Retry[0].ErrorEquals, "ResponseRetryableError") &&
      jsondecode(aws_sfn_state_machine.response.definition).States.WaitForExpiry.TimestampPath == "$.result.payload.wait_until" &&
      jsondecode(aws_sfn_state_machine.response.definition).States.WaitForExpiry.Next == "Release" &&
      aws_sfn_state_machine.response.type == "STANDARD"
    )
    error_message = "Failures must fail the workflow, transient failures retry, and lease expiry return to release."
  }
  assert {
    condition = (
      aws_cloudwatch_event_rule.reconcile.schedule_expression == "rate(1 minute)" &&
      aws_cloudwatch_event_rule.reconcile.state == "ENABLED" &&
      jsondecode(aws_cloudwatch_event_target.reconcile.input).action == "reconcile" &&
      aws_cloudwatch_event_target.reconcile.dead_letter_config[0].arn == aws_sqs_queue.async_failures.arn &&
      alltrue([for config in aws_lambda_function_event_invoke_config.failures : config.maximum_retry_attempts == 2 && config.maximum_event_age_in_seconds == 3600 && config.destination_config[0].on_failure[0].destination == aws_sqs_queue.async_failures.arn])
    )
    error_message = "Scheduled recovery and both asynchronous failures must retain their configured destinations and retries."
  }
  assert {
    condition = (
      aws_lambda_event_source_mapping.detection.batch_size == 1 &&
      contains(aws_lambda_event_source_mapping.detection.function_response_types, "ReportBatchItemFailures") &&
      aws_lambda_event_source_mapping.detection.scaling_config[0].maximum_concurrency == 2 &&
      aws_sqs_queue.detection.visibility_timeout_seconds >= 6 * aws_lambda_function.runtime["detector"].timeout &&
      jsondecode(aws_sqs_queue.detection.redrive_policy).maxReceiveCount == 5
    )
    error_message = "Queue visibility, batch failure handling and bounded redrive must match the detector."
  }
  assert {
    condition = (
      jsondecode(aws_sqs_queue_policy.s3_delivery.policy).Statement[0].Condition.StringEquals["aws:SourceAccount"] == "896986966760" &&
      jsondecode(aws_sqs_queue_policy.s3_delivery.policy).Statement[0].Condition.ArnEquals["aws:SourceArn"] == "arn:aws:s3:::cloud9-security-normalized-logs-896986966760-ap-northeast-2-an" &&
      aws_lambda_permission.agent_logs.source_account == "896986966760" &&
      aws_lambda_permission.waf_logs.source_account == "896986966760" &&
      aws_lambda_permission.reconcile.source_arn == "arn:aws:events:ap-northeast-2:896986966760:rule/respond-cloudwatch-agent-logs-reconcile"
    )
    error_message = "Source account and resource conditions must constrain all cross-service entry points."
  }
}

run "owned_notification_and_waf_module_boundary" {
  command = plan
  variables {
    enable_ingestion = true
    aws_cli_profile  = "cloud943"
  }
  assert {
    condition = (
      length(terraform_data.notification) == 1 &&
      jsondecode(terraform_data.notification[0].input.config_json).notification_id == "detect-cloudwatch-agent-logs" &&
      jsondecode(terraform_data.notification[0].input.config_json).bucket == "cloud9-security-normalized-logs-896986966760-ap-northeast-2-an" &&
      jsondecode(terraform_data.notification[0].input.config_json).queue_arn == aws_sqs_queue.detection.arn &&
      jsondecode(terraform_data.notification[0].input.config_json).input_prefix == "waf/response/v1/" &&
      jsondecode(terraform_data.notification[0].input.config_json).suffix == ".jsonl" &&
      terraform_data.notification[0].input.profile == "cloud943" &&
      !can(jsondecode(terraform_data.notification[0].input.config_json).web_acl_arn)
    )
    error_message = "Only the owned S3 notification entry may be attached, using the root provider's CLI profile."
  }
  assert {
    condition = (
      output.response_ip_sets.ipv4_arn == aws_wafv2_ip_set.block["ipv4"].arn &&
      output.response_ip_sets.ipv6_arn == aws_wafv2_ip_set.block["ipv6"].arn &&
      aws_wafv2_ip_set.block["ipv4"].name == "respond-cloudwatch-agent-logs-ipv4" &&
      aws_wafv2_ip_set.block["ipv6"].name == "respond-cloudwatch-agent-logs-ipv6" &&
      aws_wafv2_ip_set.block["ipv4"].ip_address_version == "IPV4" &&
      aws_wafv2_ip_set.block["ipv6"].ip_address_version == "IPV6" &&
      aws_dynamodb_table.response.ttl[0].attribute_name == "purge_at"
    )
    error_message = "The owning alb-waf module must receive the response IP sets, and state expiry must retain its purge_at TTL."
  }
}

run "reject_short_lease" {
  command = plan
  variables { block_seconds = 60 }
  expect_failures = [var.block_seconds]
}

run "reject_noncanonical_cidr" {
  command = plan
  variables { allowlist_cidrs = ["198.51.100.3/24"] }
  expect_failures = [var.allowlist_cidrs]
}

run "reject_changed_manual_protection_identity" {
  command = plan
  override_data {
    target = data.aws_wafv2_ip_set.manual_v4
    values = { id = "00000000-0000-0000-0000-000000000000", addresses = [] }
  }
  expect_failures = [terraform_data.identity_guard]
}

run "reject_other_bucket_region" {
  command = plan
  override_data {
    target = data.aws_s3_bucket.existing
    values = { region = "us-east-1" }
  }
  expect_failures = [terraform_data.identity_guard]
}

run "iam_boundary_and_log_retention" {
  command = plan
  variables {
    permissions_boundary_arn = "arn:aws:iam::896986966760:policy/security-boundary"
    iam_role_path            = "/security/"
    log_retention_days       = 30
  }
  assert {
    condition = (
      alltrue([for role in aws_iam_role.lambda :
        role.permissions_boundary == "arn:aws:iam::896986966760:policy/security-boundary" &&
        role.path == "/security/"
      ]) &&
      aws_iam_role.workflow.permissions_boundary == "arn:aws:iam::896986966760:policy/security-boundary" &&
      aws_iam_role.workflow.path == "/security/" &&
      alltrue([for group in aws_cloudwatch_log_group.runtime : group.retention_in_days == 30])
    )
    error_message = "Permissions boundaries and IAM paths must reach all four roles; log retention applies only to owned Lambda groups."
  }
}

run "reject_wrong_provider_account" {
  command = plan
  override_data {
    target = data.aws_caller_identity.current
    values = { account_id = "111122223333" }
  }
  expect_failures = [terraform_data.account_guard]
}

run "reject_wrong_provider_region" {
  command = plan
  override_data {
    target = data.aws_region.current
    values = { region = "us-east-1" }
  }
  expect_failures = [terraform_data.account_guard]
}

run "reject_wrong_web_acl" {
  command = plan
  override_data {
    target = data.aws_wafv2_web_acl.existing
    values = { arn = "arn:aws:wafv2:ap-northeast-2:896986966760:regional/webacl/other/00000000-0000-0000-0000-000000000000" }
  }
  expect_failures = [terraform_data.identity_guard]
}
