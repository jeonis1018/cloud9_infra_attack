data "archive_file" "runtime" {
  type             = "zip"
  output_path      = "${path.module}/runtime.zip"
  output_file_mode = "0644"
  dynamic "source" {
    for_each = toset(["normalizer.py", "agent_normalizer.py", "pipeline.py", "responder.py"])
    content {
      content  = file("${path.module}/${source.value}")
      filename = source.value
    }
  }
}

resource "aws_cloudwatch_log_group" "runtime" {
  for_each = local.functions

  name              = "/aws/lambda/${each.value.name}"
  retention_in_days = var.log_retention_days
  tags              = local.tags
  depends_on        = [terraform_data.identity_guard]
}

resource "aws_lambda_function" "runtime" {
  for_each = local.functions

  function_name                  = each.value.name
  tags                           = local.tags
  role                           = aws_iam_role.lambda[each.key].arn
  runtime                        = "python3.14"
  handler                        = each.value.handler
  memory_size                    = 256
  timeout                        = each.value.timeout
  filename                       = data.archive_file.runtime.output_path
  source_code_hash               = data.archive_file.runtime.output_base64sha256
  reserved_concurrent_executions = each.key == "responder" ? 1 : -1
  environment {
    variables = local.function_environment[each.key]
  }
  depends_on = [aws_iam_role_policy.lambda, aws_cloudwatch_log_group.runtime]
}

resource "aws_lambda_function_event_invoke_config" "failures" {
  for_each = toset(["normalizer", "responder"])

  function_name                = aws_lambda_function.runtime[each.key].function_name
  qualifier                    = "$LATEST"
  maximum_event_age_in_seconds = 3600
  maximum_retry_attempts       = 2
  destination_config {
    on_failure {
      destination = aws_sqs_queue.async_failures.arn
    }
  }
  depends_on = [aws_iam_role_policy.lambda]
}

resource "aws_lambda_event_source_mapping" "detection" {
  event_source_arn                   = aws_sqs_queue.detection.arn
  function_name                      = aws_lambda_function.runtime["detector"].arn
  enabled                            = var.enable_ingestion
  batch_size                         = 1
  maximum_batching_window_in_seconds = 0
  function_response_types            = ["ReportBatchItemFailures"]
  scaling_config {
    maximum_concurrency = 2
  }
  depends_on = [aws_sfn_state_machine.response, aws_iam_role_policy.lambda]
}

resource "aws_lambda_permission" "agent_logs" {
  statement_id   = "TeamWebNormalizerLogsV1"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.runtime["normalizer"].function_name
  principal      = "logs.amazonaws.com"
  source_account = var.account_id
  source_arn     = "arn:aws:logs:${var.region}:${var.account_id}:log-group:${local.agent_log_group}:*"
}

resource "aws_lambda_permission" "waf_logs" {
  statement_id   = "NormalizeCloudWatchAgentLogsWAF"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.runtime["normalizer"].function_name
  principal      = "logs.amazonaws.com"
  source_account = var.account_id
  source_arn     = "arn:aws:logs:${var.region}:${var.account_id}:log-group:${local.waf_log_group}:*"
}

resource "aws_lambda_permission" "reconcile" {
  statement_id   = "RespondCloudWatchAgentLogsReconcile"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.runtime["responder"].function_name
  principal      = "events.amazonaws.com"
  source_account = var.account_id
  source_arn     = local.schedule_arn
}
