locals {
  response_retry = [{
    ErrorEquals = [
      "Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException",
      "Lambda.TooManyRequestsException", "ResponseRetryableError"
    ]
    IntervalSeconds = 2
    BackoffRate     = 2
    MaxAttempts     = 5
    MaxDelaySeconds = 30
  }]
  response_tasks = {
    for name, action in { Block = "block", Release = "release" } : name => {
      Type                      = "Task"
      Resource                  = "arn:aws:states:::lambda:invoke"
      TimeoutSeconds            = 75
      Parameters = {
        FunctionName = aws_lambda_function.runtime["responder"].arn
        Payload      = { action = action, "finding.$" = "$.finding" }
      }
      ResultSelector = { "payload.$" = "$.Payload" }
      ResultPath     = "$.result"
      Retry          = local.response_retry
      Catch          = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "Failed" }]
      Next           = "CheckResult"
    }
  }
}

resource "aws_sfn_state_machine" "response" {
  tags     = local.tags
  name     = local.state_machine
  role_arn = aws_iam_role.workflow.arn
  type     = "STANDARD"
  definition = jsonencode({
    StartAt        = "WrapFinding"
    TimeoutSeconds = 86400
    States = merge(local.response_tasks, {
      WrapFinding = { Type = "Pass", Parameters = { "finding.$" = "$" }, Next = "Block" }
      CheckResult = {
        Type = "Choice"
        Choices = [
          { Variable = "$.result.payload.status", StringEquals = "SKIPPED", Next = "Done" },
          { Variable = "$.result.payload.status", StringEquals = "RELEASED", Next = "Done" },
          { Variable = "$.result.payload.status", StringEquals = "BLOCKED", Next = "WaitForExpiry" },
          { Variable = "$.result.payload.status", StringEquals = "WAITING", Next = "WaitForExpiry" }
        ]
        Default = "Failed"
      }
      WaitForExpiry = { Type = "Wait", TimestampPath = "$.result.payload.wait_until", Next = "Release" }
      Done          = { Type = "Succeed" }
      Failed        = { Type = "Fail", Error = "CloudWatchResponseFailed", Cause = "Inspect the execution and the reconciliation failure queue." }
    })
  })
  depends_on = [aws_iam_role_policy.workflow]
}

resource "aws_cloudwatch_event_rule" "reconcile" {
  tags                = local.tags
  name                = local.schedule
  schedule_expression = "rate(1 minute)"
  state               = "ENABLED"
  depends_on          = [terraform_data.identity_guard]
}

resource "aws_cloudwatch_event_target" "reconcile" {
  rule      = aws_cloudwatch_event_rule.reconcile.name
  target_id = "respond-cloudwatch-agent-logs"
  arn       = aws_lambda_function.runtime["responder"].arn
  input     = jsonencode({ action = "reconcile" })
  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 2
  }
  dead_letter_config {
    arn = aws_sqs_queue.async_failures.arn
  }
  depends_on = [aws_lambda_permission.reconcile, aws_sqs_queue_policy.schedule_failure, aws_lambda_function_event_invoke_config.failures]
}
