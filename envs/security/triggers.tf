resource "aws_lambda_permission" "from_cloudwatch_logs" {
  statement_id   = "AllowCloudWatchLogsSubscription"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.normalizer.function_name
  principal      = "logs.amazonaws.com"
  source_arn     = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  source_account = local.account_id
}

resource "aws_cloudwatch_log_subscription_filter" "security_events" {
  name            = "cloud9-security-events-to-normalizer"
  log_group_name  = aws_cloudwatch_log_group.cloudtrail.name
  destination_arn = aws_lambda_function.normalizer.arn
  filter_pattern  = "{ ($.eventSource = \"guardduty.amazonaws.com\") || ($.eventSource = \"cloudtrail.amazonaws.com\") || ($.eventSource = \"s3.amazonaws.com\") || ($.eventSource = \"ec2.amazonaws.com\") || ($.eventSource = \"iam.amazonaws.com\") || ($.eventSource = \"sts.amazonaws.com\") || ($.eventSource = \"signin.amazonaws.com\") || ($.eventSource = \"ssm.amazonaws.com\") }"

  depends_on = [aws_lambda_permission.from_cloudwatch_logs]
}

resource "aws_iam_role" "scheduler" {
  name                 = "cloud9-security-scheduler-role"
  permissions_boundary = var.permissions_boundary_arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "scheduler.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
    }]
  })
}

resource "aws_iam_role_policy" "scheduler" {
  name = "invoke-tampering-detector"
  role = aws_iam_role.scheduler.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "lambda:InvokeFunction"
      Resource = aws_lambda_function.tampering.arn
    }]
  })
}

resource "aws_scheduler_schedule" "tampering" {
  name                         = "detect-cloudtrail-tampering-every-minute"
  group_name                   = "default"
  schedule_expression          = "rate(1 minute)"
  schedule_expression_timezone = "Asia/Seoul"
  state                        = "ENABLED"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_lambda_function.tampering.arn
    role_arn = aws_iam_role.scheduler.arn
    input    = "{}"
  }

  depends_on = [aws_iam_role_policy.scheduler]
}

