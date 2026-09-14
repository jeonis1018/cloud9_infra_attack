terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
    # Lambda 소스 파일을 zip으로 묶는 데 사용한다
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  # 핸들러는 파일명에서 유도한다
  # normalize-guardduty-logs-v2.py -> normalize-guardduty-logs-v2.lambda_handler
  handler_module = replace(basename(var.lambda_source_file), ".py", "")

  # create_finding_delivery 여부와 무관하게 구독 필터가 걸릴 로그 그룹 이름
  finding_log_group_name = (
    var.create_finding_delivery
    ? aws_cloudwatch_log_group.guardduty_findings[0].name
    : var.finding_log_group_name
  )

  finding_log_group_arn = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:${var.finding_log_group_name}"

  lambda_log_arn = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.function_name}"
}

# ==============================================
# 파인딩 전달 경로 (선택)
# GuardDuty -> EventBridge -> CloudWatch Logs
# ==============================================

resource "aws_cloudwatch_log_group" "guardduty_findings" {
  count = var.create_finding_delivery ? 1 : 0

  name              = var.finding_log_group_name
  retention_in_days = var.finding_log_retention_days

  tags = merge(var.tags, {
    Name = var.finding_log_group_name
  })
}

# EventBridge가 로그 그룹에 쓸 수 있도록 리소스 정책을 연다
data "aws_iam_policy_document" "events_to_logs" {
  count = var.create_finding_delivery ? 1 : 0

  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com", "delivery.logs.amazonaws.com"]
    }

    actions = ["logs:CreateLogStream", "logs:PutLogEvents"]

    resources = ["${local.finding_log_group_arn}:*"]
  }
}

resource "aws_cloudwatch_log_resource_policy" "events_to_logs" {
  count = var.create_finding_delivery ? 1 : 0

  policy_name     = "${var.name_prefix}-guardduty-events-to-logs"
  policy_document = data.aws_iam_policy_document.events_to_logs[0].json
}

resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  count = var.create_finding_delivery ? 1 : 0

  name        = "${var.name_prefix}-guardduty-findings"
  description = "GuardDuty 파인딩을 CloudWatch Logs로 전달한다"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
  })

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-guardduty-findings"
  })
}

resource "aws_cloudwatch_event_target" "guardduty_findings_to_logs" {
  count = var.create_finding_delivery ? 1 : 0

  rule      = aws_cloudwatch_event_rule.guardduty_findings[0].name
  target_id = "guardduty-findings-to-logs"
  arn       = aws_cloudwatch_log_group.guardduty_findings[0].arn

  depends_on = [aws_cloudwatch_log_resource_policy.events_to_logs]
}

# ==============================================
# 정규화 Lambda 실행 역할
# ==============================================

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "normalizer" {
  name               = "${var.name_prefix}-guardduty-normalizer-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  path                 = var.iam_path
  permissions_boundary = var.permissions_boundary_arn

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-guardduty-normalizer-role"
  })
}

data "aws_iam_policy_document" "normalizer" {
  statement {
    sid       = "WriteOwnLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [local.lambda_log_arn, "${local.lambda_log_arn}:*"]
  }

  statement {
    sid       = "PutNormalizedFindings"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${var.normalized_bucket}/${var.normalized_prefix}/*"]
  }

  # 룰 평가 Lambda를 지정한 경우에만 호출 권한을 준다
  dynamic "statement" {
    for_each = var.rules_function_name == "" ? [] : [var.rules_function_name]

    content {
      sid       = "InvokeRulesEvaluator"
      effect    = "Allow"
      actions   = ["lambda:InvokeFunction"]
      resources = ["arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${statement.value}"]
    }
  }
}

resource "aws_iam_role_policy" "normalizer" {
  name   = "${var.name_prefix}-guardduty-normalizer-policy"
  role   = aws_iam_role.normalizer.id
  policy = data.aws_iam_policy_document.normalizer.json
}

# ==============================================
# 정규화 Lambda
# ==============================================

data "archive_file" "normalizer" {
  type        = "zip"
  source_file = var.lambda_source_file
  output_path = "${path.module}/.build/${var.function_name}.zip"
}

resource "aws_lambda_function" "normalizer" {
  function_name = var.function_name
  role          = aws_iam_role.normalizer.arn
  runtime       = var.python_runtime
  handler       = "${local.handler_module}.lambda_handler"

  filename         = data.archive_file.normalizer.output_path
  source_code_hash = data.archive_file.normalizer.output_base64sha256

  timeout     = var.timeout
  memory_size = var.memory_size

  environment {
    variables = {
      NORMALIZED_BUCKET = var.normalized_bucket
      NORMALIZED_PREFIX = var.normalized_prefix
      # 빈 값이면 Lambda가 룰 평가 호출을 건너뛴다
      RULES_FUNCTION_NAME = var.rules_function_name
    }
  }

  depends_on = [aws_iam_role_policy.normalizer]

  tags = merge(var.tags, {
    Name = var.function_name
  })
}

# ==============================================
# 실시간 경로: 로그 그룹 -> 구독 필터 -> 정규화 Lambda
# ==============================================

resource "aws_lambda_permission" "allow_cwlogs" {
  statement_id   = "AllowExecutionFromCWLogs"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.normalizer.function_name
  principal      = "logs.amazonaws.com"
  source_arn     = "${local.finding_log_group_arn}:*"
  source_account = data.aws_caller_identity.current.account_id
}

resource "aws_cloudwatch_log_subscription_filter" "normalizer" {
  name            = "${var.function_name}-filter"
  log_group_name  = local.finding_log_group_name
  destination_arn = aws_lambda_function.normalizer.arn

  # 빈 패턴 = 모든 파인딩 전달 (정규화 단계에서 거르지 않는다는 방침)
  filter_pattern = ""

  depends_on = [aws_lambda_permission.allow_cwlogs]
}
