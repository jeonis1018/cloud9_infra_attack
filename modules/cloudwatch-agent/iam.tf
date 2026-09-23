resource "aws_iam_role" "lambda" {
  for_each = local.functions

  name                 = "${each.value.name}-execution-role"
  path                 = var.iam_role_path
  permissions_boundary = var.permissions_boundary_arn
  tags                 = local.tags
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  depends_on = [terraform_data.identity_guard]
}

locals {
  lambda_statements = {
    normalizer = [
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = ["arn:aws:s3:::${local.bucket}/${local.input_prefix}*", "arn:aws:s3:::${local.bucket}/${local.agent_prefix}/*"] },
      { Effect = "Allow", Action = ["sqs:SendMessage"], Resource = [aws_sqs_queue.async_failures.arn] }
    ]
    detector = [
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = ["arn:aws:s3:::${local.bucket}/${local.input_prefix}*"] },
      { Effect = "Allow", Action = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"], Resource = [aws_sqs_queue.detection.arn] },
      { Effect = "Allow", Action = ["states:StartExecution"], Resource = [local.state_arn] },
      { Effect = "Allow", Action = ["states:DescribeExecution"], Resource = [local.execution_arn] }
    ]
    responder = [
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = ["arn:aws:s3:::${local.bucket}/${local.evidence_prefix}*"] },
      { Effect = "Allow", Action = ["wafv2:GetIPSet", "wafv2:UpdateIPSet"], Resource = [aws_wafv2_ip_set.block["ipv4"].arn, aws_wafv2_ip_set.block["ipv6"].arn] },
      { Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Scan"], Resource = [aws_dynamodb_table.response.arn] },
      { Effect = "Allow", Action = ["sqs:SendMessage"], Resource = [aws_sqs_queue.async_failures.arn] }
    ]
  }
}

resource "aws_iam_role_policy" "lambda" {
  for_each = local.functions

  name = "${each.value.name}-scoped-access"
  role = aws_iam_role.lambda[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = ["arn:aws:logs:${var.region}:${var.account_id}:log-group:/aws/lambda/${each.value.name}:*"]
    }], local.lambda_statements[each.key])
  })
}

resource "aws_iam_role" "workflow" {
  name                 = "respond-cloudwatch-agent-logs-workflow-role"
  path                 = var.iam_role_path
  permissions_boundary = var.permissions_boundary_arn
  tags                 = local.tags
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "states.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.account_id }
        ArnEquals    = { "aws:SourceArn" = local.state_arn }
      }
    }]
  })
  depends_on = [terraform_data.identity_guard]
}

resource "aws_iam_role_policy" "workflow" {
  name = "respond-cloudwatch-agent-logs-invoke-responder"
  role = aws_iam_role.workflow.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["lambda:InvokeFunction"]
      Resource = [aws_lambda_function.runtime["responder"].arn]
    }]
  })
}
