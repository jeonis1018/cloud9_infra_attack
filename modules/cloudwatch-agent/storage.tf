resource "aws_sqs_queue" "detection_dlq" {
  tags                      = local.tags
  name                      = "detect-cloudwatch-agent-logs-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
  depends_on                = [terraform_data.identity_guard]
}

resource "aws_sqs_queue" "async_failures" {
  tags                      = local.tags
  name                      = "respond-cloudwatch-agent-logs-failures"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
  depends_on                = [terraform_data.identity_guard]
}

resource "aws_sqs_queue" "detection" {
  tags                       = local.tags
  name                       = "detect-cloudwatch-agent-logs"
  message_retention_seconds  = 345600
  visibility_timeout_seconds = 180
  sqs_managed_sse_enabled    = true
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.detection_dlq.arn
    maxReceiveCount     = 5
  })
}

resource "aws_sqs_queue_policy" "s3_delivery" {
  queue_url = aws_sqs_queue.detection.url
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "s3.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.detection.arn
      Condition = {
        ArnEquals    = { "aws:SourceArn" = "arn:aws:s3:::${local.bucket}" }
        StringEquals = { "aws:SourceAccount" = var.account_id }
      }
    }]
  })
}

resource "aws_sqs_queue_policy" "schedule_failure" {
  queue_url = aws_sqs_queue.async_failures.url
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.async_failures.arn
      Condition = {
        ArnEquals    = { "aws:SourceArn" = local.schedule_arn }
        StringEquals = { "aws:SourceAccount" = var.account_id }
      }
    }]
  })
}

resource "aws_dynamodb_table" "response" {
  tags         = local.tags
  name         = local.state_table
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "cidr"
  attribute {
    name = "cidr"
    type = "S"
  }
  ttl {
    attribute_name = "purge_at"
    enabled        = true
  }
  server_side_encryption {
    enabled = true
  }
  depends_on = [terraform_data.identity_guard]
}

resource "aws_wafv2_ip_set" "block" {
  tags     = local.tags
  for_each = { ipv4 = "IPV4", ipv6 = "IPV6" }

  name               = "respond-cloudwatch-agent-logs-${each.key}"
  description        = "Owned by cloudwatch-agent response. The responder serializes address updates."
  scope              = "REGIONAL"
  ip_address_version = each.value
  addresses          = []

  # Runtime leases own the addresses after initial creation. An apply must not clear them.
  lifecycle {
    ignore_changes = [addresses]
  }
  depends_on = [terraform_data.account_guard]
}
