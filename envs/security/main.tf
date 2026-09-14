data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

data "terraform_remote_state" "attack" {
  backend = "s3"
  config = {
    bucket  = "cloud943-attack-tfstate"
    key     = "envs/${var.attack_environment}/terraform.tfstate"
    region  = "ap-northeast-2"
    profile = var.aws_profile
  }
}

locals {
  account_id         = data.aws_caller_identity.current.account_id
  attack_bucket_name = data.terraform_remote_state.attack.outputs.attack_target_bucket_name
  attack_bucket_arn  = data.terraform_remote_state.attack.outputs.attack_target_bucket_arn
  trail_name         = "cloud9-security-multi-region"
  trail_arn          = "arn:${data.aws_partition.current.partition}:cloudtrail:ap-northeast-2:${local.account_id}:trail/${local.trail_name}"
  result_bucket_name = "cloud9-security-normalized-logs-${local.account_id}-ap-northeast-2-an"
  trail_bucket_name  = "cloud9-security-cloudtrail-raw-${local.account_id}-ap-northeast-2-an"
  normalizer_name    = "normalize-cloudtrail-logs-v2"
  detector_name      = "detect_security_rules"
  tampering_name     = "detect-cloudtrail-tampering"
  lambda_assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_s3_bucket" "cloudtrail_raw" {
  bucket = local.trail_bucket_name
  lifecycle {
    precondition {
      condition     = local.account_id == "896986966760"
      error_message = "This security stack must only be applied in account 896986966760."
    }
  }
}

resource "aws_s3_bucket" "results" {
  bucket = local.result_bucket_name
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_raw" {
  bucket                  = aws_s3_bucket.cloudtrail_raw.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "results" {
  bucket                  = aws_s3_bucket.results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_raw" {
  bucket = aws_s3_bucket.cloudtrail_raw.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "results" {
  bucket = aws_s3_bucket.results.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_delivery" {
  bucket = aws_s3_bucket.cloudtrail_raw.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "CloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail_raw.arn
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
      },
      {
        Sid       = "CloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail_raw.arn}/AWSLogs/${local.account_id}/*"
        Condition = {
          StringEquals = {
            "aws:SourceArn" = local.trail_arn
            "s3:x-amz-acl"  = "bucket-owner-full-control"
          }
        }
      },
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.cloudtrail_raw]
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/cloud9-security"
  retention_in_days = 30
}

resource "aws_iam_role" "cloudtrail_to_logs" {
  name                 = "cloud9-security-cloudtrail-to-logs"
  permissions_boundary = var.permissions_boundary_arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "cloudtrail_to_logs" {
  name = "write-cloudtrail-log-group"
  role = aws_iam_role.cloudtrail_to_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

resource "aws_cloudtrail" "security" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail_raw.id
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_to_logs.arn
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  enable_logging                = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${local.attack_bucket_arn}/"]
    }
  }

  depends_on = [
    aws_s3_bucket_policy.cloudtrail_delivery,
    aws_iam_role_policy.cloudtrail_to_logs,
  ]
}
