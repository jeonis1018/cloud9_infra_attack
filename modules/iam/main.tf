terraform {
  required_version = ">= 1.3.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "s3_access" {
  dynamic "statement" {
    for_each = var.enable_least_privilege ? [] : [1]

    content {
      sid       = "BroadTestBucketAccess"
      effect    = "Allow"
      actions   = ["s3:*"]
      resources = [var.s3_bucket_arn, "${var.s3_bucket_arn}/*"]
    }
  }

  dynamic "statement" {
    for_each = var.enable_least_privilege ? [1] : []

    content {
      sid       = "ListTestBucket"
      effect    = "Allow"
      actions   = ["s3:ListBucket"]
      resources = [var.s3_bucket_arn]
    }
  }

  dynamic "statement" {
    for_each = var.enable_least_privilege ? [1] : []

    content {
      sid       = "ReadTestBucketObjects"
      effect    = "Allow"
      actions   = ["s3:GetObject"]
      resources = ["${var.s3_bucket_arn}/*"]
    }
  }
}

resource "aws_iam_role" "ec2" {
  name               = "${var.name_prefix}-ec2-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ec2-role"
  })
}

resource "aws_iam_role_policy" "s3_access" {
  name   = "${var.name_prefix}-s3-access"
  role   = aws_iam_role.ec2.id
  policy = data.aws_iam_policy_document.s3_access.json
}

resource "aws_iam_instance_profile" "ec2" {
  name = "${var.name_prefix}-ec2-profile"
  role = aws_iam_role.ec2.name

  depends_on = [aws_iam_role_policy.s3_access]

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ec2-profile"
  })
}
