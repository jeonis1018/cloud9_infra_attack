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

resource "aws_iam_role_policy_attachment" "readonly_before" {
  count      = var.enable_least_privilege ? 0 : 1
  role       = aws_iam_role.ec2.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

data "aws_iam_policy_document" "s3_access" {
  dynamic "statement" {
    for_each = var.enable_least_privilege ? [1] : []

    content {
      sid       = "ReadProfileImage"
      effect    = "Allow"
      actions   = ["s3:GetObject"]
      resources = ["${var.profile_bucket_arn}/profile/current"]
    }
  }

  dynamic "statement" {
    for_each = var.enable_least_privilege ? [1] : []

    content {
      sid       = "WriteProfileImage"
      effect    = "Allow"
      actions   = ["s3:PutObject", "s3:PutObjectTagging"]
      resources = ["${var.profile_bucket_arn}/profile/current"]
    }
  }
}

resource "aws_iam_role" "ec2" {
  name               = "${var.name_prefix}-ec2-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json

  path                 = "/whs-project/"
  permissions_boundary = "arn:aws:iam::896986966760:policy/WHSProjectRoleBoundary"

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ec2-role"
  })
}

resource "aws_iam_role_policy" "s3_access" {
  count  = var.enable_least_privilege ? 1 : 0
  name   = "${var.name_prefix}-s3-access"
  role   = aws_iam_role.ec2.id
  policy = data.aws_iam_policy_document.s3_access.json
}

resource "aws_iam_role_policy_attachment" "ssm_debug" {
  role       = aws_iam_role.ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2" {
  name = "${var.name_prefix}-ec2-profile"
  path = "/whs-project/"
  role = aws_iam_role.ec2.name

  depends_on = [
    aws_iam_role_policy.s3_access,
    aws_iam_role_policy_attachment.readonly_before,
  ]

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ec2-profile"
  })
}