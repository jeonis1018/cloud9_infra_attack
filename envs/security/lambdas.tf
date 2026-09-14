data "archive_file" "normalizer" {
  type                    = "zip"
  output_path             = "${path.module}/.build/normalizer.zip"
  output_file_mode        = "0644"
  source_content          = file("${path.module}/../../Lambda/CloudTrail/normalize-cloudtrail-logs-v2.py")
  source_content_filename = "lambda_function.py"
}

data "archive_file" "detector" {
  type                    = "zip"
  output_path             = "${path.module}/.build/detector.zip"
  output_file_mode        = "0644"
  source_content          = file("${path.module}/../../Lambda/CloudTrail/detect_security_rules.py")
  source_content_filename = "lambda_function.py"
}

data "archive_file" "tampering" {
  type                    = "zip"
  output_path             = "${path.module}/.build/tampering.zip"
  output_file_mode        = "0644"
  source_content          = file("${path.module}/../../Lambda/CloudTrail/detectTrail-v2.py")
  source_content_filename = "lambda_function.py"
}

resource "aws_iam_role" "detector" {
  name                 = "cloud9-security-detector-role"
  permissions_boundary = var.permissions_boundary_arn
  assume_role_policy   = local.lambda_assume_role_policy
}

resource "aws_iam_role" "normalizer" {
  name                 = "cloud9-security-normalizer-role"
  permissions_boundary = var.permissions_boundary_arn
  assume_role_policy   = local.lambda_assume_role_policy
}

resource "aws_iam_role" "tampering" {
  name                 = "cloud9-security-tampering-role"
  permissions_boundary = var.permissions_boundary_arn
  assume_role_policy   = local.lambda_assume_role_policy
}

resource "aws_iam_role_policy_attachment" "detector_basic" {
  role       = aws_iam_role.detector.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "normalizer_basic" {
  role       = aws_iam_role.normalizer.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "tampering_basic" {
  role       = aws_iam_role.tampering.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "detector" {
  name = "write-evaluation-results"
  role = aws_iam_role.detector.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "s3:PutObject"
      Resource = [
        "${aws_s3_bucket.results.arn}/cloudtrail/normal/*",
        "${aws_s3_bucket.results.arn}/cloudtrail/review/*",
        "${aws_s3_bucket.results.arn}/cloudtrail/findings/*",
      ]
    }]
  })
}

resource "aws_lambda_function" "detector" {
  function_name    = local.detector_name
  filename         = data.archive_file.detector.output_path
  source_code_hash = data.archive_file.detector.output_base64sha256
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.14"
  role             = aws_iam_role.detector.arn
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      RESULT_BUCKET         = aws_s3_bucket.results.id
      NORMAL_PREFIX         = "cloudtrail/normal"
      REVIEW_PREFIX         = "cloudtrail/review"
      FINDING_PREFIX        = "cloudtrail/findings"
      PROTECTED_TRAILS      = jsonencode([local.trail_name])
      PROTECTED_BUCKETS     = jsonencode([local.attack_bucket_name])
      PROTECTED_S3_PREFIXES = "{}"
      PROTECTED_S3_OBJECTS  = "[]"
      TEAM_CIDRS            = jsonencode(var.team_cidrs)
    }
  }

  depends_on = [
    aws_iam_role_policy.detector,
    aws_iam_role_policy_attachment.detector_basic,
  ]
}

resource "aws_iam_role_policy" "normalizer" {
  name = "save-and-invoke-detector"
  role = aws_iam_role.normalizer.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.results.arn}/cloudtrail/*"
      },
      {
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = aws_lambda_function.detector.arn
      },
    ]
  })
}

resource "aws_lambda_function" "normalizer" {
  function_name    = local.normalizer_name
  filename         = data.archive_file.normalizer.output_path
  source_code_hash = data.archive_file.normalizer.output_base64sha256
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.14"
  role             = aws_iam_role.normalizer.arn
  timeout          = 60
  memory_size      = 256

  environment {
    variables = {
      NORMALIZED_BUCKET      = aws_s3_bucket.results.id
      NORMALIZED_PREFIX      = "cloudtrail"
      DETECTOR_FUNCTION_NAME = aws_lambda_function.detector.function_name
    }
  }

  depends_on = [
    aws_iam_role_policy.normalizer,
    aws_iam_role_policy_attachment.normalizer_basic,
  ]
}

resource "aws_iam_role_policy" "tampering" {
  name = "lookup-and-invoke-normalizer"
  role = aws_iam_role.tampering.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "cloudtrail:LookupEvents"
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = aws_lambda_function.normalizer.arn
      },
    ]
  })
}

resource "aws_lambda_function" "tampering" {
  function_name    = local.tampering_name
  filename         = data.archive_file.tampering.output_path
  source_code_hash = data.archive_file.tampering.output_base64sha256
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.14"
  role             = aws_iam_role.tampering.arn
  timeout          = 180
  memory_size      = 256

  environment {
    variables = {
      LOOKBACK_MINUTES         = "5"
      NORMALIZER_FUNCTION_NAME = aws_lambda_function.normalizer.function_name
    }
  }

  depends_on = [
    aws_iam_role_policy.tampering,
    aws_iam_role_policy_attachment.tampering_basic,
  ]
}

