data "aws_region" "current" {}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "target" {
  bucket = "${var.bucket_name_prefix}-${random_id.bucket_suffix.hex}"
}

resource "aws_s3_bucket_public_access_block" "target" {
  bucket = aws_s3_bucket.target.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "profile" {
  bucket = "${var.profile_bucket_name_prefix}-${random_id.bucket_suffix.hex}"
}

resource "aws_s3_bucket_public_access_block" "profile" {
  bucket = aws_s3_bucket.profile.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = var.private_route_table_ids
}

# before=false: 정책 없음 (탈취한 임시자격증명이면 인터넷 어디서든 접근 가능한 취약 상태)
# after=true: VPC 엔드포인트를 거치지 않은 요청은 차단
resource "aws_s3_bucket_policy" "vpce_only" {
  count  = var.allowed_vpc_endpoint_only ? 1 : 0
  bucket = aws_s3_bucket.target.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyIfNotFromVpcEndpoint"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.target.arn,
          "${aws_s3_bucket.target.arn}/*",
        ]
        Condition = {
          StringNotEquals = {
            "aws:sourceVpce" = aws_vpc_endpoint.s3.id
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_policy" "profile_vpce_only" {
  count  = var.allowed_vpc_endpoint_only ? 1 : 0
  bucket = aws_s3_bucket.profile.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyIfNotFromVpcEndpoint"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.profile.arn,
          "${aws_s3_bucket.profile.arn}/*",
        ]
        Condition = {
          StringNotEquals = {
            "aws:sourceVpce" = aws_vpc_endpoint.s3.id
          }
        }
      }
    ]
  })
}

locals {
  content_types = {
    "png"  = "image/png"
    "jpg"  = "image/jpeg"
    "jpeg" = "image/jpeg"
    "csv"  = "text/csv"
    "txt"  = "text/plain"
  }
}

resource "aws_s3_object" "dummy_data" {
  for_each = fileset("${path.module}/dummy_data", "**")

  bucket       = aws_s3_bucket.target.id
  key          = each.value
  source       = "${path.module}/dummy_data/${each.value}"
  etag         = filemd5("${path.module}/dummy_data/${each.value}")
  content_type = lookup(local.content_types, lower(regex("[^.]+$", each.value)), "application/octet-stream")
}
