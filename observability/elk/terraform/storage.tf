data "aws_iam_policy_document" "raw_kms" {                                                                                                         # 원본 암호화 키의 사용 주체를 명시합니다.
  statement {                                                                                                                                      # 계정 IAM 정책으로 관리 권한을 위임합니다.
    sid       = "EnableAccountIAM"                                                                                                                 # 표준 관리 위임문입니다.
    actions   = ["kms:*"]                                                                                                                          # 실제 역할 권한은 각 IAM 정책으로 좁힙니다.
    resources = ["*"]                                                                                                                              # 키 정책의 별표는 이 키 자체를 의미합니다.
    principals {                                                                                                                                   # 계정 관리자에게 IAM 위임 권한을 줍니다.
      type        = "AWS"                                                                                                                          # AWS principal입니다.
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]                                                                       # 현재 계정만 허용합니다.
    }                                                                                                                                              # principal을 끝냅니다.
  }                                                                                                                                                # 관리문을 끝냅니다.
  statement {                                                                                                                                      # 신규 CloudWatch 로그 그룹을 CMK로 암호화합니다.
    sid       = "CloudWatchLogGroups"                                                                                                              # 사용 목적입니다.
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]                                        # CWL 암호화 동작입니다.
    resources = ["*"]                                                                                                                              # 이 키에서만 적용됩니다.
    principals {                                                                                                                                   # 지역 CloudWatch Logs 서비스입니다.
      type        = "Service"                                                                                                                      # 서비스 principal입니다.
      identifiers = ["logs.${local.region}.amazonaws.com"]                                                                                         # 선택 리전만 허용합니다.
    }                                                                                                                                              # principal을 끝냅니다.
    condition {                                                                                                                                    # 다른 로그 그룹에서 키를 쓰지 못하게 합니다.
      test     = "ArnEquals"                                                                                                                       # ARN을 정확히 일치시킵니다.
      variable = "kms:EncryptionContext:aws:logs:arn"                                                                                              # CWL이 제공하는 암호화 컨텍스트입니다.
      values   = [for name in values(local.log_group_names) : "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:${name}"] # 두 소스 그룹만 허용합니다.
    }                                                                                                                                              # 컨텍스트 조건을 끝냅니다.
  }                                                                                                                                                # CWL 허용문을 끝냅니다.
  dynamic "statement" {                                                                                                                            # 새 Trail을 만들 때만 서비스 쓰기를 허용합니다.
    for_each = var.create_cloudtrail ? [1] : []                                                                                                    # 명시적으로 활성화한 경우입니다.
    content {                                                                                                                                      # CloudTrail 데이터 키 발급 허용문입니다.
      sid       = "CloudTrailEncrypt"                                                                                                              # 사용 목적입니다.
      actions   = ["kms:GenerateDataKey*", "kms:DescribeKey", "kms:Decrypt"]                                                                       # Bucket Key 사용 시 Trail 생성·갱신에 필요한 복호화도 허용합니다.
      resources = ["*"]                                                                                                                            # 이 CMK에만 적용됩니다.
      principals {                                                                                                                                 # CloudTrail 서비스입니다.
        type        = "Service"                                                                                                                    # 서비스 principal입니다.
        identifiers = ["cloudtrail.amazonaws.com"]                                                                                                 # 공식 서비스 이름입니다.
      }                                                                                                                                            # principal을 끝냅니다.
      condition {                                                                                                                                  # 다른 Trail의 사용을 제한합니다.
        test     = "StringEquals"                                                                                                                  # 정확한 일치입니다.
        variable = "aws:SourceArn"                                                                                                                 # 호출을 발생시킨 Trail ARN입니다.
        values   = [local.trail_arn]                                                                                                               # 이 예제의 Trail만 허용합니다.
      }                                                                                                                                            # 조건을 끝냅니다.
    }                                                                                                                                              # 허용문 내용을 끝냅니다.
  }                                                                                                                                                # 선택 CloudTrail 허용을 끝냅니다.
  dynamic "statement" {                                                                                                                            # 기존 GuardDuty detector 내보내기를 선택한 경우입니다.
    for_each = var.enable_guardduty_export ? [1] : []                                                                                              # 기본은 생성하지 않습니다.
    content {                                                                                                                                      # GuardDuty 암호화 권한입니다.
      sid       = "GuardDutyEncrypt"                                                                                                               # 사용 목적입니다.
      actions   = ["kms:GenerateDataKey"]                                                                                                          # GuardDuty가 요구하는 동작입니다.
      resources = ["*"]                                                                                                                            # 이 키만 가리킵니다.
      principals {                                                                                                                                 # GuardDuty 서비스 principal입니다.
        type        = "Service"                                                                                                                    # 서비스 유형입니다.
        identifiers = ["guardduty.amazonaws.com"]                                                                                                  # 이 가이드의 두 리전에서 사용하는 principal입니다.
      }                                                                                                                                            # principal을 끝냅니다.
      condition {                                                                                                                                  # 현재 계정만 허용합니다.
        test     = "StringEquals"                                                                                                                  # 정확한 일치입니다.
        variable = "aws:SourceAccount"                                                                                                             # 호출 계정입니다.
        values   = [local.account_id]                                                                                                              # 현재 계정 ID입니다.
      }                                                                                                                                            # 계정 조건을 끝냅니다.
      condition {                                                                                                                                  # 지정한 detector만 허용합니다.
        test     = "ArnEquals"                                                                                                                     # ARN 일치입니다.
        variable = "aws:SourceArn"                                                                                                                 # detector ARN입니다.
        values   = [local.detector_arn]                                                                                                            # 사용자가 지정한 detector입니다.
      }                                                                                                                                            # detector 조건을 끝냅니다.
    }                                                                                                                                              # 허용문을 끝냅니다.
  }                                                                                                                                                # 선택 GuardDuty 허용을 끝냅니다.
}                                                                                                                                                  # 키 정책 문서를 끝냅니다.

resource "aws_kms_key" "raw" {                                                      # 로그 전용 고객 관리 키입니다.
  tags                    = { Name = "${var.name_prefix}-kms-raw" }                 # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  description             = "${var.name_prefix} raw logs and new source log groups" # 목적을 기록합니다.
  enable_key_rotation     = true                                                    # 자동 키 회전을 켭니다.
  deletion_window_in_days = 30                                                      # 실수에 대비한 삭제 대기 기간입니다.
  policy                  = data.aws_iam_policy_document.raw_kms.json               # 서비스별 권한 정책입니다.
}                                                                                   # 원본 키를 끝냅니다.

resource "aws_kms_alias" "raw" {                     # 콘솔에서 키를 찾기 쉽게 합니다.
  name          = "alias/${var.name_prefix}-kms-raw" # 별칭은 계정·리전 안에서 고유해야 합니다.
  target_key_id = aws_kms_key.raw.key_id             # 원본 CMK를 가리킵니다.
}                                                    # 별칭을 끝냅니다.

resource "aws_kms_key" "artifacts" {                                           # PKI/설정 전달용 버킷은 별도 CMK를 사용합니다.
  tags                    = { Name = "${var.name_prefix}-kms-artifacts" }      # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  description             = "${var.name_prefix} short lived runtime artifacts" # 원본 로그 키와 용도를 분리합니다.
  enable_key_rotation     = true                                               # 자동 회전을 켭니다.
  deletion_window_in_days = 30                                                 # 키 삭제 대기 기간입니다.
}                                                                              # 기본 키 정책은 이 계정 IAM에 권한을 위임합니다.

resource "aws_kms_alias" "artifacts" {                     # 설정 전달용 키 별칭입니다.
  name          = "alias/${var.name_prefix}-kms-artifacts" # 별칭입니다.
  target_key_id = aws_kms_key.artifacts.key_id             # 설정 전달 CMK입니다.
}                                                          # 별칭을 끝냅니다.

resource "aws_s3_bucket" "data" {                                            # 신규 버킷만 만들며 기존 버킷을 가져오지 않습니다.
  tags          = { Name = "${var.name_prefix}-s3-${each.key}" }             # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  for_each      = toset(["raw", "snapshots", "artifacts"])                   # 원본·복구·임시 배포 파일을 분리합니다.
  bucket        = "${var.name_prefix}-s3-${each.key}-${local.bucket_suffix}" # 전역 고유 이름입니다.
  force_destroy = false                                                      # 객체가 있으면 Terraform이 버킷을 강제 삭제하지 않습니다.
}                                                                            # 버킷을 끝냅니다.

resource "aws_s3_bucket_public_access_block" "data" { # 모든 버킷의 공개 접근을 차단합니다.
  for_each                = aws_s3_bucket.data        # 세 버킷 모두입니다.
  bucket                  = each.value.id             # 해당 버킷 ID입니다.
  block_public_acls       = true                      # 공개 ACL 생성 차단입니다.
  block_public_policy     = true                      # 공개 버킷 정책 차단입니다.
  ignore_public_acls      = true                      # 기존 공개 ACL도 무시합니다.
  restrict_public_buckets = true                      # 공개 정책에 의한 외부 접근을 제한합니다.
}                                                     # 공개 차단 설정을 끝냅니다.

resource "aws_s3_bucket_ownership_controls" "data" { # ACL 의존성을 제거합니다.
  for_each = aws_s3_bucket.data                      # 세 버킷 모두 적용합니다.
  bucket   = each.value.id                           # 해당 버킷입니다.
  rule {                                             # 객체 소유 규칙입니다.
    object_ownership = "BucketOwnerEnforced"         # 버킷 소유자가 모든 객체를 소유합니다.
  }                                                  # 규칙을 끝냅니다.
}                                                    # 소유권 설정을 끝냅니다.

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {                                                           # 저장 시 암호화를 기본 적용합니다.
  for_each = aws_s3_bucket.data                                                                                                  # 세 버킷 모두입니다.
  bucket   = each.value.id                                                                                                       # 해당 버킷 ID입니다.
  rule {                                                                                                                         # 기본 암호화 규칙입니다.
    bucket_key_enabled = each.key != "snapshots"                                                                                 # CMK 버킷에는 S3 Bucket Key를 사용합니다.
    apply_server_side_encryption_by_default {                                                                                    # 헤더 미지정 업로드에도 적용합니다.
      sse_algorithm     = each.key == "snapshots" ? "AES256" : "aws:kms"                                                         # 스냅샷은 SSE-S3, 나머지는 CMK입니다.
      kms_master_key_id = each.key == "raw" ? aws_kms_key.raw.arn : (each.key == "artifacts" ? aws_kms_key.artifacts.arn : null) # CMK를 선택합니다.
    }                                                                                                                            # 기본 암호화를 끝냅니다.
  }                                                                                                                              # 규칙을 끝냅니다.
}                                                                                                                                # 암호화 설정을 끝냅니다.

resource "aws_s3_bucket_versioning" "raw" { # 원본 덮어쓰기 이전 버전을 보존합니다.
  bucket = aws_s3_bucket.data["raw"].id     # 원본 버킷만 적용합니다.
  versioning_configuration {                # 버전 관리를 구성합니다.
    status = "Enabled"                      # 기존 버전 복구를 지원합니다.
  }                                         # 버전 설정을 끝냅니다.
}                                           # Versioning 리소스를 끝냅니다.

resource "aws_s3_bucket_lifecycle_configuration" "raw" { # 원본의 검색 외 보관 비용을 제한합니다.
  bucket = aws_s3_bucket.data["raw"].id                  # 원본 버킷입니다.
  rule {                                                 # 전체 원본에 적용합니다.
    id     = "${var.name_prefix}-s3-raw-retention"       # 규칙 식별자입니다.
    status = "Enabled"                                   # 수명주기 규칙을 켭니다.
    filter {}                                            # 모든 prefix에 적용합니다.
    expiration {                                         # 현재 버전에 삭제 마커를 만듭니다.
      days = var.raw_retention_days                      # 기본 30일이며 즉시 영구 삭제는 아닙니다.
    }                                                    # 현재 버전 만료를 끝냅니다.
    noncurrent_version_expiration {                      # 만료/덮어쓰기 뒤 과거 버전도 정리합니다.
      noncurrent_days = 7                                # 비현재 버전이 된 뒤 최소 7일 후 영구 삭제됩니다.
    }                                                    # 비현재 버전 만료를 끝냅니다.
    abort_incomplete_multipart_upload {                  # 실패한 대용량 업로드 조각을 정리합니다.
      days_after_initiation = 7                          # 시작 후 7일이 기준입니다.
    }                                                    # 업로드 정리를 끝냅니다.
  }                                                      # 보관 규칙을 끝냅니다.
  depends_on = [aws_s3_bucket_versioning.raw]            # Versioning 적용 후 구성합니다.
}                                                        # 원본 보관 정책을 끝냅니다.

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" { # 배포용 파일은 짧게만 보관합니다.
  bucket = aws_s3_bucket.data["artifacts"].id                  # 임시 아티팩트 버킷입니다.
  rule {                                                       # 전체 역할 prefix를 대상으로 합니다.
    id     = "${var.name_prefix}-s3-artifacts-retention"       # 규칙 이름입니다.
    status = "Enabled"                                         # 규칙을 활성화합니다.
    filter {}                                                  # 전체 객체입니다.
    expiration {                                               # 배포 파일을 자동 만료시킵니다.
      days = 3                                                 # 3일 뒤 만료 대상으로 지정하며 실제 삭제는 비동기입니다.
    }                                                          # 만료를 끝냅니다.
  }                                                            # 보관 규칙을 끝냅니다.
}                                                              # 아티팩트 수명주기를 끝냅니다.

data "aws_iam_policy_document" "bucket" {                                                                                            # 버킷 정책을 중앙에서 한 번만 관리합니다.
  for_each = aws_s3_bucket.data                                                                                                      # 각 버킷 정책입니다.
  statement {                                                                                                                        # 모든 접근에 TLS를 요구합니다.
    sid       = "DenyNonTLS"                                                                                                         # 명시적 거부문입니다.
    effect    = "Deny"                                                                                                               # 허용 정책보다 우선합니다.
    actions   = ["s3:*"]                                                                                                             # 모든 S3 동작입니다.
    resources = [each.value.arn, "${each.value.arn}/*"]                                                                              # 버킷과 객체에 적용합니다.
    principals {                                                                                                                     # 모든 principal을 대상으로 합니다.
      type        = "*"                                                                                                              # 전체 principal입니다.
      identifiers = ["*"]                                                                                                            # 인증 여부와 무관합니다.
    }                                                                                                                                # principal을 끝냅니다.
    condition {                                                                                                                      # HTTPS가 아닌 요청만 거부합니다.
      test     = "Bool"                                                                                                              # 불리언 조건입니다.
      variable = "aws:SecureTransport"                                                                                               # TLS 여부입니다.
      values   = ["false"]                                                                                                           # 평문 HTTP를 거부합니다.
    }                                                                                                                                # TLS 조건을 끝냅니다.
  }                                                                                                                                  # TLS 강제문을 끝냅니다.
  dynamic "statement" {                                                                                                              # CloudTrail 전달에 필요한 두 동작입니다.
    for_each = each.key == "raw" && var.create_cloudtrail ? { acl = "s3:GetBucketAcl", write = "s3:PutObject" } : {}                 # 원본 버킷만 대상입니다.
    content {                                                                                                                        # Trail별 허용문입니다.
      sid       = "CloudTrail${statement.key}"                                                                                       # 동작별 식별자입니다.
      actions   = [statement.value]                                                                                                  # ACL 확인 또는 객체 쓰기입니다.
      resources = statement.key == "acl" ? [each.value.arn] : ["${each.value.arn}/cloudtrail/AWSLogs/${local.account_id}/*"]         # 자기 계정 경로만 허용합니다.
      principals {                                                                                                                   # CloudTrail 서비스입니다.
        type        = "Service"                                                                                                      # 서비스 principal입니다.
        identifiers = ["cloudtrail.amazonaws.com"]                                                                                   # 공식 서비스 이름입니다.
      }                                                                                                                              # principal을 끝냅니다.
      condition {                                                                                                                    # 지정한 Trail만 허용합니다.
        test     = "StringEquals"                                                                                                    # 정확한 일치입니다.
        variable = "aws:SourceArn"                                                                                                   # 전달 주체의 Trail입니다.
        values   = [local.trail_arn]                                                                                                 # 이 모듈 Trail만 허용합니다.
      }                                                                                                                              # Trail 조건을 끝냅니다.
      dynamic "condition" {                                                                                                          # 쓰기에 객체 소유권 헤더를 요구합니다.
        for_each = statement.key == "write" ? [1] : []                                                                               # ACL 조회에는 적용하지 않습니다.
        content {                                                                                                                    # 쓰기 헤더 검사입니다.
          test     = "StringEquals"                                                                                                  # 정확한 일치입니다.
          variable = "s3:x-amz-acl"                                                                                                  # CloudTrail이 사용하는 헤더입니다.
          values   = ["bucket-owner-full-control"]                                                                                   # BucketOwnerEnforced와 호환되는 값입니다.
        }                                                                                                                            # 조건 내용을 끝냅니다.
      }                                                                                                                              # 선택 조건을 끝냅니다.
    }                                                                                                                                # 허용문을 끝냅니다.
  }                                                                                                                                  # CloudTrail 정책을 끝냅니다.
  dynamic "statement" {                                                                                                              # GuardDuty 내보내기 권한입니다.
    for_each = each.key == "raw" && var.enable_guardduty_export ? { location = "s3:GetBucketLocation", write = "s3:PutObject" } : {} # 활성화 시만 추가합니다.
    content {                                                                                                                        # GuardDuty 서비스 허용문입니다.
      sid       = "GuardDuty${statement.key}"                                                                                        # 동작별 이름입니다.
      actions   = [statement.value]                                                                                                  # 리전 확인 또는 객체 쓰기입니다.
      resources = statement.key == "location" ? [each.value.arn] : ["${each.value.arn}/guardduty/*"]                                 # GuardDuty prefix로 한정합니다.
      principals {                                                                                                                   # GuardDuty 서비스입니다.
        type        = "Service"                                                                                                      # 서비스 principal입니다.
        identifiers = ["guardduty.amazonaws.com"]                                                                                    # 공식 서비스 이름입니다.
      }                                                                                                                              # principal을 끝냅니다.
      condition {                                                                                                                    # 다른 계정에서 사용하지 못하게 합니다.
        test     = "StringEquals"                                                                                                    # 정확한 일치입니다.
        variable = "aws:SourceAccount"                                                                                               # 원본 계정입니다.
        values   = [local.account_id]                                                                                                # 현재 계정만 허용합니다.
      }                                                                                                                              # 계정 조건을 끝냅니다.
      condition {                                                                                                                    # 선택한 detector만 허용합니다.
        test     = "ArnEquals"                                                                                                       # ARN 일치입니다.
        variable = "aws:SourceArn"                                                                                                   # detector ARN입니다.
        values   = [local.detector_arn]                                                                                              # 입력한 detector입니다.
      }                                                                                                                              # detector 조건을 끝냅니다.
    }                                                                                                                                # 허용문을 끝냅니다.
  }                                                                                                                                  # GuardDuty 정책을 끝냅니다.
}                                                                                                                                    # 버킷 정책 문서를 끝냅니다.

resource "aws_s3_bucket_policy" "data" {                        # 서비스 허용과 TLS 강제를 적용합니다.
  for_each = aws_s3_bucket.data                                 # 각 버킷의 유일한 정책 소유자입니다.
  bucket   = each.value.id                                      # 대상 버킷입니다.
  policy   = data.aws_iam_policy_document.bucket[each.key].json # JSON은 HCL에서 안전하게 생성합니다.
}                                                               # 정책 리소스를 끝냅니다.

resource "aws_sqs_queue" "dlq" {                                                  # S3 읽기 실패 알림을 별도 큐에 남깁니다.
  tags                      = { Name = "${var.name_prefix}-sqs-${each.key}-dlq" } # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  for_each                  = local.sources                                       # 소스별 실패 격리입니다.
  name                      = "${var.name_prefix}-sqs-${each.key}-dlq"            # 실패 큐 이름입니다.
  message_retention_seconds = 1209600                                             # SQS 최대 14일입니다.
  sqs_managed_sse_enabled   = true                                                # SQS 관리 암호화를 사용합니다.
}                                                                                 # 실패 큐를 끝냅니다.

resource "aws_sqs_queue" "source" {                                                   # S3 객체 생성 알림 전용 큐입니다.
  tags                       = { Name = "${var.name_prefix}-sqs-${each.key}-ingest" } # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  for_each                   = local.sources                                          # 네 소스 큐입니다.
  name                       = "${var.name_prefix}-sqs-${each.key}-ingest"            # 큐 이름입니다.
  message_retention_seconds  = 1209600                                                # 중단 후 14일까지 알림을 유지합니다.
  visibility_timeout_seconds = 300                                                    # Filebeat 처리 중 메시지를 숨기는 시작값입니다.
  receive_wait_time_seconds  = 20                                                     # long polling으로 빈 요청을 줄입니다.
  sqs_managed_sse_enabled    = true                                                   # SQS 관리 암호화를 켭니다.
  redrive_policy = jsonencode({                                                       # 처리 실패 이동 정책입니다.
    deadLetterTargetArn = aws_sqs_queue.dlq[each.key].arn                             # 같은 소스의 실패 큐입니다.
    maxReceiveCount     = 5                                                           # 다섯 번 실패 후 DLQ로 이동합니다.
  })                                                                                  # 이동 정책을 끝냅니다.
}                                                                                     # 소스 큐를 끝냅니다.

resource "aws_sqs_queue_redrive_allow_policy" "dlq" {        # 각 DLQ의 사용자를 한 소스 큐로 제한합니다.
  for_each  = local.sources                                  # 네 소스 각각입니다.
  queue_url = aws_sqs_queue.dlq[each.key].url                # 설정할 DLQ입니다.
  redrive_allow_policy = jsonencode({                        # redrive 허용 정책입니다.
    redrivePermission = "byQueue"                            # 지정 큐만 사용합니다.
    sourceQueueArns   = [aws_sqs_queue.source[each.key].arn] # 대응 소스 큐입니다.
  })                                                         # 정책을 끝냅니다.
}                                                            # DLQ 허용 정책을 끝냅니다.

resource "aws_sqs_queue_policy" "source" {                                                                                          # S3 서비스가 알림을 발행할 수 있게 합니다.
  for_each  = local.sources                                                                                                         # 소스별 큐에 적용합니다.
  queue_url = aws_sqs_queue.source[each.key].url                                                                                    # 대상 큐입니다.
  policy = jsonencode({                                                                                                             # 이 큐의 resource policy입니다.
    Version = "2012-10-17"                                                                                                          # IAM 정책 버전입니다.
    Statement = [{                                                                                                                  # S3 발행 허용문입니다.
      Sid       = "AllowOnlyRawBucketNotifications"                                                                                 # 용도 식별자입니다.
      Effect    = "Allow"                                                                                                           # 발행을 허용합니다.
      Principal = { Service = "s3.amazonaws.com" }                                                                                  # S3 서비스만 허용합니다.
      Action    = "sqs:SendMessage"                                                                                                 # 알림 발행만 허용합니다.
      Resource  = aws_sqs_queue.source[each.key].arn                                                                                # 대상 큐로 한정합니다.
      Condition = {                                                                                                                 # 혼동된 대리인 공격을 제한합니다.
        ArnEquals    = { "aws:SourceArn" = each.key == "cloudtrail" ? local.cloudtrail_bucket_arn : aws_s3_bucket.data["raw"].arn } # CT는 선택한 기존 버킷을 허용할 수 있습니다.
        StringEquals = { "aws:SourceAccount" = local.account_id }                                                                   # 현재 계정만 허용합니다.
      }                                                                                                                             # 조건을 끝냅니다.
    }]                                                                                                                              # 허용문을 끝냅니다.
  })                                                                                                                                # JSON 정책을 끝냅니다.
}                                                                                                                                   # 큐 정책을 끝냅니다.

resource "aws_s3_bucket_notification" "raw" {                      # S3 notification 설정은 버킷당 한 리소스만 사용합니다.
  bucket = aws_s3_bucket.data["raw"].id                            # 신규 원본 버킷입니다.
  dynamic "queue" {                                                # 네 prefix의 알림을 네 큐로 나눕니다.
    for_each = local.enabled_raw_notification_prefixes             # 기존 Trail 버킷 알림을 이 리소스로 변경하지 않습니다.
    content {                                                      # 단일 알림 규칙입니다.
      id            = "${var.name_prefix}-s3-${queue.key}-objects" # 규칙 이름입니다.
      queue_arn     = aws_sqs_queue.source[queue.key].arn          # 해당 소스 큐입니다.
      events        = ["s3:ObjectCreated:*"]                       # PUT과 multipart 완료 모두 포함합니다.
      filter_prefix = queue.value                                  # CloudTrail digest 등 다른 종류를 제외합니다.
      filter_suffix = ".gz"                                        # 폴더 marker와 오류 객체는 정상 파서로 보내지 않습니다.
    }                                                              # 큐 규칙을 끝냅니다.
  }                                                                # 네 규칙 생성을 끝냅니다.
  depends_on = [aws_sqs_queue_policy.source]                       # S3가 대상 큐 유효성 확인에 성공하도록 먼저 권한을 만듭니다.
}                                                                  # notification 구성을 끝냅니다.
