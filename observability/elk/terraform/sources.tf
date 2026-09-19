resource "aws_cloudwatch_log_group" "source" {                                                                                                      # 기존 이름이 없는 소스 로그 그룹만 만듭니다.
  tags              = { Name = "${each.value}" }                                                                                                    # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  for_each          = { for source in local.cwl_sources : source => local.log_group_names[source] if var.existing_log_group_names[source] == null } # 기존 그룹의 보관·암호화 설정을 수정하지 않습니다.
  name              = each.value                                                                                                                    # Agent 또는 WAF의 대상 이름입니다.
  retention_in_days = 30                                                                                                                            # upstream 재전송·조사 여유를 남깁니다.
  kms_key_id        = aws_kms_key.raw.arn                                                                                                           # 신규 그룹은 CMK로 암호화합니다.
  log_group_class   = "STANDARD"                                                                                                                    # 구독 필터를 지원하는 클래스입니다.
}                                                                                                                                                   # 신규 로그 그룹을 끝냅니다.

data "aws_cloudwatch_log_group" "existing" {                                                                                               # 재사용 그룹이 실제 존재하는지 확인합니다.
  for_each = { for source in local.cwl_sources : source => local.log_group_names[source] if var.existing_log_group_names[source] != null } # 입력한 그룹만 읽습니다.
  name     = each.value                                                                                                                    # 그룹 이름으로 조회합니다.
}                                                                                                                                          # 기존 그룹 조회를 끝냅니다.

resource "aws_cloudwatch_log_group" "firehose" {                                             # Firehose 전달 오류용 별도 로그 그룹입니다.
  tags              = { Name = "${var.name_prefix}-cloudwatch-${each.key}-delivery-errors" } # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  for_each          = local.cwl_sources                                                      # 두 스트림 각각입니다.
  name              = "${var.name_prefix}-cloudwatch-${each.key}-delivery-errors"            # 소스 그룹과 분리하여 재귀 수집을 피합니다.
  retention_in_days = 30                                                                     # 오류 분석을 위해 한 달 남깁니다.
}                                                                                            # 전달 오류 그룹을 끝냅니다.

resource "aws_cloudwatch_log_stream" "firehose" {                       # Firehose에 로그 스트림 생성 권한을 주지 않습니다.
  for_each       = local.cwl_sources                                    # 두 스트림 각각입니다.
  name           = "${var.name_prefix}-cloudwatch-${each.key}-delivery" # 전달 오류 스트림 이름입니다.
  log_group_name = aws_cloudwatch_log_group.firehose[each.key].name     # 대응 오류 그룹입니다.
}                                                                       # 오류 로그 스트림을 끝냅니다.

resource "aws_kinesis_firehose_delivery_stream" "source" {                                                                                                        # CloudWatch Agent/WAF 로그를 각각 S3에 전달합니다.
  tags        = { Name = "${var.name_prefix}-firehose-${each.key}-delivery" }                                                                                     # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  for_each    = local.cwl_sources                                                                                                                                 # 두 소스를 별도 스트림으로 나눕니다.
  name        = "${var.name_prefix}-firehose-${each.key}-delivery"                                                                                                # Firehose 이름입니다.
  destination = "extended_s3"                                                                                                                                     # Amazon S3 목적지를 사용합니다.
  server_side_encryption {                                                                                                                                        # Firehose 자체 버퍼도 암호화합니다.
    enabled  = true                                                                                                                                               # 암호화를 켭니다.
    key_type = "AWS_OWNED_CMK"                                                                                                                                    # Firehose 버퍼는 AWS 소유 키를 사용합니다.
  }                                                                                                                                                               # 버퍼 암호화를 끝냅니다.
  extended_s3_configuration {                                                                                                                                     # S3 저장 형식과 경로입니다.
    role_arn            = aws_iam_role.firehose[each.key].arn                                                                                                     # 소스별 전달 역할입니다.
    bucket_arn          = aws_s3_bucket.data["raw"].arn                                                                                                           # 신규 원본 버킷입니다.
    prefix              = "${each.key}/!{timestamp:yyyy/MM/dd/HH}/"                                                                                               # UTC 전달 시각 기준 prefix입니다.
    error_output_prefix = "firehose-errors/${each.key}/!{firehose:error-output-type}/!{timestamp:yyyy/MM/dd/HH}/"                                                 # 오류를 정상 파서와 분리합니다.
    buffering_size      = 5                                                                                                                                       # 5 MiB 버퍼 기준입니다.
    buffering_interval  = 60                                                                                                                                      # 낮은 로그량에서 약 60초 전달 버퍼 기준입니다.
    compression_format  = "GZIP"                                                                                                                                  # S3에는 gzip 파일을 저장합니다.
    file_extension      = ".jsonl.gz"                                                                                                                             # S3 notification suffix와 Filebeat 자동 압축 해제가 일치합니다.
    kms_key_arn         = aws_kms_key.raw.arn                                                                                                                     # S3 전달 데이터를 원본 CMK로 암호화합니다.
    cloudwatch_logging_options {                                                                                                                                  # 전달/압축 해제 오류 로그를 켭니다.
      enabled         = true                                                                                                                                      # 오류 기록을 활성화합니다.
      log_group_name  = aws_cloudwatch_log_group.firehose[each.key].name                                                                                          # 별도 진단 그룹입니다.
      log_stream_name = aws_cloudwatch_log_stream.firehose[each.key].name                                                                                         # 진단 스트림입니다.
    }                                                                                                                                                             # 오류 로그 설정을 끝냅니다.
    processing_configuration {                                                                                                                                    # Lambda 없이 전송 형식만 변환하고 이벤트는 삭제하지 않습니다.
      enabled = true                                                                                                                                              # 기본 처리기를 활성화합니다.
      processors {                                                                                                                                                # CloudWatch Logs가 전달한 gzip 데이터를 먼저 풉니다.
        type = "Decompression"                                                                                                                                    # AWS 내장 압축 해제입니다.
        parameters {                                                                                                                                              # 입력 압축 형식입니다.
          parameter_name  = "CompressionFormat"                                                                                                                   # API가 요구하는 이름입니다.
          parameter_value = "GZIP"                                                                                                                                # CloudWatch Logs의 압축 형식입니다.
        }                                                                                                                                                         # 압축 형식 매개변수를 끝냅니다.
      }                                                                                                                                                           # 압축 해제 처리기를 끝냅니다.
      processors {                                                                                                                                                # 소유 계정·로그 그룹·스트림·이벤트 ID를 보존합니다.
        type = "CloudWatchLogProcessing"                                                                                                                          # CloudWatch envelope 처리 설정입니다.
        parameters {                                                                                                                                              # message만 추출하는 기능을 끕니다.
          parameter_name  = "DataMessageExtraction"                                                                                                               # 메시지 추출 설정 이름입니다.
          parameter_value = "false"                                                                                                                               # logEvents 배열을 포함한 전체 envelope를 남깁니다.
        }                                                                                                                                                         # 매개변수를 끝냅니다.
      }                                                                                                                                                           # envelope 처리기를 끝냅니다.
      processors {                                                                                                                                                # 여러 envelope가 붙어 잘못된 JSON이 되는 것을 방지합니다.
        type = "AppendDelimiterToRecord"                                                                                                                          # 레코드마다 줄바꿈을 추가하며 매개변수는 불필요합니다.
      }                                                                                                                                                           # 줄바꿈 처리기를 끝냅니다.
    }                                                                                                                                                             # 전송 형식 처리를 끝냅니다.
  }                                                                                                                                                               # S3 목적지 설정을 끝냅니다.
  depends_on = [aws_iam_role_policy.firehose, aws_s3_bucket_policy.data, aws_s3_bucket_server_side_encryption_configuration.data, aws_s3_bucket_notification.raw] # 권한·암호화·알림을 먼저 준비합니다.
}                                                                                                                                                                 # Firehose 생성을 끝냅니다.

resource "aws_cloudwatch_log_subscription_filter" "source" {                                                                    # 소스별로 구독 필터 한 개를 추가합니다.
  for_each        = local.cwl_sources                                                                                           # 두 로그 그룹입니다.
  name            = "${var.name_prefix}-cloudwatch-${each.key}-to-firehose"                                                     # 기존 필터와 충돌하지 않는 이름을 선택합니다.
  log_group_name  = local.log_group_names[each.key]                                                                             # 신규 또는 기존 그룹입니다.
  filter_pattern  = ""                                                                                                          # 최초 검증에서는 모든 이벤트를 보냅니다.
  destination_arn = aws_kinesis_firehose_delivery_stream.source[each.key].arn                                                   # 대응 Firehose 목적지입니다.
  role_arn        = aws_iam_role.subscription[each.key].arn                                                                     # CloudWatch의 쓰기 역할입니다.
  depends_on      = [aws_cloudwatch_log_group.source, data.aws_cloudwatch_log_group.existing, aws_iam_role_policy.subscription] # 그룹 존재와 역할 권한을 확인한 뒤 만듭니다.
}                                                                                                                               # 구독 필터를 끝냅니다.

resource "aws_wafv2_web_acl_logging_configuration" "existing" {                                                                        # 기존 web ACL의 로깅만 선택적으로 연결합니다.
  count                   = var.manage_waf_logging ? 1 : 0                                                                             # 기존 소유 스택이 있으면 false를 유지합니다.
  resource_arn            = var.waf_web_acl_arn                                                                                        # 기존 web ACL ARN입니다.
  log_destination_configs = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:${local.log_group_names.waf}"] # WAF 로그 그룹으로 보냅니다.
  depends_on              = [aws_cloudwatch_log_group.source, data.aws_cloudwatch_log_group.existing]                                  # 목적지 그룹이 먼저 있어야 합니다.
  lifecycle {                                                                                                                          # WAF 목적지 이름 규칙을 검사합니다.
    precondition {                                                                                                                     # 그룹 접두사 확인입니다.
      condition     = startswith(local.log_group_names.waf, "aws-waf-logs-")                                                           # WAF가 요구하는 접두사입니다.
      error_message = "WAF 로그 그룹 이름은 aws-waf-logs-로 시작해야 합니다."                                                                         # 오류를 안내합니다.
    }                                                                                                                                  # 사전조건을 끝냅니다.
  }                                                                                                                                    # 수명주기 설정을 끝냅니다.
}                                                                                                                                      # WAF 로깅 연결을 끝냅니다.

resource "aws_cloudtrail" "new" {                                                                                                   # Trail이 없는 검증 계정에서만 생성합니다.
  tags                          = { Name = "${local.trail_name}" }                                                                  # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  count                         = var.create_cloudtrail ? 1 : 0                                                                     # 기존 Trail 확인 후 선택합니다.
  name                          = local.trail_name                                                                                  # 계정 Trail 이름입니다.
  s3_bucket_name                = aws_s3_bucket.data["raw"].id                                                                      # 신규 원본 버킷입니다.
  s3_key_prefix                 = "cloudtrail"                                                                                      # CloudTrail이 AWSLogs/...를 뒤에 붙입니다.
  kms_key_id                    = aws_kms_key.raw.arn                                                                               # SSE-KMS 암호화 키입니다.
  enable_logging                = true                                                                                              # 생성 후 기록을 활성화합니다.
  is_multi_region_trail         = true                                                                                              # 같은 계정의 여러 리전 관리 이벤트를 수집합니다.
  include_global_service_events = true                                                                                              # IAM 같은 전역 서비스 이벤트를 포함합니다.
  enable_log_file_validation    = true                                                                                              # 로그 무결성 digest를 함께 생성합니다.
  event_selector {                                                                                                                  # 관리 이벤트만 최초 범위로 지정합니다.
    read_write_type           = "All"                                                                                               # 읽기·쓰기 관리 이벤트 모두입니다.
    include_management_events = true                                                                                                # 관리 이벤트를 활성화합니다.
  }                                                                                                                                 # 데이터 이벤트는 추가 범위를 명시하기 전까지 수집하지 않습니다.
  depends_on = [aws_s3_bucket_policy.data, aws_s3_bucket_server_side_encryption_configuration.data, aws_s3_bucket_notification.raw] # 전달 경로를 먼저 준비합니다.
}                                                                                                                                   # 신규 Trail을 끝냅니다.

resource "aws_guardduty_detector" "new" {                                           # GuardDuty가 없는 테스트 계정에서만 활성화합니다.
  tags                         = { Name = "${var.name_prefix}-guardduty-detector" } # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  count                        = var.create_guardduty_detector ? 1 : 0              # 기존 detector가 있으면 만들지 않습니다.
  enable                       = true                                               # 기본 위협 탐지를 활성화합니다.
  finding_publishing_frequency = "FIFTEEN_MINUTES"                                  # 기존 active finding의 후속 발생 내보내기 주기입니다.
}                                                                                   # 추가 Protection plan 활성화 여부는 계정 콘솔에서 별도 확인합니다.

resource "aws_s3_object" "guardduty_folders" {                                                                                                                       # GuardDuty 내보내기에 필요한 prefix를 미리 만듭니다.
  tags                   = { Name = each.value == "guardduty/" ? "${var.name_prefix}-s3-guardduty-export-prefix" : "${var.name_prefix}-s3-guardduty-region-prefix" } # 데이터 경로는 유지하고 marker의 이름 태그만 통일합니다.
  for_each               = var.enable_guardduty_export ? toset(["guardduty/", "guardduty/AWSLogs/${local.account_id}/GuardDuty/${local.region}/"]) : toset([])       # prefix와 기본 하위 경로입니다.
  bucket                 = aws_s3_bucket.data["raw"].id                                                                                                              # 원본 버킷입니다.
  key                    = each.value                                                                                                                                # 빈 folder marker 객체 경로입니다.
  content                = ""                                                                                                                                        # 민감한 데이터를 Terraform state에 쓰지 않습니다.
  server_side_encryption = "aws:kms"                                                                                                                                 # marker도 CMK로 암호화합니다.
  kms_key_id             = aws_kms_key.raw.arn                                                                                                                       # 원본 키입니다.
}                                                                                                                                                                    # 폴더 marker를 끝냅니다.

resource "aws_guardduty_publishing_destination" "s3" {                                                           # Findings만 S3로 내보냅니다.
  count           = var.enable_guardduty_export ? 1 : 0                                                          # 기존 목적지 확인 후 생성합니다.
  detector_id     = local.detector_id                                                                            # 선택한 기존 또는 신규 detector입니다.
  destination_arn = "${aws_s3_bucket.data["raw"].arn}/guardduty"                                                 # 다른 로그와 prefix를 분리합니다.
  kms_key_arn     = aws_kms_key.raw.arn                                                                          # GuardDuty S3 내보내기의 필수 암호화 키입니다.
  depends_on      = [aws_s3_bucket_policy.data, aws_s3_object.guardduty_folders, aws_s3_bucket_notification.raw] # 키 정책은 참조로, 버킷 권한과 경로는 명시적으로 기다립니다.
}                                                                                                                # 내보내기 설정을 끝냅니다.
