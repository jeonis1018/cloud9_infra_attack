mock_provider "aws" {                                                                             # 실제 AWS API를 호출하지 않고 계획의 구조와 입력 조건을 검증합니다.
  mock_data "aws_caller_identity" {                                                               # 계정 확인 data source를 가상화합니다.
    defaults = {                                                                                  # 검증용 계정 번호입니다.
      account_id = "123456789012"                                                                 # 실제 사용자 계정이 아닙니다.
      arn        = "arn:aws:iam::123456789012:role/elk-test"                                      # 가상 운영자 역할입니다.
      user_id    = "EXAMPLE"                                                                      # 가상 사용자 식별자입니다.
    }                                                                                             # 기본 응답을 끝냅니다.
  }                                                                                               # 계정 모킹을 끝냅니다.
  mock_data "aws_partition" {                                                                     # 일반 AWS partition 응답을 제공합니다.
    defaults = {                                                                                  # ARN 조립에 필요한 값입니다.
      partition  = "aws"                                                                          # 상용 AWS의 partition입니다.
      dns_suffix = "amazonaws.com"                                                                # 상용 AWS의 DNS suffix입니다.
    }                                                                                             # 기본 응답을 끝냅니다.
  }                                                                                               # partition 모킹을 끝냅니다.
  mock_data "aws_subnet" {                                                                        # 실제 subnet을 조회하지 않습니다.
    defaults = {                                                                                  # subnet 사전조건을 통과할 가상 값입니다.
      vpc_id                  = "vpc-0123456789abcdef0"                                           # 테스트에서 선택한 VPC입니다.
      map_public_ip_on_launch = false                                                             # 공인 IP 자동 할당이 꺼진 상태입니다.
      availability_zone       = "ap-northeast-2a"                                                 # 단일 AZ 검증 예시입니다.
    }                                                                                             # 기본 응답을 끝냅니다.
  }                                                                                               # subnet 모킹을 끝냅니다.
  mock_data "aws_vpc" {                                                                           # VPC data source를 가상화합니다.
    defaults = {                                                                                  # private DNS가 켜진 가상 VPC입니다.
      enable_dns_support   = true                                                                 # AWS API 이름 확인이 가능한 가정입니다.
      enable_dns_hostnames = true                                                                 # 호스트 이름을 사용할 수 있는 가정입니다.
    }                                                                                             # 기본 응답을 끝냅니다.
  }                                                                                               # VPC 모킹을 끝냅니다.
  mock_data "aws_iam_policy_document" {                                                           # AWS provider의 로컬 JSON data source도 mock으로 대체됩니다.
    defaults = {                                                                                  # 이 테스트는 IAM의 실효 권한 검증이 아니라 topology 계획 검사입니다.
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"                                      # 유효한 JSON을 제공해 형식 검사를 통과합니다.
    }                                                                                             # 기본 응답을 끝냅니다.
  }                                                                                               # 정책 data source 모킹을 끝냅니다.
  mock_resource "aws_iam_role" {                                                                  # ARN 형식을 검증하는 하위 자원에 사용할 가상 ARN입니다.
    defaults = {                                                                                  # 실제 IAM 역할을 만들지 않습니다.
      arn = "arn:aws:iam::123456789012:role/elk-test"                                             # syntactically valid ARN입니다.
    }                                                                                             # 기본 응답을 끝냅니다.
  }                                                                                               # IAM 모킹을 끝냅니다.
  mock_resource "aws_kms_key" {                                                                   # 전달 구성의 KMS ARN을 가상화합니다.
    defaults = {                                                                                  # 실제 키를 생성하지 않습니다.
      arn    = "arn:aws:kms:ap-northeast-2:123456789012:key/00000000-0000-4000-8000-000000000001" # 형식 검증용 ARN입니다.
      key_id = "00000000-0000-4000-8000-000000000001"                                             # 가상 키 ID입니다.
    }                                                                                             # 기본 응답을 끝냅니다.
  }                                                                                               # KMS 모킹을 끝냅니다.
  mock_resource "aws_s3_bucket" {                                                                 # bucket ARN을 참조하는 전달 정책을 위한 가상 응답입니다.
    defaults = {                                                                                  # 실제 버킷을 만들지 않습니다.
      arn = "arn:aws:s3:::elk-validation-test"                                                    # 형식 검증에 필요한 ARN입니다.
    }                                                                                             # 기본 응답을 끝냅니다.
  }                                                                                               # S3 모킹을 끝냅니다.
  mock_resource "aws_sqs_queue" {                                                                 # 정책·알림의 큐 ARN을 제공합니다.
    defaults = {                                                                                  # 실제 SQS 메시지를 생성하지 않습니다.
      arn = "arn:aws:sqs:ap-northeast-2:123456789012:elk-test"                                    # 유효한 큐 ARN입니다.
      url = "https://sqs.ap-northeast-2.amazonaws.com/123456789012/elk-test"                      # 가상 큐 URL입니다.
    }                                                                                             # 기본 응답을 끝냅니다.
  }                                                                                               # SQS 모킹을 끝냅니다.
  mock_resource "aws_cloudwatch_log_group" {                                                      # 구독 필터의 원천 ARN을 제공합니다.
    defaults = {                                                                                  # 실제 로그 그룹을 만들지 않습니다.
      arn = "arn:aws:logs:ap-northeast-2:123456789012:log-group:elk-test"                         # 형식이 유효한 로그 그룹 ARN입니다.
    }                                                                                             # 기본 응답을 끝냅니다.
  }                                                                                               # 로그 그룹 모킹을 끝냅니다.
  mock_resource "aws_kinesis_firehose_delivery_stream" {                                          # 구독 목적지 ARN을 제공합니다.
    defaults = {                                                                                  # 실제 Firehose를 만들지 않습니다.
      arn = "arn:aws:firehose:ap-northeast-2:123456789012:deliverystream/elk-test"                # 형식이 유효한 stream ARN입니다.
    }                                                                                             # 기본 응답을 끝냅니다.
  }                                                                                               # Firehose 모킹을 끝냅니다.
  mock_resource "aws_sns_topic" {                                                                 # 선택적 알림 대상 ARN을 제공합니다.
    defaults = {                                                                                  # 실제 SNS 알림을 보내지 않습니다.
      arn = "arn:aws:sns:ap-northeast-2:123456789012:elk-test"                                    # 가상 SNS ARN입니다.
    }                                                                                             # 기본 응답을 끝냅니다.
  }                                                                                               # SNS 모킹을 끝냅니다.
  mock_resource "aws_guardduty_detector" {                                                        # 새 detector의 형식 검증용 ID를 제공합니다.
    defaults = {                                                                                  # 실제 GuardDuty를 활성화하지 않습니다.
      id = "00000000000000000000000000000001"                                                     # 32자리 detector ID입니다.
    }                                                                                             # 기본 응답을 끝냅니다.
  }                                                                                               # GuardDuty 모킹을 끝냅니다.
}                                                                                                 # 모의 AWS provider 설정을 끝냅니다.

variables {                                     # 모든 시험에서 사용할 비밀정보 없는 입력입니다.
  expected_account_id = "123456789012"          # 가상 계정을 선택합니다.
  vpc_id              = "vpc-0123456789abcdef0" # 가상 VPC입니다.
  ami_id              = "ami-0123456789abcdef0" # 공개 SSM 조회도 하지 않도록 AMI를 고정합니다.
  private_subnet_ids = {                        # 세 역할의 가상 subnet을 지정합니다.
    collector     = "subnet-0123456789abcdef0"  # 수집 역할입니다.
    elasticsearch = "subnet-0123456789abcdef0"  # 저장 역할입니다.
    kibana        = "subnet-0123456789abcdef0"  # 조회 역할입니다.
  }                                             # subnet 입력을 끝냅니다.
}                                               # 공통 입력을 끝냅니다.

run "platform_only" {                                                                                    # 기존 소스의 설정을 바꾸지 않는 기본 계획을 검증합니다.
  command = plan                                                                                         # 실제 리소스 적용을 수행하지 않습니다.
  assert {                                                                                               # EC2 수가 처음 합의한 세 대인지 확인합니다.
    condition     = length(aws_instance.node) == 3                                                       # 정확히 세 역할이어야 합니다.
    error_message = "초기 플랫폼 EC2는 총 3대여야 합니다."                                                            # 실패 이유입니다.
  }                                                                                                      # EC2 수 검증을 끝냅니다.
  assert {                                                                                               # 기본 설정에서 새 CloudTrail을 켜지 않는지 확인합니다.
    condition     = !var.create_cloudtrail && !var.manage_waf_logging && !var.enable_guardduty_export    # 기존 로그 목적지를 기본으로 변경하지 않습니다.
    error_message = "기존 로그 연결 변경은 명시적으로 선택해야 합니다."                                                       # 실패 이유입니다.
  }                                                                                                      # 기본 연결 정책 검증을 끝냅니다.
  assert {                                                                                               # 공개 IP가 없는지 확인합니다.
    condition     = alltrue([for node in aws_instance.node : node.associate_public_ip_address == false]) # 세 EC2 모두 private입니다.
    error_message = "플랫폼 EC2에 공개 IP를 부여하면 안 됩니다."                                                        # 실패 이유입니다.
  }                                                                                                      # 공개 IP 검증을 끝냅니다.
}                                                                                                        # 기본 계획 시험을 끝냅니다.

run "all_new_sources" {                                                                                                                   # 사용자가 명시적으로 선택한 새 소스 경로를 검증합니다.
  command = plan                                                                                                                          # AWS 생성 없이 전체 의존성을 계획합니다.
  variables {                                                                                                                             # 이 시험에서만 소스를 활성화합니다.
    create_cloudtrail         = true                                                                                                      # 새 검증 Trail입니다.
    create_guardduty_detector = true                                                                                                      # 새 검증 detector입니다.
    enable_guardduty_export   = true                                                                                                      # 새 S3 export입니다.
    manage_waf_logging        = true                                                                                                      # 기존 ACL의 로깅만 이 상태에서 관리합니다.
    waf_web_acl_arn           = "arn:aws:wafv2:ap-northeast-2:123456789012:regional/webacl/elk-test/00000000-0000-4000-8000-000000000002" # 가상 regional ACL입니다.
    enable_alerting           = true                                                                                                      # SNS·EventBridge 계획도 검사합니다.
  }                                                                                                                                       # 소스 입력을 끝냅니다.
  assert {                                                                                                                                # 새로운 소스 선택 때문에 EC2가 늘어나지 않아야 합니다.
    condition     = length(aws_instance.node) == 3                                                                                        # 수집 소스 수와 EC2 수를 분리합니다.
    error_message = "소스 활성화가 플랫폼 EC2 수를 바꾸면 안 됩니다."                                                                                       # 실패 이유입니다.
  }                                                                                                                                       # topology 검증을 끝냅니다.
}                                                                                                                                         # 새 소스 계획 시험을 끝냅니다.

run "reuse_cloudtrail_archive" {                                                                                             # 기존 Trail·원본 버킷의 소유권을 유지하는 계획입니다.
  command = plan                                                                                                             # 기존 AWS 버킷을 실제로 조회·변경하지 않습니다.
  variables {                                                                                                                # 기존 원본의 가상 연결값입니다.
    existing_cloudtrail_bucket_name   = "existing-audit-test"                                                                # 새 raw 버킷으로 목적지를 바꾸지 않습니다.
    existing_cloudtrail_object_prefix = "AWSLogs/123456789012/CloudTrail/"                                                   # 일반 이벤트만 읽는 prefix입니다.
    existing_cloudtrail_kms_key_arns  = ["arn:aws:kms:ap-northeast-2:123456789012:key/00000000-0000-4000-8000-000000000003"] # 기존 키 권한의 입력입니다.
  }                                                                                                                          # 기존 원본 입력을 끝냅니다.
  assert {                                                                                                                   # source ARN이 실제로 기존 버킷을 향하는지 확인합니다.
    condition     = local.cloudtrail_bucket_arn == "arn:aws:s3:::existing-audit-test"                                        # 정책·알림 연결 대상입니다.
    error_message = "기존 CloudTrail 버킷을 참조해야 합니다."                                                                            # 실패 이유입니다.
  }                                                                                                                          # 기존 원본 대상 검증을 끝냅니다.
}                                                                                                                            # 기존 원본 계획 시험을 끝냅니다.

run "resource_naming" {                                                                                                                                                                                                                                                                                                                                                                                                                                                   # 직접 지정 가능한 AWS 이름과 이름을 지정할 수 없는 자원의 태그를 확인합니다.
  command = plan                                                                                                                                                                                                                                                                                                                                                                                                                                                          # AWS에 배포하지 않고 명명 규칙을 검증합니다.
  variables {                                                                                                                                                                                                                                                                                                                                                                                                                                                             # 선택 자원의 이름도 함께 검사합니다.
    create_cloudtrail         = true                                                                                                                                                                                                                                                                                                                                                                                                                                      # Trail 이름과 관련 ARN을 계산합니다.
    create_guardduty_detector = true                                                                                                                                                                                                                                                                                                                                                                                                                                      # 이름 대신 Name 태그를 검사할 detector입니다.
    enable_guardduty_export   = true                                                                                                                                                                                                                                                                                                                                                                                                                                      # 기존 소스와 분리된 검증 목적지입니다.
    enable_alerting           = true                                                                                                                                                                                                                                                                                                                                                                                                                                      # SNS·EventBridge·알람의 이름을 확인합니다.
  }                                                                                                                                                                                                                                                                                                                                                                                                                                                                       # 검증용 선택 자원 설정을 마칩니다.
  assert {                                                                                                                                                                                                                                                                                                                                                                                                                                                                # EC2 Name 태그와 보안 그룹 이름을 확인합니다.
    condition     = alltrue([for role in local.roles : aws_instance.node[role].tags.Name == "whs-elk-ec2-${role}" && aws_security_group.node[role].name == "whs-elk-sg-${role}"])                                                                                                                                                                                                                                                                                         # 자원 종류와 역할을 모두 표시해야 합니다.
    error_message = "EC2와 보안 그룹의 새 명명 규칙이 일치해야 합니다."                                                                                                                                                                                                                                                                                                                                                                                                                      # 명명 누락을 보고합니다.
  }                                                                                                                                                                                                                                                                                                                                                                                                                                                                       # 컴퓨팅 이름 검사를 마칩니다.
  assert {                                                                                                                                                                                                                                                                                                                                                                                                                                                                # S3의 유일성 suffix와 길이 제한을 확인합니다.
    condition     = alltrue([for role, bucket in aws_s3_bucket.data : bucket.bucket == "whs-elk-s3-${role}-123456789012-ap-northeast-2" && length(bucket.bucket) <= 63])                                                                                                                                                                                                                                                                                                  # 이름 끝에는 가상 계정과 리전이 붙습니다.
    error_message = "S3 이름은 서비스·역할·계정·리전을 포함하고 63자 이하여야 합니다."                                                                                                                                                                                                                                                                                                                                                                                                             # bucket 이름 오류를 보고합니다.
  }                                                                                                                                                                                                                                                                                                                                                                                                                                                                       # 버킷 이름 검사를 마칩니다.
  assert {                                                                                                                                                                                                                                                                                                                                                                                                                                                                # 수집 알림과 DLQ의 용도가 이름으로 구분되는지 확인합니다.
    condition     = alltrue([for source in local.sources : aws_sqs_queue.source[source].name == "whs-elk-sqs-${source}-ingest" && aws_sqs_queue.dlq[source].name == "whs-elk-sqs-${source}-dlq"])                                                                                                                                                                                                                                                                         # 네 소스에 동일하게 적용합니다.
    error_message = "SQS 수집 큐와 DLQ 이름을 구분해야 합니다."                                                                                                                                                                                                                                                                                                                                                                                                                         # 큐 이름 오류를 보고합니다.
  }                                                                                                                                                                                                                                                                                                                                                                                                                                                                       # 큐 이름 검사를 마칩니다.
  assert {                                                                                                                                                                                                                                                                                                                                                                                                                                                                # WAF 필수 접두사 예외와 일반 로그 그룹 이름을 확인합니다.
    condition     = local.log_group_names.cloudwatch == "whs-elk-cloudwatch-workload" && local.log_group_names.waf == "aws-waf-logs-whs-elk-cloudwatch-waf"                                                                                                                                                                                                                                                                                                               # 임의로 WAF 필수 접두사를 제거하면 안 됩니다.
    error_message = "로그 그룹 이름 또는 WAF 필수 접두사가 올바르지 않습니다."                                                                                                                                                                                                                                                                                                                                                                                                                  # 로그 그룹 오류를 보고합니다.
  }                                                                                                                                                                                                                                                                                                                                                                                                                                                                       # 로그 그룹 검사를 마칩니다.
  assert {                                                                                                                                                                                                                                                                                                                                                                                                                                                                # 전송 계층 이름과 구독 이름을 확인합니다.
    condition     = alltrue([for source in local.cwl_sources : aws_kinesis_firehose_delivery_stream.source[source].name == "whs-elk-firehose-${source}-delivery" && aws_cloudwatch_log_subscription_filter.source[source].name == "whs-elk-cloudwatch-${source}-to-firehose"])                                                                                                                                                                                            # 서비스와 역할을 모두 포함합니다.
    error_message = "Firehose 또는 구독 필터의 명명 규칙이 다릅니다."                                                                                                                                                                                                                                                                                                                                                                                                                     # 전송 자원 오류를 보고합니다.
  }                                                                                                                                                                                                                                                                                                                                                                                                                                                                       # 전송 이름 검사를 마칩니다.
  assert {                                                                                                                                                                                                                                                                                                                                                                                                                                                                # 이름이 없는 detector에는 태그가 필요합니다.
    condition     = aws_guardduty_detector.new[0].tags.Name == "whs-elk-guardduty-detector" && aws_cloudtrail.new[0].name == "whs-elk-cloudtrail-management"                                                                                                                                                                                                                                                                                                              # GuardDuty ID와 사람이 읽는 이름을 구분합니다.
    error_message = "GuardDuty Name 태그 또는 CloudTrail 이름이 누락됐습니다."                                                                                                                                                                                                                                                                                                                                                                                                         # 보안 서비스 이름 오류입니다.
  }                                                                                                                                                                                                                                                                                                                                                                                                                                                                       # 보안 서비스 검사를 마칩니다.
  assert {                                                                                                                                                                                                                                                                                                                                                                                                                                                                # 직접 관리하는 모든 IAM 역할의 prefix와 길이를 확인합니다.
    condition     = alltrue([for role in concat(values(aws_iam_role.node), values(aws_iam_role.firehose), values(aws_iam_role.subscription)) : startswith(role.name, "whs-elk-iam-") && length(role.name) <= 64])                                                                                                                                                                                                                                                         # IAM 역할의 64자 제한을 지킵니다.
    error_message = "IAM 역할은 통일 prefix와 길이 제한을 만족해야 합니다."                                                                                                                                                                                                                                                                                                                                                                                                                 # IAM 이름 오류입니다.
  }                                                                                                                                                                                                                                                                                                                                                                                                                                                                       # IAM 검사를 마칩니다.
  assert {                                                                                                                                                                                                                                                                                                                                                                                                                                                                # 알림 대상과 알람의 prefix를 확인합니다.
    condition     = aws_sns_topic.alerts[0].name == "whs-elk-sns-security-alerts" && aws_cloudwatch_event_rule.guardduty[0].name == "whs-elk-eventbridge-guardduty-findings" && alltrue([for alarm in concat(values(aws_cloudwatch_metric_alarm.queue_age), values(aws_cloudwatch_metric_alarm.dlq), values(aws_cloudwatch_metric_alarm.instance_status), values(aws_cloudwatch_metric_alarm.firehose_freshness)) : startswith(alarm.alarm_name, "whs-elk-cloudwatch-")]) # 선택 알림 계층도 같은 규칙을 따릅니다.
    error_message = "SNS·EventBridge·CloudWatch 알람 이름을 확인하세요."                                                                                                                                                                                                                                                                                                                                                                                                            # 알림 이름 오류입니다.
  }                                                                                                                                                                                                                                                                                                                                                                                                                                                                       # 알림 이름 검사를 마칩니다.
}                                                                                                                                                                                                                                                                                                                                                                                                                                                                         # 명명 규칙 검사를 마칩니다.

run "reject_other_name_prefix" {      # 요청한 고정 접두사와 다른 이름 입력을 거부합니다.
  command = plan                      # 리소스를 만들지 않습니다.
  variables {                         # 잘못된 접두사를 넣습니다.
    name_prefix = "other-project"     # 명명 표준을 벗어난 입력입니다.
  }                                   # 잘못된 입력을 마칩니다.
  expect_failures = [var.name_prefix] # 변수 검증에서 거부돼야 성공입니다.
}                                     # 접두사 검사를 마칩니다.

run "reject_duplicate_trail_mode" {                                        # 새 Trail과 기존 원본 선택의 충돌을 확인합니다.
  command = plan                                                           # 입력 검증만 수행합니다.
  variables {                                                              # 서로 충돌하는 모드를 의도적으로 넣습니다.
    create_cloudtrail                 = true                               # 신규 모드를 켭니다.
    existing_cloudtrail_bucket_name   = "existing-audit-test"              # 기존 모드도 켭니다.
    existing_cloudtrail_object_prefix = "AWSLogs/123456789012/CloudTrail/" # 형식은 유효합니다.
  }                                                                        # 오류 입력을 끝냅니다.
  expect_failures = [var.create_cloudtrail]                                # 이 입력이 거부되어야 시험이 통과합니다.
}                                                                          # 잘못된 모드 시험을 끝냅니다.
