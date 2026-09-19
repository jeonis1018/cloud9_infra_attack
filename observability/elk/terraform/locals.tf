data "aws_caller_identity" "current" {} # 실제 인증된 계정 ID를 읽습니다.
data "aws_partition" "current" {}       # AWS ARN의 partition을 조회합니다.

data "aws_vpc" "existing" { # 기존 VPC를 읽기만 합니다.
  id = var.vpc_id           # 사용자가 확인한 VPC입니다.
}                           # 조회를 끝냅니다.

data "aws_subnet" "selected" {      # 역할별 subnet을 확인합니다.
  for_each = var.private_subnet_ids # 세 역할을 각각 확인합니다.
  id       = each.value             # 기존 subnet ID입니다.
}                                   # 조회를 끝냅니다.

data "aws_ssm_parameter" "ubuntu" {                                                            # Canonical이 공개하는 Ubuntu 24.04 amd64 AMI를 읽습니다.
  count = var.ami_id == null ? 1 : 0                                                           # AMI를 고정한 경우 조회하지 않습니다.
  name  = "/aws/service/canonical/ubuntu/server/noble/stable/current/amd64/hvm/ebs-gp3/ami-id" # 공식 Ubuntu SSM parameter 경로입니다.
}                                                                                              # 조회를 끝냅니다.

locals {                                                                                                                                                                     # 반복 사용하는 이름과 수집 계약을 한곳에 정의합니다.
  account_id            = data.aws_caller_identity.current.account_id                                                                                                        # 현재 계정입니다.
  partition             = data.aws_partition.current.partition                                                                                                               # 일반 AWS에서는 aws입니다.
  region                = var.aws_region                                                                                                                                     # 선택한 리전입니다.
  roles                 = toset(["collector", "elasticsearch", "kibana"])                                                                                                    # EC2는 정확히 세 역할입니다.
  sources               = toset(["cloudtrail", "cloudwatch", "waf", "guardduty"])                                                                                            # SQS는 네 소스별로 만듭니다.
  cwl_sources           = toset(["cloudwatch", "waf"])                                                                                                                       # CWL을 통해 전달되는 두 소스입니다.
  bucket_suffix         = "${local.account_id}-${local.region}"                                                                                                              # 계정·리전을 넣어 전역 이름 충돌을 줄입니다.
  trail_name            = "${var.name_prefix}-cloudtrail-management"                                                                                                         # 선택적으로 만들 Trail 이름입니다.
  trail_arn             = "arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}"                                                  # 정책 순환 참조를 피하는 예상 ARN입니다.
  detector_id           = var.create_guardduty_detector ? aws_guardduty_detector.new[0].id : var.guardduty_detector_id                                                       # 선택한 detector입니다.
  detector_arn          = "arn:${local.partition}:guardduty:${local.region}:${local.account_id}:detector/${local.detector_id}"                                               # 선택한 detector의 ARN입니다.
  cloudtrail_bucket_arn = var.existing_cloudtrail_bucket_name != null ? "arn:${local.partition}:s3:::${var.existing_cloudtrail_bucket_name}" : aws_s3_bucket.data["raw"].arn # CT만 기존 버킷을 쓸 수 있습니다.
  selected_ami          = var.ami_id != null ? var.ami_id : nonsensitive(data.aws_ssm_parameter.ubuntu[0].value)                                                             # AMI ID는 비밀이 아닙니다.
  log_group_names = {                                                                                                                                                        # 신규/기존 로그 그룹을 공통 이름으로 정리합니다.
    cloudwatch = coalesce(var.existing_log_group_names.cloudwatch, "${var.name_prefix}-cloudwatch-workload")                                                                 # Agent 대상 그룹입니다.
    waf        = coalesce(var.existing_log_group_names.waf, "aws-waf-logs-${var.name_prefix}-cloudwatch-waf")                                                                # WAF가 요구하는 이름 접두사입니다.
  }                                                                                                                                                                          # 이름 매핑을 끝냅니다.
  notification_prefixes = {                                                                                                                                                  # CloudTrail digest를 일반 이벤트 파서에서 제외합니다.
    cloudtrail = "cloudtrail/AWSLogs/${local.account_id}/CloudTrail/"                                                                                                        # 다중 리전 로그가 이 경로 아래에 모입니다.
    cloudwatch = "cloudwatch/"                                                                                                                                               # 정상 전달된 CWL envelope입니다.
    waf        = "waf/"                                                                                                                                                      # 정상 전달된 WAF CWL envelope입니다.
    guardduty  = "guardduty/"                                                                                                                                                # GuardDuty JSONL입니다.
  }                                                                                                                                                                          # prefix 계약을 끝냅니다.
  enabled_raw_notification_prefixes = { for source, prefix in local.notification_prefixes : source => prefix if source != "cloudtrail" || var.create_cloudtrail }            # 기존 Trail의 알림은 원본 소유 스택에서 관리합니다.
}                                                                                                                                                                            # 공통 계산을 끝냅니다.
