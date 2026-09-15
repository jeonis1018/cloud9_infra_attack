# ==============================================
# 로컬 환경 변수 (개인 별도 설정)
# ==============================================

variable "aws_profile" {
  description = "로컬 AWS CLI 프로필 이름 (각자 환경에 맞게 설정)"
  type        = string
}

# ==============================================
# Before/After 스위치 변수
# ==============================================

variable "enable_imdsv2" {
  description = "true=IMDSv2 강제(방어), false=IMDSv1 허용(취약)"
  type        = bool
}

variable "enable_least_privilege" {
  description = "true=최소권한 IAM 정책(방어), false=과다권한(취약)"
  type        = bool
}

variable "allowed_vpc_endpoint_only" {
  description = "true=VPC Endpoint 경유만 허용(방어), false=제한 없음(취약)"
  type        = bool
}

# ==============================================
# GuardDuty 정규화 변수
# ==============================================

variable "normalized_bucket" {
  description = "정규화 결과 저장 버킷. CloudTrail 정규화와 같은 버킷을 쓰고 prefix로만 구분한다"
  type        = string
}

variable "create_finding_delivery" {
  description = <<-DESC
    true  = 파인딩 로그 그룹과 EventBridge 룰을 새로 만든다
    false = 이미 있는 로그 그룹에 구독 필터만 건다

    아래 명령 결과가 비어 있으면 true, 이미 있으면 false로 둔다.
    (이미 있는데 true로 두면 "이미 존재함" 오류로 apply가 실패한다)
      aws logs describe-log-groups --region ap-northeast-2 \
        --log-group-name-prefix /aws/events/cloud9-security/guardduty
  DESC
  type        = bool
  default     = true
}

variable "rules_function_name" {
  description = "룰 평가 Lambda 이름. 비워두면 정규화까지만 수행한다"
  type        = string
  default     = ""
}