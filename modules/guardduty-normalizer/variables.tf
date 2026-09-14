# ==============================================
# 공통
# ==============================================

variable "aws_region" {
  description = "리소스를 만들 리전"
  type        = string
  default     = "ap-northeast-2"
}

variable "name_prefix" {
  description = "IAM 역할 등 부수 리소스 이름 접두사"
  type        = string
  default     = "cloud9-security"
}

variable "tags" {
  description = "공통 태그"
  type        = map(string)
  default     = {}
}

variable "permissions_boundary_arn" {
  description = "계정 정책상 모든 신규 IAM 역할에 필수인 권한 경계"
  type        = string
  default     = "arn:aws:iam::896986966760:policy/WHSProjectRoleBoundary"
}

variable "iam_path" {
  description = "IAM 역할 경로 (기존 modules/iam 컨벤션과 동일)"
  type        = string
  default     = "/whs-project/"
}

# ==============================================
# 정규화 Lambda
# ==============================================

variable "lambda_source_file" {
  description = "정규화 Lambda 파이썬 소스 경로 (예: ../../Lambda/GuardDuty/normalize-guardduty-logs-v2.py)"
  type        = string
}

variable "function_name" {
  description = "정규화 Lambda 함수 이름"
  type        = string
  default     = "normalize-guardduty-logs-v2"
}

variable "python_runtime" {
  description = "Lambda 파이썬 런타임 (콘솔에 배포된 기존 함수와 맞춘다)"
  type        = string
  default     = "python3.14"
}

variable "timeout" {
  description = "Lambda 제한 시간(초). 기본 3초는 gzip 해제 + 다중 S3 적재에 부족하다"
  type        = number
  default     = 30
}

variable "memory_size" {
  description = "Lambda 메모리(MB)"
  type        = number
  default     = 256
}

variable "normalized_bucket" {
  description = "정규화 결과(JSON)를 저장할 S3 버킷 이름"
  type        = string
}

variable "normalized_prefix" {
  description = "정규화 결과 S3 prefix"
  type        = string
  default     = "guardduty"
}

variable "rules_function_name" {
  description = <<-DESC
    정규화 후 호출할 룰 평가 Lambda 이름.
    빈 값이면 호출을 건너뛰므로 룰 평가 Lambda 없이 정규화만 먼저 배포할 수 있다.
  DESC
  type        = string
  default     = ""
}

# ==============================================
# 파인딩 전달 경로 (GuardDuty -> EventBridge -> CloudWatch Logs)
# ==============================================

variable "finding_log_group_name" {
  description = "GuardDuty 파인딩이 적재되는 CloudWatch Logs 그룹 이름"
  type        = string
  default     = "/aws/events/cloud9-security/guardduty"
}

variable "create_finding_delivery" {
  description = <<-DESC
    true  = 로그 그룹과 EventBridge 룰을 이 모듈이 직접 만든다 (전달 경로가 아직 없을 때)
    false = 이미 있는 로그 그룹에 구독 필터만 건다 (콘솔이나 다른 모듈이 이미 만들어 둔 경우)

    판단 방법:
      aws logs describe-log-groups --region ap-northeast-2 \
        --log-group-name-prefix /aws/events/cloud9-security/guardduty
    결과가 비어 있으면 true, 이미 있으면 false.
  DESC
  type        = bool
  default     = true
}

variable "finding_log_retention_days" {
  description = "파인딩 로그 그룹 보존 기간(일). create_finding_delivery = true 일 때만 사용"
  type        = number
  default     = 90
}
