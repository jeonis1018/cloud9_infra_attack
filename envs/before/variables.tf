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