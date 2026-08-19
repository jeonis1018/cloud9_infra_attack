variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "vpc_name" {
  description = "VPC 이름"
  type        = string
  default     = "WHS_VPC"
}

variable "public_subnet_ids" {
  description = "Public 서브넷 ID"
  type        = list(string)
}

variable "certificate_arn" {
  description = "HTTPS에 사용할 ACM 인증서 ARN"
  type        = string
}