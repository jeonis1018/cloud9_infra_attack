variable "vpc_id" {
  type        = string
  description = "VPC ID (vpc 모듈 output)"
}

variable "private_route_table_ids" {
  type        = list(string)
  description = "Gateway Endpoint를 연결할 Private Route Table ID 목록 (vpc 모듈 output)"
}

variable "allowed_vpc_endpoint_only" {
  type        = bool
  description = "true면 버킷 정책에 aws:sourceVpce 조건을 걸어 VPC 엔드포인트 경유 요청만 허용 (before=false, after=true)"
  default     = false
}

variable "bucket_name_prefix" {
  type        = string
  description = "S3 버킷 이름 접두사. 전역 유일성을 위해 뒤에 랜덤 suffix가 붙는다"
  default     = "cloud9-attack-target"
}
