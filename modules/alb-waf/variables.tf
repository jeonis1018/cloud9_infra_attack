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

variable "cloudwatch_agent_response_ip_sets" {
  description = "자동 대응 모듈의 IPv4/IPv6 IP set ARN. null이면 기존 WAF 규칙과 우선순위를 유지합니다."
  type = object({
    ipv4_arn = string
    ipv6_arn = string
  })
  default = null

  validation {
    condition = var.cloudwatch_agent_response_ip_sets == null ? true : alltrue([
      can(regex("^arn:aws:wafv2:ap-northeast-2:896986966760:regional/ipset/respond-cloudwatch-agent-logs-ipv4/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.cloudwatch_agent_response_ip_sets.ipv4_arn)),
      can(regex("^arn:aws:wafv2:ap-northeast-2:896986966760:regional/ipset/respond-cloudwatch-agent-logs-ipv6/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.cloudwatch_agent_response_ip_sets.ipv6_arn))
    ])
    error_message = "Use the team's respond-cloudwatch-agent-logs-ipv4 and -ipv6 REGIONAL IP sets in account 896986966760, ap-northeast-2."
  }
}
