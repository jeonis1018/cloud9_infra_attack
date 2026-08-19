# ALB
output "alb_arn" {
    description = "ALB의 ARN"
    value = aws_lb.this.arn
}

output "alb_dns_name" {
    description = "ALB 접속용 DNS 이름"
    value = aws_lb.this.dns_name
}

output "alb_zone_id" {
    description = "ALB의 Route53 Hosted Zone ID (도메인 연결 시 사용)"
    value = aws_lb.this.zone_id
}

# Target Group
output "target_group_arn" {
    description = "Target Group ARN (EC2 인스턴스 등록 시 사용)"
    value = aws_lb_target_group.this.arn
}

# Security Group
output "alb_security_group_id" {
    description = "ALB Security Group ID (EC2 SG에서 ALB 트래픽 허용 시 참조)"
    value = aws_security_group.alb.id
}