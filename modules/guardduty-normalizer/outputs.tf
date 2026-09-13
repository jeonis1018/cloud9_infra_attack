output "function_name" {
  description = "생성된 정규화 Lambda 함수 이름"
  value       = aws_lambda_function.normalizer.function_name
}

output "function_arn" {
  description = "정규화 Lambda ARN"
  value       = aws_lambda_function.normalizer.arn
}

output "role_arn" {
  description = "정규화 Lambda 실행 역할 ARN"
  value       = aws_iam_role.normalizer.arn
}

output "finding_log_group_name" {
  description = "구독 필터를 건 파인딩 로그 그룹 이름"
  value       = local.finding_log_group_name
}

output "normalized_s3_path" {
  description = "정규화 결과가 쌓이는 S3 경로"
  value       = "s3://${var.normalized_bucket}/${var.normalized_prefix}/"
}
