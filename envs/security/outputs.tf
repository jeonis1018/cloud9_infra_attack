output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "protected_attack_bucket" {
  value = local.attack_bucket_name
}

output "trail_arn" {
  value = aws_cloudtrail.security.arn
}

output "cloudtrail_log_group" {
  value = aws_cloudwatch_log_group.cloudtrail.name
}

output "result_bucket" {
  value = aws_s3_bucket.results.id
}

output "normalizer_function_name" {
  value = aws_lambda_function.normalizer.function_name
}

output "detector_function_name" {
  value = aws_lambda_function.detector.function_name
}

output "tampering_function_name" {
  value = aws_lambda_function.tampering.function_name
}

output "tampering_schedule_arn" {
  value = aws_scheduler_schedule.tampering.arn
}

