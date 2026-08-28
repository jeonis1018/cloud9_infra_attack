output "bucket_id" {
  value       = aws_s3_bucket.target.id
  description = "attack 스크립트의 유출 타겟 버킷명"
}

output "bucket_arn" {
  value       = aws_s3_bucket.target.arn
  description = "iam 모듈에서 참조"
}

output "vpc_endpoint_id" {
  value       = aws_vpc_endpoint.s3.id
  description = "참고/로깅용"
}

output "profile_bucket_id" {
  value       = aws_s3_bucket.profile.id
  description = "webapp이 프로필 이미지를 저장하는 버킷명"
}

output "profile_bucket_arn" {
  value       = aws_s3_bucket.profile.arn
  description = "iam 모듈에서 참조"
}
