output "attack_target_bucket_name" {
  description = "S3 bucket monitored by the separate security stack."
  value       = module.s3_endpoint.bucket_id
}

output "attack_target_bucket_arn" {
  value = module.s3_endpoint.bucket_arn
}
