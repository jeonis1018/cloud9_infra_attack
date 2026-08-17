output "ec2_instance_profile_name" {
  description = "Name of the instance profile to attach to EC2 instances."
  value       = aws_iam_instance_profile.ec2.name
}

output "ec2_role_arn" {
  description = "ARN of the IAM role assumed by EC2 instances."
  value       = aws_iam_role.ec2.arn
}
