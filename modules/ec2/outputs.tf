output "instance_ids" {
  description = "IDs of the private EC2 web application instances."
  value       = aws_instance.web[*].id
}

output "instance_private_ips" {
  description = "Private IP addresses of the EC2 web application instances."
  value       = aws_instance.web[*].private_ip
}
