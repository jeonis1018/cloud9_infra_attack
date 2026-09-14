# Reuse the team's delivery path; the detector itself must already be enabled.
module "guardduty_normalizer" {
  source                   = "../../modules/guardduty-normalizer"
  lambda_source_file       = "${path.module}/../../Lambda/GuardDuty/normalize-guardduty-logs-v2.py"
  normalized_bucket        = aws_s3_bucket.results.id
  normalized_prefix        = "guardduty"
  rules_function_name      = aws_lambda_function.detector.function_name
  permissions_boundary_arn = var.permissions_boundary_arn
  create_finding_delivery  = true
}
