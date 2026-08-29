# Security Group 생성
resource "aws_security_group" "alb" {
  name        = "${var.vpc_name}-ALB-SG"
  description = "Allow HTTPS from Internet"
  vpc_id      = var.vpc_id

  ingress {
    description = "Allow HTTPS from Internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All bound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.vpc_name}-ALB-SG"
  }
}

# Target Group 생성
resource "aws_lb_target_group" "this" {
  name        = "WHS-ALB-TG"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  health_check {
  }

  tags = {
    Name = "${var.vpc_name}-ALB-TG"
  }
}


# ALB 생성
resource "aws_lb" "this" {
  name               = "WHS-ALB"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids

  tags = {
    Name = "WHS_ALB"
  }
}

# HTTPS Listener
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

# WAF Web ACL
resource "aws_wafv2_web_acl" "this" {
  name        = "${var.vpc_name}-WAF"
  description = "ALB inbound protection"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.vpc_name}-WAF"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "AWSManagedCommonRuleSet"
    priority = 3

    override_action {
      count {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.vpc_name}-WAF-CommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedKnownBadInputs"
    priority = 4

    override_action {
      count {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.vpc_name}-WAF-KnownBadInputs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedSQLiRuleSet"
    priority = 5

    override_action {
      count {}
    }

    statement{
      managed_rule_group_statement{
        name        = "AWSManagedSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config{
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.vpc_name}-WAF-SQLiRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "GeoBlockNonKR"
    priority = 6 # 기존 규칙(1, 2번)과 안 겹치게

    action {
      block {}
    }

    statement {
      not_statement {
        statement {
          geo_match_statement {
            country_codes = ["KR"]
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.vpc_name}-WAF-GeoBlock"
      sampled_requests_enabled   = true
    }
  }

  tags = {
    Name = "${var.vpc_name}-WAF"
  }

  rule {
    name     = "Custom-IMDS-SSRF-QueryArguments"
    priority = 0

    statement {
      regex_match_statement {
        regex_string = "169\\.254\\.169\\.254|2852039166|0xa9fea9fe|0251\\.0376\\.0251\\.0376|169\\.254\\.43518|169\\.16689662|::ffff:169\\.254\\.169\\.254|fd00:ec2::254|/latest/meta-data/|/latest/meta-data$|/latest/user-data/|/latest/user-data$|/latest/dynamic/|/latest/dynamic$"

        field_to_match {
          all_query_arguments {}
        }

        text_transformation {
          priority = 0
          type     = "URL_DECODE"
        }

        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }

        text_transformation {
          priority = 2
          type     = "LOWERCASE"
        }
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "WHS-WAF-CustomIMDSSSRF"
    }

    action {
     count {}
    }
  }

  rule {
    name     = "Custom-IMDS-SSRF-Body"
    priority = 1

    statement {
      regex_match_statement {
        regex_string = "169\\.0*254\\.0*169\\.0*254|::ffff:169\\.254\\.169\\.254|::ffff:a9fe:a9fe|fd00:0*ec2:(0\\*:)*0*254|2852039166|0xa9fea9fe|0xa9\\.0xfe\\.0xa9\\.0xfe|0251\\.0376\\.0251\\.0376|169\\.254\\.43518|169\\.16689662|/latest/meta-data|/latest/user-data|/latest/dynamic|/latest/api/token|identity-credentials/ec2/security-credentials"

        field_to_match {
          body {
            oversize_handling = "CONTINUE"
          }
        }

        text_transformation {
          priority = 0
          type     = "URL_DECODE"
        }

        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }

        text_transformation {
          priority = 2
          type     = "LOWERCASE"
        }
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "WHS-WAF-CustomIMDSSSRFBody"
    }

    action {
     count {}
    }
  }

  rule {
    name     = "RateLimit-PerIP"
    priority = 2

    statement {
      rate_based_statement {
        limit              = 100
        aggregate_key_type = "IP"
        evaluation_window_sec = 60
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "WHS-WAF-RateLimitPerIP"
    }

    action {
     count {}
    }
  }
}

resource "aws_wafv2_web_acl_association" "this" {
  resource_arn = aws_lb.this.arn
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}

# CloudWatch Logs Groups 생성
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-cloud9-security"
  retention_in_days = 3

  tags = {
    Name = "aws-waf-logs-cloud9-security"
  }
}

# Web ACL Logging Setting
resource "aws_wafv2_web_acl_logging_configuration" "this" {
  resource_arn = aws_wafv2_web_acl.this.arn

  log_destination_configs = [
    aws_cloudwatch_log_group.waf.arn
  ]

  depends_on = [
    aws_cloudwatch_log_group.waf
  ]
}