# Security Group 생성
resource "aws_security_group" "alb" {
    name = "${var.vpc_name}-ALB-SG"
    description = "Allow HTTPS traffic"
    vpc_id = var.vpc_id

    ingress {
        description = "HTTPS from Internet"
        from_port = 443
        to_port = 443
        protocol = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    egress {
        description = "All bound"
        from_port = 0
        to_port = 0
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }

    tags = {
        Name = "${var.vpc_name}-ALB-SG"
    }
}

# Target Group 생성
resource "aws_lb_target_group" "this" {
    name = "WHS-ALB-TG"
    port = 8080
    protocol = "HTTP"
    vpc_id = var.vpc_id
    target_type = "instance"

    health_check {
    }

    tags = {
        Name = "${var.vpc_name}-ALB-TG"
    }
}


# ALB 생성
resource "aws_lb" "this" {
    name = "WHS-ALB"
    internal = false
    load_balancer_type = "application"
    security_groups = [aws_security_group.alb.id]
    subnets = var.public_subnet_ids

    tags = {
        Name = "WHS_ALB"
    }
}

# HTTPS Listener
resource "aws_lb_listener" "https" {
    load_balancer_arn = aws_lb.this.arn
    port = 443
    protocol = "HTTPS"
    ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
    certificate_arn = var.certificate_arn

    default_action {
        type = "forward"
        target_group_arn = aws_lb_target_group.this.arn
    }
}

# WAF Web ACL
resource "aws_wafv2_web_acl" "this" {
    name = "${var.vpc_name}-WAF"
    description = "ALB inbound protection"
    scope = "REGIONAL"

    default_action {
        allow {}
    }

    rule {
        name = "AWSManagedCommonRuleSet"
        priority = 1

        override_action {
            none {}
        }

        statement {
            managed_rule_group_statement {
                name = "AWSManagedRulesCommonRuleSet"
                vendor_name = "AWS"
            }
        }

        visibility_config {
            cloudwatch_metrics_enabled = true
            metric_name = "${var.vpc_name}-WAF-CommonRuleSet"
            sampled_requests_enabled = true
        }
    }

    rule {
        name = "AWSManagedKnownBadInputs"
        priority = 2

        override_action {
            none {}
        }

        statement {
            managed_rule_group_statement {
                name = "AWSManagedRulesKnownBadInputsRuleSet"
                vendor_name = "AWS"
            }
        }

        visibility_config {
            cloudwatch_metrics_enabled = true
            metric_name = "${var.vpc_name}-WAF-KnownBadInputs"
            sampled_requests_enabled = true
        }
    }

    visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name = "${var.vpc_name}-WAF"
        sampled_requests_enabled = true
    }
    
    tags = {
        Name = "${var.vpc_name}-WAF"
    }
}
resource "aws_wafv2_web_acl_association" "this" {
    resource_arn = aws_lb.this.arn
    web_acl_arn = aws_wafv2_web_acl.this.arn
}