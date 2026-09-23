# These plans expand both actual sibling modules. AWS is mocked; the archive
# provider is real. No apply or shared-resource local-exec helper runs.
mock_provider "aws" {
  override_during = plan

  mock_data "aws_caller_identity" {
    defaults = { account_id = "896986966760" }
  }
  mock_data "aws_region" {
    defaults = { region = "ap-northeast-2" }
  }
  mock_data "aws_s3_bucket" {
    defaults = { region = "ap-northeast-2", arn = "arn:aws:s3:::cloud9-security-normalized-logs-896986966760-ap-northeast-2-an" }
  }
  mock_data "aws_wafv2_web_acl" {
    defaults = { arn = "arn:aws:wafv2:ap-northeast-2:896986966760:regional/webacl/WHS_VPC-WAF/0d04b6a4-be8a-4de8-b094-9c914efceb72" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::896986966760:role/test-execution-role" }
  }
  mock_resource "aws_lambda_function" {
    defaults = { arn = "arn:aws:lambda:ap-northeast-2:896986966760:function:test-function" }
  }
  mock_resource "aws_sqs_queue" {
    defaults = { arn = "arn:aws:sqs:ap-northeast-2:896986966760:test-queue", url = "https://sqs.ap-northeast-2.amazonaws.com/896986966760/test-queue" }
  }
  mock_resource "aws_dynamodb_table" {
    defaults = { arn = "arn:aws:dynamodb:ap-northeast-2:896986966760:table/respond-cloudwatch-agent-logs-state" }
  }
  mock_resource "aws_sfn_state_machine" {
    defaults = { arn = "arn:aws:states:ap-northeast-2:896986966760:stateMachine:respond-cloudwatch-agent-logs" }
  }
  mock_resource "aws_security_group" {
    defaults = { id = "sg-0123456789abcdef0" }
  }
  mock_resource "aws_lb" {
    defaults = { arn = "arn:aws:elasticloadbalancing:ap-northeast-2:896986966760:loadbalancer/app/WHS-ALB/d0ff76940805c393" }
  }
  mock_resource "aws_lb_target_group" {
    defaults = { arn = "arn:aws:elasticloadbalancing:ap-northeast-2:896986966760:targetgroup/WHS-ALB-TG/0123456789abcdef" }
  }
  mock_resource "aws_wafv2_web_acl" {
    defaults = { arn = "arn:aws:wafv2:ap-northeast-2:896986966760:regional/webacl/WHS_VPC-WAF/0d04b6a4-be8a-4de8-b094-9c914efceb72" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:ap-northeast-2:896986966760:log-group:aws-waf-logs-cloud9-security" }
  }
}

run "response_enabled_with_existing_alb_module" {
  command = plan
  module {
    source = "./tests/fixtures/with-alb"
  }
  variables {
    enabled = true
  }

  override_data {
    target = module.cloudwatch_agent[0].data.aws_wafv2_ip_set.manual_v4
    values = { id = "864beb1b-e691-4600-86d0-c33bc201a5f3", addresses = ["203.0.113.4/32"] }
  }
  override_data {
    target = module.cloudwatch_agent[0].data.aws_wafv2_ip_set.manual_v6
    values = { id = "b2125780-9c82-481c-8313-46fd987132d3", addresses = ["2001:db8::4/128"] }
  }
  override_resource {
    target = module.cloudwatch_agent[0].aws_wafv2_ip_set.block["ipv4"]
    values = {
      id  = "11111111-1111-1111-1111-111111111111"
      arn = "arn:aws:wafv2:ap-northeast-2:896986966760:regional/ipset/respond-cloudwatch-agent-logs-ipv4/11111111-1111-1111-1111-111111111111"
    }
    override_during = plan
  }
  override_resource {
    target = module.cloudwatch_agent[0].aws_wafv2_ip_set.block["ipv6"]
    values = {
      id  = "22222222-2222-2222-2222-222222222222"
      arn = "arn:aws:wafv2:ap-northeast-2:896986966760:regional/ipset/respond-cloudwatch-agent-logs-ipv6/22222222-2222-2222-2222-222222222222"
    }
    override_during = plan
  }

  assert {
    condition = (
      length(module.cloudwatch_agent) == 1 &&
      length(output.response_function_names) == 3 &&
      output.response_function_names.responder == "respond-cloudwatch-agent-logs" &&
      output.response_ip_sets.ipv4_arn == "arn:aws:wafv2:ap-northeast-2:896986966760:regional/ipset/respond-cloudwatch-agent-logs-ipv4/11111111-1111-1111-1111-111111111111" &&
      output.response_ip_sets.ipv6_arn == "arn:aws:wafv2:ap-northeast-2:896986966760:regional/ipset/respond-cloudwatch-agent-logs-ipv6/22222222-2222-2222-2222-222222222222" &&
      output.alb_arn == "arn:aws:elasticloadbalancing:ap-northeast-2:896986966760:loadbalancer/app/WHS-ALB/d0ff76940805c393"
    )
    error_message = "The enabled sibling modules must plan together and pass the exact response IP sets into the existing ALB/WAF module without a graph cycle."
  }
}

run "response_disabled_keeps_existing_alb_module" {
  command = plan
  module {
    source = "./tests/fixtures/with-alb"
  }
  variables {
    enabled = false
  }

  assert {
    condition = (
      length(module.cloudwatch_agent) == 0 &&
      length(output.response_function_names) == 0 &&
      output.response_ip_sets == null &&
      output.alb_arn == "arn:aws:elasticloadbalancing:ap-northeast-2:896986966760:loadbalancer/app/WHS-ALB/d0ff76940805c393"
    )
    error_message = "Disabling the response module must keep the ALB/WAF module while omitting every response function and optional IP set input."
  }
}
