resource "aws_sns_topic" "alerts" {                           # 수신자 연결 전까지 알림을 외부로 보내지 않습니다.
  tags  = { Name = "${var.name_prefix}-sns-security-alerts" } # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  count = var.enable_alerting ? 1 : 0                         # 사용자가 알림 경로를 선택한 경우입니다.
  name  = "${var.name_prefix}-sns-security-alerts"            # GuardDuty와 플랫폼 알림 주제입니다.
}                                                             # 이메일/웹훅 구독은 자동 생성하지 않습니다.

resource "aws_sns_topic_policy" "alerts" {                                                                                                                   # EventBridge와 CloudWatch 알림 발행을 허용합니다.
  count = var.enable_alerting ? 1 : 0                                                                                                                        # 주제 활성화에 맞춥니다.
  arn   = aws_sns_topic.alerts[0].arn                                                                                                                        # 대상 주제입니다.
  policy = jsonencode({                                                                                                                                      # SNS resource policy입니다.
    Version = "2012-10-17"                                                                                                                                   # 정책 버전입니다.
    Statement = [                                                                                                                                            # 동작별 허용문입니다.
      {                                                                                                                                                      # 현재 계정 관리자가 주제와 구독을 관리합니다.
        Sid       = "AccountAdministration"                                                                                                                  # 관리 권한입니다.
        Effect    = "Allow"                                                                                                                                  # 허용문입니다.
        Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }                                                                         # 현재 계정 IAM으로 위임합니다.
        Action    = "sns:*"                                                                                                                                  # 실제 관리자는 자기 IAM 권한도 필요합니다.
        Resource  = aws_sns_topic.alerts[0].arn                                                                                                              # 이 주제로 한정합니다.
      },                                                                                                                                                     # 관리 허용문을 끝냅니다.
      {                                                                                                                                                      # EventBridge의 SNS 대상 정책은 조건 블록 없이 공식 형식을 사용합니다.
        Sid       = "EventBridgePublish"                                                                                                                     # 탐지 이벤트 발행입니다.
        Effect    = "Allow"                                                                                                                                  # 허용문입니다.
        Principal = { Service = "events.amazonaws.com" }                                                                                                     # EventBridge 서비스입니다.
        Action    = "sns:Publish"                                                                                                                            # 발행만 허용합니다.
        Resource  = aws_sns_topic.alerts[0].arn                                                                                                              # 이 주제로 한정합니다.
      },                                                                                                                                                     # EventBridge 발행문을 끝냅니다.
      {                                                                                                                                                      # 현재 계정·리전의 CloudWatch alarm만 발행합니다.
        Sid       = "CloudWatchAlarmsPublish"                                                                                                                # 플랫폼 장애 알림입니다.
        Effect    = "Allow"                                                                                                                                  # 허용문입니다.
        Principal = { Service = "cloudwatch.amazonaws.com" }                                                                                                 # CloudWatch 서비스입니다.
        Action    = "sns:Publish"                                                                                                                            # 발행만 허용합니다.
        Resource  = aws_sns_topic.alerts[0].arn                                                                                                              # 이 주제로 한정합니다.
        Condition = {                                                                                                                                        # 알람 소스를 제한합니다.
          StringEquals = { "aws:SourceAccount" = local.account_id }                                                                                          # 현재 계정입니다.
          ArnLike      = { "aws:SourceArn" = "arn:${local.partition}:cloudwatch:${local.region}:${local.account_id}:alarm:${var.name_prefix}-cloudwatch-*" } # 이 패키지 알람입니다.
        }                                                                                                                                                    # 조건을 끝냅니다.
      }                                                                                                                                                      # CloudWatch 발행문을 끝냅니다.
    ]                                                                                                                                                        # 허용문 목록을 끝냅니다.
  })                                                                                                                                                         # 정책 JSON을 끝냅니다.
}                                                                                                                                                            # SNS 정책을 끝냅니다.

resource "aws_cloudwatch_event_rule" "guardduty" {                       # ELK 중단과 독립된 탐지 알림 경로입니다.
  tags  = { Name = "${var.name_prefix}-eventbridge-guardduty-findings" } # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  count = var.enable_alerting ? 1 : 0                                    # 선택적으로 만듭니다.
  name  = "${var.name_prefix}-eventbridge-guardduty-findings"            # 규칙 이름입니다.
  event_pattern = jsonencode({                                           # GuardDuty Findings 이벤트를 선택합니다.
    source      = ["aws.guardduty"]                                      # GuardDuty 발행 이벤트입니다.
    detail-type = ["GuardDuty Finding"]                                  # 탐지 결과 이벤트입니다.
    account     = [local.account_id]                                     # 현재 계정 이벤트입니다.
  })                                                                     # 이벤트 패턴을 끝냅니다.
}                                                                        # EventBridge 규칙을 끝냅니다.

resource "aws_cloudwatch_event_target" "guardduty" {            # 탐지 결과를 SNS에 전달합니다.
  count      = var.enable_alerting ? 1 : 0                      # 선택 알림입니다.
  rule       = aws_cloudwatch_event_rule.guardduty[0].name      # 위 규칙에 연결합니다.
  target_id  = "${var.name_prefix}-eventbridge-security-alerts" # 규칙 내 대상 식별자입니다.
  arn        = aws_sns_topic.alerts[0].arn                      # SNS 주제입니다.
  depends_on = [aws_sns_topic_policy.alerts]                    # 발행 권한을 먼저 만듭니다.
}                                                               # 이벤트 대상을 끝냅니다.

resource "aws_cloudwatch_metric_alarm" "queue_age" {                                     # 수집 서버가 멈추거나 밀리면 감지합니다.
  tags                = { Name = "${var.name_prefix}-cloudwatch-${each.key}-queue-age" } # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  for_each            = var.enable_alerting ? local.sources : toset([])                  # 소스별로 만듭니다.
  alarm_name          = "${var.name_prefix}-cloudwatch-${each.key}-queue-age"            # 알람 이름입니다.
  namespace           = "AWS/SQS"                                                        # SQS 기본 지표입니다.
  metric_name         = "ApproximateAgeOfOldestMessage"                                  # 가장 오래 대기한 알림 시간입니다.
  dimensions          = { QueueName = aws_sqs_queue.source[each.key].name }              # 대응 큐입니다.
  statistic           = "Maximum"                                                        # 가장 오래된 메시지를 봅니다.
  period              = 60                                                               # 1분 지표입니다.
  evaluation_periods  = 5                                                                # 5개 연속 구간을 봅니다.
  threshold           = 600                                                              # 10분 초과가 기준입니다.
  comparison_operator = "GreaterThanThreshold"                                           # 기준 초과 시 경보입니다.
  treat_missing_data  = "notBreaching"                                                   # 비활성 소스의 빈 지표는 정상 취급합니다.
  alarm_actions       = [aws_sns_topic.alerts[0].arn]                                    # SNS 주제로 전달합니다.
}                                                                                        # 적체 알람을 끝냅니다.

resource "aws_cloudwatch_metric_alarm" "dlq" {                                              # 반복 실패를 놓치지 않도록 합니다.
  tags                = { Name = "${var.name_prefix}-cloudwatch-${each.key}-dlq-messages" } # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  for_each            = var.enable_alerting ? local.sources : toset([])                     # 소스별 DLQ입니다.
  alarm_name          = "${var.name_prefix}-cloudwatch-${each.key}-dlq-messages"            # 알람 이름입니다.
  namespace           = "AWS/SQS"                                                           # SQS 기본 지표입니다.
  metric_name         = "ApproximateNumberOfMessagesVisible"                                # 대기 중인 실패 알림 수입니다.
  dimensions          = { QueueName = aws_sqs_queue.dlq[each.key].name }                    # 대응 DLQ입니다.
  statistic           = "Maximum"                                                           # 실패 메시지 최대 개수입니다.
  period              = 60                                                                  # 1분 단위입니다.
  evaluation_periods  = 1                                                                   # 한 구간만 있어도 알립니다.
  threshold           = 0                                                                   # 하나 이상이면 조사합니다.
  comparison_operator = "GreaterThanThreshold"                                              # 0 초과가 경보입니다.
  treat_missing_data  = "notBreaching"                                                      # 빈 DLQ는 정상입니다.
  alarm_actions       = [aws_sns_topic.alerts[0].arn]                                       # SNS로 전달합니다.
}                                                                                           # 실패 큐 알람을 끝냅니다.

resource "aws_cloudwatch_metric_alarm" "instance_status" {                            # EC2 기본 상태 검사를 감시합니다.
  tags                = { Name = "${var.name_prefix}-cloudwatch-${each.key}-status" } # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  for_each            = var.enable_alerting ? local.roles : toset([])                 # 세 서버입니다.
  alarm_name          = "${var.name_prefix}-cloudwatch-${each.key}-status"            # 알람 이름입니다.
  namespace           = "AWS/EC2"                                                     # EC2 기본 지표입니다.
  metric_name         = "StatusCheckFailed"                                           # 시스템·인스턴스 상태 실패입니다.
  dimensions          = { InstanceId = aws_instance.node[each.key].id }               # 해당 인스턴스입니다.
  statistic           = "Maximum"                                                     # 상태 실패를 찾습니다.
  period              = 300                                                           # 기본 EC2 모니터링 간격입니다.
  evaluation_periods  = 2                                                             # 10분 동안 지속되면 알립니다.
  threshold           = 0                                                             # 실패 상태 1을 감지합니다.
  comparison_operator = "GreaterThanThreshold"                                        # 0 초과가 경보입니다.
  treat_missing_data  = "missing"                                                     # 지표 부재는 정상으로 단정하지 않습니다.
  alarm_actions       = [aws_sns_topic.alerts[0].arn]                                 # SNS로 전달합니다.
}                                                                                     # EC2 알람을 끝냅니다.

resource "aws_cloudwatch_metric_alarm" "firehose_freshness" {                                               # S3로 전달하지 못한 지연을 감시합니다.
  tags                = { Name = "${var.name_prefix}-cloudwatch-${each.key}-firehose-freshness" }           # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  for_each            = var.enable_alerting ? local.cwl_sources : toset([])                                 # 두 Firehose입니다.
  alarm_name          = "${var.name_prefix}-cloudwatch-${each.key}-firehose-freshness"                      # 알람 이름입니다.
  namespace           = "AWS/Firehose"                                                                      # Firehose 기본 지표입니다.
  metric_name         = "DeliveryToS3.DataFreshness"                                                        # S3 전달 대기 시간입니다.
  dimensions          = { DeliveryStreamName = aws_kinesis_firehose_delivery_stream.source[each.key].name } # 대응 스트림입니다.
  statistic           = "Maximum"                                                                           # 최대 전달 지연입니다.
  period              = 60                                                                                  # 1분 단위입니다.
  evaluation_periods  = 5                                                                                   # 5분 지속을 확인합니다.
  threshold           = 600                                                                                 # 10분 초과면 조사합니다.
  comparison_operator = "GreaterThanThreshold"                                                              # 기준 초과가 경보입니다.
  treat_missing_data  = "notBreaching"                                                                      # 아직 이벤트가 없는 스트림은 정상으로 봅니다.
  alarm_actions       = [aws_sns_topic.alerts[0].arn]                                                       # SNS로 전달합니다.
}                                                                                                           # 전달 지연 알람을 끝냅니다.
