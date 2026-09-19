output "instance_ids" {                                                     # SSM 접속 대상입니다.
  value = { for role, instance in aws_instance.node : role => instance.id } # 역할별 EC2 ID입니다.
}                                                                           # 출력을 끝냅니다.

output "private_ips" {                                                              # TLS 인증서 SAN과 서비스 연결 설정에 사용합니다.
  value = { for role, instance in aws_instance.node : role => instance.private_ip } # 역할별 사설 IP입니다.
}                                                                                   # 출력을 끝냅니다.

output "selected_ami_id" {   # 최초 plan에서 확인하고 ami_id에 고정할 값입니다.
  value = local.selected_ami # Ubuntu 24.04 AMI ID입니다.
}                            # 출력을 끝냅니다.

output "raw_bucket_name" {             # 신규 원본 저장 버킷입니다.
  value = aws_s3_bucket.data["raw"].id # 버킷 이름입니다.
}                                      # 출력을 끝냅니다.

output "snapshot_bucket_name" {              # ES repository-s3 설정 대상입니다.
  value = aws_s3_bucket.data["snapshots"].id # 스냅샷 버킷 이름입니다.
}                                            # 출력을 끝냅니다.

output "artifact_bucket_name" {              # 역할별 초기 설정·인증서 배포 파일을 올릴 대상입니다.
  value = aws_s3_bucket.data["artifacts"].id # 임시 아티팩트 버킷 이름입니다.
}                                            # 출력을 끝냅니다.

output "raw_kms_key_arn" {    # 원본 업로드·조사 권한 부여에 사용합니다.
  value = aws_kms_key.raw.arn # 원본 CMK ARN입니다.
}                             # 출력을 끝냅니다.

output "artifact_kms_key_arn" {     # 운영자의 아티팩트 업로드 권한에 사용합니다.
  value = aws_kms_key.artifacts.arn # 배포 파일 CMK ARN입니다.
}                                   # 출력을 끝냅니다.

output "sqs_queue_urls" {                                                     # Filebeat의 소스별 queue_url에 입력합니다.
  value = { for source, queue in aws_sqs_queue.source : source => queue.url } # 네 소스 큐 URL입니다.
}                                                                             # 출력을 끝냅니다.

output "dlq_urls" {                                                        # 실패 알림 조사·redrive 대상입니다.
  value = { for source, queue in aws_sqs_queue.dlq : source => queue.url } # 네 실패 큐 URL입니다.
}                                                                          # 출력을 끝냅니다.

output "log_group_names" {      # 업무 서버 Agent와 WAF 목적지입니다.
  value = local.log_group_names # 신규 또는 기존 그룹 이름입니다.
}                               # 출력을 끝냅니다.

output "firehose_names" {                                                                               # 전달 상태와 오류 지표 확인에 사용합니다.
  value = { for source, stream in aws_kinesis_firehose_delivery_stream.source : source => stream.name } # 두 스트림 이름입니다.
}                                                                                                       # 출력을 끝냅니다.

output "cloudtrail_name" {                                          # 신규 Trail인 경우 무결성 검증에 사용합니다.
  value = var.create_cloudtrail ? aws_cloudtrail.new[0].name : null # 기존 Trail 이름을 변경하지 않습니다.
}                                                                   # 출력을 끝냅니다.

output "guardduty_detector_id" { # 내보내기 상태·샘플 findings 생성 대상입니다.
  value = local.detector_id      # 신규 또는 기존 detector ID입니다.
}                                # 출력을 끝냅니다.

output "guardduty_destination_id" {                                                          # export 상태 확인 대상입니다.
  value = var.enable_guardduty_export ? aws_guardduty_publishing_destination.s3[0].id : null # 비활성화 시 null입니다.
}                                                                                            # 출력을 끝냅니다.

output "alert_topic_arn" {                                         # 알림 수신자는 별도 명시적으로 구독합니다.
  value = var.enable_alerting ? aws_sns_topic.alerts[0].arn : null # 비활성화 시 null입니다.
}                                                                  # 출력을 끝냅니다.

output "collector_role_arn" {                # 기존 버킷·CMK 소유자가 읽기 권한을 줄 때 사용합니다.
  value = aws_iam_role.node["collector"].arn # 수집 서버 역할입니다.
}                                            # 출력을 끝냅니다.

output "notification_prefixes" {                                                                                                                        # 파이프라인과 S3 경로를 대조합니다.
  value = merge(local.notification_prefixes, var.existing_cloudtrail_bucket_name != null ? { cloudtrail = var.existing_cloudtrail_object_prefix } : {}) # 기존 CT는 실제 경로를 출력합니다.
}                                                                                                                                                       # 출력을 끝냅니다.

output "existing_cloudtrail_notification_queue_configuration" {           # 기존 bucket notification 소유자가 기존 목록에 병합할 데이터입니다.
  value = var.existing_cloudtrail_bucket_name != null ? {                 # 기존 버킷 사용 시만 출력합니다.
    Id       = "${var.name_prefix}-s3-cloudtrail-objects"                 # 고유 notification 식별자입니다.
    QueueArn = aws_sqs_queue.source["cloudtrail"].arn                     # 이 패키지 CT SQS입니다.
    Events   = ["s3:ObjectCreated:*"]                                     # 새로운 객체만 자동 알림을 받습니다.
    Filter = { Key = { FilterRules = [                                    # 기존 다른 prefix 규칙과 중복 여부를 검토합니다.
      { Name = "prefix", Value = var.existing_cloudtrail_object_prefix }, # CT 일반 이벤트 경로입니다.
      { Name = "suffix", Value = ".json.gz" }                             # digest와 marker를 제외합니다.
    ] } }                                                                 # 필터 객체를 끝냅니다.
  } : null                                                                # 신규 Trail이면 필요하지 않습니다.
}                                                                         # 출력을 끝냅니다.

output "resource_names" {                                                                                 # terraform output -json resource_names로 신규 자원의 실제 이름을 한 번에 확인합니다.
  value = {                                                                                               # AWS가 ID만 부여하는 자원은 명시한 Name 태그를 출력합니다.
    ec2 = { for role, instance in aws_instance.node : role => instance.tags.Name }                        # 세 EC2의 콘솔 이름입니다.
    ebs = { for role, instance in aws_instance.node : role => one(instance.root_block_device).tags.Name } # 세 root EBS의 콘솔 이름입니다.

    security_groups = { for role, group in aws_security_group.node : role => group.name }                                # 실제 보안 그룹 이름입니다.
    security_group_rules = {                                                                                             # 이름 필드가 없는 규칙은 Name 태그를 표시합니다.
      https                 = { for role, rule in aws_vpc_security_group_egress_rule.https : role => rule.tags.Name }    # HTTPS 송신 규칙입니다.
      apt                   = { for role, rule in aws_vpc_security_group_egress_rule.apt_http : role => rule.tags.Name } # apt HTTP 송신 규칙입니다.
      elasticsearch_ingress = { for role, rule in aws_vpc_security_group_ingress_rule.es : role => rule.tags.Name }      # Elasticsearch 수신 규칙입니다.
      elasticsearch_egress  = { for role, rule in aws_vpc_security_group_egress_rule.to_es : role => rule.tags.Name }    # Elasticsearch 송신 규칙입니다.
    }                                                                                                                    # 보안 그룹 규칙 이름을 끝냅니다.

    s3_buckets    = { for role, bucket in aws_s3_bucket.data : role => bucket.id }                   # 전역 고유성 확보를 위해 계정·리전 접미사가 포함됩니다.
    s3_name_tags  = { for role, bucket in aws_s3_bucket.data : role => bucket.tags.Name }            # 콘솔 Name 태그는 서비스·역할까지만 사용합니다.
    kms_aliases   = { raw = aws_kms_alias.raw.name, artifacts = aws_kms_alias.artifacts.name }       # AWS가 요구하는 alias/ 접두사를 포함합니다.
    kms_name_tags = { raw = aws_kms_key.raw.tags.Name, artifacts = aws_kms_key.artifacts.tags.Name } # UUID로 생성되는 KMS 키의 콘솔 이름입니다.

    sqs_ingest = { for source, queue in aws_sqs_queue.source : source => queue.name } # 네 수집 큐 이름입니다.
    sqs_dlq    = { for source, queue in aws_sqs_queue.dlq : source => queue.name }    # 네 실패 큐 이름입니다.

    log_groups_created   = { for source, group in aws_cloudwatch_log_group.source : source => group.name }                 # 기존 그룹은 변경하지 않으므로 이 목록에서 제외됩니다.
    delivery_log_groups  = { for source, group in aws_cloudwatch_log_group.firehose : source => group.name }               # Firehose 진단 그룹입니다.
    delivery_log_streams = { for source, stream in aws_cloudwatch_log_stream.firehose : source => stream.name }            # Firehose 진단 스트림입니다.
    subscriptions        = { for source, filter in aws_cloudwatch_log_subscription_filter.source : source => filter.name } # 로그 구독 필터입니다.
    firehose             = { for source, stream in aws_kinesis_firehose_delivery_stream.source : source => stream.name }   # 두 전달 스트림입니다.

    iam_roles = merge(                                                                                   # EC2·Firehose·구독 역할 일곱 개를 하나의 목록으로 합칩니다.
      { for role, resource in aws_iam_role.node : role => resource.name },                               # 세 EC2 역할입니다.
      { for source, resource in aws_iam_role.firehose : "${source}-firehose" => resource.name },         # 두 Firehose 역할입니다.
      { for source, resource in aws_iam_role.subscription : "${source}-subscription" => resource.name }  # 두 로그 구독 역할입니다.
    )                                                                                                    # 역할 목록을 끝냅니다.
    iam_profiles = { for role, profile in aws_iam_instance_profile.node : role => profile.name }         # EC2 instance profile입니다.
    iam_inline_policies = {                                                                              # AWS 관리 정책의 이름은 바꾸지 않고 신규 inline 정책만 표시합니다.
      artifacts     = { for role, policy in aws_iam_role_policy.artifacts : role => policy.name }        # 배포 파일 읽기 정책입니다.
      collector     = aws_iam_role_policy.collector.name                                                 # 원본 읽기·SQS 소비 정책입니다.
      snapshots     = aws_iam_role_policy.snapshots.name                                                 # 스냅샷 관리 정책입니다.
      firehose      = { for source, policy in aws_iam_role_policy.firehose : source => policy.name }     # S3 전달 정책입니다.
      subscriptions = { for source, policy in aws_iam_role_policy.subscription : source => policy.name } # Firehose 쓰기 정책입니다.
    }                                                                                                    # inline 정책 이름을 끝냅니다.

    cloudtrail           = var.create_cloudtrail ? aws_cloudtrail.new[0].name : null                      # 신규 Trail만 표시합니다.
    guardduty_name_tag   = var.create_guardduty_detector ? aws_guardduty_detector.new[0].tags.Name : null # detector는 name 필드를 지원하지 않습니다.
    s3_endpoint_name_tag = var.create_s3_gateway_endpoint ? aws_vpc_endpoint.s3[0].tags.Name : null       # endpoint도 Name 태그로 표시합니다.

    sns_topic          = var.enable_alerting ? aws_sns_topic.alerts[0].name : null                                       # 선택 알림 주제입니다.
    eventbridge_rule   = var.enable_alerting ? aws_cloudwatch_event_rule.guardduty[0].name : null                        # 선택 탐지 이벤트 규칙입니다.
    eventbridge_target = var.enable_alerting ? aws_cloudwatch_event_target.guardduty[0].target_id : null                 # 규칙 내 대상 식별자입니다.
    cloudwatch_alarms = merge(                                                                                           # 알림 옵션을 켜면 네 종류의 알람 13개가 표시됩니다.
      { for source, alarm in aws_cloudwatch_metric_alarm.queue_age : "${source}-queue-age" => alarm.alarm_name },        # 수집 큐 적체 알람입니다.
      { for source, alarm in aws_cloudwatch_metric_alarm.dlq : "${source}-dlq" => alarm.alarm_name },                    # 실패 큐 메시지 알람입니다.
      { for role, alarm in aws_cloudwatch_metric_alarm.instance_status : "${role}-status" => alarm.alarm_name },         # EC2 상태 알람입니다.
      { for source, alarm in aws_cloudwatch_metric_alarm.firehose_freshness : "${source}-delivery" => alarm.alarm_name } # Firehose 지연 알람입니다.
    )                                                                                                                    # 알람 이름 목록을 끝냅니다.
  }                                                                                                                      # 신규 이름 목록을 끝냅니다.
}                                                                                                                        # 출력을 끝냅니다.
