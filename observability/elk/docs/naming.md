# 새 자원 이름 규칙과 전체 목록

적용일: 2026-09-19. 이 패키지가 **새로 생성하고 직접 이름을 지정할 수 있는 자원**은 `whs-elk-<서비스>-<역할>`을 사용한다. 예를 들어 수집 서버는 `whs-elk-ec2-collector`, WAF 수집 큐는 `whs-elk-sqs-waf-ingest`다. `name_prefix`는 `whs-elk`로 고정 검증한다.

`서비스`는 해당 자원을 만드는 서비스 또는 자원 종류다. `ec2`, `ebs`, `sg`, `s3`, `kms`, `sqs`, `cloudwatch`, `firehose`, `iam`, `cloudtrail`, `guardduty`, `vpce`, `sns`, `eventbridge`, `ssm`을 사용한다. ELK 내부 객체는 `elasticsearch`, `kibana`, `logstash`, `filebeat`, 인증서 CA는 `pki`를 사용한다.

아래 `<role>`은 `collector`, `elasticsearch`, `kibana`이고 `<source>`는 `cloudtrail`, `cloudwatch`, `waf`, `guardduty`다. `<delivery-source>`는 Firehose를 쓰는 `cloudwatch`, `waf` 두 종류다. 꺾쇠 표시는 설명용 자리표시자이며 실제 이름에 포함하지 않는다.

## AWS 기본 자원

| 대상 | 새 이름 | 개수·표시 방식 |
|---|---|---|
| EC2 수집 서버 | `whs-elk-ec2-collector` | Name 태그 |
| EC2 Elasticsearch | `whs-elk-ec2-elasticsearch` | Name 태그 |
| EC2 Kibana | `whs-elk-ec2-kibana` | Name 태그 |
| 각 EC2 root EBS | `whs-elk-ebs-<role>-root` | Name 태그 3개 |
| 보안 그룹 | `whs-elk-sg-<role>` | 실제 그룹 이름 3개 |
| 보안 그룹 송신 규칙 | `whs-elk-sg-<role>-https-egress`, `whs-elk-sg-<role>-apt-egress` | 각 3개 규칙의 Name 태그 |
| ES 접근 규칙 | `whs-elk-sg-elasticsearch-from-<role>`, `whs-elk-sg-<role>-to-elasticsearch` | collector·kibana 각각 수신/송신 Name 태그 |
| 원본 버킷 | `whs-elk-s3-raw-<account>-<region>` | Name 태그는 `whs-elk-s3-raw` |
| 스냅샷 버킷 | `whs-elk-s3-snapshots-<account>-<region>` | Name 태그는 `whs-elk-s3-snapshots` |
| 배포 파일 버킷 | `whs-elk-s3-artifacts-<account>-<region>` | Name 태그는 `whs-elk-s3-artifacts` |
| 원본 KMS 키 | `whs-elk-kms-raw` | Name 태그, 별칭 `alias/whs-elk-kms-raw` |
| 배포용 KMS 키 | `whs-elk-kms-artifacts` | Name 태그, 별칭 `alias/whs-elk-kms-artifacts` |
| 소스별 SQS | `whs-elk-sqs-<source>-ingest` | 4개 |
| 소스별 DLQ | `whs-elk-sqs-<source>-dlq` | 4개 |
| 서버 로그 그룹 | `whs-elk-cloudwatch-workload` | 기존 그룹을 지정하면 새로 만들지 않음 |
| WAF 로그 그룹 | `aws-waf-logs-whs-elk-cloudwatch-waf` | AWS 필수 접두사 예외 |
| Firehose 진단 그룹 | `whs-elk-cloudwatch-<delivery-source>-delivery-errors` | 2개 |
| Firehose 진단 스트림 | `whs-elk-cloudwatch-<delivery-source>-delivery` | 2개 |
| 로그 구독 필터 | `whs-elk-cloudwatch-<delivery-source>-to-firehose` | 2개 |
| Firehose | `whs-elk-firehose-<delivery-source>-delivery` | 2개 |
| S3 객체 알림 규칙 | `whs-elk-s3-<source>-objects` | 신규 CloudTrail 선택 여부에 따라 raw 버킷 규칙 3~4개 |
| 원본 보관 규칙 | `whs-elk-s3-raw-retention` | lifecycle 내부 규칙 ID |
| 배포 파일 보관 규칙 | `whs-elk-s3-artifacts-retention` | lifecycle 내부 규칙 ID |

## IAM 역할과 권한

| 대상 | 새 이름 | 개수 |
|---|---|---:|
| EC2 역할 | `whs-elk-iam-<role>-role` | 3 |
| EC2 instance profile | `whs-elk-iam-<role>-profile` | 3 |
| Firehose 역할 | `whs-elk-iam-<delivery-source>-firehose-role` | 2 |
| 구독 전달 역할 | `whs-elk-iam-<delivery-source>-subscription-role` | 2 |
| 배포 파일 읽기 정책 | `whs-elk-iam-<role>-read-artifacts` | 3 |
| 수집 권한 정책 | `whs-elk-iam-collector-read-raw-and-sqs` | 1 |
| 스냅샷 권한 정책 | `whs-elk-iam-elasticsearch-manage-snapshots` | 1 |
| Firehose S3 전달 정책 | `whs-elk-iam-<delivery-source>-deliver-to-s3` | 2 |
| 로그 구독 권한 정책 | `whs-elk-iam-<delivery-source>-put-to-firehose` | 2 |

위 정책은 이름을 지정할 수 있는 **새 inline policy**다. `AmazonSSMManagedInstanceCore` 같은 기존 AWS 관리 정책과 IAM 정책 JSON의 `Sid`는 자원 이름 변경 대상이 아니다.

## 선택 자원과 업무 Agent 예제

| 대상 | 새 이름 | 생성 조건 |
|---|---|---|
| CloudTrail | `whs-elk-cloudtrail-management` | `create_cloudtrail=true` |
| GuardDuty detector | `whs-elk-guardduty-detector` | `create_guardduty_detector=true`, Name 태그로 표시 |
| S3 endpoint | `whs-elk-vpce-s3-access` | `create_s3_gateway_endpoint=true`, Name 태그로 표시 |
| SNS 주제 | `whs-elk-sns-security-alerts` | `enable_alerting=true` |
| EventBridge 규칙 | `whs-elk-eventbridge-guardduty-findings` | `enable_alerting=true` |
| EventBridge 대상 ID | `whs-elk-eventbridge-security-alerts` | 위 규칙 내부 대상 |
| SQS 적체 알람 | `whs-elk-cloudwatch-<source>-queue-age` | 4개 |
| DLQ 알람 | `whs-elk-cloudwatch-<source>-dlq-messages` | 4개 |
| EC2 상태 알람 | `whs-elk-cloudwatch-<role>-status` | 3개 |
| Firehose 지연 알람 | `whs-elk-cloudwatch-<delivery-source>-firehose-freshness` | 2개 |
| 업무 Agent SSM 설정 | `whs-elk-ssm-workload-agent-config` | Agent 가이드의 HCL을 별도 적용 |
| 업무 Agent IAM 정책 | `whs-elk-iam-workload-send-logs` | 기존 업무 역할에 별도 추가 |
| 업무 Agent 검증 스트림 | `whs-elk-cloudwatch-<instance-id>-validation` | 실제 Agent 수집 시 생성 |
| 업무 Agent 앱 스트림 | `whs-elk-cloudwatch-<instance-id>-app-<N>` | 앱 파일을 명시한 경우 생성 |

GuardDuty export 설정 자체, 버킷 정책·암호화 설정, 큐 redrive 설정, WAF 로깅 설정처럼 독립적인 이름 필드가 없는 연결 설정은 연결 대상과 AWS ID로 식별한다. 이들에게 임의의 이름 필드를 추가하지 않는다.

## ELK 내부 객체

| 대상 | 새 이름 |
|---|---|
| Elasticsearch 클러스터 / 노드 | `whs-elk-elasticsearch-cluster` / `whs-elk-elasticsearch-node` |
| Logstash 노드 / 파이프라인 | `whs-elk-logstash-collector` / `whs-elk-logstash-normalize` |
| Kibana 서버 | `whs-elk-kibana-dashboard` |
| Filebeat 수집기 / 입력 ID | `whs-elk-filebeat-collector` / `whs-elk-filebeat-<source>` |
| 내부 CA CN | `whs-elk-pki-root-ca` |
| 서버 인증서 CN | `whs-elk-elasticsearch-tls`, `whs-elk-kibana-tls` |
| 보관 정책 ILM | `whs-elk-elasticsearch-retention` |
| 인덱스 템플릿 | `whs-elk-elasticsearch-logs` |
| 정상 로그 인덱스 | `whs-elk-elasticsearch-logs-<source>-YYYY.MM.dd` |
| 오류 격리 인덱스 | `whs-elk-elasticsearch-logs-quarantine-YYYY.MM.dd` |
| 스냅샷 저장소 등록 | `whs-elk-elasticsearch-snapshots` |
| 스냅샷 일정 SLM | `whs-elk-elasticsearch-daily-backup` |
| 자동 스냅샷 | `whs-elk-elasticsearch-daily-<날짜>` 기반 이름. Elasticsearch가 고유 suffix를 추가할 수 있음 |
| 수동 스냅샷 | `whs-elk-elasticsearch-manual-<UTC시각>` |
| 복원 시험 인덱스 | `whs-elk-elasticsearch-restore-<source>-YYYY.MM.dd` |
| 수집 API 키 이름 | `whs-elk-elasticsearch-collector` |
| API 키 내부 권한 정의 | `whs-elk-elasticsearch-writer` |
| Kibana 서비스 토큰 이름 | `whs-elk-kibana-service-<UTC시각>` |
| 조회 역할 / 사용자 | `whs-elk-elasticsearch-reader` / `whs-elk-kibana-reader` |
| 수동 생성 Data View 표시 이름 | `whs-elk-kibana-security-logs` |
| 수동 생성 Dashboard 표시 이름 | `whs-elk-kibana-security-dashboard` |

인덱스 패턴은 `whs-elk-elasticsearch-logs-*`로 통일했다. 수집 API 키 권한, 조회 역할, ILM 템플릿, 스냅샷 대상, 상태 조회, 복원 규칙도 함께 변경했다. OS 서비스 이름·패키지 이름·필수 파일 경로, 기본 계정 `elastic`, 서비스 계정 `elastic/kibana`, ECS 필드 `aws.*`는 제품의 식별자이므로 유지한다.

## AWS가 요구하는 예외

1. **WAF 로그 그룹:** 반드시 `aws-waf-logs-`로 시작해야 하므로 앞에 필수 접두사를 붙인다. WAF가 직접 만드는 로그 스트림 이름도 AWS의 `<Region>_<web-acl-name>_<number>` 형식을 따른다. [AWS WAF 이름 규칙](https://docs.aws.amazon.com/waf/latest/developerguide/logging-cw-logs.html)
2. **S3 버킷:** 이 코드의 일반 버킷은 전역 이름 충돌을 줄이기 위해 계정 번호와 리전을 뒤에 붙인다. 계정·리전 suffix만으로 제3자의 선점을 완전히 막는 것은 아니며, 실제 생성 시 사용 가능해야 한다. [S3 이름 규칙](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html)
3. **KMS:** 키 ID는 AWS가 생성하므로 Name 태그와 alias를 사용한다. alias에는 `alias/`가 필요하다. [KMS alias 생성](https://docs.aws.amazon.com/kms/latest/developerguide/alias-create.html)
4. **EC2·EBS·GuardDuty 등:** `i-*`, `vol-*`, detector ID는 AWS가 발급한다. 지원되는 Name 태그에 사람이 읽는 통일 이름을 저장한다. [GuardDuty 생성 API](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_CreateDetector.html)
5. **원본 내부 경로:** `cloudtrail/`, `cloudwatch/`, `waf/`, `guardduty/`, `AWSLogs/...`, 스냅샷 `elastic` prefix는 수집·권한 계약에 쓰이는 데이터 경로다. 자원 이름과 구분하여 유지한다. Terraform 내부 `aws_instance.node` 같은 주소도 클라우드 자원 이름이 아니므로 유지한다.

## 실제 이름 조회와 기존 배포

적용된 상태에서 패키지 루트의 Bash로 조회한다. 기존 자원을 재사용하면 해당 기존 이름은 그대로이며, 새 자원의 이름 출력과 기존 로그 그룹 출력을 구분한다.

```bash
terraform -chdir=terraform output -json resource_names # 이번 Terraform이 만든 주요 자원의 실제 이름과 Name 태그를 확인한다.
terraform -chdir=terraform output -json log_group_names # 기존 그룹 재사용 여부까지 포함한 실제 수집 대상 이름을 확인한다.
```

이 변경은 **새 구축용 코드 변경**이며 실제 AWS에서 이름 변경이나 배포를 실행하지 않았다. 이전 이름으로 이미 구축했다면 단순히 파일을 교체하고 적용하지 않는다. 버킷·큐·IAM 등의 이름 변경은 자원 교체가 될 수 있으므로 실제 plan에서 교체·삭제 범위를 확인하고 원본·큐·권한의 이전 순서를 정한다. Elastic의 기존 인덱스·정책·API 키도 자동 마이그레이션되지 않는다. Filebeat 입력 ID와 Logstash pipeline ID 변경은 상태·디스크 큐의 경로에 영향을 줄 수 있으므로 기존 대기 데이터를 처리하고 별도 전환한다.

IAM 역할·instance profile 이름은 계정 전체 범위다. 이 패키지는 한 계정의 첫 단일 리전 스택을 대상으로 하며, 같은 계정에 두 번째 독립 스택을 그대로 생성하면 같은 IAM 이름이 충돌한다. 추가 리전 구축 전에는 기존 역할을 공유할지, 역할 부분에 리전/환경 구분을 추가할지 정하고 그 확장 구성을 별도로 계획한다.
