# Terraform 구성과 적용 가이드

이 디렉터리는 **기존 VPC·private subnet 안에 EC2 세 대를 새로 만들고, 원본 S3 → SQS → Filebeat 수집 경로를 준비하는 독립 스택**이다. 코드 생성과 로컬 검증만 수행했다. 실제 계정에서 `plan`·`apply`나 데이터 전달 시험을 완료한 결과는 아니다. 실제 SCP, 버킷 정책, KMS 정책, 소스 형식을 확인한 뒤 적용한다.

전체 콘솔 구축은 [AWS 콘솔 가이드](aws-console-guide.md), 대상 확인은 [사전 점검](preflight.md)을 함께 본다. `.tf` 파일과 입력 예시의 각 의미 있는 줄에 한국어 주석을 달았다. JSON 정책은 주석을 지원하는 HCL의 `jsonencode`/policy document에서 생성한다. 실제 JSON 문자열에 주석을 넣지 않는다.

## 1. 관리 범위

| 파일 | 관리 대상 | 기존 리소스 취급 |
|---|---|---|
| `versions.tf`, `variables.tf`, `locals.tf` | 버전·계정·리전·소스 선택 | caller 계정과 subnet을 읽고 입력 검증 |
| `compute.tf` | Ubuntu 24.04 EC2 세 대, SG, 선택 S3 gateway endpoint | VPC/subnet은 읽기만 함; endpoint 선택 시 route table에 S3 경로 추가 |
| `storage.tf` | 원본·스냅샷·아티팩트 S3 세 개, CMK 두 개, SQS 네 개와 DLQ 네 개 | 기존 Trail 버킷 정책·notification은 변경하지 않음 |
| `iam.tf` | EC2·Firehose·구독 역할과 권한 | 기존 CMK 정책은 소유자가 collector 읽기를 허용해야 함 |
| `sources.tf` | CWL 그룹·구독·Firehose 두 개, 선택 Trail·GuardDuty·WAF 연결 | 기존 설정을 다른 스택과 공동 관리하지 않음 |
| `monitoring.tf` | 선택 SNS·EventBridge·SQS/EC2/Firehose 경보 | 이메일·웹훅 구독을 자동으로 만들지 않음 |
| `outputs.tf` | IP·ID·버킷·큐·소스 이름 | 비밀번호·개인키·API 키는 출력하지 않음 |

VPC·NAT·VPN·ALB·CloudFront·업무 EC2·WAF web ACL/규칙/연결은 기존 프로젝트가 소유한다. 소프트웨어 설치와 인증서 생성도 Terraform user data에 넣지 않는다. **`terraform apply` 후 별도 런타임 설치 단계가 필요**하다.

## 2. 기본값과 보관 정책

- EC2는 collector `t3.large`, Elasticsearch `t3.large`, Kibana `t3.medium` 각 한 대다. amd64이므로 T4g 등 arm64 변경 시 AMI와 설치 파일도 함께 바꿔야 한다. CPU credit·지속 부하는 측정하고 운영 규모에서는 M 계열 등을 검토한다.
- root EBS는 50/100/30 GiB, gp3, 암호화, `delete_on_termination=false`다. 첫 검증의 Filebeat 상태·Logstash PQ·ES 인덱스는 root EBS에 둔다.
- 새 자원 이름은 `whs-elk-<AWS 서비스>-<역할>`이고 `name_prefix`는 `whs-elk`로 고정 검증한다. S3 이름은 `whs-elk-s3-raw-<account>-<region>`, `whs-elk-s3-snapshots-<account>-<region>`, `whs-elk-s3-artifacts-<account>-<region>`이다. 계정·리전 suffix는 전역 이름 충돌 가능성을 줄이지만 사용 가능성을 보장하지는 않는다. 이미 점유됐다면 해당 버킷의 소유·이전 배포 여부를 확인한다. 자원별 이름과 서비스 제약은 [이름 규칙](naming.md)을 따른다.
- 원본 S3는 SSE-KMS·Versioning·공개 차단·TLS 강제다. 현재 버전은 기본 30일 뒤 만료하고, 비현재 버전은 비현재가 된 뒤 7일 후 영구 삭제 대상이다. **정확히 30일째 모든 바이트가 삭제되는 정책은 아니다.** 새 객체는 대략 30일+7일과 비동기 수명주기 처리 시간이 남을 수 있다.
- 스냅샷 S3는 SSE-S3다. 임의 S3 lifecycle로 저장소 파일을 지우지 않고 ES의 SLM/Snapshot API로 정리한다.
- 아티팩트 S3는 별도 SSE-KMS·공개 차단·TLS 강제, Versioning 없음, 3일 뒤 만료 대상이다. 각 EC2 역할은 자기 `<role>/*`만 읽는다. 장기 CA 개인키 보관소로 쓰지 않는다.
- 기본 CWL 그룹은 `whs-elk-cloudwatch-workload`, `aws-waf-logs-whs-elk-cloudwatch-waf`이고 신규 그룹은 30일 보관한다. WAF 그룹 앞부분은 AWS가 요구하는 접두사다. 기존 이름을 입력하면 기존 이름·보관·암호화 정책은 수정하지 않는다.
- 소스 SQS 네 개와 DLQ 네 개는 SQS 관리 암호화·14일 보관이다. 로그 본문 대신 S3 객체 위치 알림이 들어간다.
- 새 Trail, 새 GuardDuty detector, GuardDuty export, WAF 로깅 관리, 알림, S3 gateway endpoint는 기본 `false`다. **기본 apply만으로 CloudTrail/WAF/GuardDuty 로그가 자동 발생하지 않는다.**

## 3. 네트워크와 관리 접속

모든 EC2는 public IP 없이 기존 private subnet에 둔다. Internet Gateway 경로만 있는 subnet은 공인 IP 없는 EC2의 인터넷 접속을 제공하지 않는다. **기존 NAT/승인된 프록시, 443·80 출구, VPC DNS, NACL 반환 트래픽, subnet의 여유 IP**를 확인한다. S3 gateway endpoint 하나로 패키지 저장소·SSM·SQS 경로까지 해결되지는 않는다.

| 출발 → 도착 | 포트/경로 | 목적 |
|---|---|---|
| collector → ES | TCP 9200 | TLS 로그 색인 |
| Kibana → ES | TCP 9200 | TLS 조회 |
| 각 노드 → 외부/AWS API | TCP 443 | SSM·SQS·S3·패키지 다운로드 |
| 각 노드 → Ubuntu 저장소 | TCP 80 | 기본 apt가 HTTP인 경우; HTTPS mirror 전환 뒤 제거 가능 |
| 운영자 → SSM → Kibana localhost | SSM port forwarding | 5601/22 인바운드를 열지 않음 |
| Filebeat → 같은 collector의 Logstash | localhost:5044 | EC2 사이 규칙 불필요 |

AMI는 Canonical 공식 SSM 경로 `/aws/service/canonical/ubuntu/server/noble/stable/current/amd64/hvm/ebs-gp3/ami-id`에서 조회한다. 최초 계획의 `selected_ami_id`를 검토하고 `ami_id`에 고정할 수 있다. `ignore_changes=[ami]`는 최신 AMI 공개 때문에 기존 서버를 자동 교체하지 않게 한다. OS 패치·교체는 별도 절차다. [Canonical AMI 경로](https://documentation.ubuntu.com/aws/aws-how-to/instances/build-cloudformation-templates/)

## 4. 입력과 적용 명령

AWS CLI v2의 사용할 SSO/profile을 인증하고 Terraform CLI 1.10 이상과 AWS provider 6.x를 사용한다. 아래는 **저장소 루트에서 시작하는 Windows PowerShell** 예시다. `terraform.tfvars` 복사 후 계정·VPC·subnet 등 실제 값을 편집하고 나서 `plan`을 실행한다. 기존 파일이 있으면 복사 단계는 건너뛴다.

```powershell
$env:AWS_PROFILE = "REPLACE-PROFILE" # 배포용으로 승인된 profile을 선택합니다.
aws sts get-caller-identity # Account가 expected_account_id와 같은지 확인합니다.
Set-Location 'observability/elk/terraform' # 저장소 루트에서 새 독립 스택 디렉터리로 이동합니다.
Copy-Item -LiteralPath '.\terraform.tfvars.example' -Destination '.\terraform.tfvars' # 최초 한 번 복사한 뒤 실제 ID를 편집합니다.
terraform init # 공급자와 lock 파일을 준비하며 AWS 리소스를 생성하지 않습니다.
terraform fmt -check -recursive # HCL 형식을 확인합니다.
terraform validate # 문법·스키마를 확인하며 실제 서비스 성공을 보장하지 않습니다.
terraform plan -out=review.tfplan # 현재 AWS 상태를 읽고 Git에서 제외되는 계획 파일을 저장합니다.
terraform show -no-color review.tfplan # 기존 소스 변경·삭제·비용 발생 항목을 검토합니다.
terraform apply review.tfplan # 검토한 계획만 실제 적용합니다.
terraform output # 서버·버킷·큐 출력을 런타임 설정과 대조합니다.
terraform output -json resource_names # 생성 대상 자원별 실제 이름과 이름 태그를 확인합니다.
```

`terraform.tfvars`, plan, state는 Git/공유 ZIP에 넣지 않는다. 키·비밀번호·인증서 개인키를 Terraform 변수/user data/`aws_s3_object.content`에 넣지 않는다. 코드의 S3 object는 GuardDuty용 **빈 폴더 marker**뿐이다.

이전 이름 규칙의 패키지를 이미 적용했다면 새 이름은 일부 AWS 자원의 **교체**를 유발한다. `terraform plan`의 `-/+`, `+/-`, 삭제 항목과 IAM·큐·구독 연결 변경을 확인하고, 원본·큐 잔여 메시지·EBS·스냅샷을 보존하는 이관 순서를 정한다. 이름 규칙 개정 자체가 기존 AWS 자원을 즉시 변경하지는 않는다. 재사용 입력으로 연결한 기존 소스 이름은 유지한다.

권장 순서는 기반 생성 → ES/Kibana/Logstash/Filebeat 설치 → CloudTrail A/B 하나 선택 → 나머지 소스를 한 종류씩 연결 → 장애/복구 검증이다. 기존 CWL 그룹을 선택하면 첫 apply에서 **구독 필터 한 개가 추가되어 앞으로의 전달·비용이 시작**된다. 그룹당 기존 구독 수·중복 수집을 확인한다. `enable_alerting=true`도 SNS 구독까지 만들지는 않으므로 승인된 수신 경로를 별도로 연결해야 사람이 알림을 받는다.

### A. 기존 Trail 목적지와 보관을 유지

```hcl
create_cloudtrail = false # 기존 Trail을 그대로 유지합니다.
existing_cloudtrail_bucket_name = "REPLACE-EXISTING-BUCKET" # 이 리전·같은 계정 버킷입니다.
existing_cloudtrail_object_prefix = "AWSLogs/123456789012/CloudTrail/" # 실제 일반 이벤트 경로를 확인합니다.
existing_cloudtrail_kms_key_arns = ["arn:aws:kms:ap-northeast-2:123456789012:key/REPLACE"] # SSE-KMS라면 기존 키 ARN을 입력합니다.
```

이 설정은 collector IAM과 CT SQS의 S3 발행 권한만 연결한다. **기존 버킷의 notification·정책·보관·Trail 목적지는 변경하지 않는다.** 기존 버킷 소유 스택의 notification에 규칙을 병합해야 새 객체 알림이 온다. 조직 Trail은 `AWSLogs/o-.../<account>/CloudTrail/` 등 실제 경로가 다르다. 여러 계정 수집은 별도 prefix·권한·계정 매핑 설계가 필요하다.

다음 블록은 **기존 `aws_s3_bucket_notification` 리소스 안에 병합**하는 예시다. 같은 버킷에 새로운 독립 notification 리소스를 추가하지 않는다. 출력 `existing_cloudtrail_notification_queue_configuration`에 동일한 AWS API 형식 데이터가 있다.

```hcl
queue { # 기존 notification 리소스 내부에 추가할 블록입니다.
  id = "whs-elk-s3-cloudtrail-objects" # 기존 버킷용 Terraform 출력과 일치하는 알림 식별자입니다.
  queue_arn = "arn:aws:sqs:ap-northeast-2:123456789012:whs-elk-sqs-cloudtrail-ingest" # 출력의 실제 CT 큐 ARN으로 바꿉니다.
  events = ["s3:ObjectCreated:*"] # 새 객체 생성 알림입니다.
  filter_prefix = "AWSLogs/123456789012/CloudTrail/" # 실제 일반 이벤트 prefix입니다.
  filter_suffix = ".json.gz" # digest와 marker를 제외합니다.
} # 기존 다른 notification 규칙을 보존합니다.
```

동일 이벤트 종류에 겹치는 prefix/suffix가 있으면 S3가 거부할 수 있다. 기존 경로 재사용 또는 EventBridge fan-out을 별도로 설계한다. `put-bucket-notification-configuration`은 설정을 통째로 교체하므로 출력 조각을 그대로 PUT하지 않는다. 연결 전의 과거 S3 객체는 자동 알림이 발생하지 않는다.

IAM Allow만으로 bucket/endpoint policy·SCP·CMK policy의 Deny를 넘을 수 없다. `collector_role_arn`을 기존 소유자에게 제공하고 지정 prefix 읽기·필요 목록 조회 및 기존 CMK `kms:Decrypt`를 허용한다. 기존 버킷은 신규 원본 30일 lifecycle 대상도 아니다.

### B. Trail이 없는 검증 계정에 신규 생성

```hcl
create_cloudtrail = true # 기존 조직/계정 Trail 중복이 없는지 확인한 뒤 선택합니다.
existing_cloudtrail_bucket_name = null # 신규 생성과 기존 버킷 사용은 상호 배타적입니다.
existing_cloudtrail_object_prefix = null # 신규 경로는 코드가 만듭니다.
existing_cloudtrail_kms_key_arns = [] # 신규 원본 CMK를 자동 사용합니다.
```

새 다중 리전 **계정 Trail**이 관리 읽기·쓰기 및 전역 서비스 이벤트를 수집한다. 일반 이벤트는 `cloudtrail/AWSLogs/<account>/CloudTrail/...json.gz`, digest는 `CloudTrail-Digest`다. digest는 SQS 일반 파서에서 제외한다. 무결성 검증과 삭제 방지/불변 보관은 다르다. S3 객체 작업·Lambda Invoke 등 Data events는 기본 수집하지 않으므로 구체적인 ARN/선택기와 과금을 추가 검토한다. [CloudTrail 기록 범위](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html)

### GuardDuty 선택

기존 detector가 있으면 `create_guardduty_detector=false`, `guardduty_detector_id`에 실제 ID, `enable_guardduty_export=true`로 한다. 기존 publishing destination이 있으면 원래 소유 스택에서 경로를 결정하며 같은 목적지를 이중 관리하지 않는다. GuardDuty가 없는 독립 테스트 계정에서만 아래를 쓴다.

```hcl
create_guardduty_detector = true # 리전 detector가 없음을 먼저 확인합니다.
guardduty_detector_id = "" # 신규 생성과 기존 ID는 상호 배타적입니다.
enable_guardduty_export = true # 신규 detector Findings를 S3로 내보냅니다.
```

새 detector는 `enable=true`, 후속 Finding 발생 내보내기는 15분 주기다. **Protection plans를 모두 명시적으로 관리하는 코드는 아니다.** 계정/조직 자동 활성화 정책과 S3·EKS·RDS·Runtime·Malware Protection 상태를 확인하고 필요한 범위·비용을 결정한 뒤 별도 feature 리소스로 관리한다. 기존 detector의 주기/보호 설정은 바꾸지 않는다. 신규 active Finding과 반복 발생 갱신의 주기는 다르며 archived/suppressed export 제외가 있다. [GuardDuty export](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_exportfindings.html), [detector 리소스](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/guardduty_detector)

### WAF 선택

web ACL당 로깅 목적지는 하나다. 기존 CWL 목적지가 있으면 `existing_log_group_names.waf`에 실제 그룹을 넣고 `manage_waf_logging=false`로 로깅 소유권을 유지한다. 이 패키지는 CWL 구독만 추가한다. 새 연결을 이 스택이 소유할 때만 `manage_waf_logging=true`와 기존 `waf_web_acl_arn`을 입력한다. 그룹 이름은 `aws-waf-logs-`로 시작해야 하므로 신규 그룹에는 `aws-waf-logs-whs-elk-cloudwatch-waf`를 사용한다. CloudFront scope는 `us-east-1` 별도 스택이 필요하다. [WAF CWL 설정](https://docs.aws.amazon.com/waf/latest/developerguide/logging-cw-logs.html)

## 5. 런타임 입력 계약

| 소스 | S3 정상 객체 | 해석할 구조 |
|---|---|---|
| 신규 CloudTrail | `cloudtrail/AWSLogs/<account>/CloudTrail/<region>/...json.gz` | gzip 해제 후 `Records` 배열의 각 항목 |
| 기존 CloudTrail | 입력한 기존 버킷·prefix | 동일; digest는 제외 |
| CloudWatch Agent | `cloudwatch/YYYY/MM/dd/HH/...jsonl.gz` | JSONL envelope의 `logEvents`; owner/group/stream 및 ID/timestamp/message 보존 |
| WAF | `waf/YYYY/MM/dd/HH/...jsonl.gz` | CWL envelope를 분리한 뒤 message 안 WAF JSON 해석 |
| GuardDuty | `guardduty/...jsonl.gz` | JSONL Finding 하나가 이벤트 하나 |

Firehose는 `Decompression=GZIP` → `CloudWatchLogProcessing/DataMessageExtraction=false` → `AppendDelimiterToRecord` 후 S3 출력만 다시 GZIP 압축한다. 이벤트 삭제 없는 형식 처리다. message만 추출하면 계정·그룹·스트림 메타데이터가 사라져 껐다. 줄바꿈 처리기는 매개변수가 필요 없다. [AWS 메시지 추출](https://docs.aws.amazon.com/firehose/latest/dev/Message_extraction.html), [Processor API](https://docs.aws.amazon.com/firehose/latest/APIReference/API_Processor.html)

정상 알림은 `.gz`만 대상이며 `firehose-errors/<source>/...`는 따로 조사·복구한다. Filebeat는 `sqs.max_receive_count: -1`로 자체 자동 삭제를 끄고 **SQS redrive 5회 정책**이 DLQ 이동을 담당하게 한다. SQS 14일을 넘는 중단은 알림 만료 때문에 원본 목록 기반 재수집이 필요하다. [Filebeat S3 input](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-aws-s3)

## 6. 실행 주체별 권한

| 주체 | 필요한 동작 | 확인할 제한 |
|---|---|---|
| Terraform 배포 역할 | EC2/SG·S3·SQS·KMS·IAM·CWL·Firehose 관리, 선택 CloudTrail/GuardDuty/WAF/SNS/EventBridge/alarms, 지정 역할의 `iam:PassRole` | SCP·permission boundary·리전·이름 정책 |
| SSM 운영자 | 지정 instance의 StartSession, 본인 세션 종료/재개, 지정 SSM document | instance의 SSMManagedInstanceCore는 운영자 권한을 대신하지 않음 |
| 배포 파일 업로드 운영자 | artifact의 역할 prefix PutObject, CMK GenerateDataKey/multipart Decrypt, 필요 목록/삭제 | EC2 역할에는 업로드 권한 없음 |
| collector 역할 | 원본 S3 읽기·소스 SQS 소비·원본 KMS 복호화·자기 artifact 읽기 | 원본 쓰기/삭제·다른 역할 artifact·DLQ 자동 소비 없음 |
| ES 역할 | 별도 snapshot S3 읽기/쓰기/정리·자기 artifact 읽기 | 원본 버킷 쓰기/삭제 없음 |
| 업무 Agent 역할 | 지정 그룹의 로그 스트림 생성·로그 쓰기·필요 설명 API | 기존 업무 역할을 이 스택에서 변경하지 않음 |
| 기존 원본 소유자 | collector prefix 읽기/CMK 권한, 기존 notification 병합 | 기존 규칙·prefix 중복·계정/리전 확인 |

WAF 로깅 실행자는 AWS 로그 전달 resource policy/서비스 연결 역할 구성 권한도 필요하다. GuardDuty 목적지 실행자는 버킷 위치·prefix 조회/검증 및 CMK 조회 권한이 필요하다. EC2 생성 권한만으로 전체 적용이 되지는 않는다. [GuardDuty 권한](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_exportfindings.html), [CloudTrail KMS](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-kms-key-policy-for-cloudtrail.html)

## 7. 팀 공유 상태 저장소

처음은 local backend로 검증할 수 있다. 팀 실습은 **기존 별도 상태 버킷**에 Versioning·암호화·접근 제한·잠금을 적용한다. 원본/스냅샷/3일 만료 artifact 버킷을 state 버킷으로 재사용하지 않는다. 이 스택이 자신의 backend 버킷을 만드는 구조도 아니다. 기존 상태 버킷을 준비한 뒤 `backend.tf`에 다음을 저장하고 `backend.hcl.example`을 실제 값으로 고쳐 `backend.hcl`로 저장한다. 예시 key `whs-elk/terraform.tfstate`처럼 ELK 전용 key를 사용하며, `envs/before` 또는 `envs/after`의 state key와 공유하지 않는다.

```hcl
terraform { # 기존 required_version/provider 블록과 함께 사용할 backend 선언입니다.
  backend "s3" {} # 세부 값은 backend.hcl로 전달하고 비밀 키는 넣지 않습니다.
} # backend 선언을 끝냅니다.
```

```powershell
terraform init -backend-config=backend.hcl # local state가 없는 최초 초기화 예시입니다.
```

이미 local state가 있다면 백업·동시 실행 중단·대상 확인 후 `-migrate-state`로 이전한다. S3 backend는 state 객체의 GetObject/PutObject, `<key>.tflock`의 GetObject/PutObject/DeleteObject 등 잠금 권한이 필요하다. [Terraform S3 backend](https://developer.hashicorp.com/terraform/language/backend/s3)

## 8. 적용 후 검증과 운영 한계

- 로컬 validate/mock 계획은 실제 AWS 수락·전달·IAM 경로의 성공을 보장하지 않는다. 실제 S3 객체를 내려받아 압축·파서를 검사하고 SQS→Kibana까지 대조한다. 파일 수와 이벤트 수는 다르다.
- 기본 경보는 SQS 적체·DLQ·EC2 상태·Firehose 전달 지연과 GuardDuty 알림이다. ES JVM/디스크, Logstash PQ/파싱 실패, Filebeat publish, CWL DeliveryErrors의 지표/알림은 추가해야 한다.
- SNS는 별도 구독이 필요한 기본 연결점이며 SNS용 CMK는 이 예제에서 구성하지 않는다. 조직이 SNS 저장 암호화를 요구하면 CMK와 EventBridge/CloudWatch 키 정책을 함께 구성·검증한다. `alias/aws/sns`만 추가해 모든 연동이 해결된다고 가정하지 않는다.
- Versioning/collector Delete 금지는 운영자 삭제를 막는 WORM이 아니다. Object Lock·별도 Log Archive 계정은 다음 운영 확장 단계다.
- `delete_on_termination=false`는 EBS 보존이며 재생성 EC2가 이전 볼륨을 자동 연결하지 않는다. 교체는 새 root EBS를 만들므로 기존 볼륨 복원 또는 snapshot/원본 재색인 절차가 필요하다.
- `terraform destroy`를 일상 검증 명령처럼 실행하지 않는다. 새 GuardDuty detector 삭제는 해당 리전 비활성화와 기존 Findings 제거, Trail 삭제는 향후 기록 중단으로 이어진다. 버킷은 `force_destroy=false`여서 객체가 남으면 삭제가 거부되며, 남은 EBS/버킷/CMK의 보관 비용도 별도 정리 대상이다.

추가 공식 스키마: [Firehose Terraform](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kinesis_firehose_delivery_stream), [S3 notification](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_notification), [GuardDuty destination](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/guardduty_publishing_destination), [EventBridge SNS 권한](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-use-resource-based.html). 문서 확인 기준일: 2026-09-16.
