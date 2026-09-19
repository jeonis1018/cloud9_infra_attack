# AWS 서비스 구축 가이드 — EC2 역할별 1대

범위는 **기존 VPC의 private subnet + 수집 EC2 1대(Filebeat·Logstash) + Elasticsearch EC2 1대 + Kibana EC2 1대**이다. AWS 소스 로그를 S3에 먼저 보관하고, S3 생성 알림을 SQS로 받은 Filebeat가 객체를 읽는다. Logstash가 분리·파싱·필드를 정리하고 Elasticsearch에 저장한다. 불필요한 로그 삭제는 첫 검증에서는 적용하지 않는다. 완전한 원본을 대조하여 필터 규칙을 검증한 뒤 도입한다.

**권장 실행은 Terraform이며, 아래 콘솔 절차는 학습·설정 확인 또는 Terraform을 사용하지 않을 때의 대안이다.** 같은 리소스를 두 방식으로 중복 생성하지 않는다. Terraform으로 만들었다면 콘솔은 값과 상태를 확인하는 용도로 사용하고 수정은 코드에서 수행한다. [배포 전 확인](preflight.md)을 먼저 끝낸다. 기존 자원 소유권을 확인하지 않은 상태에서 실제 `apply`를 실행하지 않는다.

콘솔 수동 생성에도 [자원 이름 규칙](naming.md)의 `whs-elk-<서비스>-<역할>`을 적용한다. 자동 할당 ID를 이름처럼 바꾸지는 않으며, EC2·EBS·GuardDuty처럼 지원되는 곳에는 `Name` 태그를 사용한다. 기존 소스 자원을 재사용할 때는 원래 이름을 그대로 입력한다.

## 1. 서비스 역할과 사용 필요성

“필수”는 AWS 전체에서 반드시 써야 한다는 뜻이 아니라 **이 가이드가 선택한 경로에서 필요한 역할**이라는 뜻이다. 대체 설계를 채택하면 일부 서비스는 바뀔 수 있다.

| 구성 | 역할 | 이 구조에서 사용하는 이유 | 필요성 구분 |
|---|---|---|---|
| EC2 3대·EBS | 수집/저장/조회 프로세스와 영구 디스크 | 역할별 CPU·메모리 사용량, 재시작 영향, 접근 권한을 분리한다. | 선택한 자체 운영 ELK 구조의 필수 기반 |
| Elasticsearch | 검색용 색인과 데이터 저장 | 시간·IP·사용자·계정·Finding 기준으로 여러 로그를 검색한다. | ELK 검색 계층 필수 |
| Logstash | JSON 분리, 시간 변환, 공통 필드 정리, 오류 분리 | Filebeat가 나눈 CloudTrail 이벤트와 CWL `logEvents`, WAF 메시지, GuardDuty JSONL의 서로 다른 형식을 정리한다. | 선택한 전처리 계층 필수; 다른 파이프라인으로 대체 가능 |
| Kibana | 대시보드와 검색 UI | 비개발 운영자도 로그 검색·필터·집계를 수행하게 한다. | 사용자 요구의 조회 계층 필수 |
| Filebeat | SQS 알림 수신·S3 다운로드·Logstash 전달 | Logstash의 단순 S3 polling과 달리 queue 기반 수집을 분리하고 후속 확장 시 여러 수집기를 둘 수 있다. | 선택한 S3→SQS 소비 방식에 필요; 다른 consumer로 대체 가능 |
| S3 원본 | 재처리 가능한 감사 원본 보관 | EC2·파서 오류 이후 원본을 다시 읽고 전처리 결과와 대조한다. | 이번 복구 요구의 필수 저장 계층 |
| SQS + DLQ | 파일 처리 대기·재시도·반복 실패 분리 | 수집 서버가 잠시 중단되어도 알림을 보관하고 문제 파일을 찾는다. 로그 본문을 저장하는 곳은 아니다. | 이번 queue 기반 구조에 필요 |
| KMS·IAM·SG | 저장 암호화 키, 권한, 네트워크 경계 | 서비스별 쓰기·읽기 범위를 나누고 키와 데이터에 별도 권한을 적용한다. GuardDuty S3 export는 KMS가 필요하다. | IAM/네트워크 제어 필수; 고객 관리 KMS는 GuardDuty 경로 필수 및 나머지 보안 설계 선택 |
| CloudWatch Agent | 업무 서버의 파일 로그를 CWL로 전달 | 서버의 OS·애플리케이션 로그를 수집한다. WAF/CloudTrail/GuardDuty 로그를 직접 받는 Agent가 아니다. | 서버 로그 소스 경로에 필요; 다른 shipper로 대체 가능 |
| CloudWatch Logs | 서버·WAF 로그 수신과 원본 단기 보관 | Firehose 구독의 출발점이며 수집 상태를 ELK 외부에서 대조한다. | 이번 서버/WAF 경로에 필요 |
| Firehose | CWL gzip 해제·배치·S3 쓰기 | 별도 Lambda 없이 CWL 봉투를 유지하며 S3 gzip JSONL 객체로 묶는다. | 이번 CWL→S3 경로에 필요; WAF 직접 S3 등 대안 가능 |
| WAF | 웹 요청 허용/차단과 요청 로그 | 웹 접근 보안 시나리오를 검증한다. ELK 자체를 위해 새 WAF를 만들 필요는 없다. | 해당 로그 소스·보호 대상이 있을 때 |
| CloudTrail trail | AWS API 활동 로그를 S3에 지속 전달 | 콘솔·IAM·인프라 API 활동을 감사한다. 이미 적합한 trail이 있으면 재사용한다. | CloudTrail 소스 수집에 필요 |
| GuardDuty | 보안 위협을 분석해 Findings 생성 | 규칙·통계·위협 정보 기반 탐지 결과를 검색·조사한다. | GuardDuty Findings 소스에 필요 |
| SSM Session Manager | 관리 세션과 Kibana 포트 포워딩 | 운영자 인터넷 SSH·5601 개방 없이 접근한다. | 이번 접속 방식에 필요; 기업 VPN 등으로 대체 가능 |
| S3 스냅샷 | Elasticsearch 인덱스 백업 | 원본 재수집과 별개로 인덱스를 복원한다. | 이번 복구 검증에서 사용 |
| S3 artifact | 설치 설정·인증서 전달을 위한 제한된 저장소 | 공용 링크 없이 EC2 role로 필요한 파일을 전달한다. 개인키를 전달한다면 prefix별 role과 lifecycle을 엄격히 제한한다. | 제공한 배포 절차의 편의 기능; SSM 등으로 대체 가능 |
| EventBridge·SNS·CloudWatch Alarm | ELK 장애와 독립된 탐지/플랫폼 알림 | ELK가 내려가도 GuardDuty Finding이나 queue 적체를 알린다. | 운영 검증 권장; 첫 CloudTrail 연결만 검증할 때 선택 |

Filebeat는 S3 gzip 처리와 SQS 기반 수집을 지원하며, 복수 소비자·visibility timeout·처리 확인 규칙을 제공한다. 수집 확인은 Elasticsearch 색인 성공 시점과 같지 않으므로 S3 원본 및 Logstash 디스크 큐를 함께 사용한다. [Filebeat AWS S3 input](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-aws-s3)

## 2. 구축 순서와 Terraform 대응

| 순서 | AWS 콘솔에서 만들거나 확인할 것 | 함께 보는 Terraform 파일/입력 |
|---|---|---|
| ① | 기존 VPC, subnet, NAT/endpoint, 기존 로그 소스와 owner 확인 | `vpc_id`, `private_subnet_ids`, `existing_log_group_names`, `guardduty_detector_id` |
| ② | KMS, S3 원본·스냅샷·artifact, SQS/DLQ와 각 정책 | `terraform/`의 storage·IAM 정의, `raw_retention_days` |
| ③ | 역할별 SG, instance profile, EC2 3대 | `compute.tf`, `instance_types`, `root_volume_gib`, `ami_id` |
| ④ | EC2 내부 Elasticsearch → Kibana → Logstash·Filebeat 설치 | `runtime/` 설치·인증·템플릿 절차 |
| ⑤ | CloudTrail→S3 첫 이벤트 검증 | 기존 trail 재사용 경로 또는 `create_cloudtrail` 명시적 선택 |
| ⑥ | Firehose 2개 및 CWL 구독, Agent·WAF 로그 | `existing_log_group_names`, `manage_waf_logging`, `waf_web_acl_arn` |
| ⑦ | GuardDuty S3 export 및 선택적 알림 | `enable_guardduty_export`, `guardduty_detector_id`, `enable_alerting` |
| ⑧ | 대조, 중단/복구, 스냅샷·S3 재처리 | 상위 가이드 검증 절차 |

첫 패키지는 기존 VPC를 재사용하지만 원본·스냅샷·artifact 버킷과 소스별 SQS/DLQ는 새로 만든다. 기존 CloudTrail 버킷을 소비할 때는 `existing_cloudtrail_bucket_name`, `existing_cloudtrail_object_prefix`, `existing_cloudtrail_kms_key_arns`를 입력한다. 코드가 collector 읽기·복호화와 queue 발행 허용을 구성하지만, **기존 버킷의 notification 병합과 필요한 bucket/key 정책은 원 소유자가 반영**한다. 기존 trail의 목적지를 자동 이관하지 않는다. 새 검증 trail을 만들면 중복 관리 이벤트 수집료가 발생할 수 있다. [CloudTrail 복수 trail 요금 주의](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-multiple-trails.html)

다음은 `terraform.tfvars`의 **입력 형태 예시**다. 기존값을 모른 채 적용하는 기본 설정이 아니며 `terraform/terraform.tfvars.example` 전체 항목을 함께 검토한다. 모든 실행 줄에 주석을 달았다.

```hcl
aws_region = "ap-northeast-2" # 서울 리전의 예시이며 소스·버킷·queue 리전을 맞춘다.
expected_account_id = "123456789012" # 실제 배포 계정 ID를 넣어 계정 오적용을 차단한다.
name_prefix = "whs-elk" # 신규 자원 공통 접두사이며 입력 검증으로 이 값을 고정한다.
vpc_id = "vpc-REPLACE_ME" # 새 VPC를 만들지 않고 사전 확인한 VPC를 사용한다.
private_subnet_ids = { # 역할별 EC2를 배치할 기존 private subnet을 지정한다.
  collector = "subnet-REPLACE_ME" # Filebeat와 Logstash가 함께 설치될 subnet이다.
  elasticsearch = "subnet-REPLACE_ME" # 검색 데이터를 저장할 EC2의 subnet이다.
  kibana = "subnet-REPLACE_ME" # 조회 서버 subnet이며 첫 단계에서는 같은 subnet도 가능하다.
} # subnet 입력을 끝낸다.
existing_log_group_names = { # 기존 소스 로그 그룹의 이름을 입력하여 중복 생성을 피한다.
  cloudwatch = "/REPLACE_WITH_EXISTING_APP_LOG_GROUP" # 실제 업무 CloudWatch Agent 로그 그룹이다.
  waf = "aws-waf-logs-REPLACE_ME" # 기존 WAF logging configuration이 가리키는 그룹이다.
} # 로그 그룹 입력을 끝낸다.
create_cloudtrail = false # 기존 trail을 임의로 중복 생성하지 않으며 재사용 연결을 별도 구성한다.
existing_cloudtrail_bucket_name = null # 기존 trail을 연결할 단계에서 실제 원본 버킷 이름을 넣는다.
existing_cloudtrail_object_prefix = null # 기존 trail 연결 시 /CloudTrail/로 끝나는 실제 prefix를 넣는다.
existing_cloudtrail_kms_key_arns = [] # 기존 로그가 SSE-KMS이면 읽어야 하는 기존 키 ARN들을 넣는다.
create_guardduty_detector = false # 기존 detector를 우선 확인하며 신규 생성을 기본 해제한다.
guardduty_detector_id = "" # GuardDuty 단계에서 실제 기존 detector ID를 넣는다.
enable_guardduty_export = false # detector·bucket/KMS 정책을 확인한 뒤 export를 켠다.
manage_waf_logging = false # 기존 Web ACL 로깅은 원 Terraform owner가 계속 관리한다.
create_s3_gateway_endpoint = false # 기존 endpoint를 확인했을 때 중복 생성하지 않는다.
raw_retention_days = 30 # 원본 보관 한 달이라는 프로젝트 가정이며 규정 요구에 맞게 조정한다.
enable_alerting = false # 첫 연결 후 외부 알림 시험 단계에서 선택적으로 켠다.
```

`false`인 소스 옵션은 그 소스의 로그 발생·전달까지 자동 완성하지 않는다. 이 예제는 **플랫폼 인프라를 먼저 준비**하는 설정이다. 다음 단계에서 소스별 연결을 하나씩 켜고 원본 도착을 확인한다.

## 3. KMS·S3·SQS를 먼저 준비

### 3-1. 키와 IAM 역할

1. [KMS 콘솔](https://console.aws.amazon.com/kms/)에서 대상 리전의 **고객 관리형 대칭 암호화 키**를 준비한다. 원본용과 artifact용 키는 소유자·목적을 구분한다. 제공 Terraform의 스냅샷 버킷은 **SSE-S3**이므로 별도 고객 관리 KMS 권한이 필요하지 않다. SSE-KMS로 바꾸려면 저장소 설정과 ES role/key 정책도 함께 변경한다.
2. key administrator는 정책·수명 주기를 관리하고, key user는 지정 서비스 작업을 수행한다. collector에 key administrator 권한을 주지 않는다.
3. [IAM 콘솔](https://console.aws.amazon.com/iam/)의 Roles에서 EC2 role 3개와 서비스 role을 만든다. EC2 role 신뢰 주체는 EC2, Firehose role은 Firehose, CWL 구독 전달 role은 CloudWatch Logs이다.
4. 역할 이름을 만들었다고 전달이 되는 것은 아니다. 아래 **identity policy + resource policy + key policy**가 함께 맞아야 한다.

| 호출 경로 | 역할/서비스 주체의 권한 | 대상 리소스 정책에서 확인할 것 |
|---|---|---|
| CWL→Firehose | Logs 전달 role의 지정 stream `firehose:PutRecord`, `PutRecordBatch` | role trust는 Logs 서비스와 해당 account/region 로그 소스 조건에 제한 |
| Firehose→S3 | Firehose role의 대상 bucket 위치/목록·multipart 관련 권한, 해당 prefix `s3:PutObject`, 필요한 KMS 사용 | raw key 정책의 Firehose role 허용; 목적지가 다른 계정이면 bucket 허용도 필수 |
| CloudTrail→S3 | CloudTrail 서비스의 bucket ACL 확인·소스 계정 경로 쓰기 | `cloudtrail.amazonaws.com`, trail ARN `aws:SourceArn`, 공식 ACL 조건·KMS 정책 |
| GuardDuty→S3 | GuardDuty 서비스의 bucket 위치 확인·Finding 객체 쓰기, 키 생성/암호화에 필요한 권한 | `guardduty.amazonaws.com`와 해당 detector ARN/account 제한, bucket·KMS 정책 둘 다 |
| S3→SQS | S3 서비스의 지정 queue `sqs:SendMessage` | queue policy에 bucket ARN+소스 계정 조건. SQS를 고객 관리 KMS로 암호화하면 S3 서비스의 해당 키 사용도 허용 |
| collector→S3/SQS | raw `GetObject`·필요한 bucket 조회, SQS `ReceiveMessage/DeleteMessage/ChangeMessageVisibility/GetQueueAttributes`, raw key `Decrypt` | collector role에 원본 `DeleteObject`를 부여하지 않는다. endpoint policy도 같은 리소스를 허용 |
| Elasticsearch→스냅샷 | snapshot bucket 목록·읽기·쓰기·삭제·multipart; SSE-KMS 변경 시 해당 키 사용 추가 | 기본은 SSE-S3. snapshot 저장소 범위에만 한정하고 raw 원본 수정 권한과 분리 |
| EC2→SSM | `AmazonSSMManagedInstanceCore` 또는 동등한 최소 권한 | SSM endpoint/네트워크, 운영자의 대상 인스턴스 StartSession 권한 |
| 업무 Agent→CWL | 지정 그룹/stream의 로그 쓰기, SSM 설정 사용 시 지정 파라미터 읽기 | 기존 role·설정 owner에 필요한 권한만 추가 |

AWS 전달 서비스는 EC2의 S3 gateway endpoint를 통과하지 않는다. 로그 bucket에 `aws:sourceVpce` 조건으로 모든 외부 요청을 거부하면 서비스 전달도 실패할 수 있다. explicit Deny를 넣을 때는 서비스 호출 조건과 공식 서비스 정책을 함께 검토한다. 암호화 헤더를 지나치게 강제하면 CloudTrail digest 등 다른 정상 객체 형식도 거부할 수 있으므로 제공된 정책을 임의로 일반화하지 않는다. [CloudTrail 보안 정책 주의](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html)

### 3-2. S3 버킷

1. [S3 콘솔](https://console.aws.amazon.com/s3/) → **버킷 만들기**에서 동일 리전의 전용 원본 버킷을 만든다. 이름은 전역 유일해야 한다. `whs-elk-s3-raw-123456789012-ap-northeast-2` 형식에서 계정·리전을 실제 값으로 바꾼다.
2. Block Public Access 전체 활성화, Object Ownership은 Bucket owner enforced, 기본 암호화는 실제 raw KMS 키, Versioning 활성화로 맞춘다.
3. Management → Lifecycle에서 원본 보관 기간과 비현재 버전 보관 기간을 **각각** 설정한다. 예를 들어 원본 30일이 목표라면 이 값이 규정 보존 기간인지 비용 검증용 가정인지 적는다.
4. `whs-elk-s3-snapshots-<account>-<region>`과 `whs-elk-s3-artifacts-<account>-<region>` 버킷을 만들고 공개 차단·암호화를 설정한다. artifact에는 배포 파일 정리 주기를 설정하되, **스냅샷 버킷에는 객체를 임의 만료시키는 일반 lifecycle을 적용하지 않고 Elasticsearch snapshot/SLM으로 정리**한다. artifact에는 비밀번호를 포함한 평문 설정을 올리지 않는다. 서버 인증서 개인키는 필요한 수신 role/prefix만 읽을 수 있게 하고 CA 개인키는 올리지 않는다.
5. 원본 bucket policy를 연결하되 기존 정책이 있다면 전체를 통합한다. 관리 권한과 로그 전달 권한, collector 읽기 권한은 분리한다.
6. Object Lock은 첫 패키지의 기본값이 아니다. 기업의 변경 불가 보존 요구를 검증할 때 별도 retention·해제 권한·테스트 비용을 정해 도입한다. Versioning만으로 삭제 방지가 완성되지는 않는다.

### 3-3. SQS와 DLQ

1. [SQS 콘솔](https://console.aws.amazon.com/sqs/) → **큐 생성**에서 소스별 DLQ 네 개와 main queue 네 개를 만든다. 이름은 `whs-elk-sqs-<source>-dlq`와 `whs-elk-sqs-<source>-ingest`이며 `<source>`는 `cloudtrail`, `cloudwatch`, `waf`, `guardduty`다.
2. 유형은 **Standard**. 첫 설정은 retention 14일, visibility timeout 300초, long polling 20초를 기준으로 삼되 제공 Terraform과 값을 맞춘다. DLQ retention은 main queue보다 짧지 않게 한다.
3. main queue에서 해당 DLQ로 redrive를 켜고 반복 수신 기준을 설정한다. 시작 예시는 5회다. 실제 파일 처리 시간이 길면 visibility timeout 연장과 최대 재시도 동작을 함께 확인한다.
4. 첫 구성은 SQS 자체 서버 암호화(SSE-SQS)를 사용하면 S3→queue용 KMS 정책 복잡도를 줄일 수 있다. 고객 관리 KMS로 변경하면 queue key policy에 S3의 `GenerateDataKey`/`Decrypt`를 허용한다.
5. main queue access policy에 **정확한 원본 bucket ARN과 소스 계정 조건**으로 S3의 SendMessage만 허용한다. collector role의 소비 권한은 IAM으로 부여한다.

S3와 SQS는 같은 리전에 있어야 한다. queue 암호화에 따른 키 정책까지 맞아야 S3 콘솔의 알림 목적지 검증을 통과한다. [S3 알림 목적지](https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-event-types-and-destinations.html), [S3→SQS 권한](https://docs.aws.amazon.com/AmazonS3/latest/userguide/grant-destinations-permissions-to-s3.html)

### 3-4. S3 객체 생성 알림

원본 bucket → Properties → Event notifications → Create event notification에서 `All object create events`를 선택하고 아래처럼 분리한다. suffix `.gz`는 실제 생성 파일과 일치해야 한다.

| 알림 | prefix 예시 / 패키지 계약 | 목적지 |
|---|---|---|
| CloudTrail | `cloudtrail/AWSLogs/ACCOUNT/CloudTrail/` | CloudTrail main queue |
| 서버 로그 | `cloudwatch/` | CloudWatch main queue |
| WAF | `waf/` | WAF main queue |
| GuardDuty | `guardduty/` | GuardDuty main queue |

CloudTrail-Digest는 무결성 검증 자료이므로 원본 S3에는 보존하고 일반 이벤트 파서 알림에서 제외한다. 조직 trail의 경로는 조직 ID 등이 포함되어 달라질 수 있으므로 위 account trail prefix를 그대로 적용하지 않는다. 기존 객체에는 새 알림이 소급 생성되지 않으므로 이전 로그는 별도 재수집 작업으로 처리한다. **SQS 콘솔에서 main queue 메시지를 임의로 소비·삭제하지 않는다.**

## 4. EC2 3대와 내부 통신

1. [EC2 콘솔](https://console.aws.amazon.com/ec2/) → Launch instance에서 역할별로 한 대씩 만든다. Name은 `whs-elk-ec2-collector`, `whs-elk-ec2-elasticsearch`, `whs-elk-ec2-kibana`다. 같은 Ubuntu 24.04 x86_64 계열 AMI와 같은 Elastic 버전을 사용한다. 실제 AMI ID는 해당 리전에서 조회하여 확인한다.
2. Network settings에서 기존 VPC/private subnet을 고르고 Auto-assign public IP를 비활성화한다. 업무 서버의 instance profile을 복사하지 않고 로그 역할별 profile을 지정한다.
3. 초기 사양 예시는 collector `t3.large`, Elasticsearch `t3.large`, Kibana `t3.medium`; gp3 볼륨은 각각 50/100/30 GiB이다. 이는 성능 보장값이 아니다. 지속 부하에서 burst credit·CPU·JVM·디스크와 처리량을 측정한다.
4. IMDSv2 required, EBS 암호화, 상세 태그를 적용한다. root EBS의 Name은 `whs-elk-ebs-<role>-root`다. 영구 데이터·설정·큐의 백업 방법과 인스턴스 삭제 시 EBS 보존 동작을 확인한다.
5. 역할별 `whs-elk-sg-<role>` 보안 그룹을 아래 표로 제한한다. SSM 세션은 인스턴스의 outbound 경로를 사용하므로 인터넷 inbound 22를 열 필요가 없다.
6. SSM Fleet Manager/Managed nodes에서 세 인스턴스 Online을 확인하고 Session Manager로 접속한다. 이후 설치는 `runtime/` 가이드를 따른다. Terraform은 인프라를 만들며 Elastic 설치가 완료됐다는 뜻은 아니다.

| 출발지 | 목적지 | 연결 | 이유 |
|---|---|---|---|
| collector SG | Elasticsearch SG | TCP 9200 / HTTPS | 로그 색인 |
| Kibana SG | Elasticsearch SG | TCP 9200 / HTTPS | 검색·관리 API |
| 같은 collector 내부 Filebeat | Logstash localhost | TCP 5044 | 같은 서버의 수집→전처리; 원격에 개방하지 않음 |
| 운영자 PC | SSM 서비스 → Kibana localhost | 터널의 local 5601 | 프로젝트 조회 접속 |
| 각 EC2 | AWS API·패키지 저장소 | HTTPS 443, 필요시 apt용 HTTP 80 | SSM·SQS·S3·설치; 실제 NAT/endpoint 경로 필요 |
| 향후 클러스터 노드 | 다른 ES 노드 | TCP 9300 / transport TLS | 이번 단일 노드에서는 외부에 열지 않음 |

private subnet에 배치했다는 사실만으로 안전하지 않다. Elasticsearch·Kibana 자체 인증과 TLS를 함께 사용한다. SSM 포트 포워딩은 네트워크 경로이며 브라우저의 서버 인증서 검증을 대신하지 않는다. CA 신뢰·SAN이 실제 접속 이름과 맞아야 한다. [Session Manager 세션/포트 포워딩](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-sessions-start.html)

## 5. CloudTrail로 첫 데이터 흐름 완성

1. [CloudTrail 콘솔](https://console.aws.amazon.com/cloudtrail/) → Trails에서 기존 multi-region/organization trail의 S3 위치와 status를 먼저 확인한다.
2. **기존 trail이 충분하면:** S3 목적지를 바꾸지 않고 `existing_cloudtrail_*` 입력으로 기존 bucket/prefix/KMS를 연결한다. 제공 Terraform의 읽기·복호화·SQS 정책 외에, 기존 owner가 bucket/key 정책을 확인하고 S3 notification→CloudTrail queue를 전체 기존 알림에 병합해야 한다. notification 병합은 이 패키지가 자동 수행하지 않는다.
3. **독립 검증 trail을 의도적으로 만들면:** Create trail에서 이름 `whs-elk-cloudtrail-management` → 기존에 준비한 raw bucket → prefix `cloudtrail` → 해당 KMS → log file validation 활성화 → Management events Read/Write를 선택한다. CloudWatch Logs 중복 전달과 SNS 파일 알림은 이 경로에 필요하지 않다. 조직 trail로 만들려면 관리/위임 권한이 별도로 필요하다.
4. S3 데이터 이벤트는 기본 관리 이벤트와 다르다. 이번 첫 검증에는 전체 버킷 데이터 이벤트를 추가하지 않는다. 필요할 때 업무 대상 bucket/prefix만 selector로 추가하여 비용과 원본 로그 버킷의 자기 자신 수집을 검토한다.
5. trail 상태의 S3 전달 오류가 없는지 확인한다. 준비한 테스트 계정/역할로 비파괴 API 조회를 수행하고 CloudTrail Event history와 원본 S3에서 같은 `eventID`를 찾는다.
6. S3 `.json.gz` 생성 → 해당 SQS main queue → Filebeat → Logstash → Kibana 검색 순서로 확인한다. `Records` 내부 이벤트 수와 실제 색인 수를 대조한다. CloudTrail이 항상 즉시 전달된다고 가정하지 않고 실제 발생/수집/검색 시각을 기록한다.

콘솔로 만드는 trail은 multi-region이며, S3에 지속 기록하고 무결성 digest를 활성화할 수 있다. bucket policy는 CloudTrail 서비스와 trail ARN을 허용해야 한다. [CloudTrail 콘솔 생성](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-a-trail-using-the-console-first-time.html)

## 6. 서버·WAF 로그용 Firehose와 CWL

### 6-1. Firehose 2개

1. [Firehose 콘솔](https://console.aws.amazon.com/firehose/) → Create Firehose stream → Source **Direct PUT**, Destination **Amazon S3**를 선택한다. CWL 구독이 Direct PUT으로 전달한다.
2. `whs-elk-firehose-cloudwatch-delivery`와 `whs-elk-firehose-waf-delivery` stream을 각각 만들어 source prefix와 오류 prefix를 분리한다. 다른 형태의 직접 전송 데이터를 이 stream에 섞지 않는다.
3. CloudWatch Logs decompression을 **활성화**, message extraction을 **비활성화**한다. owner/logGroup/logStream/logEvents[].id를 보존해야 소스 추적과 중복 처리가 쉽다.
4. Lambda transformation·dynamic partitioning·Parquet format conversion은 첫 구현에서 끈다. S3 output compression은 **GZIP**, 레코드 사이 delimiter는 newline으로 맞춘다. 압축 해제는 CWL 입력 포장 해제이며 S3 output gzip은 보관 파일 압축이므로 목적이 다르다.
5. 목적지 prefix는 각각 `cloudwatch/`와 `waf/`; 실패 prefix는 IAM 정책이 허용하는 `firehose-errors/cloudwatch/`와 `firehose-errors/waf/` 아래로 둔다. `error-output-type`과 시간 토큰까지 제공 Terraform의 `error_output_prefix`와 맞춘다.
6. buffering은 제공 Terraform의 size/interval로 시작하고 실제 지연을 측정한다. 작은 interval만으로 모든 전달 지연을 보장할 수 없다.
7. 지정 Firehose IAM role·raw KMS·CWL 오류 로그를 연결한다. 상태 Active와 S3 전달 지표를 확인한다.

CWL은 gzip 묶음을 Firehose에 전송하며 Firehose에서 이를 해제할 수 있다. message extraction은 metadata를 없애므로 이 가이드에서는 사용하지 않는다. [CWL→Firehose](https://docs.aws.amazon.com/firehose/latest/dev/writing-with-cloudwatch-logs.html), [message extraction 동작](https://docs.aws.amazon.com/firehose/latest/dev/Message_extraction.html)

### 6-2. CloudWatch Logs 구독

1. [CloudWatch 콘솔](https://console.aws.amazon.com/cloudwatch/) → Logs → Log groups에서 실제 업무 로그 그룹을 선택한다. 새 그룹을 만드는 경우 이름은 `whs-elk-cloudwatch-workload`다. Standard log class와 기존 구독을 확인한다.
2. Subscription filters → Create → Firehose destination을 선택하고 서버용 stream·전달 role을 지정한다. 신규 필터 이름은 `whs-elk-cloudwatch-cloudwatch-to-firehose`이며 WAF용은 `whs-elk-cloudwatch-waf-to-firehose`다.
3. 처음에는 filter pattern을 비워 모든 **신규 전달 이벤트**를 보낸다. source group 전체 history가 자동 재전송되는 것은 아니다.
4. WAF 그룹에는 WAF용 stream을 같은 방식으로 연결한다. Firehose 자신의 오류 log group을 이 구독 대상에 넣으면 순환 수집을 만들 수 있다.
5. 원 그룹의 테스트 이벤트, Firehose 지표, raw S3 객체를 대조한다. S3 파일 안에 `owner`, `logGroup`, `logStream`, `logEvents`가 있고 마지막 줄까지 JSON으로 읽히는지 확인한다.

구독은 실제 계정·리전 한도와 기존 계정/그룹 정책을 확인한 뒤 추가한다. 현재 저장소의 대응 Lambda 구독과 이름·목적지를 섞지 않는다. [CWL 구독 설정과 Firehose 예제](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html)

### 6-3. CloudWatch Agent

1. 수집 대상은 **업무 서버**다. 세 ELK 서버의 자체 상태 로그를 추가 수집하려면 별도 로그 그룹과 설정으로 나중에 확장한다.
2. 기존 SSM document/association/parameter가 Agent를 관리하면 해당 자원의 원래 배포 경로를 사용한다. 동일 인스턴스에 다른 association으로 설정을 덮어쓰지 않는다.
3. 실제 파일 존재, Agent OS 사용자 읽기 권한, rotation 방식, timestamp 형식을 확인한다. journald 자체는 파일 경로처럼 지정할 수 없으므로 기존 파일 출력/수집 방식을 확인한다.
4. 새 업무 Ubuntu 서버는 [CloudWatch Agent 설치·설정 가이드](cloudwatch-agent-guide.md)의 주석 Python 생성기, scoped IAM/SSM Terraform 예제, 공식 DEB 서명 검증과 설정 적용 순서를 따른다. 기존 Agent를 관리하는 SSM document/association이 있으면 원 소유자의 절차로 변경한다.
5. 고유 문자열을 실제 수집 파일에 남긴 뒤 CWL→S3→Kibana에서 찾는다. 메트릭 수집이 정상이라는 사실만으로 파일 로그 수집이 정상이라고 판단하지 않는다.

Agent의 log file path, log group/stream, timestamp, encoding, multiline 설정은 실제 로그 형식에 맞춰야 한다. [CloudWatch Agent 구성 필드](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-Configuration-File-Details.html)

### 6-4. WAF

1. [WAF 콘솔](https://console.aws.amazon.com/wafv2/) → 보호할 Web ACL → Logging and metrics에서 **현 logging configuration**을 확인한다. 기존 CWL 목적지가 있으면 새 목적지를 덮어쓰지 않고 그 그룹에 구독만 추가한다.
2. 로깅이 없는 경우에만 기존 Web ACL에 logging을 활성화하고 **같은 계정·리전**의 CWL 그룹 `aws-waf-logs-whs-elk-cloudwatch-waf`를 선택한다. 앞의 `aws-waf-logs-`는 AWS 필수 접두사다. 이 가이드는 ALB의 REGIONAL WAF 기준이다.
3. logging filter는 첫 검증에서 필요한 ALLOW/BLOCK 사례를 모두 포함하도록 정한다. redaction은 요구되는 민감 필드에 적용하고 파서가 필드 누락을 처리하도록 한다.
4. log delivery 권한이 없으면 WAF 설정 저장 역할에 `PutLoggingConfiguration`과 CWL log delivery/resource policy 관리 권한이 필요한지 확인한다. IAM 전체 관리자 권한을 EC2에 부여해서 해결하지 않는다.
5. 통제된 테스트 URL에 정상 요청과 기존 테스트 차단 규칙에 해당하는 요청을 보내 `action`, `terminatingRuleId`, `httpRequest.clientIp`, `uri`, `requestId`를 확인한다. 이 가이드는 업무 WAF rule 자체를 변경하지 않는다.

WAF의 CWL log group 이름과 계정·리전 요구사항은 서비스 제약이다. WAF가 직접 만드는 로그 stream의 `Region_web-acl-name_number` 형식도 서비스가 결정하므로 사용자 지정 이름으로 바꾸지 않는다. [WAF→CWL 설정·권한](https://docs.aws.amazon.com/waf/latest/developerguide/logging-cw-logs.html)

## 7. GuardDuty Findings와 선택적 알림

1. [GuardDuty 콘솔](https://console.aws.amazon.com/guardduty/)에서 대상 리전의 기존 detector/관리 계정을 확인한다. 기존 detector는 `guardduty_detector_id`로 재사용한다. detector가 전혀 없는 검증 계정에서만 `create_guardduty_detector=true`를 선택할 수 있으며, 기존 ID와 동시에 지정하지 않는다. 활성 보호 범위·비용은 별도로 확인한다.
2. Settings → Findings export options에서 기존 목적지를 먼저 확인하고, 필요한 경우 raw bucket/prefix와 같은 리전의 KMS 키를 지정한다. bucket policy와 key policy에 detector ARN·계정 조건을 추가한다.
3. 현행 AWS 문서가 요구하는 optional prefix와 `AWSLogs/ACCOUNT/GuardDuty/REGION` 경로를 먼저 준비한다. 제공 Terraform은 해당 folder marker를 만들도록 구성한다. 실제 export된 `.jsonl.gz` key가 S3 notification의 `guardduty/` prefix와 일치하는지 확인한다.
4. 갱신 Findings 주기를 프로젝트 목적에 맞게 선택한다. 이는 S3와 EventBridge의 갱신 export에 영향을 주며 새 Finding이 항상 동일한 지연으로 도착한다고 가정하지 않는다.
5. Settings의 Generate sample findings로 합성 테스트 Finding을 만들고 ID/type/severity/리소스를 S3 및 Kibana에서 대조한다. archived/suppressed 결과까지 전부 S3 내보내기로 수집된다고 가정하지 않는다.

S3 export에는 KMS와 bucket 양쪽 정책이 필요하며 두 자원은 같은 리전에 있어야 한다. 수집하는 것은 Findings이고 원시 VPC Flow/DNS/CloudTrail 데이터의 복사본이 아니다. [GuardDuty S3 export](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_exportfindings.html)

EventBridge/SNS 알림을 선택했다면 [EventBridge 콘솔](https://console.aws.amazon.com/events/)에서 default bus rule을 만들고 source `aws.guardduty`, detail-type `GuardDuty Finding`을 선택한다. [SNS 콘솔](https://console.aws.amazon.com/sns/)에서 별도 topic을 생성하여 해당 rule의 Publish를 허용하고 운영자가 선택한 구독자를 연결한다. 이메일 구독은 수신자가 확인해야 활성화된다. 이 가이드 작성·Terraform 예제만으로 실제 사용자에게 알림이 발송되지는 않는다. [GuardDuty EventBridge](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_eventbridge.html)

## 8. 성공 판정·문제 분리

| 관측 결과 | 먼저 확인할 곳 |
|---|---|
| 소스 CWL에 테스트 로그가 없음 | 업무 파일·Agent 상태·읽기 권한·IAM·CWL 그룹/stream |
| CWL에는 있으나 Firehose 입력이 없음 | 구독 pattern/destination/role, quota, 계정 구독, 오류 지표 |
| Firehose 입력은 있으나 raw S3가 비어 있음 | decompression·delimiter·buffer, delivery error, Firehose role/KMS/bucket Deny |
| S3 객체는 있으나 SQS가 비어 있음 | 실제 key prefix/suffix, queue policy, 같은 리전, 기존 notification 덮어쓰기, 알림 생성 전 객체 여부 |
| SQS에 쌓이지만 Filebeat 처리 안 됨 | EC2 role·endpoint policy·SQS URL·KMS·네트워크·Filebeat 로그 |
| Filebeat 전송 후 Logstash 실패 | 입력 형식과 gzip/JSON 계약, pipeline 설정·큐·파싱 실패 경로 |
| ES bulk 오류·검색 누락 | 인증서·사용자/API key 권한·mapping 충돌·디스크·ES 상태·DLQ |
| Kibana 화면만 비어 있음 | data view·시간 범위·원본 시간대·읽기 권한·실제 index |

단일 Elasticsearch에서는 replica를 0으로 설정해도 고가용성이 되지 않는다. 노드 중단 동안 조회는 중단되며, collector와 S3에서 복구를 준비하는 구조다. SQS retention은 유한하므로 중단 기간이 보관 한도를 넘으면 원본 S3 목록을 기준으로 재수집해야 한다. SQS DLQ는 파일 다운로드 실패, Logstash 오류 저장소는 파싱/색인 실패라는 서로 다른 경계를 담당한다.

최종 검증은 소스별 **원본 이벤트 ID·원본 객체 key·원본 이벤트 수·ES 문서 ID·발생/색인 시각**을 한 표에 기록한다. collector 중단, ES 중단, 같은 S3 원본 재처리, 잘못된 형식 격리, snapshot 복원 테스트를 완료한 다음 삭제 필터 도입과 다중 AZ 확장을 진행한다.
