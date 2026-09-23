# 수집 검증·장애 복구·운영 절차

## 검증 기록을 먼저 만든다

수집 화면에 로그가 보이는 것과 모든 시험 이벤트를 빠짐없이 처리한 것은 다르다. 각 소스에서 **식별 가능한 표본**을 선정해 아래 항목을 기록한다. AWS 전체 이벤트 수를 콘솔 화면의 단순 건수와 비교하지 않는다. 중복 전달과 GuardDuty Findings 갱신은 별도 처리 정책을 가진다.

| 항목 | 기록 예 |
|---|---|
| 검증 ID | `elk-validation-날짜-일련번호` |
| 소스 | CloudTrail / 서버 로그 / WAF / GuardDuty |
| 실제 전달·수동 입력 구분 | 실제 서비스 발생 / S3 이후만 검증한 수동 샘플 |
| 원본 식별자 | CloudTrail `eventID`, CloudWatch `logEvents.id`, WAF request ID, Finding ID |
| 발생 시각 | 서비스가 기록한 UTC 시각 |
| S3 객체 | 버킷·키·버전 ID(사용하는 경우) |
| 수집·검색 시각 | S3 도착 시각과 Elasticsearch 검색 가능 시각을 구분 |
| 파싱 결과 | 시간·계정·리전·IP·event dataset·필수 필드 |
| 실패 처리 | 큐·DLQ·격리 인덱스에서 확인한 원인 |
| 결과 | 통과/실패와 증거 경로, 재처리 후 결과 |

샘플마다 **발생 → S3 도착**과 **S3 도착 → 검색 가능**을 따로 측정한다. Firehose buffering이나 GuardDuty export 주기로 생긴 시간을 EC2 처리 지연과 혼동하지 않는다. 목표 지연 시간은 먼저 측정하고 정한다.

## 1. 서비스 기본 상태

역할에 맞는 EC2에서 SSM Session Manager로 실행한다. 설정 검사와 인증서·사용자 초기화의 정확한 순서는 [runtime 가이드](runtime-guide.md)를 따른다.

```bash
sudo systemctl status elasticsearch --no-pager # Elasticsearch EC2에서 서비스 기동 상태를 확인한다.
sudo journalctl -u elasticsearch -n 100 --no-pager # Elasticsearch EC2에서 TLS·메모리·권한 오류를 확인한다.
```

```bash
sudo systemctl status kibana --no-pager # Kibana EC2에서 Elasticsearch 연결과 서비스 상태를 확인한다.
sudo journalctl -u kibana -n 100 --no-pager # Kibana의 인증·CA·service token 오류를 확인한다.
```

```bash
sudo systemctl status logstash filebeat --no-pager # 수집 EC2의 두 서비스가 실행되는지 확인한다.
sudo filebeat test config -e # 수집 EC2에서 Filebeat 설정 문법을 검사한다.
sudo filebeat test output -e # Filebeat가 localhost Logstash에 연결 가능한지 검사한다.
sudo journalctl -u filebeat -u logstash -n 100 --no-pager # S3·SQS·KMS·파싱·색인 오류를 확인한다.
```

`filebeat test output` 성공은 Logstash까지 연결했다는 뜻이다. Elasticsearch 색인 성공까지 증명하지 않는다. Logstash config 검사도 AWS 권한·실제 데이터 호환성을 대신하지 않는다. Elasticsearch에서 replica 0으로 `green`이어도 단일 노드 이중화는 아니다.

## 2. 소스별 실제 전달 시험

### CloudTrail

CloudTrail 관리 이벤트를 대상으로 시험한다. Trail이 켜져 있고 S3 전달 상태가 정상인지 확인한 뒤, 선택한 계정에서 관리 API의 조회 이벤트를 발생시킨다. CloudTrail Event history 화면과 Trail의 S3 전달을 구분한다.

```bash
aws ec2 describe-vpcs --region ap-northeast-2 --query 'Vpcs[].VpcId' --output table # 실제 계정에서 조회형 관리 API를 호출한다.
aws cloudtrail describe-trails --region ap-northeast-2 --include-shadow-trails --query 'trailList[].{Name:Name,ARN:TrailARN,Bucket:S3BucketName,Prefix:S3KeyPrefix}' --output table # 전달 원천 Trail과 목적지 버킷을 확인한다.
```

원본 JSON의 `Records`에서 자신이 발생시킨 시각·principal·eventName에 해당하는 `eventID`를 하나 고른다. Elasticsearch에 같은 식별자의 문서가 존재하고, `eventTime`이 `@timestamp`로 정상 처리되는지 확인한다. CloudTrail Digest 파일이 업무 로그로 색인되지 않는지도 확인한다.

### CloudWatch Agent 서버 로그

Agent 설정에 포함한 **검증용 파일 경로**에 고유 문자열을 추가한다. 운영 로그 파일의 형식을 모르는 상태에서 임의 문자열을 삽입하지 않는다. 아래 `/var/log/elk-validation.log`는 Agent 설정에서 먼저 수집하도록 지정해야 한다.

```bash
MARKER="ELK_VALIDATION_$(date -u +%Y%m%dT%H%M%SZ)" # 실행마다 다른 식별자를 만든다.
printf '%s\n' "$MARKER" | sudo tee -a /var/log/elk-validation.log # 사전에 Agent 수집 대상으로 등록한 검증 파일에 기록한다.
printf '%s\n' "$MARKER" # Kibana 검색과 기록표에 사용할 문자열을 확인한다.
```

CloudWatch Logs → Firehose → S3 → Kibana를 순서대로 확인한다. S3 파일의 `logGroup`, `logStream`, `logEvents.id`, `timestamp`, `message`가 보존되는지 대조한다. Agent 메트릭까지 이 로그 파이프라인에 자동으로 들어오는 것은 아니다.

### WAF

현재 Web ACL이 실제 ALB·CloudFront 등 보호 대상에 연결됐는지 확인한다. 정상 요청 한 건과 **검증용 경로·라벨·규칙으로 명시적으로 차단되도록 만든 요청** 한 건을 보내 비교한다. 정상 서비스의 모든 요청을 차단하는 규칙을 추가하지 않는다.

```bash
TEST_URL='https://replace-with-your-approved-test-domain.example/elk-validation' # 사용자 소유의 승인된 검증 URL로 교체한다.
curl --fail-with-body --show-error "$TEST_URL" # 해당 경로의 허용·차단 정책에 따른 응답을 기록한다.
```

요청의 `httpRequest.clientIp`, URI, request ID, `action`, `terminatingRuleId`를 S3 원본과 색인 결과에서 확인한다. 403은 검증 규칙이 의도한 차단일 수 있으므로, curl 종료 코드만으로 수집 실패를 판단하지 않는다. 모든 ALLOW 로그가 불필요하다고 가정해 초기부터 삭제하지 않는다.

### GuardDuty

export destination과 KMS·S3 정책을 설정한 후 샘플 Findings를 생성한다. 실제 공격을 발생시킬 필요는 없다. 샘플은 AWS 계정에 Findings를 생성하므로 읽기 전용 확인과 구분한다.

```bash
DETECTOR_ID='replace-with-selected-detector-id' # 현재 리전의 기존 또는 새 검증 detector ID를 넣는다.
aws guardduty create-sample-findings --detector-id "$DETECTOR_ID" --region ap-northeast-2 # GuardDuty에 공식 샘플 Findings를 생성한다.
aws guardduty list-findings --detector-id "$DETECTOR_ID" --region ap-northeast-2 --max-results 10 # 샘플 식별자를 조회해 결과표에 기록한다.
```

S3 export의 Finding과 EventBridge 규칙의 알림을 별도로 확인한다. Findings S3 export는 활성 Finding을 대상으로 하며, 보관·억제 처리된 항목은 기본 제외된다. 같은 Finding ID의 갱신이 새 이벤트 이력인지 현재 상태 갱신인지 인덱스 정책으로 정한다. [AWS 샘플 생성](https://docs.aws.amazon.com/guardduty/latest/ug/sample_findings.html), [Findings 내보내기](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_exportfindings.html)

## 3. 장애·복구 시험

실제 업무에 영향을 주지 않는 검증 시간과 표본을 정한 뒤 한 번에 한 장애만 발생시킨다. 이 패키지에는 자동으로 EC2를 삭제하거나 클러스터 데이터를 지우는 명령이 없다.

| 시험 | 실행 방법 | 기대 관측 | 통과 기준 |
|---|---|---|---|
| 수집 중단 | 수집 EC2의 Filebeat·Logstash를 중지하고 표본 발생 | SQS visible 메시지·oldest age 증가 | 재시작 후 선정 표본 누락 없음, 적체 해소 시간 기록 |
| 저장 중단 | Elasticsearch 서비스를 중지하고 표본 발생 | Logstash PQ 증가; 충분히 길면 Filebeat/SQS에도 역압 | ES 재시작 후 대기 표본 색인 |
| 일시적 S3 읽기 실패 | 별도 테스트 prefix/권한으로 제한된 오류 재현 | 오류 원인 확인, 재시도, 필요 시 DLQ | 원인 수정 후 재처리 성공 |
| 파싱 실패 | 검증 입력에 깨진 JSON 전달 | 정상 이벤트와 실패 이벤트 분리 | 정상 입력은 지속, 실패 원본·오류 사유 조회 가능 |
| 중복 전달 | 동일 객체의 알림을 재처리 | 동일 ID·인덱스의 문서 갱신 | 의도하지 않은 문서 증가 여부 측정 |
| 스냅샷 복원 | 검증용 인덱스 snapshot 후 새 이름으로 restore | 원본 인덱스를 보존한 채 복원 | 표본 ID·건수 일치 |
| 원본 재수집 | 특정 원본 객체 범위만 재처리 | 대상 범위의 로그가 재색인 | 재처리 범위와 결과를 기록 |

```bash
sudo systemctl stop filebeat logstash # 수집 EC2에서 시험 범위의 두 서비스를 중지한다.
sudo systemctl start logstash # 수집 EC2에서 수신·디스크 큐 계층을 먼저 복구한다.
sudo systemctl start filebeat # Logstash가 기동한 뒤 SQS 소비를 재개한다.
```

위 세 명령 사이에서 시험 이벤트 발생과 큐 관측을 수행한다. 명령을 붙여 실행해 중단 시간을 없애지 않는다.

```bash
sudo systemctl stop elasticsearch # 저장 EC2에서 검증 시간 동안 Elasticsearch 서비스를 중지한다.
sudo systemctl start elasticsearch # 대기 큐를 관측한 뒤 저장 서비스를 복구한다.
```

SQS 보관 시간이 지났거나 디스크 큐가 손실되면 자동 재시도만으로 복구되지 않을 수 있다. 그 경우 S3에 남아 있는 범위를 지정해 재처리한다. `delete_on_termination=false`는 인스턴스 종료 시 EBS를 남기는 설정일 뿐, 새 EC2에 그 볼륨을 자동 복구·연결하는 기능이 아니다.

## 4. 실패 경로를 정확히 구분한다

**SQS DLQ**는 객체 알림 처리의 반복 실패를 다룬다. Filebeat 자체 최대 수신 횟수에 의해 먼저 메시지를 삭제하지 않도록 SQS redrive 정책과 Filebeat 설정을 함께 정한다. 이 가이드의 설정값은 [runtime 가이드](runtime-guide.md)에서 확인한다. SQS 알림 삭제 성공이 Elasticsearch 전체 보관의 완벽한 증명은 아니며, 수집기가 ACK한 뒤에는 Logstash PQ 등 후속 보관 계층도 관련된다.

**Logstash DLQ**는 지원하는 색인 오류 등을 다룬다. 모든 JSON·grok 파싱 실패가 자동으로 DLQ에 저장되는 것은 아니다. 파싱 실패는 별도 격리 인덱스·출력 경로로 보내도록 설정한다. DLQ 적체를 감시하고 수정 후 재처리 절차를 둔다. [Filebeat S3/SQS](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-aws-s3), [Logstash DLQ](https://www.elastic.co/docs/reference/logstash/dead-letter-queues)

### 원본 객체 한 개를 다시 수집하는 코드

큐 보관 기간이 지났거나 Logstash 오류를 수정한 뒤에는 원본이 S3에 남아 있는지 확인하고 **정확한 객체 한 개**부터 재처리한다. `tools/make_s3_replay.py`는 S3 객체를 수정하지 않고 SQS에 보낼 JSON만 만든다. Filebeat는 알림에 있는 객체를 다시 읽는다. S3 Versioning을 사용하는 경우 이 방법은 해당 키의 **현재 객체**를 읽으므로, 다른 버전으로 덮어쓴 키의 과거 버전을 자동 복원하지 않는다.

아래 명령은 패키지 루트의 운영자 Linux/CloudShell에서 실행한다. 운영자에게 대상 원본 읽기와 해당 큐의 `sqs:SendMessage` 권한이 필요하다. 수집 EC2 역할에 전송 권한을 추가하는 방식은 사용하지 않는다. 새 키로 복사하지 않아야 이번 문서 ID 방식의 중복 억제 조건을 유지할 수 있다.

```bash
SOURCE_BUCKET='실제-원본-버킷' # CloudTrail을 재사용하면 기존 archive 버킷을 지정한다.
SOURCE_KEY='cloudwatch/실제/경로/객체.jsonl.gz' # S3에서 확인한 기존 로그 객체의 정확한 키를 입력한다.
SOURCE_QUEUE_URL='https://sqs.ap-northeast-2.amazonaws.com/실제계정/실제cloudwatch큐' # 객체 형식에 맞는 소스 큐를 선택한다.
aws s3api head-object --bucket "$SOURCE_BUCKET" --key "$SOURCE_KEY" --query '{Bytes:ContentLength,Modified:LastModified,Version:VersionId}' # 객체 존재와 현재 버전을 확인한다.
python3 tools/make_s3_replay.py --bucket "$SOURCE_BUCKET" --key "$SOURCE_KEY" --region ap-northeast-2 --output replay-message.json # 전송 전 검토할 알림 한 개를 생성한다.
python3 -m json.tool replay-message.json # 목적지 버킷·객체 키가 의도한 범위인지 읽는다.
aws sqs send-message --queue-url "$SOURCE_QUEUE_URL" --message-body file://replay-message.json --region ap-northeast-2 # 검토한 객체 알림 한 개를 해당 파서의 큐로 보낸다.
```

동일한 출력 파일이 있으면 생성기가 중단한다. 재시험할 때는 다른 `--output` 이름을 사용한다. 다른 서비스 큐로 보내면 그 큐에 연결된 파서가 적용되므로 원본 형식과 큐를 반드시 맞춘다. 이 도구의 JSON 생성은 로컬에서 검사했으며 실제 AWS에서의 재처리 성공은 적용 계정에서 표본 ID를 대조해 확인해야 한다.

SQS DLQ는 원인을 수정한 후 콘솔의 **Start DLQ redrive**에서 대상 source queue와 처리 속도를 지정할 수 있다. 대량 redrive 전에 위 방법으로 실패 원본 한 개를 먼저 확인한다. 이미 격리 인덱스나 Logstash DLQ에 ACK된 입력은 SQS DLQ redrive 대상이 아니다. Logstash DLQ 원본 위치를 확인하고 이 S3 재수집 절차를 사용하거나 별도의 `dead_letter_queue` input 파이프라인을 검토한다. 원인을 해결하기 전에 DLQ 디렉터리를 삭제하지 않는다. [S3 알림 구조와 객체 키 인코딩](https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-content-structure.html), [SQS DLQ redrive 절차·필요 권한](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-configure-dead-letter-queue-redrive.html)

## 5. 보관·권한·스냅샷

Elasticsearch 일별 인덱스의 삭제 정책과 S3 lifecycle은 별개다. S3 Versioning이 켜져 있으면 현재 버전 만료와 이전 버전 정리 시점도 다르다. 정확히 30일째 모든 물리 바이트가 사라진다는 가정으로 비용을 계산하지 않는다. 지연된 로그·오래된 로그를 재처리할 때는 일별 인덱스의 날짜와 삭제 시점을 확인한다.

스냅샷 버킷의 객체를 S3 CLI로 임의 삭제하거나 일반 lifecycle으로 부분 삭제하지 않는다. Elasticsearch의 snapshot/SLM API가 저장소 안의 공유 데이터를 관리하도록 한다. 복원 테스트는 기존 업무 인덱스를 삭제하는 대신 새 이름의 검증 인덱스로 수행한다. instance profile의 S3 권한을 사용하며 장기 access key를 Elasticsearch 설정에 넣지 않는다. [S3 repository](https://www.elastic.co/docs/deploy-manage/tools/snapshot-and-restore/s3-repository)

원본 삭제 권한 시험은 **전용 검증 객체**에서만 진행한다. 수집 역할로 수행한 삭제가 AccessDenied인지 확인하고, 실제 감사 원본의 삭제 명령을 시험용으로 사용하지 않는다. 수집 역할에 `DeleteObject`가 없더라도 다른 정책이나 권한 경계·SCP가 결과에 영향을 줄 수 있으므로 실제 principal을 확인한다.

## 6. 최초 운영 대시보드

Kibana에서는 데이터가 확인된 뒤 이름 `whs-elk-kibana-security-logs`, 인덱스 패턴 `whs-elk-elasticsearch-logs-*`인 Data View를 만들고 `@timestamp`를 시간 필드로 선택한다. 대시보드 이름은 `whs-elk-kibana-security-dashboard`로 정한다. 고정 날짜 샘플은 시간 범위를 해당 UTC 날짜로 변경한다. 초기에는 아래 지표를 분리해서 표시한다.

- CloudTrail: 이벤트 이름·주체·리전별 건수와 권한 관련 활동.
- WAF: 최종 ALLOW/BLOCK 등의 action, 차단 규칙, URI, IP별 요청 수.
- 서버 로그: `aws.cloudwatch.log_group`, `aws.cloudwatch.log_stream`별 건수와 `message` 오류 문자열.
- GuardDuty: Finding 유형(`event.action`)·심각도(`event.severity`)·Finding ID·갱신 시각.
- 파이프라인: 소스별 수집량, 이벤트 발생→수집 지연, 격리된 파싱 실패.

CloudWatch에서는 Firehose 전달 실패·데이터 신선도, SQS oldest message age·DLQ 메시지, EC2 상태와 디스크 사용량을 감시한다. 표준 EC2 기본 지표만으로 OS 디스크 잔량이나 모든 프로세스 상태를 알 수 없으므로, 별도 Agent 메트릭 또는 운영 점검을 추가한다. Logstash API·PQ 통계는 runtime 가이드의 로컬 검증 절차로 확인한다.

`aws.payload`는 원문을 `_source`에 보존하지만 자동 색인하지 않는다. 따라서 WAF의 COUNT 관련 `nonTerminatingMatchingRules`, 애플리케이션 고유 로그 레벨, GuardDuty 대상 리소스의 개별 속성을 집계하려면 `normalize.rb`에서 해당 필드를 추출하고 `30-admin.py`의 매핑에도 추가해야 한다. 매핑 변경은 기존 문서를 자동 재색인하지 않으므로 새 테스트 인덱스에서 먼저 검증한다.

## 7. 결과로 남길 것

최종 제출물에는 적용한 구성도와 버전, Terraform 변경 계획·출력의 비밀정보를 제거한 요약, 소스별 표본 대조, 장애별 복구 시간, 알려진 누락·중복 조건, 스냅샷 복원 결과를 포함한다. 인증서 비밀키·비밀번호·토큰·전체 state·실제 고객 로그를 보고서나 공유 ZIP에 넣지 않는다.
