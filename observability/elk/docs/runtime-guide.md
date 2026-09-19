# EC2 3대의 Elastic Stack 설치·보안·복구 가이드

이 문서는 Terraform으로 AWS 기반을 만든 다음 실행합니다. EC2 수집 서버에는 Filebeat와 Logstash, 저장 서버에는 Elasticsearch, 조회 서버에는 Kibana를 설치합니다. Ubuntu 24.04 amd64와 네 구성 요소 9.5.3을 대상으로 작성했습니다. 스크립트는 그 버전이 apt 저장소에 없으면 중단하며, 임의로 다른 버전을 설치하지 않습니다. 공식 문서와 코드를 확인해 작성했고 **실제 EC2에서 설치·AWS 수집을 실행한 결과물은 아닙니다.** 각 단계의 완료 기준으로 적용 환경에서 확인해야 합니다. [Elastic Debian 설치](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-with-debian-package), [공식 Stack 설치 가이드](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/tutorial-self-managed-install)

## 1. 서비스가 필요한 이유와 통신 경계

| 구성 요소 | 이 구조에서 맡는 역할 | 필수인 범위 |
|---|---|---|
| Filebeat | SQS 알림을 읽고 S3 객체를 다운로드하며 처리 완료 ACK·재시도를 관리 | 선택한 S3+SQS 수집 방식의 구현체로 사용합니다. 다른 동등한 수집기로 대체는 가능합니다. |
| Logstash | CloudTrail·CloudWatch·WAF·GuardDuty의 서로 다른 형태를 정규화하고 실패를 격리 | 이번 프로젝트에서 전처리를 EC2 안에서 검증하기 위해 사용합니다. AWS나 Elastic 전체에서 보편적으로 필수인 제품이라는 뜻은 아닙니다. |
| Elasticsearch | 검색용 인덱스, 권한, ILM 보관, 스냅샷을 관리 | 사용자가 선택한 ELK 검색 저장소입니다. S3 원본 저장을 대체하지 않습니다. |
| Kibana | 데이터 뷰, 검색, 대시보드를 제공 | 선택한 ELK 조회 UI입니다. 수집 과정은 Kibana 중단과 독립적으로 동작합니다. |
| 내부 CA와 TLS | Logstash·Kibana가 실제 Elasticsearch 서버인지 검증하고 전송 내용을 암호화 | 사설망에서도 서비스 인증정보와 보안 로그를 전달하므로 이 설계에서 필수로 적용합니다. |
| 서비스 API 키·Kibana 토큰 | 수집과 조회 서버가 관리자 계정을 상시 사용하지 않게 권한을 분리 | 이 운영 가정에서 필수인 접근 통제입니다. |

외부 5044·9300·9600·5066 포트를 열지 않습니다. Filebeat→Logstash는 **동일 EC2의 127.0.0.1:5044**, Logstash/Kibana→Elasticsearch는 **private IP의 HTTPS 9200**, 운영자→Kibana는 **SSM 포트 전달을 통한 HTTPS 5601**입니다. Elasticsearch transport는 단일 노드이므로 localhost에만 bind합니다. 3개 노드를 만드는 후속 단계에서는 discovery·transport SAN·SG·복제본 설정을 다시 설계해야 합니다.

SSM Session Manager는 관리 접속 수단입니다. API·SSH처럼 별도 인증 경로가 있는 환경에서는 대체 가능하며, 인터넷에서 9200/5601을 공개해야 한다는 의미가 아닙니다.

## 2. 적용 전에 확인할 값

| 확인 대상 | 확인할 내용 |
|---|---|
| Ubuntu EC2 3대 | OS 24.04, CPU amd64, 기본 DNS·시간 동기화, SSM Online |
| 네트워크 | collector·Kibana SG에서 ES 9200 접근, apt 공식 도메인·Ubuntu mirror에 나가는 HTTPS 경로 |
| AWS 접근 | collector의 S3 GetObject·SQS Receive/Delete/ChangeVisibility/GetQueueAttributes·원본 KMS Decrypt, ES의 snapshot S3 읽기·쓰기·삭제 |
| 인스턴스 메타데이터 | IMDSv2 required 상태에서 역할 자격 증명 획득 가능; 정적 AWS access key는 설정하지 않음 |
| EBS | ES `/var/lib/elasticsearch`, LS `/var/lib/logstash`, Filebeat `/var/lib/filebeat`가 충분한 영구 저장장치에 있음; 루트 EBS 사용 시 루트 디스크 공유라는 한계 기록 |
| 버킷 | 원본·스냅샷·배포 아티팩트 버킷의 목적 분리; 스냅샷 prefix가 IAM 정책과 일치 |
| SQS 4개 | 소스별 URL, 14일 보관, DLQ redrive 설정; Filebeat 자체 실패 메시지 삭제는 끔 |
| S3 객체 형태 | CloudTrail Records JSON / CW·WAF GZIP JSONL envelope / GuardDuty GZIP JSONL |
| 인증서 | 실제 ES·Kibana private IP를 발급 시점에 확정; EC2 교체로 IP가 바뀌면 SAN 인증서 재발급 |
| 운영자 IAM | 배포 아티팩트 S3 PutObject, 해당 CMK GenerateDataKey·Decrypt, 대상 EC2의 SSM 접속 권한 |

`runtime/settings.env.example`을 `runtime/settings.env`로 복사합니다. 각 줄의 주석이 설명하는 Terraform 값으로 모두 교체하세요. `AWS_REGION`은 네 큐와 같은 리전이어야 합니다. `SNAPSHOT_PREFIX=elastic`은 기본값이며 버킷의 자동 폴더 생성 작업은 필요하지 않습니다. 여기에는 비밀번호·API 키·토큰을 넣지 않습니다.

```bash
cp runtime/settings.env.example runtime/settings.env # 예시를 실행용 비밀정보 없는 파일로 복사합니다.
chmod 600 runtime/settings.env # AWS 리소스 목록이 다른 로컬 사용자에게 보이지 않게 합니다.
${EDITOR:-vi} runtime/settings.env # Terraform이 출력한 IP·SQS URL·버킷 이름을 입력합니다.
```

## 3. 관리자 Linux에서 CA 발급 및 배포 준비

관리자 PC의 Linux/WSL 또는 AWS CloudShell에서 수행합니다. Python 3, OpenSSL, AWS CLI가 필요합니다. CA private key는 패스프레이즈로 암호화하여 생성합니다. 프로젝트 ZIP에 들어가는 것은 **생성 코드뿐**이며, 생성한 인증서·private key를 Git에 커밋하지 않습니다. `private-pki/offline-ca`는 EC2나 아티팩트 버킷에 올리지 않습니다.

```bash
umask 077 # CA와 leaf private key의 기본 권한을 소유자 전용으로 제한합니다.
python3 runtime/10-generate-pki.py runtime/settings.env "$HOME/elk-private-pki" # 기존에 없는 경로에 CA·역할별 인증서를 생성합니다.
openssl x509 -in "$HOME/elk-private-pki/elasticsearch/elasticsearch.crt" -noout -ext subjectAltName # ES 실제 private IP·127.0.0.1·localhost SAN을 확인합니다.
openssl x509 -in "$HOME/elk-private-pki/kibana/kibana.crt" -noout -ext subjectAltName # Kibana private IP와 localhost SAN을 확인합니다.
```

OpenSSL이 여러 번 CA 패스프레이즈를 물어보는 것은 동일한 CA로 서버별 인증서를 서명하기 때문입니다. 운영자는 CA 키·패스프레이즈를 승인된 암호화 저장소에 보관합니다. 서버 leaf key는 서비스 자동 시작을 위해 자체 패스프레이즈 없이 생성하고, 암호화 EBS·역할별 IAM·0600/0640 권한으로 보호합니다. 실제 기업에 사설 PKI가 있다면 조직 CA가 서명한 같은 SAN/용도의 인증서로 대체하세요.

아티팩트 버킷은 새 Terraform의 배포용 버킷을 사용합니다. **전체 `elk-private-pki` 폴더를 `sync`하지 않습니다.** 아래는 배포 자료를 역할별 prefix로 구분해서 올리는 예시입니다. 실제 값은 Terraform 출력으로 채웁니다. `settings.env`까지 포함한 runtime ZIP은 비밀정보 없는 구성 코드입니다.

```bash
ARTIFACT_BUCKET='실제-Terraform-아티팩트-버킷' # 원본 로그 버킷이 아닌 배포용 버킷 이름입니다.
ARTIFACT_KMS_KEY_ARN='실제-Terraform-아티팩트-CMK-ARN' # 배포 버킷 전용 KMS 키 ARN입니다.
zip -r runtime-config.zip runtime -x '*/__pycache__/*' '*.pyc' # 코드·설정만 묶고 CA와 인증 키는 포함하지 않습니다.
aws s3 cp runtime-config.zip "s3://${ARTIFACT_BUCKET}/elasticsearch/runtime-config.zip" --sse aws:kms --sse-kms-key-id "$ARTIFACT_KMS_KEY_ARN" # 저장 서버가 읽을 수 있는 자기 prefix에 올립니다.
aws s3 cp runtime-config.zip "s3://${ARTIFACT_BUCKET}/collector/runtime-config.zip" --sse aws:kms --sse-kms-key-id "$ARTIFACT_KMS_KEY_ARN" # 수집 서버용 코드를 올립니다.
aws s3 cp runtime-config.zip "s3://${ARTIFACT_BUCKET}/kibana/runtime-config.zip" --sse aws:kms --sse-kms-key-id "$ARTIFACT_KMS_KEY_ARN" # 조회 서버용 코드를 올립니다.
aws s3 cp "$HOME/elk-private-pki/elasticsearch/" "s3://${ARTIFACT_BUCKET}/elasticsearch/certs/" --recursive --sse aws:kms --sse-kms-key-id "$ARTIFACT_KMS_KEY_ARN" # ES의 leaf key·인증서·공개 CA만 보냅니다.
aws s3 cp "$HOME/elk-private-pki/collector/" "s3://${ARTIFACT_BUCKET}/collector/certs/" --recursive --sse aws:kms --sse-kms-key-id "$ARTIFACT_KMS_KEY_ARN" # collector에는 공개 CA만 보냅니다.
aws s3 cp "$HOME/elk-private-pki/kibana/" "s3://${ARTIFACT_BUCKET}/kibana/certs/" --recursive --sse aws:kms --sse-kms-key-id "$ARTIFACT_KMS_KEY_ARN" # Kibana의 leaf key·인증서·공개 CA만 보냅니다.
```

이 단계의 완료 기준은 역할별 EC2가 자기 prefix만 읽을 수 있고, 다른 서버 leaf private key와 CA private key는 읽을 수 없는 것입니다. 임시 아티팩트 버킷의 짧은 Lifecycle은 별도의 CA 백업이나 서비스 keystore 백업을 대신하지 않습니다.

## 4. 각 EC2의 작업 파일 준비

AWS 콘솔 → Systems Manager → Session Manager에서 대상 EC2에 연결합니다. 세 서버마다 아래에서 `ROLE`을 다르게 지정하여 실행합니다. AWS CLI가 이미 설치되어 있으면 CLI 설치는 생략합니다. 아래 apt `awscli`는 Ubuntu 패키지를 이용하는 가장 간단한 준비 경로이며, 조직에서 AWS CLI v2 고정 배포를 요구한다면 승인된 설치본으로 대체하세요.

```bash
sudo apt-get update # Ubuntu 패키지 목록을 읽습니다.
sudo apt-get install -y awscli unzip # 배포 S3 파일 다운로드와 압축 해제 도구를 설치합니다.
ROLE='elasticsearch' # 현재 EC2에 맞게 elasticsearch·collector·kibana 중 하나를 선택합니다.
ARTIFACT_BUCKET='실제-Terraform-아티팩트-버킷' # 배포 자료가 있는 버킷 이름입니다.
umask 077 # SSM 사용자 작업 폴더도 읽기 권한을 제한합니다.
mkdir -p "$HOME/elk-setup/certs" # 역할별 다운로드 파일을 담을 폴더를 만듭니다.
cd "$HOME/elk-setup" # 이후 상대 경로의 기준을 맞춥니다.
aws s3 cp "s3://${ARTIFACT_BUCKET}/${ROLE}/runtime-config.zip" runtime-config.zip # EC2 instance profile로 자기 역할의 코드만 받습니다.
unzip runtime-config.zip # runtime 디렉터리를 현재 폴더에 풉니다.
aws s3 cp "s3://${ARTIFACT_BUCKET}/${ROLE}/certs/" certs/ --recursive # 자기 역할의 인증서 파일만 받습니다.
sudo bash runtime/00-install.sh "$ROLE" # 공식 서명 검증 후 9.5.3을 고정 설치합니다.
sudo python3 runtime/20-configure.py "$ROLE" runtime/settings.env certs # 인증서·설정·파일 소유권을 설치하고 아직 서비스는 시작하지 않습니다.
```

`00-install.sh`는 패키지마다 apt hold를 설정합니다. 이후 버전 업그레이드 때는 호환성·백업 검토 후 명시적으로 hold를 풀고 네 구성 요소를 계획하여 업데이트해야 합니다. `20-configure.py`는 최초 설정 전용이며 재실행 시 기존 구성을 덮어쓰지 않고 중단합니다.

## 5. Elasticsearch부터 시작

Elasticsearch EC2의 `$HOME/elk-setup`에서 실행합니다. `elastic`은 초기 설정에만 쓰는 관리자 계정입니다. 비밀번호를 `-p`, URL, shell 변수, Terraform variable에 넣지 않습니다. `-i` 옵션의 프롬프트에 직접 입력하고 비밀번호 관리자에 보관합니다. [Elastic 보안 초기 설정](https://www.elastic.co/docs/deploy-manage/security/self-setup)

```bash
sudo systemctl enable --now elasticsearch # 부팅 때 시작하도록 설정하고 서비스를 시작합니다.
sudo systemctl status elasticsearch --no-pager # 프로세스가 실행 상태인지 확인합니다.
sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i --url https://127.0.0.1:9200 # TLS를 유지한 채 관리자 비밀번호를 인터랙티브하게 설정합니다.
sudo python3 runtime/30-admin.py initialize runtime/settings.env # 매핑·30일 ILM·S3 스냅샷 저장소·스냅샷 일정을 등록합니다.
sudo python3 runtime/30-admin.py health runtime/settings.env # 클러스터·인덱스·ILM·SLM 상태를 확인합니다.
```

시작 직후 9200이 준비되기까지 시간이 걸릴 수 있습니다. reset-password가 연결 오류를 내면 서비스 로그를 확인하고 정상 시작 후 재시도합니다. 설정 오류를 `-k`, `verification_mode: none`, `xpack.security.enabled: false`로 우회하지 않습니다.

`initialize`가 만드는 항목은 다음과 같습니다. 실제 JSON은 주석을 허용하지 않아 `30-admin.py`가 **각 코드 줄에 주석이 있는 Python 객체**를 표준 JSON으로 직렬화합니다.

| 항목 | 값과 의미 |
|---|---|
| Index template | `whs-elk-elasticsearch-logs`, 패턴 `whs-elk-elasticsearch-logs-*`, primary 1, replica 0 |
| 정상 인덱스 | `whs-elk-elasticsearch-logs-<source>-YYYY.MM.dd`; source는 `cloudtrail`, `cloudwatch`, `waf`, `guardduty` |
| 파싱 실패 인덱스 | `whs-elk-elasticsearch-logs-quarantine-YYYY.MM.dd` |
| 보관 정책 | `whs-elk-elasticsearch-retention`, **인덱스 생성 시각부터 30일** 후 삭제; 이벤트 시각 기준 정확히 30일은 아님 |
| 원문 보존 | `event.original`, `aws.payload`는 `_source`에 남김; `aws.payload`의 임의 필드를 자동 색인하지 않음 |
| Snapshot repository | `whs-elk-elasticsearch-snapshots`, 별도 버킷의 `elastic` prefix, EC2 instance profile |
| SLM policy | `whs-elk-elasticsearch-daily-backup`, 매일 UTC 18:00/KST 다음 날 03:00, `whs-elk-elasticsearch-logs-*`만 백업, 최근 7일·최소 1개·최대 14개 |

서비스의 표시 이름도 같은 규칙을 적용합니다. Elasticsearch cluster/node는 `whs-elk-elasticsearch-cluster`/`whs-elk-elasticsearch-node`, Logstash node/pipeline은 `whs-elk-logstash-collector`/`whs-elk-logstash-normalize`, Kibana server는 `whs-elk-kibana-dashboard`입니다. Filebeat name은 `whs-elk-filebeat-collector`, input ID는 `whs-elk-filebeat-<source>`입니다. 인증서 CN은 CA에 `whs-elk-pki-root-ca`, 서버에 `whs-elk-elasticsearch-tls`와 `whs-elk-kibana-tls`를 사용합니다. OS 서비스명·파일 경로와 Elastic 고정 서비스 계정 `elastic/kibana`는 제품 계약이므로 유지합니다. 전체 값은 [자원 이름 규칙](naming.md)에서 확인합니다.

이전 이름으로 설치한 환경에서 이름 개정판을 실행해도 기존 인덱스·사용자·정책이 자동으로 이름을 바꾸지는 않습니다. 초기 구축 스크립트를 이름 변경 도구로 다시 실행하지 말고 기존 인덱스 이관과 데이터 뷰·권한·보관 정책 연결을 함께 검토합니다. 변경된 Logstash pipeline ID는 PQ/DLQ의 저장 경로에도 영향을 주므로 기존 큐를 비우거나 보존·재처리 계획을 세운 뒤 전환합니다.

일별 인덱스는 소량에서 이해하기 쉬운 검증 선택입니다. 로그 종류가 늘거나 매우 적으면 샤드 수 대비 데이터량이 작아지므로 이후 rollover/data stream으로 전환을 검토합니다. replica 0이므로 이 노드의 EBS가 사라지면 검색 데이터가 복구될 때까지 접근할 수 없습니다. ILM 삭제와 S3 원본 Lifecycle은 서로 별개입니다.

스냅샷 저장소 등록은 실제 S3 읽기·쓰기·삭제 검증을 수행합니다. 오류가 발생하면 ES 역할·버킷 정책·VPC endpoint 정책과 리전을 확인하세요. 이 스냅샷은 **로그 인덱스 복원 검증용**이며, Kibana 저장 객체·보안 feature state·keystore의 완전 백업은 아닙니다. Kibana Saved Objects의 내보내기와 비밀 저장소 백업을 별도로 운영합니다. [S3 스냅샷 저장소](https://www.elastic.co/docs/deploy-manage/tools/snapshot-and-restore/s3-repository)

## 6. 수집 서버 시작

collector EC2에서 실행합니다. `collector-key`는 TLS로 ES에 접속하여 이름이 `whs-elk-elasticsearch-collector`인 최소 권한 API 키를 만들고 값을 출력하지 않은 채 Logstash keystore에 stdin으로 저장합니다. 키는 `whs-elk-elasticsearch-logs-*` 색인과 자동 생성·클러스터 상태 확인만 허용하고, 로그 읽기·삭제·템플릿 변경·ILM 변경을 허용하지 않습니다. 설정에서 `${ES_API_KEY}`는 비밀정보 치환용 keystore 이름으로 남습니다. [Logstash 보안 연결](https://www.elastic.co/docs/reference/logstash/secure-connection), [Logstash keystore](https://www.elastic.co/docs/reference/logstash/keystore)

```bash
sudo python3 runtime/30-admin.py collector-key runtime/settings.env # elastic 비밀번호를 프롬프트로 받아 수집 API 키를 keystore에 직접 저장합니다.
sudo /usr/share/filebeat/bin/filebeat test config -c /etc/filebeat/filebeat.yml --path.home /usr/share/filebeat --path.config /etc/filebeat --path.data /var/lib/filebeat # Filebeat YAML과 설정을 검증합니다.
sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash --config.test_and_exit # 파이프라인 문법과 normalize.rb의 내장 테스트를 실행합니다.
sudo systemctl enable --now logstash # 먼저 Beats 5044를 받을 서버를 시작합니다.
sudo /usr/share/filebeat/bin/filebeat test output -c /etc/filebeat/filebeat.yml --path.home /usr/share/filebeat --path.config /etc/filebeat --path.data /var/lib/filebeat # 루프백 Logstash 연결 성공을 확인합니다.
sudo systemctl enable --now filebeat # SQS에서 S3 알림을 읽기 시작합니다.
sudo systemctl status logstash filebeat --no-pager # 두 서비스의 실행 상태를 확인합니다.
curl --fail --silent --show-error http://127.0.0.1:9600/_node/stats/pipelines?pretty # 로컬 Logstash 큐와 이벤트 처리 수를 확인합니다.
curl --fail --silent --show-error http://127.0.0.1:5066/stats?pretty # 로컬 Filebeat 상태를 확인합니다.
```

`test output`은 **Filebeat→Logstash**까지만 검사합니다. Elasticsearch에 저장됐다는 증거는 아닙니다. 내장 Ruby 테스트도 S3/SQS/AWS 실제 연결을 검증하지 않습니다. 샘플 S3 업로드→Kibana 이벤트 ID 대조까지 완료해야 수집 성공으로 판단합니다.

Logstash API 키는 90일 만료입니다. 만료 전에 후속 키를 발급해 keystore에 교체하고 재시작·색인 검증 후 이전 키를 폐기합니다. 이 초기화 명령은 기존 `ES_API_KEY`가 있으면 중단합니다. 키의 값이나 keystore `show` 결과를 기록하지 않고, 키 ID·발급일·만료일·교체 검증 결과만 운영 기록에 남깁니다. 실운영에서는 조직의 secret manager와 회전 절차를 연결하세요.

Filebeat 디스크 큐와 Logstash persistent queue는 각각 초기 2GB입니다. 전달량·로그 팽창률·최대 장애 시간을 측정해서 변경합니다. SQS ACK는 Logstash가 ES에 최종 색인한 시점보다 먼저 발생할 수 있습니다. 따라서 SQS만으로 종단 간 무손실을 주장할 수 없고, 디스크 손실 시 **S3 원본 재수집**이 최종 복구 수단입니다. Logstash checkpoint를 매 이벤트로 설정하면 내구성에 도움이 되지만 I/O 비용과 처리량을 측정해야 합니다. [Logstash persistent queue](https://www.elastic.co/docs/reference/logstash/persistent-queues)

## 7. Kibana와 조회 계정 시작

Kibana EC2에서 실행합니다. 키를 설정하는 도구는 `kibana` 사용자로 동작합니다. 서비스 계정 토큰을 일반 사용자의 로그인 비밀번호로 사용하지 않습니다. [Kibana secure settings](https://www.elastic.co/docs/deploy-manage/security/secure-settings)

```bash
sudo python3 runtime/30-admin.py kibana-token runtime/settings.env # ES 서비스 토큰과 안정적인 세 가지 암호화 키를 Kibana keystore에 저장합니다.
sudo systemctl enable --now kibana # HTTPS Kibana를 시작합니다.
sudo systemctl status kibana --no-pager # 서비스 실행 상태를 확인합니다.
sudo python3 runtime/30-admin.py reader runtime/settings.env # 별도 프롬프트로 whs-elk-kibana-reader 비밀번호를 정하고 최소 조회 역할을 부여합니다.
```

관리자 PC에서 AWS CLI·Session Manager 플러그인이 준비된 터미널로 포트 전달을 시작합니다. EC2의 5601 inbound를 인터넷에 공개하지 않습니다.

```bash
KIBANA_INSTANCE_ID='i-실제Kibana인스턴스ID' # Terraform이 출력한 Kibana EC2 ID입니다.
aws ssm start-session --target "$KIBANA_INSTANCE_ID" --document-name AWS-StartPortForwardingSession --parameters '{"portNumber":["5601"],"localPortNumber":["5601"]}' # 이 터미널을 유지하며 로컬 HTTPS 포트를 연결합니다.
```

운영자 브라우저는 `https://localhost:5601`로 접속합니다. 관리자 PC의 승인된 인증서 저장소에 생성한 **공개 `ca.crt`만** 신뢰하도록 등록해야 합니다. 브라우저 경고를 무시하지 않습니다. 이 가이드의 Kibana 인증서에는 `localhost` SAN이 포함되어 있습니다. 로컬 5601이 사용 중이면 localPortNumber만 변경하고 접속 URL 포트도 맞추면 됩니다. 인증서 SAN은 포트 번호와 무관합니다.

최초 한 번 `elastic`으로 접속하여 Stack Management → Data Views에서 이름 `whs-elk-kibana-security-logs`, 인덱스 패턴 `whs-elk-elasticsearch-logs-*`, 시간 필드 `@timestamp`로 만듭니다. Discover에서 `event.dataset`, `event.action`, `cloud.account.id`, `cloud.region`, `source.address`, `aws.s3.object.key`를 열에 추가합니다. Dashboard 이름은 `whs-elk-kibana-security-dashboard`로 정합니다. Dashboard와 데이터 뷰를 만든 뒤 일상 조회에는 `whs-elk-kibana-reader`를 사용합니다. 조회 역할은 `whs-elk-elasticsearch-reader`이며 기본 공간의 Discover·Dashboard 읽기만 허용하므로 데이터 뷰 편집 메뉴가 없는 것이 정상입니다.

Kibana keystore 암호화 키는 새로 만들 때마다 바꾸면 기존 저장 객체를 읽지 못할 수 있습니다. 운영 백업에 보관하고 복원 때 같은 키를 사용해야 합니다. 토큰은 폐기·재발급 가능하지만 저장 객체 암호화 키는 키 교체 절차를 따라야 합니다.

## 8. 로그 형식과 실패·중복 처리

| 소스 | S3 파일과 Filebeat 처리 | Logstash 결과 |
|---|---|---|
| CloudTrail | GZIP JSON의 `Records` 배열을 Filebeat가 개별 `message` JSON으로 전개 | `eventTime`, `eventID`, `eventName`, 계정, 리전을 보존 |
| CloudWatch Agent | Firehose가 압축 해제한 envelope를 JSONL로 구분한 뒤 S3 GZIP; Filebeat는 한 줄씩 읽음 | `logEvents` 항목별로 분리, `owner`·그룹·스트림 보존, timestamp 사용 |
| WAF | CloudWatch 경유이므로 위와 같은 envelope; 항목의 `message`는 WAF JSON | action·rule·요청 주소·URI와 WAF timestamp를 추출 |
| GuardDuty | GZIP JSONL, 한 줄에 Finding 하나 | Finding ID·updatedAt·severity·accountId·region을 보존 |

Filebeat 공식 CloudTrail 파이프라인도 `message`를 `event.original`로 옮긴 뒤 JSON 파싱하여 `eventTime`을 해석합니다. 이 가이드에서는 같은 입력 계약의 정규화를 Logstash에서 수행합니다. [공식 CloudTrail 파이프라인 소스](https://raw.githubusercontent.com/elastic/beats/main/x-pack/filebeat/module/aws/cloudtrail/ingest/pipeline.yml)

CloudWatch 서버 로그는 envelope에 리전 필드가 없으므로 **이 단일 리전 수집 구성의 리전**을 `cloud.region`에 보완합니다. 여러 리전의 Firehose를 한 큐로 합치는 후속 구성에서는 소스 리전을 S3 prefix/메타데이터로 전달하도록 확장해야 합니다.

CloudTrail에는 JSON content_type와 Records 확장을 사용하고, 나머지는 text/plain으로 한 줄씩 읽어 Logstash에서 JSON을 해석합니다. Filebeat는 gzip signature를 인식하여 압축을 풉니다. CloudWatch/WAF의 Firehose에서 **Decompression=GZIP, DataMessageExtraction=false, AppendDelimiterToRecord** 계약을 변경하면 파서를 함께 바꿔야 합니다. [Filebeat AWS S3 입력](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-aws-s3)

중복 문서 ID는 Filebeat의 객체 기반 `@metadata._id`, 서비스 ID, 배열 위치를 조합합니다. 같은 S3 객체를 같은 내용으로 재수신하면 같은 날짜 인덱스의 같은 문서 ID에 저장됩니다. 다른 키로 복사한 객체·덮어쓴 객체·다른 날짜의 격리 인덱스까지 전역 중복 제거를 보장하지는 않습니다. GuardDuty는 같은 Finding의 updatedAt 변경을 다른 버전으로 남깁니다.

실패 보관은 세 층으로 구분합니다.

| 실패 지점 | 보관/복구 지점 | 확인 방법 |
|---|---|---|
| S3 다운로드·JSON 입력 디코딩 오류 | SQS 재시도 → SQS DLQ; S3 원본 유지 | SQS DLQ 개수, Filebeat 오류, KMS/IAM 상태 |
| Logstash JSON·배열·시간 파싱 오류 | `whs-elk-elasticsearch-logs-quarantine-*`; 원문·실패 이유·S3 정보 보존 | `event.dataset: aws.quarantine`, `error.message` |
| Elasticsearch 문서별 매핑 400 등의 실패 | `/var/lib/logstash/dead_letter_queue`; 원본 S3로 재수집 | Logstash 오류 및 DLQ 크기; 처리 실패율 알람 |

SQS DLQ와 Logstash DLQ는 다릅니다. `sqs.max_receive_count: -1`은 Filebeat가 반복 실패 메시지를 스스로 삭제하지 않고 SQS redrive에 맡기게 합니다. `dead_letter_queue.enable`은 일반 파싱 실패를 자동 수집하지 않으므로 별도 quarantine 코드가 필요합니다. 크기 제한에 도달하면 DLQ도 새 오류를 보존하지 못할 수 있어 알람을 먼저 설정해야 합니다.

한 JSONL envelope 읽기 상한은 16MiB입니다. Filebeat의 `max_bytes`를 넘는 부분은 보존되지 않을 수 있으므로 테스트에서 실제 압축 해제 후 **최대 한 줄 크기**를 확인하세요. 원본 S3 객체는 남아 있으므로 설정을 조정한 뒤 해당 객체 알림만 재전송합니다. 큰 payload는 Elasticsearch HTTP 요청 제한과 Logstash 메모리에도 영향을 줍니다.

기본 구성에는 불필요한 로그를 삭제하는 필터가 없습니다. 필요 필드만 검색용으로 색인하는 것과 원문 로그를 폐기하는 것은 다릅니다. 불필요 로그 비율을 관측한 다음, 승인한 소스별 삭제 조건과 테스트 근거를 별도 변경으로 반영합니다.

## 9. 스냅샷 생성 및 복원 검증

Elasticsearch EC2에서 실행합니다. 첫 이벤트가 색인된 뒤 수행하세요.

```bash
sudo python3 runtime/30-admin.py snapshot runtime/settings.env # whs-elk-elasticsearch-logs-*의 비동기 수동 스냅샷을 만들고 이름을 출력합니다.
sudo python3 runtime/30-admin.py health runtime/settings.env # 현재 클러스터와 관리 기능 상태를 확인합니다.
sudo python3 runtime/30-admin.py restore runtime/settings.env --snapshot whs-elk-elasticsearch-manual-실제시각 --index whs-elk-elasticsearch-logs-cloudtrail-2026.09.16 # SUCCESS 스냅샷의 단일 인덱스를 whs-elk-elasticsearch-restore- 이름으로 복원합니다.
```

스냅샷 명령의 `accepted: true`는 완료가 아닙니다. Kibana Dev Tools 또는 Elasticsearch API에서 `GET /_snapshot/whs-elk-elasticsearch-snapshots/스냅샷이름`의 `state: SUCCESS`를 확인합니다. restore 명령도 이 상태를 검사합니다. `--index`에는 실제 스냅샷에 있는 날짜를 넣으세요.

복원본은 `whs-elk-elasticsearch-restore-cloudtrail-2026.09.16`처럼 생성하며 기존 인덱스를 덮어쓰지 않습니다. 복원본에서는 ILM 정책을 제거하므로 원본·복원본의 선택 이벤트 ID·문서 개수를 대조한 뒤 관리자가 **그 테스트 인덱스만** 정리해야 합니다. 일상 조회 사용자는 `whs-elk-elasticsearch-restore-*` 권한이 없으므로 관리자 검증용 데이터 뷰가 필요합니다.

S3 원본 재수집은 같은 원본 객체에 대한 알림을 다시 SQS에 넣는 방식으로 수행하면 객체 기반 ID가 유지됩니다. 원본 파일을 새 키로 복사하는 방식은 여기에서 사용하는 ID 정책상 새 문서로 간주될 수 있습니다. 정상 인덱스를 대상으로 반복 시험할 때는 검증 문서의 고유 ID를 기준으로 수량을 대조하세요.

## 10. 장애 점검과 운영 증거

```bash
sudo journalctl -u elasticsearch --since '15 minutes ago' --no-pager # ES 시작·디스크·TLS 오류를 확인하며 저장 서버에서 실행합니다.
sudo journalctl -u logstash --since '15 minutes ago' --no-pager # 수집 서버의 파싱·색인·API 권한 오류를 확인합니다.
sudo journalctl -u filebeat --since '15 minutes ago' --no-pager # SQS·S3·KMS·Beats 연결 오류를 확인합니다.
sudo journalctl -u kibana --since '15 minutes ago' --no-pager # 조회 서버의 TLS·서비스 토큰·암호화 키 오류를 확인합니다.
df -h /var/lib/elasticsearch # 저장 서버 EBS 여유 공간을 확인합니다.
sudo du -sh /var/lib/logstash/queue /var/lib/logstash/dead_letter_queue # 수집 서버의 디스크 큐와 DLQ 증가를 확인합니다.
```

패키지는 journal 외에 `/var/log/elasticsearch`, `/var/log/logstash` 파일에도 로그를 남길 수 있습니다. 운영 기록을 외부로 공유하기 전에 사용자 정보·요청 URI·IP·계정 ID가 포함됐는지 확인합니다. 디버그로 요청 본문이나 토큰 값을 출력하는 검증은 사용하지 않습니다.

완료 증거에는 버전 출력, 설정 검사 성공, 원본 S3 객체 키, 테스트 이벤트 ID, Kibana 검색 결과, 발생→색인 지연, 수집 서버 중단 후 복구, ES 중단 후 복구, 같은 객체 재처리의 중복 수, 파싱 실패 격리, 스냅샷 복원 대조를 남깁니다. 실제 AWS 자원 생성과 서비스 시작은 이 문서의 적용 단계에서 수행하며, 로컬 문법 검사를 통과했다고 운영 검증이 끝난 것은 아닙니다.

## 11. 배포 전 정규화 함수 테스트

`tools/test-normalize.rb`는 실제 `runtime/normalize.rb`를 읽고 합성 샘플과 오류 사례를 넣습니다. Ruby/JRuby의 최소 `Event`·`Timestamp`·테스트 DSL shim을 사용하므로 외부 서비스와 비밀정보가 필요 없습니다. 내장 테스트, CloudTrail 전개 경계, CloudWatch 배열 분리·밀리초 시간·재처리 ID, WAF 내부 JSON, 정상/오류 혼합 배열, GuardDuty 갱신 버전, 제어 메시지·깨진 JSON·시간 오류 격리를 검사합니다.

```bash
ruby tools/test-normalize.rb # 설치된 Ruby로 실제 정규화 함수와 합성 입력의 변환 결과를 검사합니다.
```

이 검사는 **실제 Filebeat JSON 디코더, Logstash JVM 플러그인, Elasticsearch 매핑, S3/SQS 네트워크 동작을 실행하지 않습니다.** 따라서 위 `filebeat test`, Logstash 내장 설정 검사, 실제 S3 알림 수집·검색 검증을 계속 수행해야 합니다.
