# 작성 패키지 검증 기록

최초 검증일: 2026-09-16. 이름 규칙 변경 후 재검증일: 2026-09-19. 저장소 배치 후 재검증일: 2026-09-20. 이 기록은 **가이드·Terraform·코드의 로컬 검사**다. 실제 AWS 계정에서 생성·전달·권한·복원에 성공한 배포 기록이 아니다.

## 수행한 검사

| 검사 | 도구·대상 | 결과와 증명 범위 |
|---|---|---|
| Terraform 포맷 | Terraform 1.16.2 `fmt -check -recursive` | 통과 |
| Terraform 스키마·참조 | AWS provider 6.60.0, `terraform validate` | 통과. 구성 문법·provider 스키마·참조 확인 |
| Terraform 모의 계획 | `terraform/tests/guide.tftest.hcl` | 6개 통과: 기본 플랫폼, 소스 연결 활성화, 기존 CloudTrail 재사용, 이름 규칙·AWS 예외, 잘못된 접두사 거부, 충돌 입력 거부 |
| 로그 정규화 | JRuby 9.4.14.0 / Java 17, `tools/test-normalize.rb` | 13개 통과: 실제 `normalize.rb` 함수에 가상 이벤트 주입 |
| YAML 구문 | JRuby의 `YAML.safe_load`, `runtime/templates/*.yml.in` | 5개 통과: Filebeat·Logstash·pipeline·Elasticsearch·Kibana |
| Bash 구문 | Git Bash의 `bash -n runtime/00-install.sh` | 통과. 설치 명령 자체는 실행하지 않음 |
| Python 구문 | `ast.parse` | 패키지 Python 소스의 구문 확인. AWS·시스템 변경 코드는 실행하지 않음 |
| 샘플 파일 | 표준 `gzip`·`json` 파서 | 5개 gzip의 CRC·JSON·압축 전후 내용 일치 확인 |
| 재처리 알림 생성 | `tools/make_s3_replay.py` | 로컬 JSON 생성, 객체 키의 공백·더하기 문자 인코딩 왕복 확인. SQS 전송 없음 |
| Agent 설정 생성 | `tools/make_cloudwatch_agent_config.py` | 검증 파일·앱 파일 설정, 잘못된 입력 거부, JSON 형식·기존 출력 보호 검사. 업무 서버에는 적용하지 않음 |
| 설명·연결 | `tools/verify_package.py` | 코드와 문서의 줄 주석, 닫힌 코드 블록, 로컬 문서 링크 확인 |
| 설계 검토 | 문서와 Terraform·runtime 교차 확인 | CloudTrail Bucket Key 복호화 권한, Firehose 오류 prefix, Agent 설치 절차 보완 |

Terraform 테스트의 AWS provider는 mock이다. 실제 IAM의 허용·거부, 서비스 측 유효성 검사, 계정의 SCP·권한 경계·기존 정책까지 검증한 것이 아니다. `aws_iam_policy_document` mock은 정책 계산을 대체하므로 이 시험을 IAM 정책 검증이라고 부르지 않는다.

Ruby 시험은 작은 `LogStash::Event`·`Timestamp`·test DSL 대체 객체를 사용한다. CloudTrail 샘플은 Filebeat가 `Records`를 분리한 후의 입력을 가정한다. 정상 배열 분리, 원본 시간·계정·리전·S3 위치, 같은 입력 ID, WAF 필드, GuardDuty 갱신 버전, 깨진 JSON과 제어 메시지 보존을 확인했다. **실제 Filebeat의 S3 해석이나 Logstash 플러그인 런타임을 실행한 시험은 아니다.**

## 아직 적용 계정에서 수행해야 할 검사

- 실제 계정·VPC·private subnet·NAT/endpoint·SSM 접근, AMI와 고정 패키지 다운로드 가능 여부.
- 원래 자원을 관리하던 Terraform과의 중복·S3 notification 병합, WAF 기존 목적지, 기존 Trail·GuardDuty export 설정.
- EC2 세 대의 실제 패키지 설치·인증서 생성·서비스 시작·keystore·HTTPS 검증.
- 각 소스에서 발생한 실제 표본을 S3 → SQS → Filebeat → Logstash → Elasticsearch → Kibana에서 대조.
- 최대 압축 해제 후 JSONL 한 줄 크기, 로그량, 비용, CPU·메모리·EBS·큐 적체 측정.
- 수집 중단·ES 중단·잘못된 입력·동일 객체 재처리·DLQ 복구·스냅샷 새 이름 복원.
- TLS 인증서 만료, API 키 90일 만료 전 교체, 일상 조회 계정의 접근 제한.

세부 실행 방법과 통과 기준은 [검증 runbook](docs/validation-runbook.md), [runtime 설치](docs/runtime-guide.md), [Terraform 적용](docs/terraform-notes.md)에 있다. 실제 검증 결과는 이 기록을 덮어 단순히 “완료”로 바꾸기보다 계정·실행일·표본 ID·오류·증거를 별도 운영 기록에 남긴다.

## 로컬 검사 재현

저장소의 `observability/elk/`에서 실행한다. Terraform과 Ruby는 운영자 PC에 설치해야 하며 저장소에는 해당 실행 파일·provider 캐시를 포함하지 않는다. Python 검사는 표준 라이브러리만 사용한다.

```bash
python3 tools/verify_package.py # Python 구문·줄 주석·문서 링크·샘플 일치를 검사한다.
bash -n runtime/00-install.sh # 설치 스크립트의 Bash 구문만 검사한다.
ruby tools/test-normalize.rb # 실제 정규화 함수와 가상 Logstash 이벤트로 13개 검사를 수행한다.
terraform -chdir=terraform init -backend=false -input=false -lockfile=readonly # lock 파일을 유지하며 provider를 준비하고 backend는 연결하지 않는다.
terraform -chdir=terraform fmt -check -recursive # HCL 포맷을 확인한다.
terraform -chdir=terraform validate # AWS provider 스키마와 정적 참조를 검증한다.
terraform -chdir=terraform test # mock provider로 여섯 구성·이름 검사를 수행하며 AWS 자원을 만들지 않는다.
```

배포 시에는 [Terraform 적용 절차](docs/terraform-notes.md)의 backend·실제 입력값·계획 검토 순서를 따른다. `init -backend=false`는 위 로컬 코드 검사용 설정이다.
