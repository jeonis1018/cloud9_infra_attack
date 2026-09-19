# AWS 보안 로그 → EC2 3대 ELK: 첫 구축 가이드

작성 기준: 2026-09-16 · 저장소 구성 반영: 2026-09-20 · 대상: 단일 리전 검증 환경 · 문서 언어: 한국어

이 가이드는 **수집 EC2 1대(Filebeat + Logstash), Elasticsearch EC2 1대, Kibana EC2 1대**로 CloudTrail, CloudWatch Agent의 서버 로그, WAF 요청 로그, GuardDuty Findings를 검색하는 환경을 구성한다. 원본은 먼저 S3에 보관하고, S3 객체 생성 알림을 SQS로 받아 수집한다. Lambda 전처리는 포함하지 않는다. 아직 확정되지 않은 삭제 기준은 Logstash에서 검증하며, 기본 설정은 정상 로그를 임의로 버리지 않는다.

이 패키지의 작성·검증은 로컬 작업이다. 실제 계정의 리소스 존재 여부, 비용, 권한, 네트워크 연결은 사용자의 AWS에서 확인해야 한다. `terraform apply`는 리소스를 생성하며, 본 패키지를 읽거나 로컬 검증하는 것만으로 AWS에 배포되지는 않는다.

저장소의 `observability/elk/terraform`은 **독립적으로 실행하는 Terraform 루트 스택**이다. `envs/before`, `envs/after`에서 자동 호출하지 않으며, 기존 VPC·private subnet·NAT를 확인해 입력으로 참조한다. 기존 환경과 다른 state를 사용하고, CloudTrail·GuardDuty·WAF·업무 서버 Agent 연결은 자원 소유자를 확인한 뒤 순서대로 적용한다. 기존 WAF 로그 그룹을 입력하면 첫 적용에서 구독이 추가되므로, [사전 확인](docs/preflight.md)과 [연결 옵션](docs/terraform-notes.md)을 먼저 읽는다.

새로 만드는 AWS·Elastic 자원 이름은 **`whs-elk-<서비스>-<자원 역할>`**로 통일한다. 예를 들어 수집 EC2는 `whs-elk-ec2-collector`, CloudTrail 수집 큐는 `whs-elk-sqs-cloudtrail-ingest`, CloudTrail 검색 인덱스는 `whs-elk-elasticsearch-logs-cloudtrail-YYYY.MM.dd`다. S3는 전역 유일성을 위해 계정·리전을 덧붙이고, WAF 로그 그룹은 AWS 필수 접두사 `aws-waf-logs-`를 앞에 둔다. 이름을 직접 지정할 수 없는 자원은 지원되는 `Name` 태그로 표시한다. 전체 목록과 예외는 [자원 이름 규칙](docs/naming.md)에서 확인한다. 재사용하는 기존 자원, 서비스가 정한 고정 이름, 소스별 S3 경로는 유지한다.

## 읽는 순서

1. [구성도·서비스 역할·필수성](docs/architecture.md): 무엇을 왜 사용하는지 확인한다.
2. [적용 전 AWS 자원 확인](docs/preflight.md): VPC, 기존 로그 목적지, 자원 소유 Terraform을 확인한다.
3. [Terraform 구성과 적용](docs/terraform-notes.md): 새 플랫폼과 선택한 수집 경로를 만든다.
4. [EC2 소프트웨어·TLS 설치](docs/runtime-guide.md): Elasticsearch를 먼저 시작하고 수집 서버와 Kibana의 인증을 연결한다.
5. [AWS 콘솔 구축·확인 방법](docs/aws-console-guide.md): Terraform의 각 설정을 콘솔에서 확인하거나 수동으로 구성한다.
6. [업무 서버 CloudWatch Agent 설치](docs/cloudwatch-agent-guide.md): 실제 파일 로그를 CloudWatch Logs에 연결한다.
7. [검증·장애 복구·운영 절차](docs/validation-runbook.md): 정상 수집과 복구를 확인한다.
8. [검증 결과와 제한](VALIDATION.md): 실제로 수행한 로컬 검증과 미실행 항목을 구분한다.

자원을 콘솔에서 찾을 때는 [자원 이름 전체 목록](docs/naming.md)을 함께 본다. 이전 버전을 이미 배포했다면 이름 변경으로 일부 자원이 교체될 수 있으므로 새 `plan`에서 교체·삭제와 원본 보관 영향을 확인한다.

**콘솔 수동 생성과 Terraform 생성은 같은 자원에 중복 적용하지 않는다.** 이미 다른 Terraform 상태가 관리하는 CloudTrail, GuardDuty, WAF 로깅, S3 알림 설정은 원래 소유한 구성에서 변경하거나 이 패키지의 연결 옵션을 사용한다. 가져오기만 하면 안전해지는 것은 아니므로, 자원 하나의 소유 상태는 하나로 유지한다.

## 이번 구축의 전제

| 항목 | 기본 방침 | 적용 전에 결정할 값 |
|---|---|---|
| AWS 리전 | 서울 `ap-northeast-2` 예시 | 실제 운영 리전과 로그 발생 리전 |
| 계정 | Terraform 한 번의 적용은 단일 계정·리전 | 계정 ID, 사용 프로파일, 기존 조직 정책 |
| 네트워크 | 기존 VPC·private subnet 재사용 | VPC ID, 역할별 subnet ID, 라우트와 DNS |
| 인터넷 통신 | 공개 IP 없이 기존 NAT·프록시 등 사용 | Elastic 패키지 저장소 접근 가능 여부 |
| 운영체제 | Ubuntu Server 24.04 LTS, amd64 | AMI와 설치 시점 패키지 호환성 |
| Elastic Stack | 확인한 `9.5.3` 계열 고정 | 배포 전 공식 지원·릴리스 노트 재확인 |
| EC2 수 | 로그 플랫폼 3대 | 업무 서버·ALB·WAF는 별도 기존 자원 |
| 원본 보관 | S3 기본 30일, 버전 정리 정책 별도 | 실제 감사·프로젝트 보관 요구사항 |
| 조회 가용성 | Elasticsearch/Kibana 각 1대 | 중단 후 복구 검증, 무중단은 후속 단계 |
| 원본 수정·삭제 | 수집 역할에는 원본 삭제 권한 없음 | 삭제 담당 관리 역할과 lifecycle 정책 |
| 비밀정보 | 실행 시 생성·keystore 저장 | 운영자 접근 경로와 인증서 보관 위치 |

EC2 종류와 EBS 용량은 **소량 검증의 시작값**이다. 실제 로그량, 색인 증가율, 동시 검색량을 측정해 조정한다. 버스트형 인스턴스의 CPU 크레딧과 EBS, NAT, KMS, CloudWatch Logs, Firehose, S3, SQS, GuardDuty 비용도 확인한다. 서비스 세 개의 EC2 요금만 합산한 금액을 전체 비용으로 사용하지 않는다.

## 단계별 완료 기준

| 단계 | 작업 | 다음 단계로 넘어가는 기준 |
|---|---|---|
| 1 | 사전 자원·권한·소유 상태 조사 | 계정·리전·VPC·subnet·기존 로그 목적지를 식별 |
| 2 | Terraform `init`, `validate`, `plan` | 새 플랫폼의 계획과 선택한 기존 자원 변경을 설명 가능 |
| 3 | Terraform 적용 | EC2 3대가 SSM에서 Online, 버킷·큐·IAM 준비 |
| 4 | TLS·Elasticsearch·Kibana·수집기 설치 | 인증된 HTTPS 조회, 설정 검사, 서비스 재시작 정상 |
| 5 | CloudTrail 한 종류 연결 | 선정한 `eventID`가 S3 원본과 Elasticsearch에서 일치 |
| 6 | 서버 로그 → WAF → GuardDuty 순서로 추가 | 각 원본 식별자·발생 시각·핵심 필드가 검색됨 |
| 7 | 오류·재시도·재처리 시험 | 정상 로그와 실패 로그가 구분되고 복구 결과 기록 |
| 8 | 보관·스냅샷·접근 제어 검증 | 테스트 복원 성공, 수집 역할의 원본 삭제 거부 |

## 코드를 읽고 실행하는 방법

실행 가능한 HCL, YAML, Bash, Python과 Logstash 설정에는 각 유효 코드 줄의 의미를 주석으로 설명한다. 빈 줄과 주석 자체는 설명 대상에서 제외한다. JSON은 표준 문법상 주석을 지원하지 않으므로, 주석이 있는 생성 코드로 JSON을 만들거나 설명 문서와 실제 JSON을 분리한다. JSON 본문에 `//` 또는 `#`를 붙여 AWS API에 전달하지 않는다.

문서의 Bash 명령은 **AWS CloudShell 또는 Linux 운영자 환경** 기준이다. 사전 확인 문서의 `powershell` 블록은 Windows 로컬용이며, Windows PowerShell에서는 Bash 블록을 그대로 실행하지 않는다. SSM 포트 포워딩은 로컬 PC의 AWS CLI와 Session Manager 플러그인에서 실행해야 로컬 브라우저가 터널에 접근할 수 있다. CloudShell에서 실행한 포트 포워딩의 localhost는 CloudShell 환경을 가리킨다.

문서에서 **패키지 루트**는 저장소의 `observability/elk`를 뜻한다. `runtime/`, `tools/`, `terraform/` 상대 경로는 이 위치가 기준이며, Terraform 명령은 `observability/elk/terraform`에서 실행한다. 각 EC2의 설치·관리 명령은 문서에 명시한 서버 작업 디렉터리를 따른다.

```bash
aws sts get-caller-identity # 실제 명령이 실행될 AWS 계정과 역할을 확인한다.
aws configure get region # 현재 CLI 기본 리전을 확인하고 문서의 리전과 대조한다.
terraform version # 사용할 Terraform CLI 버전을 확인한다.
```

실제 값은 `terraform/terraform.tfvars.example`을 복사해 작성한다. 예시의 계정 번호·ID는 실존 자원으로 간주하지 않는다. Terraform 상태, 계획 파일, 실제 tfvars, keystore, 비밀키, 비밀번호와 토큰은 공유 ZIP이나 저장소에 포함하지 않는다.

## 제공 파일

- `terraform/`: 네트워크 참조, EC2 3대, IAM, S3, KMS, SQS, Firehose와 선택적 소스 연결 코드.
- `runtime/`: 서버별 설치·인증서·설정·API 초기화 코드와 주석이 있는 설정 파일.
- `docs/`: 구축 방법, 서비스 필요성, 사전 조사와 검증·복구 절차.
- `samples/`: 실제 계정 정보가 없는 검증용 샘플과 설명.
- `tools/`: 패키지의 로컬 검사·샘플 생성 도구.
- `VALIDATION.md`: 수행한 검사와 실행하지 못한 검사의 구분.

## 다음 확장 단계

원본 저장·검색·복구가 검증되면 수집 서버 2대, Elasticsearch 3노드·AZ 분산, Kibana 2대·내부 ALB 순서로 확장한다. 계정 분리, CloudTrail 조직 Trail, 추가 리전 수집, S3 Object Lock, 키 회전·수명 관리와 원격 Terraform 상태는 실제 운영 요구사항에 맞춰 추가한다. 이 패키지의 단일 계정·단일 노드 예시는 해당 운영 기능을 이미 충족했다고 주장하지 않는다.
