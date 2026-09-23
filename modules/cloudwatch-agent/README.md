# CloudWatch Agent 로그 정규화·탐지·대응 모듈

기존 모듈과 같은 Terraform child module입니다. `envs/after`의 AWS provider와 상태 저장소를 사용하며, 모듈 자체에 provider/backend를 선언하지 않습니다. Lambda 소스 4개가 Lambda 함수 3개로 배포됩니다.

| 함수 이름 | 핸들러 | 역할 |
| --- | --- | --- |
| `normalize-cloudwatch-agent-logs` | `normalizer.handler` | 기존 Agent/WAF 로그를 구분해 정규화하고 S3에 저장 |
| `detect-cloudwatch-agent-logs` | `pipeline.detect_handler` | SQS로 받은 WAF 정규화 객체를 검사하고 대응 실행 시작 |
| `respond-cloudwatch-agent-logs` | `responder.handler` | WAF IP set 차단·만료 해제·증거 저장 |

`agent_normalizer.py`와 `pipeline.py`는 공용 코드이기도 하므로 소스 파일이 4개입니다. Terraform이 이 파일들만 ZIP 루트에 넣어 패키징합니다. `scripts/`의 배포 보조 코드는 Lambda ZIP에 넣지 않습니다.

## 생성 및 연결 범위

- Lambda 3개와 `/aws/lambda/<함수명>` 로그 그룹 3개(기본 보존 14일)
- Lambda 실행 역할 3개와 Step Functions 실행 역할 1개, 각 역할의 제한된 정책
- 탐지 SQS, 탐지 DLQ, 비동기 실패 큐와 호출 연결
- `respond-cloudwatch-agent-logs` Step Functions
- `respond-cloudwatch-agent-logs-state` DynamoDB
- `respond-cloudwatch-agent-logs-ipv4` / `-ipv6` WAF IP set
- 매분 실행되는 만료 차단 정리 스케줄
- 수집을 활성화하면 기존 Agent/WAF 로그 그룹에 구독 2개와 기존 S3 버킷의 탐지용 알림 1개

기존 EC2, CloudWatch Agent, 원본 로그 그룹, ALB, Web ACL, 정규화 S3 버킷을 다시 생성하지 않습니다. `alb-waf` 모듈의 기존 Web ACL에 자동 차단 규칙을 추가하는 연결은 필요합니다. 기존 WAF 규칙의 상대 순서를 유지하고 새 규칙을 우선순위 0에 배치합니다. 설정이 꺼져 있으면 기존 우선순위를 유지합니다.

현재 탐지 경로는 **WAF 로그 → 정규화 S3 → SQS → 탐지 Lambda → Step Functions → 대응 Lambda → WAF IP set / S3 증거**입니다. Agent 로그도 같은 정규화 Lambda에서 별도 S3 경로에 저장하지만, 실제 클라이언트 IP를 확인할 수 없는 Agent 이벤트만으로 IP를 차단하지 않습니다.

## PR에 포함하는 파일

```text
modules/cloudwatch-agent/
  main.tf                  # Lambda, 실행 로그, 호출 권한/연결
  variables.tf
  outputs.tf
  versions.tf
  locals.tf                # 현재 팀 계정의 리소스 식별자와 검증
  iam.tf
  storage.tf               # SQS, DynamoDB, IP sets
  workflow.tf              # Step Functions, 만료 정리 스케줄
  integrations.tf          # 기존 로그 구독과 S3 알림 연결
  normalizer.py
  agent_normalizer.py
  pipeline.py
  responder.py
  scripts/aws_cli.py
  scripts/integrations.py
  tests/module.tftest.hcl
  tests/with-alb.tftest.hcl
  tests/fixtures/with-alb/main.tf
  .gitignore
  README.md
modules/alb-waf/main.tf
modules/alb-waf/variables.tf
envs/after/main.tf
envs/after/cloudwatch_agent.tf
```

`modules/cloudwatch-agent/`만 넣으면 환경에서 모듈을 호출하지 않으며, ALB 차단 규칙도 연결되지 않습니다. 위 네 개의 환경/ALB 연결 파일을 함께 반영하세요. `envs/before`에는 호출을 추가하지 않습니다. 같은 이름의 자원을 두 상태 파일에서 동시에 관리하면 안 됩니다.

PR ZIP의 기존 파일 3개는 공개 저장소의 `0fa6761a343d937d3b146efa0f6f0aec5df5475d`를 기준으로 연결 변경만 추가했습니다. 이후 팀의 `main`이 바뀌었다면 해당 파일은 통째로 덮어쓰지 말고 차이를 병합하세요. ZIP은 저장소 루트에 맞는 경로로 구성되어 있습니다.

## 배포 전 조건

이 모듈은 검증된 팀 환경 전용입니다. 계정은 `896986966760`, 리전은 `ap-northeast-2`이며, 현재 S3·ALB·Web ACL과 수동 허용 IP set의 식별자를 확인합니다. Python 소스도 같은 대상을 검사하므로 `locals.tf`만 다른 계정 값으로 바꾸는 방식은 지원하지 않습니다.

1. 기존 v2 자동 대응 스택과 별도 Agent 정규화 Lambda를 앞서 제공한 철거 절차로 정리해야 합니다. 이전 Terraform 패키지로 같은 이름의 자원을 이미 만들었다면 먼저 기존 상태에서 이관할지, 종료 후 다시 만들지 결정하세요. 새 상태에서 같은 이름을 그대로 생성하지 마세요. 이 PR은 철거·상태 이관을 자동 실행하지 않습니다.
2. **실제 ALB/WAF를 소유하는 기존 `envs/after` 상태**를 사용해야 합니다. 빈 상태에서 기존 인프라 전체를 중복 생성하면 안 됩니다. 기존 ALB/WAF가 다른 상태 소유라면 먼저 이 모듈 호출과 WAF 연결을 그 소유 환경에 병합하세요.
3. Terraform 1.10 이상, AWS CLI v2, Python 3.9 이상이 필요합니다. 검증 버전은 Terraform 1.16.2, AWS provider 6.60.0, archive provider 2.7.1입니다. root에서 생성한 `.terraform.lock.hcl`은 팀의 버전 관리 규칙에 따라 관리하세요.
4. 배포 자격 증명에는 신규 Lambda/IAM/SQS/Step Functions/DynamoDB/IP set/로그/스케줄 관리와 기존 S3 알림·WAF 규칙 변경 권한이 필요합니다. 별도 IAM 경계가 필요하면 `cloudwatch_agent_permissions_boundary_arn`에 지정하세요. 기존 모듈의 역할 정책은 수정하지 않습니다.
5. 대응 Lambda는 동시 실행을 **1**로 제한합니다. 리전 동시 실행 할당량은 이 예약 1개와 최소 100개의 미예약 실행을 수용해야 하며, 다른 함수 예약도 고려해야 합니다. 할당량이 부족하면 증액 후 배포하세요. 제한을 삭제하면 IP set 갱신의 직렬 처리가 깨집니다.
6. 기존 Agent/WAF 로그 그룹에 구독 슬롯이 남아 있어야 합니다. 정규화 S3는 기존 SSE-S3 설정을 사용합니다. 기존 수동 허용 IP set 주소를 배포 시점에 읽고 추가 보호 CIDR과 합칩니다. 허용 IP가 바뀌면 다시 plan/apply하여 Lambda 환경에도 반영하세요.

## 환경에서 호출하는 구조

ZIP의 `envs/after/cloudwatch_agent.tf`에 다음 호출이 이미 포함되어 있습니다.

```hcl
module "cloudwatch_agent" {
  count  = var.enable_cloudwatch_agent_response ? 1 : 0
  source = "../../modules/cloudwatch-agent"

  enable_ingestion         = var.cloudwatch_agent_enable_ingestion
  allowlist_cidrs           = var.cloudwatch_agent_allowlist_cidrs
  block_seconds            = var.cloudwatch_agent_block_seconds
  permissions_boundary_arn = var.cloudwatch_agent_permissions_boundary_arn
  aws_cli_profile          = var.aws_profile
}
```

기존 `module "alb_waf"`에는 다음 입력이 추가됩니다.

```hcl
cloudwatch_agent_response_ip_sets = var.enable_cloudwatch_agent_response ? module.cloudwatch_agent[0].response_ip_sets : null
```

기본값은 `enable_cloudwatch_agent_response = false`, `cloudwatch_agent_enable_ingestion = false`입니다. PR을 병합하는 것만으로 자동 대응 자원이 생성되지는 않습니다. 두 값을 구분해 먼저 자원과 WAF 연결을 확인하고 이후 로그 처리를 시작할 수 있습니다.

## 적용 순서

기존 `envs/after`에서 사용하는 로컬 변수 파일과 인증 설정을 유지합니다. 아래 `terraform.tfvars`에는 기존 필수 변수도 있어야 합니다. 새로운 파일로 기존 내용을 덮어쓰지 말고 다음 항목을 추가하세요.

```hcl
enable_cloudwatch_agent_response      = true
cloudwatch_agent_enable_ingestion     = false
cloudwatch_agent_block_seconds        = 600
cloudwatch_agent_allowlist_cidrs       = [] # 보호할 실제 관리자 CIDR을 추가
# cloudwatch_agent_permissions_boundary_arn = "arn:aws:iam::896986966760:policy/WHSProjectRoleBoundary"
```

저장소 루트에서 실행합니다. 팀이 `-var-file=...`을 따로 사용한다면 두 plan 모두 동일하게 지정하세요.

```bash
terraform -chdir=envs/after init
terraform -chdir=envs/after validate
terraform -chdir=envs/after plan -out=cloudwatch-agent-resources.tfplan
terraform -chdir=envs/after show cloudwatch-agent-resources.tfplan
```

기존 잠금 파일이 AWS provider 6.60 미만을 고정해 `init`이 버전 충돌로 멈춘다면, provider 변경 범위를 검토한 뒤 `terraform -chdir=envs/after init -upgrade`로 잠금 파일을 갱신하고 다시 검증하세요.

계획에는 신규 자동 대응 자원과 기존 Web ACL 규칙 변경이 나타나야 합니다. 기존 EC2·ALB·버킷의 교체/삭제 등 관련 없는 변경이 있으면 먼저 상태/설정을 맞추세요. 검토한 계획을 적용합니다.

```bash
terraform -chdir=envs/after apply cloudwatch-agent-resources.tfplan
```

이후 같은 변수 파일에서 `cloudwatch_agent_enable_ingestion = true`로 변경하고 다음 계획을 확인·적용합니다.

```bash
terraform -chdir=envs/after plan -out=cloudwatch-agent-ingestion.tfplan
terraform -chdir=envs/after show cloudwatch-agent-ingestion.tfplan
terraform -chdir=envs/after apply cloudwatch-agent-ingestion.tfplan
terraform -chdir=envs/after output -json cloudwatch_agent_response
```

수집 활성화 때 CloudWatch 구독과 S3 알림이 연결되고 탐지 큐 소비가 활성화됩니다. 이후 들어오는 로그가 처리 대상입니다. 기존 S3 객체가 자동 재처리되는 것은 아닙니다. Agent 객체는 `cloudwatch-agent/v1/`, WAF 객체는 `waf/response/v1/`, 대응 증거는 `evidence/cloudwatch-agent-response/v1/` 아래에서 확인합니다.

AWS provider의 `profile`은 AWS CLI에 자동 전달되지 않습니다. 이 모듈은 `aws_cli_profile`을 S3 알림 보조 프로그램에 전달합니다. CloudShell의 기본 자격 증명을 쓴다면 `aws_profile = null`을 사용하고, 기존 backend에 하드코딩된 로컬 `profile`도 CloudShell 환경에 맞게 별도로 조정해야 합니다. 기존 팀 backend 설정을 이 ZIP에서 바꾸지는 않았습니다.

## 공유 자원 관리

- WAF는 기존 `alb-waf`의 inline 규칙 한 곳에서 관리합니다. 별도의 `UpdateWebACL` 배포 보조 프로그램은 실행하지 않습니다. 대응 Lambda에는 전용 IP set 변경 권한만 있습니다.
- S3 알림은 버킷 전체 설정이 하나이므로 `aws_s3_bucket_notification`을 추가해 기존 알림을 대체하지 않습니다. 검증된 보조 프로그램이 이 모듈의 알림 ID `detect-cloudwatch-agent-logs`만 추가/제거하고 기존 SQS/SNS/Lambda/EventBridge 설정을 보존합니다. 이 단계는 실행하는 컴퓨터에 Python과 AWS CLI가 필요합니다.
- 같은 버킷의 알림 설정을 다른 Terraform 상태나 담당자가 동시에 수정하지 않도록 조정하세요. 보조 프로그램은 충돌을 감지하면 실패로 보고하며 무조건 덮어쓰지 않습니다. S3 알림 변경에는 원자적 잠금 기능이 없어 외부의 동시 변경을 완전히 막을 수는 없습니다.
- S3 보조 단계가 실패하면 출력된 비공개 감사 디렉터리와 실제 알림 상태를 확인한 뒤 복구하세요. 실패한 생성 단계에서 자원이 tainted된 경우 Terraform의 destroy provisioner가 생략될 수 있으므로, 바로 모듈을 제거해도 알림이 항상 정리된다고 가정하면 안 됩니다.

HashiCorp 문서: [S3 bucket notification의 단일 설정 관리](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_notification).

## 수집 중지와 철거

새 모듈의 자원은 기존 v2 전용 철거 스크립트 대상이 아닙니다. 우선 `cloudwatch_agent_enable_ingestion = false`로 plan/apply하면 구독·S3 알림을 제거하고 탐지 이벤트 연결을 중지합니다. 이 변경은 이미 실행 중인 Lambda나 Step Functions 실행을 즉시 종료하지 않습니다.

그다음 실행 중인 대응과 차단 만료 정리가 완료됐는지 확인하고, 큐에 남은 메시지가 있는지도 확인하세요. 차단을 유지해야 할 사건이 없고 철거가 가능할 때 `enable_cloudwatch_agent_response = false`로 plan/apply합니다. 기존 `alb-waf`에서 대응 규칙을 제거하고 이 모듈이 소유한 자원을 삭제합니다. 큐 메시지·상태 테이블·Lambda 실행 로그는 삭제되며, 기존 S3 버킷의 저장 데이터는 남습니다.

**기존 인프라도 함께 있는 `envs/after`에서 `terraform destroy`를 실행하면 전체 환경이 철거될 수 있습니다.** 자동 대응만 제거할 때는 위 두 변수를 사용해 저장된 계획을 검토하세요. 상태 파일을 지워서 철거를 대신하지 마세요.

## 검증과 커밋

실제 AWS 호출 없이 모듈 계획을 검사하는 테스트가 포함되어 있습니다. 테스트에서는 AWS provider를 mock으로 대체하며 S3 변경 프로그램은 실행되지 않습니다.

로컬 검증에서 Terraform 모의 계획 14개(기존 ALB 모듈과의 활성화/비활성화 연결 포함), 런타임·공유 알림 보존 모의 테스트 104개를 통과했습니다. 실제 AWS 계정에 대한 plan/apply나 실시간 공격 차단 시험은 이번 PR 패키지 작성 중 실행하지 않았습니다.

```bash
terraform -chdir=modules/cloudwatch-agent init -backend=false
terraform -chdir=modules/cloudwatch-agent validate
terraform -chdir=modules/cloudwatch-agent test
```

저장소 루트에서 PR 파일만 지정해 추가합니다.

```bash
git add modules/cloudwatch-agent modules/alb-waf/main.tf modules/alb-waf/variables.tf envs/after/main.tf envs/after/cloudwatch_agent.tf
git diff --cached --stat
git diff --cached
git commit -m "feat: add CloudWatch Agent response Terraform module"
```

계획 파일(`*.tfplan`), 생성된 Lambda ZIP, `.terraform/`, 상태 파일, 로컬 `terraform.tfvars`, 자격 증명은 커밋하지 않습니다. 이 패키지는 PR 파일과 로컬 검증 결과이며 실제 AWS 배포 완료를 의미하지 않습니다.
