# 업무 서버 CloudWatch Agent 연결

이 절차는 **새 Ubuntu 24.04 amd64 업무 EC2**의 파일 로그를 기존 ELK 파이프라인에 연결한다. ELK 3대에 설치하는 절차와 별개다. 결과 경로는 `업무 파일 → CloudWatch Agent → Terraform이 출력한 CloudWatch Logs 그룹 → Firehose → S3 → Filebeat/Logstash → Elasticsearch`이다.

기존 업무 서버에 CloudWatch Agent가 있거나 SSM State Manager association이 설정을 관리한다면 아래 신규 설치·`fetch-config`를 실행하지 않는다. 원 소유자의 기존 설정에 새 파일을 통합한다. Agent의 설정 소유자는 AWS 계정의 SSM association·Parameter Store와 실제 배포 코드를 대조해 확인한다. `fetch-config`는 기존 설정 교체에 영향을 주므로 기존 서버의 단순 “추가 설정” 명령으로 쓰지 않는다. 다중 설정이 필요하면 이름 충돌·중복 수집을 확인하여 원 소유자가 `append-config`를 선택한다. [AWS 다중 설정 파일](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/create-cloudwatch-agent-configuration-file.html)

이 문서와 생성기는 실제 AWS 작업을 수행한 결과가 아니다. `tools/make_cloudwatch_agent_config.py` 자체는 **JSON 파일만 생성**하며 AWS에 연결하지 않는다. 아래 Terraform·CLI 명령은 사용자가 적용할 때만 자원을 변경한다.

## 1. 확인할 값과 실행 위치

| 값 | 확인할 곳 | 조건 |
|---|---|---|
| 업무 EC2 ID와 instance profile role 이름 | EC2 콘솔 → 해당 인스턴스 → Security | ELK collector role이 아니라 로그가 발생하는 업무 서버의 역할 |
| CloudWatch Logs 그룹 | 이 패키지 `terraform output -json log_group_names`의 `cloudwatch` | 이미 그룹과 Firehose 구독이 생성되어 있어야 함 |
| SSM 관리 | Systems Manager → Managed nodes | 업무 서버도 SSM Online이고 운영자가 해당 서버에 StartSession 가능 |
| 네트워크 | 업무 서버 route/SG/endpoint 정책 | CWL HTTPS 443, SSM, Agent 패키지·Ubuntu 패키지 다운로드 경로 |
| 검증 파일 | `/var/log/elk-validation.log` | 이 파일만 먼저 수집; 앱 로그는 명시적으로 선택 |
| 앱 로그 | 실제 절대 파일 경로와 로그 형식 | UTF-8 한 줄 로그가 기본. journald·멀티라인·다른 인코딩은 별도 설정 필요 |
| 설정 owner | 기존 Terraform/SSM association/배포 도구 | 같은 서버의 Agent 설정을 두 도구가 번갈아 덮어쓰지 않음 |

관리자 쪽 명령은 **패키지 루트(`observability/elk`)의 Linux/WSL/CloudShell Bash**, 설치 명령은 **업무 EC2의 SSM Bash 세션**에서 실행한다. 로컬 PC에서 named profile을 사용하면 그 터미널의 `AWS_PROFILE` 또는 `--profile`을 먼저 설정한다. PowerShell의 `$elkProfile` 변수는 Bash 환경으로 자동 전달되지 않는다.

## 2. 주석이 있는 생성기로 JSON 만들기 — 관리자 환경

처음에는 검증 파일 하나만 포함한다. 생성 JSON에는 `retention_in_days`를 넣지 않으므로 Agent가 Terraform의 보관 정책을 바꾸지 않는다. metrics/traces와 삭제 필터도 넣지 않는다. 파일 내용의 발생 시각 파싱은 생략하므로 CWL timestamp는 기본 수집 시각이며, 앱 자체 시각이 필요하면 확인한 포맷으로 `timestamp_format`을 추가한다. [Agent 설정 필드](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-Configuration-File-Details.html)

```bash
export AWS_REGION=ap-northeast-2 # Terraform과 업무 서버가 사용하는 실제 리전으로 맞춘다.
aws sts get-caller-identity --region "$AWS_REGION" # 현재 관리자 역할이 올바른 계정인지 다시 확인한다.
CWL_LOG_GROUP=$(terraform -chdir=terraform output -json log_group_names | python3 -c 'import json,sys; print(json.load(sys.stdin)["cloudwatch"])') # 신규 또는 재사용한 서버 로그 그룹 이름을 읽는다.
python3 tools/make_cloudwatch_agent_config.py --region "$AWS_REGION" --log-group "$CWL_LOG_GROUP" --output cloudwatch-agent-elk.json # 검증 파일 한 개만 읽는 새 JSON을 만든다.
python3 -m json.tool cloudwatch-agent-elk.json # 주석 없는 표준 JSON인지와 수집 경로를 눈으로 확인한다.
```

앱 로그도 처음부터 검증할 때만 위 생성 명령 대신 다음을 사용한다. 두 예제를 연달아 실행하면 기존 출력 보호로 중단한다. `--app-log`를 반복하여 필요한 파일만 추가할 수 있다. 임의의 `/var/log/*` 전체 수집은 하지 않는다.

```bash
APP_LOG='/var/log/REPLACE_WITH_APPROVED_APP.log' # 업무 서버에서 실제로 존재하는 UTF-8 한 줄 앱 로그 파일로 교체한다.
python3 tools/make_cloudwatch_agent_config.py --region "$AWS_REGION" --log-group "$CWL_LOG_GROUP" --app-log "$APP_LOG" --output cloudwatch-agent-elk.json # 검증 파일과 명시한 앱 파일을 각각의 stream으로 보낸다.
```

생성기는 기존 파일을 덮어쓰지 않는다. 변경본은 다른 출력 파일로 만들어 기존 JSON과 대조한 다음 원 소유자의 변경 절차로 적용한다.

## 3. 기존 업무 역할 권한과 SSM 설정 — Terraform 예제

아래 HCL은 **기존 업무 EC2 role을 소유한 Terraform 구성에 반영할 예제**이며 이 ELK 패키지의 자동 적용 파일에는 들어 있지 않다. 새 role/instance profile을 만드는 대신 확인한 기존 role 이름에 전용 inline policy를 추가한다. 기존 owner가 같은 정책이나 SSM parameter를 이미 관리하면 그 정의에 통합하고 두 state에서 관리하지 않는다.

생성한 `cloudwatch-agent-elk.json`을 아래 HCL 파일이 있는 모듈 디렉터리에 놓는다. `elk_agent_region`, `elk_agent_group_name`, `elk_workload_role_name`을 확인한 값으로 바꾼다. Parameter Store의 **String**은 로그 경로 설정용이고 비밀번호·API 키를 넣는 곳이 아니다. 역할에 이미 SSM 기본 관리 권한이 연결되어 있다는 전제다.

```hcl
data "aws_caller_identity" "elk_agent" {} # 이 업무 Terraform이 적용되는 실제 계정 ID를 읽는다.
locals { # 로그 대상과 기존 역할 이름을 명시적으로 입력한다.
  elk_agent_region = "ap-northeast-2" # 실제 provider 리전과 일치시킨다.
  elk_agent_group_name = "/REPLACE_WITH_TERRAFORM_OUTPUT" # log_group_names.cloudwatch의 실제 값을 넣는다.
  elk_workload_role_name = "REPLACE_WITH_EXISTING_WORKLOAD_ROLE" # instance profile 이름이 아닌 내부 IAM role 이름이다.
  elk_agent_parameter_name = "whs-elk-ssm-workload-agent-config" # 신규 SSM parameter 이름을 공통 규칙에 맞춘다.
  elk_agent_group_arn = "arn:aws:logs:${local.elk_agent_region}:${data.aws_caller_identity.elk_agent.account_id}:log-group:${local.elk_agent_group_name}" # 허용할 그룹 한 개의 ARN이다.
} # 로컬 값을 끝낸다.
resource "aws_ssm_parameter" "elk_workload_agent" { # 새 업무 Agent의 검토된 설정을 저장한다.
  name = local.elk_agent_parameter_name # 기존 parameter와 충돌하지 않는 이름이다.
  type = "String" # 비밀정보가 없는 설정 JSON이다.
  value = file("${path.module}/cloudwatch-agent-elk.json") # 주석 Python 생성기가 만든 표준 JSON을 읽는다.
  description = "ELK validation workload file logs" # 관리 목적을 표시한다.
} # 설정 parameter를 끝낸다.
resource "aws_iam_role_policy" "elk_workload_logs" { # 기존 업무 role에 필요한 로그 전달 권한만 추가한다.
  name = "whs-elk-iam-workload-send-logs" # 기존 업무 역할에 추가할 새 inline 정책 이름이다.
  role = local.elk_workload_role_name # 새 역할이나 profile 교체를 수행하지 않는다.
  policy = jsonencode({ # 주석이 있는 HCL을 유효한 정책 JSON으로 변환한다.
    Version = "2012-10-17" # IAM 정책 버전이다.
    Statement = [ # 동작을 리소스 범위별로 나눈다.
      { # 해당 로그 그룹 안의 stream만 만들고 전송한다.
        Effect = "Allow" # 허용문이다.
        Action = ["logs:CreateLogStream", "logs:PutLogEvents"] # 로그 삭제·보관 변경·그룹 생성 권한은 주지 않는다.
        Resource = "${local.elk_agent_group_arn}:log-stream:*" # 다른 로그 그룹에는 쓰지 못하게 한다.
      }, # stream 전송 권한을 끝낸다.
      { # 해당 그룹의 stream 상태를 확인한다.
        Effect = "Allow" # 조회만 허용한다.
        Action = ["logs:DescribeLogStreams"] # Agent의 stream 확인에 사용한다.
        Resource = [local.elk_agent_group_arn, "${local.elk_agent_group_arn}:*"] # 그룹과 해당 그룹 범위 ARN만 허용한다.
      }, # stream 조회 권한을 끝낸다.
      { # 자기 Agent 설정만 읽는다.
        Effect = "Allow" # 조회 허용문이다.
        Action = ["ssm:GetParameter"] # 수정·삭제·다른 파라미터 열거 권한은 주지 않는다.
        Resource = aws_ssm_parameter.elk_workload_agent.arn # 정확한 설정 parameter 하나만 허용한다.
      } # 설정 조회 권한을 끝낸다.
    ] # 권한 목록을 끝낸다.
  }) # 정책 JSON을 끝낸다.
} # 업무 역할의 추가 정책을 끝낸다.
```

적용 plan에서 **기존 업무 role/instance profile의 교체가 없어야** 한다. Source log group은 ELK 쪽에서 먼저 생성하며, 이 정책은 실수로 로그 그룹이 사라졌을 때 Agent가 임의 재생성하는 것을 허용하지 않는다. Log group 암호화는 CWL 서비스와 KMS key policy가 처리하므로 단순 `PutLogEvents`를 위해 업무 Agent에 원본 S3 KMS 복호화 권한을 줄 필요는 없다. 메트릭·X-Ray·태그 조회를 추가한다면 그 기능의 권한은 별도로 필요하다. AWS의 범용 정책은 더 많은 기능을 포함하므로 이 파일 로그 예제와 범위를 구분한다. [AWS Agent 범용 정책](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/CloudWatchAgentServerPolicy.html)

콘솔을 대안으로 쓸 경우 IAM → 해당 기존 role → Add permissions → 전용 inline policy, Systems Manager → Parameter Store → Create parameter에서 위와 같은 값으로 구성한다. **같은 정책·parameter를 콘솔과 Terraform으로 중복 관리하지 않는다.**

## 4. 신규 업무 EC2에서 공식 DEB 설치·서명 검증

업무 EC2의 SSM 세션에서 수행한다. 아래 설치 구간은 새 세션에서 한 블록으로 실행한다. Agent가 이미 있으면 첫 검사에서 중단하며 기존 owner 절차로 돌아간다. 지역별 S3 endpoint만 허용하는 VPC에서는 해당 리전의 공식 패키지 bucket과 공개키 다운로드 경로를 허용하거나 승인된 내부 배포 저장소를 사용한다.

```bash
set -euo pipefail # 서명·다운로드·설치 오류가 있으면 이후 단계를 실행하지 않는다.
if sudo test -e /opt/aws/amazon-cloudwatch-agent; then echo '기존 Agent가 있으므로 원 소유자의 설정 통합 절차를 사용하세요.' >&2; exit 1; fi # 이미 설치된 Agent를 덮어쓰지 않는다.
. /etc/os-release # 업무 서버의 운영체제 정보를 읽는다.
test "$ID" = ubuntu && test "$VERSION_ID" = 24.04 && test "$(dpkg --print-architecture)" = amd64 # 예제의 OS와 CPU 아키텍처를 검증한다.
sudo apt-get update # Ubuntu 패키지 목록을 갱신한다.
sudo apt-get install -y ca-certificates curl gnupg # 공식 DEB 다운로드와 GPG 서명 검증 도구를 준비한다.
CWA_DOWNLOAD_DIR=$(mktemp -d) # 이 설치에서만 사용할 새 임시 디렉터리를 만든다.
chmod 700 "$CWA_DOWNLOAD_DIR" # 다른 로컬 사용자의 읽기·쓰기를 차단한다.
cd "$CWA_DOWNLOAD_DIR" # 이후 다운로드 파일의 상대 경로 기준이다.
curl --fail --silent --show-error --location https://amazoncloudwatch-agent.s3.amazonaws.com/assets/amazon-cloudwatch-agent.gpg -o agent-signing-key.gpg # AWS 공식 공개 서명키를 받는다.
curl --fail --silent --show-error --location https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb -o amazon-cloudwatch-agent.deb # Ubuntu amd64용 공식 DEB를 받는다.
curl --fail --silent --show-error --location https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb.sig -o amazon-cloudwatch-agent.deb.sig # 같은 경로의 서명 파일을 받는다.
mkdir -m 700 gpg-home # 사용자 기존 GPG keyring과 분리된 검증용 keyring을 만든다.
CWA_FINGERPRINT=$(gpg --homedir "$PWD/gpg-home" --show-keys --with-colons agent-signing-key.gpg | awk -F: '$1 == "fpr" {print $10; exit}') # 받은 공개키 fingerprint를 읽는다.
test "$CWA_FINGERPRINT" = 937616F3450B7D806CBD9725D58167303B789C72 # AWS 공식 문서의 fingerprint와 다르면 중단한다.
gpg --homedir "$PWD/gpg-home" --import agent-signing-key.gpg # 검증한 공개키만 임시 keyring에 등록한다.
gpg --homedir "$PWD/gpg-home" --verify amazon-cloudwatch-agent.deb.sig amazon-cloudwatch-agent.deb # DEB가 공식 키로 서명됐는지 검증한다.
sha256sum amazon-cloudwatch-agent.deb # 재현 기록에 남길 다운로드 파일의 SHA-256을 출력한다.
sudo dpkg -i -E ./amazon-cloudwatch-agent.deb # 서명 검증이 성공한 공식 패키지만 설치한다.
dpkg-query -W -f='${Package} ${Version}\n' amazon-cloudwatch-agent # 실제 설치 버전을 기록한다.
```

Agent 다운로드의 `latest`는 고정 버전이 아니다. 서명·설치 버전·SHA-256을 검증 결과에 남기고 반복 구축에서는 검증한 같은 DEB와 서명을 내부 저장소에서 사용한다. 패키지와 서명 사이에 배포가 갱신되어 검증에 실패하면 둘을 다시 받으며 검증을 생략하지 않는다. 신뢰 서명에 대한 GPG 경고와 `BAD signature`는 구분하되 fingerprint와 명령 성공을 모두 확인한다. [AWS 서명 검증·fingerprint](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/verify-CloudWatch-Agent-Package-Signature.html), [Ubuntu 수동 설치](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/manual-installation.html)

## 5. 검증 파일 준비와 설정 적용 — 같은 업무 EC2

이 단계는 바로 앞 단계에서 **새로 설치한 Agent**에만 적용한다. 이미 운영 중이던 서버는 원 소유자에게 변경된 JSON과 필요한 경로를 전달한다. 예제 Agent는 root로 실행하여 파일 읽기를 단순화한다. 이후 `cwagent` 사용자로 바꾸려면 파일의 읽기 권한과 모든 상위 디렉터리의 실행 권한, rotation 뒤 새 파일의 소유·권한을 함께 설정한다. [Agent 실행 사용자와 파일 권한](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-common-scenarios.html)

```bash
CWA_PARAMETER_NAME='whs-elk-ssm-workload-agent-config' # 원 소유 Terraform이 생성한 실제 parameter 이름으로 맞춘다.
sudo touch /var/log/elk-validation.log # 기존 내용은 지우지 않고 검증 파일이 없을 때만 만든다.
sudo chown root:root /var/log/elk-validation.log # 새 검증 파일의 소유권을 고정한다.
sudo chmod 0640 /var/log/elk-validation.log # root Agent가 읽고 다른 일반 사용자는 보지 못하게 한다.
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c "ssm:${CWA_PARAMETER_NAME}" # 지정 설정을 읽어 검증하고 신규 Agent를 시작한다.
sudo systemctl enable amazon-cloudwatch-agent # 재부팅 후에도 Agent가 시작되게 한다.
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a status # Agent 버전·구성/실행 상태를 확인한다.
sudo systemctl status amazon-cloudwatch-agent --no-pager # systemd 관점의 기동 상태를 확인한다.
sudo tail -n 80 /opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log # 파일·IAM·endpoint·configuration 오류를 확인한다.
```

선택한 앱 파일이 있다면 적용 전에 `sudo test -f /실제/앱로그`로 존재를 확인한다. 없는 앱 파일을 `touch`해서 성공한 것처럼 만들지 않는다. Agent가 보고하는 file-not-found와 실제 앱 로그 미발생을 구분한다. Parameter Store를 쓰는 Agent는 instance profile로 설정을 읽으며 정적 access key를 `common-config.toml`에 넣지 않는다. [SSM 기반 Agent 설정](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/installing-cloudwatch-agent-ssm.html)

## 6. 마지막으로 고유 이벤트를 대조

```bash
CWA_MARKER="ELK_VALIDATION_$(date -u +%Y%m%dT%H%M%SZ)" # 이번 시험의 검색 식별자를 만든다.
printf '%s\n' "$CWA_MARKER" | sudo tee -a /var/log/elk-validation.log # 수집 대상으로 지정한 검증 파일에 한 줄만 추가한다.
printf '%s\n' "$CWA_MARKER" # 결과표에 기록할 식별자를 확인한다.
```

CloudWatch 콘솔에서 정확한 출력 그룹과 `whs-elk-cloudwatch-{instance_id}-validation` stream을 찾아 이 문자열을 확인한다. `{instance_id}`는 Agent가 실제 인스턴스 ID로 치환한다. 앱 파일을 추가했다면 stream은 입력 순서에 따라 `whs-elk-cloudwatch-{instance_id}-app-1`, `...-app-2`가 된다. 이후 S3의 `cloudwatch/` 파일에서 `logEvents[].id`와 메시지를 대조하고 Kibana에서 검색한다. **Agent running, CWL 도착, Elasticsearch 색인 성공은 각각 별도 완료 기준**이다. 서버 로그 원본을 파괴하는 필터는 넣지 않는다. 검증 파일의 무한 증가를 막는 rotation은 실제 앱 운영 정책과 함께 추가한다.
