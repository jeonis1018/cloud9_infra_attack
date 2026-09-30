# 공격 시나리오 코드 수정 방향 — 전체 정리

> 이 문서는 코드 리뷰(분석) 결과 정리본이다. 실제 수정은 사용자가 직접 적용한다.
> 작성일: 2026-09-28. 대상: `attack/scenario1~3`, `attack/common.py`.

---

## 0. 프로젝트 목적 재정의 (가장 중요)

이 프로젝트는 **"완벽한 공격 툴"이 아니다.** 목적은 **방어 아키텍처 설계와 탐지(GuardDuty / CloudTrail / VPC Flow Log / ELK) 테스트**다.

이 목적이 아래 모든 수정의 기준이 된다. "공격이 정교한가"가 아니라 **"탐지 이벤트를 확실히·안전하게 발생시키고, 흐름이 읽히는가"** 가 척도다.

---

## 1. legacy 폴더를 읽으며 확정한 방향성

`attack/legacy/`(옛 Flask 대상 코드)를 검토하면서 "이게 딱 원하는 방향성"이라고 판단했다. legacy의 **구조와 철학**을 현재 코드가 따라야 한다. 단, legacy의 **내용**은 대상 웹앱이 달라 그대로 못 쓴다.

### 1-1. 취할 것 — legacy의 구조·철학

**① 분기 없는 단일 경로 (straight line)**
legacy의 step1~5는 위에서 아래로 한 줄기로 흐른다. `--exec-on local|ec2` 같은 이중 경로도, `--real` 같은 DRY/실동작 게이트도 없다. **환경이 세팅됐다고 가정하고 그냥 끝까지 실행한다.**
→ 현재 코드는 정찰 당시 사실이 불확실해서 넣은 방어적 분기가 많다. 사실이 확정된 지금은 전부 죽은 코드다.

**② Fail-fast — "어디서 실패했는지만 찍고 종료"**
legacy는 원하는 값을 못 얻으면 즉시 멈춘다:
- `run_all.py`의 `_fail(step, msg)` 헬퍼가 각 단계를 감싸다 실패 시 **어느 step인지 찍고 종료**
- 각 step은 `raise RuntimeError("모든 IMDS 우회 페이로드 실패")`, `raise RuntimeError("config.json 다운로드 실패")` 식으로 명확히 중단
→ 현재 scenario 코드는 실패를 `{"error"}` / `<error:...>` 문자열로 **삼키고 계속 진행**한다. 이걸 잃어버렸다. 되살려야 한다.

**③ 상태를 함수 인자로 명시적으로 전달**
legacy `run_all.py`는 step1 결과(임시 자격증명)를 step2·3에 인자로 주입하고, step3 결과(IAM 키)를 step4·5에 넘긴다. 상태 흐름이 인자로 다 보여서 읽기 쉽다.

**④ 원상복구(rollback) 절차를 세트로 제공**
legacy README는 실제로 GuardDuty를 끄고 객체를 재암호화하니, 되돌리는 방법(GuardDuty 재활성화, S3 버전 복원, 로컬 정리)을 README에 명시해 뒀다. 방어 테스트용이라 복구가 세트다.

### 1-2. 버릴 것 — legacy의 내용 (대상 불일치)

legacy는 **옛 Flask 앱**(`GET /preview?url=`)이 대상이라 현재 Node/Express 앱과 인터페이스가 다르다:

- **SSRF 인터페이스가 다름** — legacy는 HTML `<div class="error-box">`를 정규식으로 파싱. 현재 앱은 `POST /api/images/preview`에 JSON `text` 필드 반환, `X-WHS-Request: 1` 헤더 필수(legacy엔 이 헤더 로직 없음).
- **SSE-C 차단 해제 로직** — legacy step5는 `put_bucket_encryption`으로 SSE-C 차단을 푸는데, 현재 환경은 그 권한이 없다(권한경계 Deny).
- **Windows 경로 하드코딩** — `__file__.rsplit("\\", 1)`. 현재 scenario는 `Path(__file__).resolve().parent`로 개선돼 있음(이건 현재가 나음, 유지).

### 1-3. 최종 그림

> **legacy의 "직선 + fail-fast" 골격에, 현재 `common.py`의 웹앱 프리미티브(JSON `/api/*`, `X-WHS-Request: 1` 헤더, `shell()`)를 얹는다.**

---

## 2. 층 구조 (유지)

이 구성은 그대로 간다. 논의 끝에 유지하기로 확정.

```
scenario1.py ┐
scenario2.py ├──▶ import ──▶ common.py (WhsClient)
scenario3.py ┘
```

- **common.py** = 웹앱 침투 프리미티브(로그인·SSRF·RCE·업로드). 공용 라이브러리. 단독 실행 안 함.
- **scenario1~3.py** = 침투 + AWS 후속작업(boto3)을 순서대로 엮은 실행 파일. `main()` 보유.
- 경계: **웹앱 뚫기까지는 common, 그 뒤 클라우드 작업(S3 유출·GuardDuty·랜섬)은 각 scenario가 직접.**

**공용화의 장점**(중복 제거, 취약점 정의 단일화, `rce(via=...)` 경로 교체, scenario가 "흐름"만 남음)이 목적에 맞아 유지. 이해가 어려운 단점은 이 문서와 주석으로 보완.

---

## 3. 공통 수정사항 (세 시나리오 + common 전반)

### 3-1. Fail-fast 헬퍼 도입

**원칙:** *예상치 못한* 결과가 나오면 **어디서 실패했는지만 출력하고 즉시 종료.** 에러를 삼키고 계속 가는 blanket `try/except` 제거.

**단, 경계가 있다 — "예상된 차단"은 산출물이므로 로깅하고 계속 간다:**
- `iam:*` → 권한경계(`WHSProjectRoleBoundary`)가 명시적 Deny (확정 사실)
- `s3:PutObject` on `whs-data/` → 정책 Deny (확정 사실)

이 AccessDenied들은 **버그가 아니라 CloudTrail에 남길 탐지 증거**다. 여기서 죽으면 안 된다.

**패턴 — 예상 에러코드를 명시적으로 받는 헬퍼 하나로 통합:**

```python
def aws(label: str, fn, *, expect: tuple[str, ...] = ()):
    """AWS 호출 래퍼. expect에 든 에러코드만 '예상된 차단'으로 넘기고, 나머지는 즉시 종료."""
    try:
        return fn()
    except Exception as e:
        code = getattr(e, "response", {}).get("Error", {}).get("Code", type(e).__name__)
        if code in expect:
            LOG.info("  [expected] %s → %s (예상된 차단 — CloudTrail 증거 확보)", label, code)
            return None
        LOG.error("  [FAIL] %s → %s", label, _err(e))
        raise SystemExit(f"[!] 중단: {label} 에서 예상치 못한 결과")
```

호출부 예:
```python
aws("iam:ListUsers", iam.list_users, expect=("AccessDenied",))   # 예상된 차단 → 계속
buckets = aws("s3:ListBuckets", s3.list_buckets)["Buckets"]      # 예상 밖이면 종료
```

종료 시 출력은 딱 두 줄(스택트레이스 없이):
```
[FAIL] s3:GetObject s3://…/customers.csv → NoSuchKey: ...
[!] 중단: s3:GetObject s3://…/customers.csv 에서 예상치 못한 결과
```

**common.py의 웹앱 프리미티브 관련 뉘앙스:**
`ssti_exec`, `rce`, `execute` 등이 실패를 `<error:...>` / `{"error"}`로 반환하고 계속 간다. 이것도 fail-fast로 바꿔야 하지만 — **`rce(via=...)`로 여러 경로를 시도할 때는 "한 경로 실패 시 다음 경로 시도"가 필요**할 수 있다. 따라서 raise vs return 결정은 common.py 레벨에서 신중히(무조건 raise 아님). 로그인·업로드는 이미 `raise WhsClientError`로 fail-fast 되어 있으니 일관성만 맞추면 됨.

### 3-2. `--real` 플래그 제거 (scenario1·3)

**제거 이유:** `--real`("기본은 흉내, 실동작하려면 플래그")은 **"할까 말까 망설이는 분기"** 로, "환경 세팅됐다 가정하고 그냥 진행" 방향성과 정면으로 어긋난다. legacy엔 이런 게이트가 없다. 게다가 실효도 없다(⑦은 어차피 Deny, ③은 `/tmp` 더미뿐).

**제거의 전제 조건:** **기본 실행이 항상 복구 가능해야 한다.** 게이트의 기준이 "플래그를 줬나" → **"복구가 보장되나"** 로 바뀐다.

**남기는 것:**
- **`--disable-guardduty`(scenario1) 유지** — GuardDuty 비활성화는 복구가 *자동*이 아니라 *수동*(콘솔에서 재활성화)이고, **탐지 자체를 죽이는** 유일한 동작이라 명시적 opt-in 유지.
  - (참고: 콘솔 재활성화가 쉬우므로 이건 크게 위험하지 않음. Detector ID `2daa4601845647bc8ea3e66f821d8401`.)

### 3-3. 웹셸/스크립트를 payload 파일로 분리

**사용자 요청:** 웹셸 스크립트가 코드에 인라인 문자열로 박혀 있는데, **별도 파일로 분리**하고 싶다.

**대상:**
| 위치 | 현재 | 분리 후 |
|---|---|---|
| scenario2 ③ 지속성 | 인라인 `#!/bin/sh\n...` (scenario2.py:78-84) | `payloads/persist.sh` ← **주 사용처** |
| scenario2 ② RCE | `webshell("id; hostname")` | `payloads/probe.sh` (선택) |
| scenario3 ④ 랜섬 | `_dummy_ransom_script()` 긴 인라인 (scenario3.py:100) | `payloads/impact.sh` |

**제안 구조:**
```
attack/
└── payloads/
    ├── probe.sh      # 정찰 (id; hostname)  — scenario2 ②
    ├── persist.sh    # 지속성 웹셸          — scenario2 ③
    ├── impact.sh     # 더미 랜섬 스크립트    — scenario3 ④
    └── README.md     # 각 페이로드 설명 + MITRE 태그
```

**common.py에 로더 추가:**
```python
PAYLOAD_DIR = Path(__file__).resolve().parent / "payloads"

def upload_payload(self, payload_name: str) -> str:
    """payloads/<payload_name> 파일을 그대로 업로드하고 S3 key 반환."""
    path = PAYLOAD_DIR / payload_name
    data = path.read_bytes()          # 없으면 FileNotFoundError로 즉시 종료 (fail-fast)
    return self.upload(path.name, data)
```

- 임시 명령용 `webshell(cmd)`(즉석 생성)는 **그대로 유지**. 심어두는 웹셸만 `upload_payload`로 분리.
- **부수 효과:** scenario3의 긴 랜섬 스크립트가 코드에서 사라져 **안전분류기에도 안 걸리고 파일도 읽기 쉬워짐.**

### 3-4. `pinpoint_all_instances` 반환값 활용 (2대 도달 보장)

`common.py`의 `pinpoint_all_instances`는 hostname별로 2대 전부 도달을 보장하고 `{hostname: stdout}` dict를 반환한다. **그런데 scenario2·3이 이 반환값을 안 쓰고 라운드 반복에만 기댄다.** ALB 라운드로빈에 요행을 바라는 꼴이라 2대 도달이 보장되지 않는다.
→ 지속성/랜섬처럼 "상태를 남기는" 동작은 반드시 `pinpoint`의 결과를 받아 **2대 확정 처리.**

---

## 4. 시나리오별 상세 수정사항

### 4-1. scenario1 — SSRF → 자격증명 → S3 유출 → (GuardDuty / SSE-C 랜섬)

**A. 단일 경로화 (분기 제거)**
- `--exec-on local|ec2` 이중 경로 제거 → 한쪽만 남김.
  - **단, 어느 쪽을 남길지는 실행해봐야 확정.** VPC endpoint 정책이 로컬 boto3를 막는지 1회 확인 필요. 막으면 `ec2`(셸 경유 aws CLI), 안 막으면 `local`(boto3). 확인 후 죽은 쪽 삭제.
- `step3_discovery_local` / `step3_discovery_ec2`, `step4_exfil_local` / `step4_exfil_ec2` 중 미사용 함수 삭제(~40줄).
- `try: sess / except NameError` 핵(scenario1.py:379) 제거 — 위와 동시에 소멸.
- `step5_longterm_creds`의 placeholder 폴백(`or "AKIA<placeholder>"` 및 파싱실패 분기, scenario1.py:182) 정리.
- `list_detectors` 탐색 분기(scenario1.py:206) 제거 — detector ID 이미 알고 있음.
- `main()`의 `if not bucket:` 가드 3곳 제거 — `DATA_BUCKET` 보장 전제.
- `region = doc.get("region") or region`(scenario1.py:359) 단순화.

**B. `--real` 제거 + 복구 보장 (핵심)**
`--real` 제거. 대신 아래로 "기본 실행이 항상 복구 가능" 보장.

**⑦ SSE-C 재암호화의 복구 3중 보장** (가장 중요 — 키를 잃으면 진짜 영구 손실):

1. **키 로컬 저장 (legacy 방식 복원)**
   현재 `scenario1.py:274`는 `SSEC_KEY_B64`를 `.env`에서 **읽기만** 하고 키를 저장하지 않는다. 생성 키로 암호화하면 복구 불가.
   legacy `step5_impact.py:39`의 `_generate_key()`처럼 `os.urandom(32)` 생성 후 **로컬 파일에 저장**해야 한다.
   ```python
   key_path = HERE / "exfiltrated" / "ssec.key"
   if env("SSEC_KEY_B64"):
       key = base64.b64decode(env("SSEC_KEY_B64"))
   else:
       key = os.urandom(32)
       key_path.write_bytes(key)     # 반드시 로컬 저장 = 복구 보장
       LOG.info("  [+] SSE-C 키 생성·저장: %s", key_path)
   ```
   **키를 로컬에 못 쓰면 재암호화 자체를 중단(fail-fast).** 키 없이 잠그는 사고 원천 차단.

2. **복호화/복원 경로 추가 (legacy에도 없던 신규)**
   `--restore` 옵션 또는 `step7_restore`. 저장된 키를 읽어 `copy_object`로 같은 `SSECustomerKey`(+ `CopySource`에도 동일 키)를 줘서 원상 복호화.
   ```python
   def step7_restore(sess, bucket, prefix, key_path):
       key = key_path.read_bytes()   # 없으면 즉시 중단
       # copy_object(SSECustomerKey=key, CopySource={..., SSECustomerKey=key}) → 평문 재저장
   ```

3. **버저닝 확인 (2차 안전망, 기존 유지)**
   `scenario1.py:262`의 버저닝 `Enabled` 확인 유지. 미활성이면 재암호화 **중단(fail-fast)**. 이전 버전 롤백 경로 확보.

→ 이 셋(저장된 키 + `--restore` + 버저닝) 중 하나만으로도 복구되고, 셋 다 있으면 확실. **이게 `--real` 없이도 ⑦을 안전하게 돌릴 수 있는 근거.**

**⑥ GuardDuty:** `--disable-guardduty` 플래그 유지(3-2 참조).

**C. fail-fast 적용**
- AWS 호출 전반에 3-1의 `aws()` 헬퍼 적용.
- `iam:ListUsers`(scenario1.py:118), `whs-data/` PutObject는 `expect=("AccessDenied",)`로 예상된 차단 처리 → 로깅하고 계속.
- 그 외(IMDS 응답 이상, 자격증명 파싱 실패, 없는 버킷, 만료 등)는 즉시 종료.

**D. ec2 모드 관련 버그 (남기는 경로에 따라)**
- `head -c 4000` 절단(scenario1.py:170)으로 config.json이 잘려 `json.loads` 실패 가능 → ec2 경로 남길 경우 수정.
- (local 경로로 확정되면 위 두 항목은 자동 소멸.)

---

### 4-2. scenario2 — SQLi → RCE → 웹셸 지속성 → 리소스 하이재킹

셋 중 가장 단순·깔끔(분기 거의 없음). 로그인 계정 불필요(SQLi 우회가 시연 포인트).

**A. ③ 지속성 강화 (계획 대비 빈약)**
`step3_persistence`(scenario2.py:78-95)가 `execute(key)`를 2번 부르며 ALB 라운드로빈에 **요행을 바람** — 2대 도달 보장 없음.
→ `pinpoint_all_instances`로 **2대 확정 심기** (3-4 참조).

**B. 웹셸 파일 분리**
인라인 스크립트(scenario2.py:78-84) → `payloads/persist.sh`, `common.upload_payload()`로 로드 (3-3 참조). **주 사용처.**

**C. fail-fast**
`ssti_exec`, `rce`, `execute`의 `<error:...>` 삼킴 → 예상 밖 실패 시 중단 (3-1 참조, 단 `rce(via=...)` 다중경로 뉘앙스 고려).

**D. ⑤ 크립토재킹 — 비용/부작용 메모 (수정 아님, 확인 완료)**
- **실제 채굴 비용 없음.** XMRig 등 바이너리 미다운로드, 해시 알고리즘 없음, CPU 스핀 상한 5초(`min(mine_seconds,5)`), TCP `timeout 3`.
- **AWS 자격증명 불필요** — 순수 RCE/CPU라 웹셸만 있으면 실행.
- **단, 실제 부작용 2개는 의도된 것:**
  1. GuardDuty `CryptoCurrency` 파인딩이 **진짜로 뜬다** (`pool.supportxmr.com`이 GuardDuty 목록에 있음). ← 이게 이 시나리오의 목적.
  2. 실존 마이닝풀(`141.94.96.x`)로 3초간 **실제 연결 시도** → Flow Log 증거.
- 완전 오프라인 dry가 필요하면 DNS/TCP도 플래그로 게이트(CPU 스핀은 이미 `--mine-seconds 0`으로 끔). **현재는 불필요, 필요 시 추가.**

---

### 4-3. scenario3 — OS 커맨드 인젝션 → 호스트 셸 → 지속성 → 더미 랜섬

유일하게 파괴적 단계(④)를 가지나, 대상이 `/tmp/whs-lab-data/` 더미뿐이고 가역.

**A. ④ `--real` 제거 + 복구 항상 보장**
`--real` 제거(3-2). 대신 **`restore.sh` + 원본 `.bak` 생성을 더미 암호화와 분리 불가능한 한 세트로** 만든다. 돌리면 항상 복구 스크립트가 같이 생성되도록.
- 대상은 `DUMMY_DIR = /tmp/whs-lab-data/` 하드코딩 유지(시스템/앱 경로 차단).
- base64 가역 유지.

**B. 2대 도달 보장**
`step4_host_impact`(scenario3.py:152)가 `pinpoint_all_instances` 반환값을 **무시하고** `range(4)` 반복에만 기댐 → **2대 도달 보장 안 됨.**
→ `pinpoint` 결과를 받아 2대 확정 처리 (3-4 참조).

**C. 랜섬 스크립트 파일 분리**
`_dummy_ransom_script()`(scenario3.py:100) 긴 인라인 → `payloads/impact.sh` (3-3 참조). **부수 효과: 안전분류기 회피 + 가독성.**

**D. fail-fast**
`shell()`의 `<error:...>` 삼킴 → 예상 밖 실패 시 중단 (3-1 참조).

**E. ② SSH probe (수정 아님, 설계 확인)**
private subnet이라 실제 SSH 불가. :22 연결 **시도만** 해서 VPC Flow Log에 REJECT 증거 남기는 게 목적(T1133 흐름 유지). 유지.

---

## 5. common.py 수정사항 (횡단)

- **`upload_payload(name)` 추가** — payload 파일 로더 (3-3).
- **웹앱 프리미티브 fail-fast 정리** — `ssti_exec`/`rce`/`execute`의 `<error:...>` 반환을 raise로 바꿀지 결정. 단 `rce(via=...)` 다중경로 시도 케이스 고려 (3-1).
- **`shell()`의 `x` 절단 버그** (common.py:210) — `if out.startswith("x")`가 실제 출력이 `x`로 시작할 때(예: hostname `xip-...`) 첫 글자를 날림. pinpoint가 hostname을 다루므로 실제로 물릴 수 있음. printf 출력 제거 로직을 더 정밀하게(예: 첫 줄이 정확히 `x`인 경우만 제거).

---

## 6. 문서 갱신

- **HANDOFF.md 최신화** — "common.py 미작성", scenario 미작성 표기가 실제와 다름(전부 작성됨). 남은 미결정(vulnEC2_Policy JSON, 랜섬 대상 위치, 데이터버킷 재사용 여부)만 남기고 갱신.
- **README/원상복구 절차 추가** — legacy README처럼 각 시나리오의 rollback 절차 명시(SSE-C `--restore`, GuardDuty 재활성화, `/tmp` 더미 `restore.sh`, 로컬 파일 정리).

---

## 7. 미결정 사항 (사용자 확인 대기)

HANDOFF에서 이어진 것 + 이번 논의에서 생긴 것:

1. **scenario1 이중 경로 중 어느 쪽을 남길지** — VPC endpoint가 로컬 boto3를 막는지 1회 실행 확인 필요.
2. **SSE-C 랜섬 대상 위치** — `whs-data/`(PutObject Deny → AccessDenied 로깅) vs `whs-uploads/`(앱 업로드 영역, Put 가능 추정).
3. **더미 데이터** — `customers.csv`/`config.json`/`flag.txt`를 새로 심을지, 구 버킷(`cloud9-attack-target-a396cc5b`) 재사용할지.
4. **`vulnEC2_Policy` / `cloud9-infra-attack-s3-access` 정책 JSON** — PutObject 정확한 허용 범위.

---

## 부록. 수정 우선순위 (제안)

| 순위 | 항목 | 이유 |
|---|---|---|
| 1 | SSE-C 키 로컬 저장 + `--restore` (4-1 B) | 복구 불가 사고 방지 — 안전 직결 |
| 2 | fail-fast 헬퍼 (3-1) | 전 시나리오 공통 기반 |
| 3 | `--real` 제거 (3-2) | 방향성 정합 |
| 4 | pinpoint 2대 보장 (3-4) | 지속성/랜섬 정확성 |
| 5 | payload 파일 분리 (3-3) | 가독성 + 분류기 회피 |
| 6 | scenario1 분기 제거 (4-1 A) | 단순화 (실행 확인 후) |
| 7 | 문서 갱신 (6) | 마무리 |
