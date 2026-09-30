# scenario1 — SSRF → 자격증명 탈취 → S3 유출 → 랜섬

Capital One 2019(SSRF + IMDS 자격증명 탈취)와 Codefinger 2025(SSE-C 랜섬)를 이어붙인 시나리오.
**웹앱을 통해 클라우드로 넘어가는** 흐름을 다룬다.

## 단계

| # | MITRE | 하는 일 |
|---|---|---|
| 1 | T1190 | `/api/images/preview` SSRF 로 웹앱이 내부 주소를 대신 조회 |
| 2 | T1552.005 | IMDSv1 에서 EC2 역할의 임시 자격증명(ASIA…) 평문 획득 |
| 3 | T1580 | STS / S3 / IAM 리소스 열거 (`iam:*` 는 권한 경계가 Deny) |
| 4 | T1530·T1537 | `whs-data/` 의 파일 3개를 로컬로 유출 |
| 5 | — | `config.json` 탈취 = 장기 자격증명 확보로 간주, 이후 단계를 그 키로 전환 |
| 6 | T1562.008 | GuardDuty 비활성화 |
| 7 | T1486 | SSE-C 차단 해제 후 객체를 공격자 키로 재암호화 |

5단계부터 principal 이 `assumed-role/...` 에서 `user/WHS-Scenario-Persistence-User` 로
바뀐다. CloudTrail 에서 자격증명 전환이 그대로 보인다.

## 사전 조건

**공격**
- 웹앱 로그인 계정, `DATA_BUCKET`, `DATA_PREFIX`, `GUARDDUTY_DETECTOR_ID`
- `PERSIST_AWS_*` — 6·7 단계를 실행할 IAM User 키. S3 의 `config.json` 에는 가상의
  값만 들어 있고, 실제 호출에 쓰는 키는 `.env` 에서 읽는다.
- 대상 prefix 에 유출할 파일이 심겨 있을 것 (없으면 4단계가 조용히 0건으로 끝난다)

**복구** — `RESTORE_AWS_*` (공격용과 **다른** IAM User)
- 필요 권한: `s3:GetObject`/`PutObject`(대상 prefix), `s3:PutEncryptionConfiguration`,
  `guardduty:UpdateDetector`

## 실행

```bash
python scenario1.py             # 1~7 전부
python scenario1.py --restore   # 전부 되돌림
```

`--restore` 는 **웹앱을 건드리지 않는다.** SSRF·로그인 없이 AWS API 만 호출한다 —
복구는 공격이 아니므로 공격 트래픽을 로그에 덧칠하지 않는다.

한 번에 셋을 되돌린다:

```
1) 객체 평문화       recovery/ssec.key 로 복호
2) SSE-C 차단 복원   변경 전 설정으로 되돌림
3) GuardDuty 재활성화
```

객체 복구가 실패해도 GuardDuty 는 되살린다(`finally`). 탐지가 꺼진 채 남으면 안 되기 때문이다.

## 복구 자료 (`recovery/`, `.gitignore` 처리됨)

| 파일 | 내용 |
|---|---|
| `ssec.key` | 32바이트 SSE-C 키 — **이게 없으면 객체를 되돌릴 수 없다** |
| `ssec.key.b64` | 같은 키의 base64 (CLI 에 붙여쓰기용) |
| `ssec.key.meta.json` | 대상 버킷·prefix, 키 출처, 생성 시각, 복구 명령 |
| `encrypted_objects.json` | 실제로 암호화된 키 목록. 복구하면 비워진다 |
| `bucket_encryption_before.json` | SSE-C 차단을 풀기 전 설정. 복구하면 삭제된다 |
| `guardduty_before.json` | 끄기 전 detector 상태. 복구하면 삭제된다 |

키는 재암호화를 시작하기 **전에** 저장하고 되읽어 검증한다. 저장에 실패하면 한 객체도
건드리지 않는다. 버저닝이 꺼져 있어도 진행하지만 경고를 남긴다.

`--restore` 가 실패했을 때의 2차 수단:

1. **원본 재업로드** — 같은 파일이 `modules/s3-endpoint/dummy_data/` 와 구 버킷
   `cloud9-attack-target-a396cc5b` 에 있다. 가장 확실하다.
2. **버저닝 롤백** — 버저닝이 켜져 있을 때만 가능하다.

## 알아둘 것

**미복구 상태면 재실행이 막힌다.** 되돌리지 않은 채 또 돌리면 `ssec.key` 와
`guardduty_before.json` 을 덮어써서 원래대로 못 돌아가기 때문이다. 진입 시점에
중단하므로 웹앱에 요청이 나가지 않는다.

**SSE-C 차단 해제는 `["NONE"]` 으로만 된다.**

```python
"BlockedEncryptionTypes": {"EncryptionType": ["NONE"]}   # 동작
```

필드를 빼면 `PutBucketEncryption` 이 200 을 주고도 차단이 남고, 빈 목록은
`InvalidArgument` 로 거부된다. 차단이 남은 채로 SSE-C 를 쓰면 S3 가 `AccessDenied` 를
주는데 **권한 거부와 에러 코드가 같아서** 원인을 찾기 어렵다.
그래서 해제 후 되읽어 확인하고, 안 풀렸으면 암호화를 시작하지 않는다.

**유출 파일은 `exfiltrated/` 에 실제로 내려온다.** 실습 후 삭제할 것.
