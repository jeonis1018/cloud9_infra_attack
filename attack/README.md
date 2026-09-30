# attack/ — 공격 시나리오 도구

WHS-Cloud9-Vuln-Web(팀이 세운 취약 웹앱, https://whs4namu.click) 대상 공격 재현 도구.

목적은 완벽한 공격 툴이 아니라 **방어 아키텍처와 탐지(GuardDuty / CloudTrail /
VPC Flow Log / WAF / ELK) 테스트**다. 척도는 "공격이 정교한가"가 아니라
"탐지 이벤트를 확실히·안전하게 발생시키고 흐름이 읽히는가"다.

## 구조

```
attack/
├── common.py       웹앱 침투 프리미티브(WhsClient) + AWS fail-fast 래퍼 + 복구자료 관리
├── payloads/       업로드해서 실행하는 스크립트 (MITRE 매핑은 payloads/README.md)
├── scenario1/      SSRF → 자격증명 탈취 → S3 유출 → GuardDuty 무력화 → SSE-C 랜섬
├── scenario2/      SQLi → RCE → 웹셸 지속성 → 리소스 하이재킹
├── scenario3/      OS 커맨드 인젝션 → 호스트 셸 → 지속성 → 파일 변형
└── legacy/         옛 Flask 대상 코드 (참고용 보존, 실행하지 않음)
```

경계: **웹앱을 뚫는 데까지는 `common.py`, 그 뒤 클라우드·호스트 작업은 각 시나리오가 직접.**

## 실행

각 시나리오 디렉터리에서 `.env` 를 만들고 값을 채운 뒤 실행한다.

```bash
cd scenario1 && cp .env.example .env
python scenario1.py             # 공격
python scenario1.py --restore   # 복구
```

셋 다 같은 모양이고 순서는 상관없다. 각 시나리오가 자기가 바꾼 것만 되돌린다.

| 시나리오 | 남기는 것 | 상세 |
|---|---|---|
| 1 | S3 객체 암호화, 버킷 SSE-C 차단 해제, GuardDuty OFF | [scenario1/README.md](scenario1/README.md) |
| 2 | S3 업로드 객체(웹셸) | [scenario2/README.md](scenario2/README.md) |
| 3 | 호스트 파일 변형, bashrc 마커, S3 업로드 객체 | [scenario3/README.md](scenario3/README.md) |

## `.env` 는 공격/복구로 나뉜다

각 `.env.example` 이 두 블록으로 갈려 있다.

- **공격** — 웹앱 로그인, 대상 버킷, 탈취당한 것으로 치는 `PERSIST_AWS_*` 등
- **복구 전용** — `RESTORE_AWS_*`. **공격 단계는 이 키를 절대 쓰지 않는다.**

복구는 공격자가 아니라 실습 운영자의 일이라 **다른 IAM User** 를 쓴다.
CloudTrail 에서도 공격 행위와 뒷정리가 다른 principal 로 구분된다.

## 복구하지 않으면 다시 실행되지 않는다

이전 실행을 되돌리지 않은 채 또 돌리면 복구 자료(SSE-C 키, GuardDuty 이전 상태 등)를
덮어써서 원래대로 못 돌아간다. 그래서 진입 시점에 막는다.

```
[!] 이전 실행이 아직 복구되지 않았다:
      - SSE-C 로 잠긴 S3 객체가 남아 있다  (recovery/encrypted_objects.json)
    먼저 복구를 끝내고 다시 실행할 것:  python scenario1.py --restore
```

웹앱에 요청 한 번 보내기 전에 중단하므로, 실수로 두 번 돌려도 상태가 나빠지지 않는다.

## 설계 원칙

- **직선 실행** — 환경이 세팅됐다고 가정하고 분기 없이 끝까지 간다.
- **fail-fast** — 예상 밖 결과는 삼키지 않고 어디서 멈췄는지만 남기고 종료한다.
- **예상된 차단은 산출물** — 정책 Deny 는 버그가 아니라 CloudTrail 증거다.
  `aws(..., expect=(DENY,))` 로 명시해 통과시킨다.
- **복구 자료는 동작 전에 저장** — 상태를 바꾸기 전에 키·대상목록을 `recovery/` 에
  쓰고 되읽어 검증한다. 저장에 실패하면 한 객체도 건드리지 않는다.
- **단일 대상 고정** — scenario2/3 은 로그인 직후 인스턴스 1대를 잡고 모든 단계를
  그 한 대에서만 실행한다. ALB 가 라운드로빈이라 단계마다 따로 요청하면 흔적이
  양쪽에 흩어진다. 대상이 아니면 셸 가드가 아무것도 실행하지 않고 빠진다.

## 로컬 정리 체크리스트

- [ ] `scenario*/recovery/` — **복구 완료를 확인한 뒤에만** 삭제 (키를 먼저 지우면 복구 불가)
- [ ] `scenario1/exfiltrated/` — 유출 데이터 삭제
- [ ] `scenario*/*.log` — 보고서용으로 보관하거나 삭제
- [ ] `scenario*/.env` — 커밋되지 않았는지 확인 (`.gitignore` 처리됨)
