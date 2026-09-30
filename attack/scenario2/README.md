# scenario2 — SQLi → RCE → 웹셸 지속성 → 리소스 하이재킹

비밀번호 없이 들어가서 코드 실행 경로를 확보하고, S3 에 상주하는 웹셸로 지속성을
만든 뒤 마이닝풀에 붙는다. **웹앱 레이어 안에서 완결되는** 시나리오다.

## 단계

| # | MITRE | 하는 일 |
|---|---|---|
| 1 | T1190 | `' OR '1'='1' -- ` 로 인증 우회 (비밀번호 불필요) |
| 2 | T1059 | EJS SSTI + 업로드→실행, **두 경로로** 코드 실행 |
| 3 | T1505.003 | S3 에 남는 업로드 파일을 재호출하는 stateless 웹셸 |
| 4 | T1552.005 | 웹셸 셸에서 IMDS 질의 — scenario1 로 피벗 가능함을 확인 |
| 5 | T1496 | 마이닝풀 DNS 해석 + TCP 연결 + 짧은 CPU 스핀 |

2단계에서 경로가 **두 개**라는 게 포인트다. 하나를 패치해도 다른 쪽으로 들어온다.

## 사전 조건

**공격** — `WEBAPP_URL` 정도면 된다. **로그인 계정이 필요 없다**(SQLi 로 들어간다).
`users` 테이블에 행이 1개 이상 있어야 한다(`LIMIT 1` 이 첫 행을 집는다).

**복구** — `UPLOAD_BUCKET`, `RESTORE_AWS_*` (`s3:DeleteObject` 권한)

## 실행

```bash
python scenario2.py             # 1~5 전부
python scenario2.py --restore   # S3 업로드 객체 삭제
```

| 플래그 | 설명 |
|---|---|
| `--via os\|ssti\|upload` | 4·5단계의 RCE 경로 (기본 `ssti`) |
| `--mine-seconds N` | 5단계 CPU 스핀 시간, 상한 5초. `0` 이면 생략 |

## 남는 것과 복구

**호스트는 건드리지 않는다.** 남는 건 S3 업로드 객체뿐이고, 그게 곧 웹셸이라 반드시 지운다.

```bash
python scenario2.py --restore
```

`recovery/uploaded_objects.json` 에 올린 key 가 전부 들어 있다. 업로드할 때마다
갱신되고 이전 실행 기록을 이어받으므로, 중간에 실패해도 목록은 남는다.

삭제는 공격 경로로는 불가능하다 — EC2 역할에도 공격용 장기키에도 `s3:DeleteObject`
가 없다. 그래서 `RESTORE_AWS_*` (운영자 계정)로 지운다. 공격자는 웹셸을 심을 수만
있고 지울 수는 없다는 게 정확한 그림이기도 하다.

> `--via upload` 로 돌리면 **명령마다 임시 `runner.sh` 가 추가로 올라간다.**
> 기본값(`--via ssti`)은 2·3단계 payload 외에 아무것도 남기지 않는다.

지우지 않은 객체가 있으면 **다음 실행이 막힌다.** 웹셸이 겹겹이 쌓여 어느 것이 어느
실행 것인지 구분이 안 되는 상황을 방지한다.

## 알아둘 것

**SSTI 가젯이 일반적인 것과 다르다.** 대상 앱이 ESM 이라 `require` 와
`process.mainModule` 이 둘 다 `undefined` 다. 흔히 쓰는
`mainModule.require('child_process')` 는 통하지 않고, `process.binding('spawn_sync')`
를 쓴다.

**5단계는 실제로 채굴하지 않는다.** 바이너리를 내려받지 않고, DNS 해석과 TCP 연결
수립 후 즉시 종료한다. 데이터를 보낼 경로 자체가 없다. 그래도 GuardDuty
`CryptoCurrency:EC2/BitcoinTool.B` 와 `!DNS` 두 종류 파인딩이 **실제로 발생한다** —
의도된 산출물이므로 탐지 확인 후 archive 처리한다.

보고서에는 "마이닝 풀 연결 시도" 또는 "TCP 연결 수립 후 즉시 종료"로 적는 게 정확하다.

**`--via os` 는 5단계 CPU 스핀이 깨진다.** 스핀 명령이 `$end` / `$c` 셸 변수를 쓰는데,
os-command 경로는 페이로드가 서버쪽 큰따옴표 안에 들어가 바깥 셸이 `$변수` 를 먼저
비워버린다. 기본값 `ssti` 로는 정상이다.
