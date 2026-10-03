# scenario2 — SQLi → RCE → 웹셸 지속성 → 리소스 하이재킹 → 외부 송신

비밀번호 없이 들어가서 코드 실행 경로를 확보하고, S3 에 상주하는 웹셸로 지속성을
만든 뒤 마이닝풀에 붙는다. 1~5 는 **웹앱 레이어 안에서 완결되고**, 6·7 은
호스트에서 외부로 나가는 통제(DNS Firewall·egress)를 검증한다.

## 단계

| # | MITRE | 하는 일 |
|---|---|---|
| 1 | T1190 | `' OR '1'='1' -- ` 로 인증 우회 (비밀번호 불필요) |
| 2 | T1059 | EJS SSTI + 업로드→실행, **두 경로로** 코드 실행 |
| 3 | T1505.003 | S3 에 남는 업로드 파일을 재호출하는 stateless 웹셸 |
| 4 | T1552.005 | 웹셸 셸에서 IMDS 질의 — scenario1 로 피벗 가능함을 확인 |
| 5 | T1496 | 마이닝풀 DNS 해석 + TCP 연결 + 짧은 CPU 스핀 |
| 6 | — | DNS 송신 통제(Resolver DNS Firewall) 동작 확인 — 질의 1회 |
| 7 | T1041 | 더미 파일 1개를 수신 서버로 전송 — 데이터가 실제로 나가는지 |

2단계에서 경로가 **두 개**라는 게 포인트다. 하나를 패치해도 다른 쪽으로 들어온다.

6·7 은 짝이다. 6 이 "이름 해석이 되는가", 7 이 "데이터가 나가는가"를 본다.
DNS Firewall 이 BLOCK 이면 이름을 못 찾아 둘 다 실패한다 — 그게 의도된 결과다.

## 사전 조건

**공격 (1~5)** — `WEBAPP_URL` 정도면 된다. **로그인 계정이 필요 없다**(SQLi 로 들어간다).
`users` 테이블에 행이 1개 이상 있어야 한다(`LIMIT 1` 이 첫 행을 집는다).

**6단계** — `DNS_PROBE_DOMAIN`. 내 소유 도메인이어야 하고, DNS Firewall 도메인 목록에
등록한 이름을 넣는다. 비우면 건너뛴다.

**7단계** — `C2_URL`(스킴 포함), `C2_SRC_FILE`. 수신 서버가 떠 있어야 하고,
대상 파일이 `/opt/whs-lab-data/` 아래에 있어야 한다. 비우면 건너뛴다.
수신 서버는 `tools/upload-server/` 참고.

**복구** — `UPLOAD_BUCKET`, `RESTORE_AWS_*` (`s3:DeleteObject` 권한)

## 실행

```bash
python scenario2.py             # 1~7 전부 (6·7 은 .env 미설정 시 자동 생략)
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

**`--restore` 는 수신 서버의 파일을 지우지 않는다.** 7단계로 보낸 더미가 그쪽에
그대로 쌓이므로 실습 후 직접 비운다.

```bash
sudo rm -f /srv/incoming/*
```

## 6단계 — DNS 송신 통제 검증

`DNS_PROBE_DOMAIN` 에 넣은 이름을 대상 호스트에서 **한 번 조회하고 결과만 찍는다.**
데이터를 보내지 않고 호스트 상태도 바꾸지 않는다. 비워두면 건너뛴다.

DNS Firewall 은 이름 해석 단계에서만 동작하므로 질의 한 번으로 판정이 끝난다.

같은 코드를 설정만 바꿔 세 번 돌리는 것이 용도다.

| 설정 | 프로브 결과 | 쿼리 로그 |
|---|---|---|
| 규칙 없음 | `RESOLVE OK` | `firewall_rule_action` 없음 |
| ALERT | `RESOLVE OK` | `ALERT` |
| BLOCK | `RESOLVE FAILED` | `BLOCK` |

**코드는 그대로 두고 방어 설정만 바꿔서 결과가 뒤집히는 것**이 보여주려는 바다.

판정은 CloudWatch Logs Insights 에서 한다. Resolver 쿼리 로깅이 먼저 켜져 있어야 한다.

```
fields @timestamp, srcaddr, query_name, firewall_rule_action
| filter ispresent(firewall_rule_action)
| sort @timestamp desc | limit 20
```

`srcaddr` 이 대상 인스턴스의 사설 IP 로 찍히는 것이 "VPC 안에서 나간 질의"의 증거다.
프로브가 리졸버 주소도 같이 출력하므로, VPC 리졸버(`.2`)가 아닌 경우 로그에 경고가 남는다.

## 7단계 — 데이터 송신 확인

`C2_SRC_FILE` 하나를 `C2_URL` 로 POST 하고 결과만 찍는다. 파일을 읽기만 하므로
호스트 상태는 바뀌지 않는다.

| 설정 | 7단계 결과 |
|---|---|
| 규칙 없음 / ALERT | `HTTP 200` — 전송 성공 |
| BLOCK | `HTTP 000` — 이름 해석 실패로 전송 불가 |

**ALERT 단계가 핵심이다.** 탐지는 됐는데 데이터는 나갔다는 상태를 한 화면에서 보여준다.

송신 경로는 페이로드가 `/opt/whs-lab-data/` 로 제한한다. 다른 경로를 주면 `REFUSED`
로 거부하고 시나리오가 중단된다. 대상 파일이 없으면 `NO_SRC` 경고만 남기고 계속한다
(인스턴스가 교체되면 더미가 사라지므로 흔한 상황이다).

실행 기록은 `recovery/c2_egress.json` 에 남는다. `run_id` 가 수신 서버 접근 로그에도
같이 찍히므로, 공격 측과 수신 측 로그를 그 값으로 연결할 수 있다.

```
공격 측  scenario2.log   run_id=58e4312e0a1a  HTTP 200
수신 측  upload-server   POST /upload?name=orders.csv&run=58e4312e0a1a -> 200
                         출발지 = 랩 VPC NAT 주소
```

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
