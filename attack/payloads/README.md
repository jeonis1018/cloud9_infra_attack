# payloads/ — 시나리오가 업로드·실행하는 스크립트

시나리오 코드에 인라인 문자열로 박혀 있던 스크립트를 파일로 분리한 것이다.

**분리 이유**
- 시나리오 파일에는 *흐름*만 남고, 스크립트 내용은 여기서 한눈에 검토된다.
- 각 페이로드의 대상·가역성·MITRE 기법을 이 문서에서 함께 관리한다.
- 같은 페이로드를 여러 시나리오/RCE 경로(os·ssti·upload)에서 재사용할 수 있다.

## 목록

| 파일 | 사용처 | MITRE | 상태 변경 | 가역성 |
|---|---|---|---|---|
| `probe.sh` | scenario2 2단계 | T1082 System Information Discovery | 없음 (읽기 전용) | 해당 없음 |
| `persist.sh` | scenario2 3단계 | T1505.003 Web Shell | 없음 (S3에 파일이 남는 것 자체가 지속성) | 업로드 객체 삭제로 제거 |
| `impact.sh` | scenario3 4단계 | T1486 Data Encrypted for Impact | `/opt/whs-lab-data/` 더미만 | **완전 가역** (`restore.sh`, `.bak`) |
| `dnscheck.sh` | scenario2 6단계 | — (방어 검증) | 없음 (읽기 전용) | 해당 없음 |

## 규약

1. **출력 첫 줄은 반드시 `hostname`.**
   `common.run_payload_on_target()` 이 이 줄로 "어느 인스턴스에서 실행됐는지"를 식별한다.
   ALB 라운드로빈이라 hostname을 별도 요청으로 물으면 다른 인스턴스로 갈 수 있어서,
   실행과 식별이 같은 응답 안에 있어야 한다.

2. **`hostname` 바로 뒤에 `@@TARGET@@` 대상 가드.**
   단일 대상 정책 — 고정된 인스턴스가 아니면 `__MISS__` 를 찍고 `exit 0` 으로 빠진다.
   **가드보다 위에는 상태를 바꾸는 명령을 절대 두지 않는다.** 대상이 아닌 인스턴스에
   흔적이 남으면 정리 대상에서 누락된다.

   ```sh
   hostname
   case $(hostname) in
     @@TARGET@@.*) ;;
     *) echo "__MISS__"; exit 0 ;;
   esac
   ```

   패턴 뒤의 `.` 이 중요하다. `@@TARGET@@*` 로 두면 `ip-10-3-11-4` 고정 시
   `ip-10-3-11-45` 같은 접두사 관계의 다른 인스턴스까지 매칭되어 단일 대상 보장이
   깨진다. FQDN 은 항상 짧은 이름 뒤에 `.` 가 온다.

3. **자리표시자는 `@@NAME@@` 형식.**
   `common.render_payload(name, NAME="값")` 이 치환한다. 미치환 자리표시자가 남으면
   즉시 중단하므로, 오타로 빈 값이 들어가는 사고가 생기지 않는다.

4. **상태를 바꾸는 페이로드는 복구 수단을 같은 스크립트에서 만든다.**
   `impact.sh` 는 변형을 시작하기 *전에* `restore.sh` 를 생성하고, 파일마다 `.bak` 을
   남기며, 변경 목록을 `MANIFEST_BEGIN`/`MANIFEST_END` 사이에 출력한다.
   시나리오 쪽은 그 매니페스트를 `recovery/` 에 로컬 저장한다
   (호스트가 날아가도 무엇이 바뀌었는지 남도록).

5. **대상 경로 가드를 페이로드 안에 둔다.**
   `impact.sh` 는 대상이 `/tmp` 하위가 아니면 실행을 거부한다. 호출부 실수로
   시스템 경로가 들어가도 스크립트 단계에서 막힌다.

## 원상복구

- `impact.sh` → 대상 호스트의 `/opt/whs-lab-data/restore.sh` 실행.
  시나리오3이 종료 시 복구 명령을 로그와 `scenario3/recovery/` 에 남긴다.
- `persist.sh` → S3 업로드 객체(`whs-uploads/<userId>/…persist.sh`) 삭제.
  key 는 `scenario2/recovery/webshell_keys.json` 에 기록된다.
