"""
실행 전 반드시 TARGET_BUCKET을 실제 값으로 교체하세요.
  - ALB_URL    : terraform output alb_dns_name  (예: https://whs-alb-xxxx.ap-northeast-2.elb.amazonaws.com)
  - TARGET_BUCKET : terraform output bucket_id  (예: cloud9-attack-target-a1b2c3d4)
"""

# ── 수정 항목 ──────────────────────────────────────────────────
TARGET_BUCKET  = "cloud9-attack-target-a396cc5b"   # terraform output bucket_id

# ── 고정 항목 (코드에서 확인된 값) ───────────────────────────────
WEBAPP_URL     = "https://whs4namu.click"

REGION         = "ap-northeast-2"
SSRF_PATH      = "/preview"                        # app.py:45  GET /preview?url=
SSRF_PARAM     = "url"                             # app.py:47  request.args.get("url")
IMDS_BASE      = "http://169.254.169.254"
IMDS_CRED_PATH = "/latest/meta-data/iam/security-credentials/"

# IAM User (config.json 에 박혀 있는 더미 값)
IAM_USER_NAME  = "WHS-Scenario-Persistence-User"

# IMDS 페이로드 선택 모드
# "default" : 기본 페이로드(169.254.169.254)만 사용
# "random"  : imds_payloads.py 목록에서 매 요청마다 무작위 선택 (WAF 로그 다양화용)
IMDS_PAYLOAD_MODE = "default"

# 유출 대상 파일 키
EXFIL_FILES    = ["customers.csv", "config.json", "flag.txt"]

# 로컬 저장 디렉토리 (attack/ 기준 상대 경로)
EXFIL_DIR      = "exfiltrated"
