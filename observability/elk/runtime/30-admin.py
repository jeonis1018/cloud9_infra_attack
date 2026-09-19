#!/usr/bin/env python3
import argparse # 작업 명령과 설정 파일을 받습니다.
import base64 # HTTP Basic 인증 헤더를 메모리에서 만듭니다.
import datetime # 토큰과 스냅샷의 고유 이름에 UTC를 사용합니다.
import getpass # 관리자 비밀번호를 화면에 표시하지 않고 읽습니다.
import json # 주석이 없는 표준 JSON 요청 본문을 생성합니다.
import os # 파일 권한과 환경을 제어합니다.
import pathlib # 인증서와 keystore 경로를 찾습니다.
import re # 복원할 인덱스와 스냅샷 이름을 검증합니다.
import secrets # Kibana 암호화 키를 생성합니다.
import shutil # 서비스 계정에 keystore 읽기 권한을 부여합니다.
import ssl # CA와 호스트 이름을 검증하는 TLS 연결을 만듭니다.
import stat # 임시로 바꾼 설정 디렉터리 권한을 원복합니다.
import subprocess # 비밀정보는 stdin으로만 keystore 도구에 전달합니다.
import urllib.error # HTTP 오류를 토큰 노출 없이 처리합니다.
import urllib.request # 외부 의존성 없이 REST API를 호출합니다.
from common import load_settings # 설정을 실행하지 않고 파싱합니다.
parser = argparse.ArgumentParser(description="Elastic 초기 정책·서비스 인증·복구 도구; 비밀번호는 프롬프트로만 입력합니다.") # 목적을 설명합니다.
parser.add_argument("command", choices=["initialize", "collector-key", "kibana-token", "reader", "health", "snapshot", "restore"]) # 지원하는 작업만 허용합니다.
parser.add_argument("settings") # 실제 Terraform 리소스 값이 담긴 파일입니다.
parser.add_argument("--snapshot") # 복원할 기존 스냅샷 이름을 받습니다.
parser.add_argument("--index") # 복원할 정확한 원본 인덱스 한 개를 받습니다.
args = parser.parse_args() # 명령을 읽습니다.
values = load_settings(args.settings) # 설정과 URL을 검증합니다.
if os.geteuid() != 0: # 서비스 keystore와 CA를 읽는 root 실행을 요구합니다.
    raise SystemExit("EC2에서 sudo python3로 실행하세요.") # 비권한 실행을 중단합니다.
ca = next((p for p in (pathlib.Path("/etc/elasticsearch/certs/ca.crt"), pathlib.Path("/etc/logstash/certs/ca.crt"), pathlib.Path("/etc/kibana/certs/ca.crt")) if p.exists()), None) # 이 서버 역할의 CA를 찾습니다.
if ca is None: # TLS 설정을 완료했는지 확인합니다.
    raise SystemExit("20-configure.py로 인증서부터 설치하세요.") # CA 없는 접속을 허용하지 않습니다.
context = ssl.create_default_context(cafile=str(ca)) # 자체 CA와 IP SAN 검증을 함께 사용합니다.
url = f'https://{values["ES_PRIVATE_IP"]}:9200' # Elasticsearch private HTTPS 주소입니다.
password = getpass.getpass("elastic 관리자 비밀번호: ") # 화면·명령행·환경변수에 비밀번호를 남기지 않습니다.
authorization = "Basic " + base64.b64encode(("elastic:" + password).encode()).decode() # 인증 헤더를 메모리에서 구성합니다.
del password # 원본 비밀번호 변수를 즉시 해제합니다.
def request(method, path, body=None): # TLS로 Elasticsearch API를 호출합니다.
    data = None if body is None else json.dumps(body).encode("utf-8") # Python 객체를 올바른 JSON으로 직렬화합니다.
    req = urllib.request.Request(url + path, data=data, method=method, headers={"Authorization": authorization, "Content-Type": "application/json"}) # 인증을 argv에 노출하지 않습니다.
    try: # HTTP 실패를 명확히 처리합니다.
        with urllib.request.urlopen(req, context=context, timeout=180) as response: # 서버 인증서를 검증하고 응답을 기다립니다.
            return json.load(response) # 성공 응답을 JSON으로 읽습니다.
    except urllib.error.HTTPError as error: # API 오류의 원인을 확인합니다.
        detail = error.read().decode("utf-8", "replace") # 실패 이유를 읽습니다.
        raise SystemExit(f"Elasticsearch HTTP {error.code}: {detail}") from None # 인증 헤더나 성공 토큰은 출력하지 않습니다.
def run_keystore(command, **options): # Kibana의 keystore 쓰기에 필요한 짧은 권한 변경을 감쌉니다.
    directory = pathlib.Path("/etc/kibana") if command[0] == "runuser" else None # Kibana 서비스 사용자 실행에만 적용합니다.
    previous = stat.S_IMODE(directory.stat().st_mode) if directory else None # 원래 디렉터리 권한을 기억합니다.
    try: # 성공·실패와 무관하게 디렉터리 권한을 원복합니다.
        if directory: # root:kibana인 설정 디렉터리를 사용합니다.
            directory.chmod(previous | stat.S_IWGRP) # keystore 생성·원자적 교체 중에만 서비스 그룹 쓰기를 허용합니다.
        return subprocess.run(command, check=True, **options) # shell 없이 keystore 명령을 실행합니다.
    finally: # 예외가 발생해도 실행합니다.
        if directory: # Kibana 설정 경로인 경우입니다.
            directory.chmod(previous) # 그룹 쓰기 권한을 원래 상태로 되돌립니다.
def keystore_add(command, key, value, env=None): # 토큰 값을 파일 대신 표준입력으로 전달합니다.
    run_keystore(command + ["add", key, "--stdin"], input=value + "\n", text=True, env=env) # 커맨드 라인에는 비밀 값이 없습니다.
if args.command == "initialize": # Elasticsearch 첫 시작 후 관리 정책을 설치합니다.
    policy = {"policy": {"phases": {"hot": {"actions": {}}, "delete": {"min_age": "30d", "actions": {"delete": {}}}}}} # 인덱스 생성 후 30일에 삭제하며 rollover는 사용하지 않습니다.
    request("PUT", "/_ilm/policy/whs-elk-elasticsearch-retention", policy) # 검색용 보관 정책을 등록합니다.
    properties = { # 매핑 폭발과 타입 충돌을 줄일 필드 집합입니다.
        "@timestamp": {"type": "date"}, # 원본 이벤트 발생 시각입니다.
        "message": {"type": "match_only_text"}, # 서버 메시지와 원본 JSON을 텍스트 검색합니다.
        "event": {"properties": {"dataset": {"type": "keyword"}, "id": {"type": "keyword"}, "action": {"type": "keyword"}, "provider": {"type": "keyword"}, "outcome": {"type": "keyword"}, "severity": {"type": "float"}, "ingested": {"type": "date"}, "original": {"type": "keyword", "index": False, "doc_values": False}}}, # 자주 검색하는 이벤트 속성과 저장 전용 원문입니다.
        "cloud": {"properties": {"provider": {"type": "keyword"}, "account": {"properties": {"id": {"type": "keyword"}}}, "region": {"type": "keyword"}}}, # 클라우드 계정과 리전 검색 필드입니다.
        "aws": {"properties": {"payload": {"type": "object", "enabled": False}, "cloudwatch": {"properties": {"owner": {"type": "keyword"}, "log_group": {"type": "keyword"}, "log_stream": {"type": "keyword"}, "message_type": {"type": "keyword"}}}, "guardduty": {"properties": {"finding_id": {"type": "keyword"}}}, "s3": {"properties": {"bucket": {"properties": {"name": {"type": "keyword"}, "arn": {"type": "keyword"}}}, "object": {"properties": {"key": {"type": "keyword"}}}}}}}, # 원본 payload는 보존하되 자동 필드 확장을 하지 않습니다.
        "source": {"properties": {"address": {"type": "keyword"}}}, # AWS 서비스 이름도 수용하는 주소 필드입니다.
        "user": {"properties": {"id": {"type": "keyword"}}}, # 호출 주체 ARN 필드입니다.
        "rule": {"properties": {"id": {"type": "keyword"}}}, # WAF 규칙 식별자입니다.
        "url": {"properties": {"path": {"type": "keyword", "ignore_above": 4096}}}, # 요청 경로 검색 필드입니다.
        "http": {"properties": {"request": {"properties": {"method": {"type": "keyword"}}}}}, # HTTP 메서드 검색 필드입니다.
        "tags": {"type": "keyword"}, # 파싱 실패 태그 등을 검색합니다.
        "error": {"properties": {"message": {"type": "text"}, "item_position": {"type": "integer"}}}, # 격리 사유와 배열 위치입니다.
    } # 명시 매핑 정의를 마칩니다.
    template = {"index_patterns": ["whs-elk-elasticsearch-logs-*"], "priority": 500, "template": {"settings": {"number_of_shards": 1, "number_of_replicas": 0, "index.lifecycle.name": "whs-elk-elasticsearch-retention"}, "mappings": {"dynamic": False, "properties": properties}}} # 단일 노드에서 할당 불가능한 복제본을 만들지 않습니다.
    request("PUT", "/_index_template/whs-elk-elasticsearch-logs", template) # 새 일별 인덱스에 공통 매핑을 적용합니다.
    repository = {"type": "s3", "settings": {"bucket": values["SNAPSHOT_BUCKET"], "base_path": values["SNAPSHOT_PREFIX"]}} # 인스턴스 IAM 역할과 버킷 기본 암호화를 사용합니다.
    request("PUT", "/_snapshot/whs-elk-elasticsearch-snapshots", repository) # 스냅샷 S3 저장소를 등록하고 권한을 검증합니다.
    request("POST", "/_snapshot/whs-elk-elasticsearch-snapshots/_verify", {}) # 실제 쓰기·읽기·삭제 권한을 확인합니다.
    slm = {"schedule": "0 0 18 * * ?", "name": "<whs-elk-elasticsearch-daily-{now/d}>", "repository": "whs-elk-elasticsearch-snapshots", "config": {"indices": ["whs-elk-elasticsearch-logs-*"], "include_global_state": False}, "retention": {"expire_after": "7d", "min_count": 1, "max_count": 14}} # 매일 한국시간 03시에 로그 인덱스를 스냅샷하고 최근 7일을 남깁니다.
    request("PUT", "/_slm/policy/whs-elk-elasticsearch-daily-backup", slm) # 스냅샷 일정을 Elasticsearch 내부에 저장합니다.
    print("ILM whs-elk-elasticsearch-retention, template whs-elk-elasticsearch-logs, repository whs-elk-elasticsearch-snapshots, SLM whs-elk-elasticsearch-daily-backup 등록 완료") # 비밀 값 없이 결과를 알립니다.
elif args.command == "collector-key": # 수집 서버에서 최초 색인 권한을 설정합니다.
    command = ["/usr/share/logstash/bin/logstash-keystore", "--path.settings", "/etc/logstash"] # 이 서버의 Logstash keystore를 선택합니다.
    path = pathlib.Path("/etc/logstash/logstash.keystore") # keystore 파일 경로입니다.
    if not path.exists(): # 기존 key 저장소를 덮어쓰지 않습니다.
        subprocess.run(command + ["create"], check=True) # 비밀번호 없는 keystore를 만들고 파일 권한으로 보호합니다.
    keys = subprocess.run(command + ["list"], check=True, capture_output=True, text=True).stdout.splitlines() # 이름만 조회하며 값은 보지 않습니다.
    if "ES_API_KEY" in keys: # 이미 운영 중인 키를 자동 교체하지 않습니다.
        raise SystemExit("ES_API_KEY가 이미 있습니다. 문서의 키 교체 절차로 진행하세요.") # 초기 설정 명령의 반복 실행을 막습니다.
    descriptor = {"cluster": ["monitor"], "indices": [{"names": ["whs-elk-elasticsearch-logs-*"], "privileges": ["auto_configure", "index"]}]} # 템플릿·정책 변경이나 삭제 권한은 주지 않습니다.
    result = request("POST", "/_security/api_key", {"name": "whs-elk-elasticsearch-collector", "expiration": "90d", "role_descriptors": {"whs-elk-elasticsearch-writer": descriptor}}) # 90일 만료의 최소 권한 API 키를 만듭니다.
    keystore_add(command, "ES_API_KEY", result["id"] + ":" + result["api_key"]) # Logstash가 요구하는 id:api_key 형식을 stdin으로 저장합니다.
    path.chmod(0o640) # 서비스 그룹 외에는 keystore를 읽지 못하게 합니다.
    shutil.chown(path, user="root", group="logstash") # Logstash 서비스가 키를 읽게 합니다.
    print("수집 API 키 저장 완료. 90일 만료 전 교체 일정을 등록하세요. 키 값은 출력하지 않았습니다.") # 만료 관리 의무를 명시합니다.
elif args.command == "kibana-token": # Kibana 서버에서 서비스 인증을 구성합니다.
    env = os.environ.copy() # keystore 실행 환경을 복사합니다.
    env["KBN_PATH_CONF"] = "/etc/kibana" # 패키지 설정 디렉터리를 명시합니다.
    command = ["runuser", "-u", "kibana", "--", "/usr/share/kibana/bin/kibana-keystore"] # Kibana 사용자로 keystore를 조작합니다.
    path = pathlib.Path("/etc/kibana/kibana.keystore") # 서비스 keystore 경로입니다.
    if not path.exists(): # 기존 저장소를 덮어쓰지 않습니다.
        run_keystore(command + ["create"], env=env) # 토큰을 보관할 keystore를 만듭니다.
    keys = subprocess.run(command + ["list"], check=True, env=env, capture_output=True, text=True).stdout.splitlines() # 이미 설정한 항목 이름을 읽습니다.
    if "elasticsearch.serviceAccountToken" in keys: # 운영 토큰을 임의로 교체하지 않습니다.
        raise SystemExit("Kibana 토큰이 이미 있습니다. 최초 설정 명령을 반복하지 마세요.") # 초기 설정의 중복을 막습니다.
    name = "whs-elk-kibana-service-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S") # 고유 토큰 이름을 만듭니다.
    result = request("POST", "/_security/service/elastic/kibana/credential/token/" + name, {}) # Kibana 전용 서비스 계정 토큰을 발급합니다.
    keystore_add(command, "elasticsearch.serviceAccountToken", json.dumps(result["token"]["value"]), env) # 문자열 JSON으로 stdin 전달하여 숫자 자동 해석을 피합니다.
    for key in ("xpack.security.encryptionKey", "xpack.encryptedSavedObjects.encryptionKey", "xpack.reporting.encryptionKey"): # 재시작 후에도 유지할 세 가지 암호화 키입니다.
        if key not in keys: # 저장 객체 복호화 키를 덮어쓰지 않습니다.
            keystore_add(command, key, json.dumps(secrets.token_hex(32)), env) # 강한 무작위 키를 keystore에 저장합니다.
    path.chmod(0o600) # keystore는 Kibana 서비스 계정만 읽게 합니다.
    print("Kibana 서비스 토큰과 암호화 키를 저장했습니다. keystore를 암호화된 운영 백업에 보관하세요.") # 값 대신 필요한 후속 조치를 안내합니다.
elif args.command == "reader": # 매일 사용할 조회 전용 계정을 만듭니다.
    role = {"cluster": [], "indices": [{"names": ["whs-elk-elasticsearch-logs-*"], "privileges": ["read", "view_index_metadata"]}], "applications": [{"application": "kibana-.kibana", "privileges": ["feature_discover.read", "feature_dashboard.read"], "resources": ["space:default"]}]} # 기본 공간의 Discover·Dashboard와 로그 인덱스만 읽게 합니다.
    request("PUT", "/_security/role/whs-elk-elasticsearch-reader", role) # 관리자와 서비스 쓰기 역할을 분리합니다.
    reader_password = getpass.getpass("새 whs-elk-kibana-reader 비밀번호: ") # 사용자가 보관할 로그인 비밀번호를 직접 입력받습니다.
    if len(reader_password) < 16 or reader_password != getpass.getpass("같은 비밀번호 다시 입력: "): # 짧거나 오타가 있는 비밀번호를 거부합니다.
        raise SystemExit("16자 이상이며 두 입력이 일치해야 합니다.") # 다시 입력할 이유를 알려줍니다.
    request("PUT", "/_security/user/whs-elk-kibana-reader", {"password": reader_password, "roles": ["whs-elk-elasticsearch-reader"], "full_name": "whs-elk-kibana-reader"}) # 수퍼유저 대신 사용할 조회 계정과 표시 이름을 통일합니다.
    del reader_password # 비밀번호 참조를 해제합니다.
    print("whs-elk-kibana-reader 생성 완료. 데이터 뷰와 대시보드는 관리자가 먼저 준비하세요.") # 읽기 권한 사용 방법을 알려줍니다.
elif args.command == "health": # 읽기 전용 상태 확인입니다.
    for endpoint in ("/_cluster/health", "/_cat/indices/whs-elk-elasticsearch-logs-*?format=json&h=health,index,docs.count,store.size", "/_ilm/status", "/_slm/status"): # 저장·보관·스냅샷 기능을 조회합니다.
        print(endpoint, json.dumps(request("GET", endpoint), ensure_ascii=False, indent=2)) # 로그 본문 대신 상태 정보를 출력합니다.
elif args.command == "snapshot": # 검증 전에 수동 스냅샷을 만듭니다.
    name = "whs-elk-elasticsearch-manual-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S") # 충돌하지 않는 이름입니다.
    print(json.dumps(request("PUT", f"/_snapshot/whs-elk-elasticsearch-snapshots/{name}?wait_for_completion=false", {"indices": ["whs-elk-elasticsearch-logs-*"], "include_global_state": False}), ensure_ascii=False)) # 비동기로 백업을 시작합니다.
    print(f"스냅샷 이름: {name}; 완료 확인은 GET /_snapshot/whs-elk-elasticsearch-snapshots/{name}") # 성공 완료와 요청 수락을 구분합니다.
else: # 기존 스냅샷의 지정 인덱스를 새 이름으로 복원합니다.
    if not args.snapshot or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]+", args.snapshot): # snapshot path 주입을 막습니다.
        raise SystemExit("--snapshot에 실제 스냅샷 이름을 지정하세요.") # 필수 입력을 안내합니다.
    if not args.index or not re.fullmatch(r"whs-elk-elasticsearch-logs-(?:cloudtrail|cloudwatch|waf|guardduty|quarantine)-\d{4}\.\d{2}\.\d{2}", args.index): # wildcard·시스템 인덱스 복원을 거부합니다.
        raise SystemExit("--index에 whs-elk-elasticsearch-logs-cloudtrail-2026.09.16 같은 단일 인덱스를 지정하세요.") # 검증용 단일 복원만 허용합니다.
    target = args.index.replace("whs-elk-elasticsearch-logs-", "whs-elk-elasticsearch-restore-", 1) # 기존 수집 인덱스와 다른 이름입니다.
    existing_targets = request("GET", "/_cat/indices/whs-elk-elasticsearch-restore-*?format=json&h=index&expand_wildcards=all") # 닫힌 인덱스도 포함해 기존 복원본을 조회합니다.
    if any(item["index"] == target for item in existing_targets): # 같은 이름의 기존 복원본을 덮어쓰지 않습니다.
        raise SystemExit(f"이미 존재하는 복원 대상: {target}; 이름과 정리 필요성을 먼저 검토하세요.") # 반복 복원 전에 운영자가 확인하도록 합니다.
    snapshot = request("GET", f"/_snapshot/whs-elk-elasticsearch-snapshots/{args.snapshot}") # 백업 완료 상태와 인덱스 포함 여부를 확인합니다.
    selected = snapshot["snapshots"][0] # 요청한 스냅샷 메타데이터입니다.
    if selected["state"] != "SUCCESS" or args.index not in selected["indices"]: # 불완전한 백업이나 없는 인덱스는 진행하지 않습니다.
        raise SystemExit("SUCCESS 스냅샷에 해당 인덱스가 포함되어야 합니다.") # 원인을 알려줍니다.
    body = {"indices": args.index, "include_global_state": False, "include_aliases": False, "rename_pattern": "^whs-elk-elasticsearch-logs-(.+)$", "rename_replacement": "whs-elk-elasticsearch-restore-$1", "ignore_index_settings": ["index.lifecycle.name"], "index_settings": {"index.number_of_replicas": 0}} # 원본·정책을 덮어쓰지 않고 복구 검증용 인덱스를 만듭니다.
    print(json.dumps(request("POST", f"/_snapshot/whs-elk-elasticsearch-snapshots/{args.snapshot}/_restore?wait_for_completion=true", body), ensure_ascii=False)) # 실제 복원이 끝날 때까지 기다립니다.
    print(f"복원 결과: {target}; 검증 후 관리자가 이 테스트 인덱스만 명시적으로 정리하세요.") # ILM에서 제외한 복원본 정리를 안내합니다.
