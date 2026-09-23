#!/usr/bin/env python3
"""실제 계정 정보가 없는 S3 입력 샘플을 결정적으로 생성한다.""" # AWS 호출을 수행하지 않는 로컬 도구이다.
from pathlib import Path # 패키지 내부 출력 경로를 계산한다.
from datetime import datetime, timezone # UTC 발생 시각을 일관되게 계산한다.
import gzip # 실제 S3 전달과 같은 gzip 파일을 만든다.
import json # 주석을 지원하지 않는 JSON을 유효한 문법으로 생성한다.

ROOT = Path(__file__).resolve().parents[1] # 도구 위치를 기준으로 패키지 루트를 찾는다.
OUT = ROOT / "samples" # 샘플은 이 폴더에만 저장한다.
OUT.mkdir(parents=True, exist_ok=True) # 샘플 디렉터리가 없으면 생성한다.
ACCOUNT = "123456789012" # 문서 전용 가상 계정 번호이다.
WHEN = "2026-09-16T00:00:00Z" # 비교에 사용할 고정 UTC 시각이다.
MILLIS = int(datetime.fromisoformat(WHEN.replace("Z", "+00:00")).timestamp() * 1000) # CloudWatch와 WAF의 밀리초 시각이다.

def compact(value): # 한 객체를 한 줄의 JSON 문자열로 만든다.
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")) # 한글과 JSON 데이터형을 보존한다.

def write_sample(name, value): # 사람이 읽을 파일과 입력용 압축 파일을 함께 만든다.
    payload = (compact(value) + "\n").encode("utf-8") # Firehose delimiter 처리와 동일한 JSONL 경계를 만든다.
    (OUT / (name + ".json")).write_bytes(payload) # 원문 비교를 위한 JSON을 저장한다.
    (OUT / (name + ".json.gz")).write_bytes(gzip.compress(payload, mtime=0)) # 시각 메타데이터를 고정한 gzip을 저장한다.

def envelope(group, event_id, message, source="cloudwatch"): # CloudWatch Logs 구독 envelope를 만든다.
    stream = "ap-northeast-2_elk-sample_0" if source == "waf" else "whs-elk-cloudwatch-i-EXAMPLE-validation" # WAF 자동 스트림 형식과 직접 지정하는 Agent 스트림 이름을 구분한다.
    return {"owner": ACCOUNT, "logGroup": group, "logStream": stream, "subscriptionFilters": [f"whs-elk-cloudwatch-{source}-to-firehose"], "messageType": "DATA_MESSAGE", "logEvents": [{"id": event_id, "timestamp": MILLIS, "message": message}]} # Firehose에서 message extraction을 끈 형태이다.

trail_event = {"eventVersion": "1.11", "userIdentity": {"type": "AssumedRole", "accountId": ACCOUNT, "arn": "arn:aws:sts::123456789012:assumed-role/elk-lab/operator"}, "eventTime": WHEN, "eventSource": "ec2.amazonaws.com", "eventName": "DescribeInstances", "awsRegion": "ap-northeast-2", "sourceIPAddress": "192.0.2.10", "eventID": "00000000-0000-4000-8000-000000000001", "eventType": "AwsApiCall", "readOnly": True, "recipientAccountId": ACCOUNT, "requestParameters": {}, "responseElements": None} # 조회형 API의 가상 감사 이벤트이다.
write_sample("cloudtrail", {"Records": [trail_event]}) # CloudTrail의 Records 배열을 유지한다.
server_message = compact({"level": "INFO", "message": "ELK_VALIDATION_MARKER", "test_id": "elk-sample-server-001", "service": "demo"}) # 외부 정보가 없는 서버 로그 본문이다.
write_sample("cloudwatch", envelope("whs-elk-cloudwatch-workload", "cw-sample-001", server_message)) # 새 이름의 서버 로그 envelope를 저장한다.
waf_event = {"timestamp": MILLIS, "formatVersion": 1, "webaclId": "arn:aws:wafv2:ap-northeast-2:123456789012:regional/webacl/elk-sample/00000000-0000-4000-8000-000000000002", "terminatingRuleId": "ELKValidationRule", "terminatingRuleType": "REGULAR", "action": "BLOCK", "httpSourceName": "ALB", "httpSourceId": "example-alb", "httpRequest": {"clientIp": "192.0.2.20", "country": "KR", "headers": [], "uri": "/elk-validation", "args": "test_id=elk-sample-waf-001", "httpVersion": "HTTP/1.1", "httpMethod": "GET", "requestId": "waf-sample-001"}} # 실제 공격 없이 차단 결과의 구조만 재현한다.
write_sample("waf", envelope("aws-waf-logs-whs-elk-cloudwatch-waf", "cw-waf-sample-001", compact(waf_event), "waf")) # WAF 필수 접두사와 통일 이름을 적용한 구독 envelope이다.
finding = {"schemaVersion": "2.0", "accountId": ACCOUNT, "region": "ap-northeast-2", "partition": "aws", "id": "00000000000000000000000000000003", "arn": "arn:aws:guardduty:ap-northeast-2:123456789012:detector/00000000000000000000000000000000/finding/00000000000000000000000000000003", "type": "UnauthorizedAccess:EC2/SSHBruteForce", "severity": 2.0, "title": "[SAMPLE] ELK validation finding", "description": "Synthetic fixture only", "createdAt": WHEN, "updatedAt": WHEN, "resource": {"resourceType": "Instance", "instanceDetails": {"instanceId": "i-EXAMPLE"}}, "service": {"archived": False, "count": 1, "eventFirstSeen": WHEN, "eventLastSeen": WHEN}} # S3 export의 Finding 객체이며 EventBridge wrapper는 없다.
write_sample("guardduty", finding) # GuardDuty는 JSONL의 한 Finding 객체이다.
write_sample("cloudwatch-control", {"owner": ACCOUNT, "logGroup": "whs-elk-cloudwatch-workload", "messageType": "CONTROL_MESSAGE", "logEvents": []}) # 업무 이벤트가 없는 제어 메시지를 처리하는지 확인한다.
(OUT / "malformed.json.txt").write_text('{"broken":\n', encoding="utf-8") # 정상 입력과 분리해 격리 경로 시험에 사용하는 오류 표본이다.
print("samples 생성 완료: AWS API 호출 및 실제 로그 접근 없음") # 로컬 작업 완료만 출력한다.
