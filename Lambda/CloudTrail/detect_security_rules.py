import ipaddress
import json
import os
from datetime import datetime, timezone

import boto3

s3 = boto3.client("s3")

SCHEMA_VERSION = "2.0"
LOG_TYPE = "cloudtrail"

RESULT_BUCKET = os.environ["RESULT_BUCKET"]
NORMAL_PREFIX = os.environ.get("NORMAL_PREFIX","cloudtrail/normal").strip("/")
REVIEW_PREFIX = os.environ.get("REVIEW_PREFIX","cloudtrail/review").strip("/")
FINDING_PREFIX = os.environ.get("FINDING_PREFIX","cloudtrail/finding").strip("/")

def load_json_list_environment(name,default):
  raw_value = os.environ.get(name)

  # 환경 변수가 없거나, 공백인 경우, default 반환
  if raw_value is None or not raw_value.strip():
    return default

  try:
    value = json.loads(raw_value)
  # json 파싱중, 문법이 유효한 json 문법이 아닌경우 예외 처리 후 실패
  except json.JSONDecodeError as error:
    raise ValueError(f"Environment variable {name} must be a JSON array") from error

  # json 파싱을 했는데, list가 아닌경우, 오류 반환
  if not isinstance(value, list):
    raise ValueError(f"Environment variable {name} must be a JSON array")

  return value

PROTECTED_TRAILS = set(load_json_list_environment("PROTECTED_TRAILS", ["Managed-role"]))

TEAM_CIDRS = []
# TEAM_CIDRS에 정의된 JSON 배열(예: ["203.0.113.0/24", "198.51.100.50/32"])을 파이썬 문자열 리스트로 가져옴
for cidr_value in load_json_list_environment("TEAM_CIDRS",[]):
  try:
    # 단순 문자열인 IP/CIDR 표기법을 ipaddress라이브러리의 네트워크 대역 객체로 변환함
    # 만약 203.0.113.55/24가 들어오면 -> 203.0.113.0으로 자동 보정
    TEAM_CIDRS.append(ipaddress.ip_network(str(cidr_value), strict=False))
  except ValueError as error:
    raise ValueError(f"Invalid CIDR in TEAM_CIDRS: {cidr_value}") from error


CLOUDTRAIL_RULES = {
    "StopLogging": {
        "rule_id": "AWS-CT-001",
        "title": "CloudTrail 로깅 중지",
        "description": "보호 대상 CloudTrail 추적의 로깅이 중지되었습니다.",
        "base_score": 90,
        "severity": "HIGH",
        "recommended_action": (
            "작업 승인 여부와 호출 주체를 확인하고, 보호 Trail의 "
            "로깅 상태를 즉시 점검하세요."
        ),
    },
    "DeleteTrail": {
        "rule_id": "AWS-CT-002",
        "title": "CloudTrail 추적 삭제",
        "description": "보호 대상 CloudTrail 추적이 삭제되었습니다.",
        "base_score": 100,
        "severity": "CRITICAL",
        "recommended_action": (
            "삭제 승인 여부를 즉시 확인하고, 원래 Trail 설정과 "
            "로그 전달 경로의 복구 절차를 검토하세요."
        ),
    },
    "UpdateTrail": {
        "rule_id": "AWS-CT-003",
        "title": "CloudTrail 추적 설정 변경",
        "description": "보호 대상 CloudTrail 추적 설정이 변경되었습니다.",
        "base_score": 65,
        "severity": "MEDIUM",
        "recommended_action": (
            "변경 전후 Trail 설정과 변경 승인 내역을 확인하세요."
        ),
    },
    "PutEventSelectors": {
        "rule_id": "AWS-CT-004",
        "title": "CloudTrail 이벤트 선택기 변경",
        "description": "보호 대상 Trail의 이벤트 수집 범위가 변경되었습니다.",
        "base_score": 70,
        "severity": "HIGH",
        "recommended_action": (
            "관리 이벤트와 필요한 데이터 이벤트가 제외되지 않았는지 확인하세요."
        ),
    },
    "PutInsightSelectors": {
        "rule_id": "AWS-CT-005",
        "title": "CloudTrail Insights 선택기 변경",
        "description": "보호 대상 Trail의 Insights 설정이 변경되었습니다.",
        "base_score": 55,
        "severity": "MEDIUM",
        "recommended_action": (
            "Insights 활성화 상태와 변경 승인 내역을 확인하세요."
        ),
    },
}

def utc_now():
  return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def extract_normalized_event(lambda_event):
  if not isinstance(lambda_event, dict):
    raise ValueError("Lambda input must be a JSON Object")

  # normalized_event가 정규화 lambda의 로그를 가지고 온다 
  normalized_event = lambda_event.get("normalized_event")

  # normalized_event 키가 없는 경우 그냥 본문 전체를 정규화 로그로 처리 
  if normalized_event is None:
    normalized_event = lambda_event

  if not isinstance(normalized_event, dict):
    raise ValueError("Lambda input must be a JSON Object")

  return normalized_event

def validate_normalized_event(normalized_event):
  if normalized_event.get("schema_version") != SCHEMA_VERSION:
    raise ValueError("Unsupported or missing schema_version")

  if normalized_event.get("log_type") != LOG_TYPE:
    raise ValueError("Unsupported or missing log_type")

  event_data = normalized_event.get("event")
  cloud_data = normalized_event.get("cloud")
  outcome_data = normalized_event.get("outcome")

  if not isinstance(event_data, dict):
    raise ValueError("event must be a JSON object")
  
  if not isinstance(cloud_data, dict):
    raise ValueError("event must be a JSON object")

  if not isinstance(outcome_data, dict):
      raise ValueError("event must be a JSON object")

  required_fields = {
    "event.id": event_data.get("id"),
    "event.service": event_data.get("service"),
    "event.action": event_data.get("action"),
  }

  # 필수 입력 항목(required_fields)중에서 값이 비어 있거나 누락된 항목의 이름만 골라내서 리스트로 만듦
  missing_fields = []

  # required_fields 딕셔너리에서 (키, 값)을 하나씩 꺼내며 순회
  for field_name, field_value in required_fields.items():
    if not field_value:
      missing_fields.append(field_name)

  if missing_fields:
    raise ValueError("Missing required fields:"+",".join(missing_fields))

def trail_name_from_value(value):
  if not value:
    return None

  text_value = str(value)

  if "/" in text_value:
    return text_value.rsplit("/", 1)[-1]

  return text_value.rsplit(":", 1)[-1]

# 정규화된 로그에서 변경 대상이된 CloudTrail 추적의 이름을 찾아서 중복없이 깔끔하게 정렬된 리스트로 뽑아주는 함수 
def extract_trail_names(normalized_event):
  trail_names = set()

  for resource in normalized_event.get("resources") or normalized_event.get("resource") or normalized_event.get("recources") or[]:
    if not isinstance(resource, dict):
      continue

    # resource항목을 하나씩 검사 -> type이 cloudtrail인지 확인
    resource_type = resource.get("type")
    if resource_type != "AWS::CloudTrail::Trail":
      continue

    
    for candidate in (resource.get("id"), resource.get("arn")):
      trail_name = trail_name_from_value(candidate)
      if trail_name:
        trail_names.add(trail_name)

  details = normalized_event.get("details") or {}
  request_parameters = details.get("request_parameters") or {}

  if isinstance(request_parameters, dict):
    trail_name = trail_name_from_value(request_parameters.get("name"))
    if trail_name:
      trail_names.add(trail_name)

  return sorted(trail_names)

def source_ip_team_status(source_ip):
# 입력된 ip가 팀 내부 CIDR인지 확인하는 함수 

  # TEAM_CIDRS가 비어있거나, 입력된 IP가 없는 경우 None 반환
  if not TEAM_CIDRS or not source_ip:
    return None 

  # 입력된 문자열 형태의 ip를 파이썬의 ip객체로 변환
  try:
    source_address = ipaddress.ip_address(source_ip)

  except ValueError:
    return None


  return any(
    # 버전 일치 검사 (ipv4인지, ipv6인지 비교)
    # any 사용으로 하나라도 일치할 시 반환한다
    source_address.version == team_network.version
    # 입력된 ip가 팀 ip리스트에 있는지 하나씩 꺼내보면서 조회 
    and source_address in team_network
    for team_network in TEAM_CIDRS
  )

# 입력된 점수 기반으로 분석 반환값 분기 함수 
def classification_from_score(risk_score):
  if risk_score >= 80:
    return "FINDING"

  if risk_score >= 30:
    return "REVIEW"

  return "NO_MATCH"

# 분석 반환값을 입력받아서 람다 호출을 분기 하는 함수 
def prefix_from_classification(classification):
  if classification == "FINDING":
    return FINDING_PREFIX

  if classification == "REVIEW":
    return REVIEW_PREFIX

  return NORMAL_PREFIX

# 정규화 로그를 받아, 위험 점수 판독기에 통과 시킨 후 결과표 뽑는 함수 
# 결과표는 evaluation이다. 
def evaluate_cloudtrail_event(normalized_event):
  event_data = normalized_event["event"]
  outcome_data = normalized_event["outcome"]
  source_data = normalized_event.get("source") or {}

  action = event_data["action"]
  service = event_data["service"]
  outcome_status = outcome_data.get("status")
  source_ip = source_data.get("ip")

  # 호출자 ip가 팀 내 공인 ip인지 확인 
  source_ip_team_cidrs = source_ip_team_status(source_ip)
  trail_names = extract_trail_names(normalized_event)

  # 매트릭스 조건에 부합했을 때 최종 할당될 룰 식별자
  # (예: "AWS-CT-001") 매칭된 룰이 없으면 기본값인 None을 유지
  matched_rule = None
  # 탐지 판단에 사용된 근거 조건들을 추적용으로 남기기 위한 리스트
  matched_conditions = []
  risk_score = 0
  severity = "INFORMATIONAL"

  if service != "cloudtrail.amazonaws.com":
    matched_conditions.append("NOT_CLOUDTRAIL_SERVICE")
  elif outcome_status != "SUCCESS" or outcome_data.get("error_code"):
    matched_conditions.append("API_CALL_NOT_SUCCESSFUL")
  # 룰셋에 등록된 핵심 파괴행동이 아니면 탈락
  elif action not in CLOUDTRAIL_RULES:
    matched_conditions.append("ACTION_NOT_IN_CLOUDTRAIL_RULESET")

  # 지정한 보호 Trail이 아니면 탈락
  elif not set(trail_names).intersection(PROTECTED_TRAILS):
    matched_conditions.append("TRAIL_NOT_PROTECTED")

  # 룰 적중시 동작 로직 
  else:
    # 룰셋 정의대로 기본 점수 및 심각도 부여 
    matched_rule = CLOUDTRAIL_RULES[action]
    risk_score = matched_rule["base_score"]
    severity = matched_rule["severity"]

    matched_conditions.extend(
      [
        "CLOUDTRAIL_RULE_MATCHED",
        "API_CALL_SUCCESS",
        "PROTECTED_TRAIL",
      ]
    )

    # 만약 팀원 IP가 아닌, 외부 IP에서 호출 시, 가산점 +10점
    if source_ip_team_cidrs is False:
      risk_score = min(risk_score + 10, 100)
      matched_conditions.append("SOURCE_IP_OUTSIDE_TEAM_CIDRS")

    elif source_ip_team_cidrs is True:
      matched_conditions.append("SOURCE_IP_INSIDE_TEAM_CIDRS")

    else:
      matched_conditions.append("SOURCE_IP_TEAM_STATUS_UNKNOWN")

  # 점수 분기 
  classification = (
    classification_from_score(matched_rule["base_score"]) if matched_rule else "NO_MATCH"
  )

  return {
    "evaluation_schema_version": "1.0",
    "evaluated_at": utc_now(),
    "classification": classification,
    "risk_score": risk_score,
    "severity": severity,
    "human_review_required": classification in {"REVIEW", "FINDING"},
    "rule_id": matched_rule["rule_id"] if matched_rule else None,
    "title": matched_rule["title"] if matched_rule else None,
    "description": matched_rule["description"] if matched_rule else None,
    "recommended_action": [matched_rule["recommended_action"]] if matched_rule else [],
    "matched_conditions": matched_conditions,
    "context":{
      "source_ip": source_ip,
      "source_ip_in_team_cidrs": source_ip_team_cidrs,
      "detected_trail_names": trail_names,
      "protected_trails": sorted(PROTECTED_TRAILS)
    },
  }

def build_result_key(normalized_event, evaluation):
  event_data = normalized_event["event"]
  event_id = event_data["id"]
  event_time = event_data.get("time")

  try:
    partition_time = datetime.fromisoformat(
      str(event_time).replace("Z", "+00:00")
    )
    # 파싱된 시각 객체에 타임존 정보가 없으면(Naive 객체), 
    # .replace(tzinfo=timezone.utc)로 강제로 UTC 타임존을 부여
    if partition_time.tzinfo is None:
      partition_time = partition_time.replace(tzinfo=timezone.utc)
    # 다른 타임존 (예: KST +09:00)이 들어오더라도 기준 시간인 UTC 기준으로 통일 해 변환
    partition_time = partition_time.astimezone(timezone.utc)

  # 시각 데이터가 깨졌거나 None인 경우, 
  # 파이프라인이 중단되지 않도록 현재 UTC 시각(datetime.now(timezone.utc))을 대체값으로 사용
  except(TypeError, ValueError):
    partition_time = datetime.now(timezone.utc)

  prefix = prefix_from_classification(evaluation["classification"])
  rule_id = evaluation.get("rule_id") or "NO-RULE"

  return (
    f"{prefix}/"
    f"year={partition_time:%Y}/"
    f"month={partition_time:%m}/"
    f"day={partition_time:%d}/"
    f"hour={partition_time:%H}/"
    f"{event_id}/{rule_id}.json"
  )

def save_evaluation_result(normalized_event, evaluation):
  object_key = build_result_key(normalized_event, evaluation)

  result_document = {
    "evaluation": evaluation,
    "normalized_event": normalized_event,
  }

  s3.put_object(
    Bucket = RESULT_BUCKET,
    Key = object_key,
    Body = json.dumps(
      result_document,
      ensure_ascii=False,
      indent = 2
    ).encode("utf-8"),
    ContentType = "application/json",
    ServerSideEncryption = "AES256",
  )

  return object_key


# ---------------------------------------------------------------------------
# S3 단일 이벤트 룰
# 승인 예외는 아직 구현하지 않습니다. FINDING은 승인 여부를 확인한 결과가 아닙니다.
# 정책/ACL 내용은 자동 공개 판정 없이 REVIEW로 전달합니다.
# ---------------------------------------------------------------------------

S3_RULES = {
    "AWS-S3-001": {
        "events": ["DeleteBucket"], "enabled": True,
        "title": "보호 S3 버킷 삭제",
        "description": "보호 대상 버킷 삭제 API가 성공했습니다. 승인 예외 검사는 아직 적용하지 않습니다.",
        "base_score": 100, "classification": "FINDING", "severity": "CRITICAL",
        "recommended_action": "호출 주체와 삭제 경위를 확인하고, 백업 및 복구 가능 여부를 점검하세요.",
    },
    "AWS-S3-002": {
        "events": ["DeleteBucketPublicAccessBlock", "PutBucketPublicAccessBlock"], "enabled": True,
        "title": "S3 필수 공개 차단 설정 제거 또는 약화",
        "description": "보호 버킷에 요구한 공개 차단 설정이 제거되거나 false로 설정되었습니다. 실제 공개 상태를 확정하지는 않습니다.",
        "base_score": 90, "classification": "FINDING", "severity": "HIGH",
        "recommended_action": "버킷 및 계정의 공개 차단 상태와 변경 주체를 확인하고 승인된 기준 설정과 비교하세요.",
        # 요청 내용이 불완전해 약화 여부를 판단할 수 없을 때 쓰는 REVIEW 표현.
        "review_variant": {
            "base_score": 70,
            "title": "S3 공개 차단 설정 변경 - 요청 내용 확인 필요",
            "description": "공개 차단 설정 변경 API는 성공했으나 요청 내용이 불완전하여 약화 여부를 판단할 수 없습니다.",
        },
    },
    "AWS-S3-003": {
        "events": ["DeleteBucketPolicy"], "enabled": True,
        "title": "S3 버킷 정책 삭제",
        "description": "보호 버킷 정책 삭제 API가 성공했습니다. 삭제된 허용 및 거부 정책의 영향을 검토해야 합니다.",
        "base_score": 70, "classification": "REVIEW", "severity": "HIGH",
        "recommended_action": "이전 버킷 정책과 비교하여 필요한 접근 제한이나 서비스 권한이 제거됐는지 확인하세요.",
    },
    "AWS-S3-004": {
        "events": ["PutBucketPolicy"], "enabled": True,
        "title": "S3 버킷 정책 변경",
        "description": "보호 버킷의 접근 정책이 설정 또는 교체되었습니다.",
        "base_score": 70, "classification": "REVIEW", "severity": "HIGH",
        "recommended_action": "Principal, Action, Resource, Condition을 함께 검토하여 공개 및 미승인 접근 허용 여부를 확인하세요.",
    },
    "AWS-S3-005": {
        "events": ["PutBucketAcl"], "enabled": True,
        "title": "S3 버킷 ACL 변경",
        "description": "보호 버킷의 ACL 변경 API가 성공했습니다.",
        "base_score": 70, "classification": "REVIEW", "severity": "HIGH",
        "recommended_action": "권한 수신자와 부여된 권한을 확인하세요. 정상적인 비공개 설정 변경일 수도 있습니다.",
    },
    "AWS-S3-006": {
        "events": ["PutObjectAcl"], "enabled": True,
        "title": "S3 객체 ACL 변경",
        "description": "보호 범위에 해당하는 객체의 ACL 변경 API가 성공했습니다.",
        "base_score": 65, "classification": "REVIEW", "severity": "MEDIUM",
        "recommended_action": "객체 ACL의 권한 수신자와 공개 및 미승인 권한 부여 여부를 검토하세요.",
    },
    "AWS-S3-007": {
        "events": ["DeleteObject", "DeleteObjects"], "enabled": True,
        "title": "S3 보호 범위 객체 삭제 요청",
        "description": "보호 범위의 객체 삭제 요청이 수신되었습니다. 일괄 삭제는 객체별 결과 확인이 필요합니다.",
        "base_score": 65, "classification": "REVIEW", "severity": "MEDIUM",
        "recommended_action": "객체별 성공/실패와 버전 ID, 삭제 마커를 확인하고 관련 삭제 이벤트와 연결하여 검토하세요.",
    },
    "AWS-S3-008": {
        "events": ["GetObject"], "enabled": True,
        "title": "팀 CIDR 외부에서 S3 보호 객체 읽기",
        "description": "팀 CIDR 외부 IP에서 보호 범위 객체 읽기 API가 성공했습니다.",
        "base_score": 45, "classification": "REVIEW", "severity": "MEDIUM",
        "recommended_action": "호출 주체와 업무상 접근 목적을 확인하세요. 외부 IP만으로 데이터 유출을 확정하지 않습니다.",
    },
    "AWS-S3-009": {
        "events": ["ListObjects", "ListObjectsV2"], "enabled": True,
        "title": "팀 CIDR 외부에서 S3 보호 버킷 목록 조회",
        "description": "팀 CIDR 외부 IP에서 보호 버킷의 객체 목록 조회 API가 성공했습니다.",
        "base_score": 35, "classification": "REVIEW", "severity": "LOW",
        "recommended_action": "조회 주체와 목적을 확인하고 후속 객체 읽기/변경 이벤트와 연결하여 검토하세요.",
    },
    "AWS-S3-010": {
        "events": ["PutObject", "CopyObject"], "enabled": False,
        "title": "S3 SSE-C 객체 쓰기",
        "description": "후속 구현 대상으로 예약된 룰입니다. SSE-C 조건 판정 및 멀티파트 처리는 구현하지 않았습니다.",
        "base_score": 90, "classification": "FINDING", "severity": "HIGH",
        "recommended_action": "실제 SSE-C 데이터 이벤트와 팀 사용 정책을 검증한 후 탐지 로직을 구현하세요.",
    },
    "AWS-S3-011": {
        "events": ["PutBucketEncryption", "DeleteBucketEncryption"], "enabled": True,
        "title": "S3 버킷 암호화 설정 변경 또는 삭제",
        "description": "보호 버킷의 암호화 설정이 변경 또는 삭제되었습니다. 객체 암호화 상태 변경을 확정하지 않습니다.",
        "base_score": 70, "classification": "REVIEW", "severity": "HIGH",
        "recommended_action": "변경 전후 암호화 설정, KMS 키, SSE-C 차단 설정을 비교하여 검토하세요.",
    },
}
for _rule_id, _rule in S3_RULES.items():
    _rule["rule_id"] = _rule_id

S3_EVENT_RULES = {
    action: rule
    for rule in S3_RULES.values()
    for action in rule["events"]
}


def load_s3_string_list(name):
    values = load_json_list_environment(name, [])
    if any(not isinstance(value, str) or not value for value in values):
        raise ValueError(f"{name} must contain non-empty strings")
    return values


# 버킷 이름만 사용합니다. ARN, s3://, wildcard는 허용하지 않습니다.
PROTECTED_BUCKETS = set(load_s3_string_list("PROTECTED_BUCKETS"))
if any("/" in value or ":" in value or "*" in value for value in PROTECTED_BUCKETS):
    raise ValueError("PROTECTED_BUCKETS must contain bucket names, not ARNs or patterns")

# 예: {"example-bucket": ["critical/", "backup/"]}
# PROTECTED_BUCKETS에 포함된 버킷은 모든 객체가 보호됩니다.
# Prefix만 보호하려면 PROTECTED_BUCKETS에서 해당 버킷을 제외하세요.
try:
    PROTECTED_S3_PREFIXES = json.loads(os.environ.get("PROTECTED_S3_PREFIXES", "{}"))
except json.JSONDecodeError as error:
    raise ValueError("PROTECTED_S3_PREFIXES must be a JSON object") from error
if not isinstance(PROTECTED_S3_PREFIXES, dict):
    raise ValueError("PROTECTED_S3_PREFIXES must be a JSON object")
for _bucket, _prefixes in PROTECTED_S3_PREFIXES.items():
    if not _bucket or "/" in _bucket or ":" in _bucket or "*" in _bucket:
        raise ValueError("PROTECTED_S3_PREFIXES keys must be bucket names")
    if not isinstance(_prefixes, list) or any(
        not isinstance(prefix, str) or not prefix for prefix in _prefixes
    ):
        raise ValueError("PROTECTED_S3_PREFIXES values must be lists of non-empty literal prefixes")

# 선택 항목: 특정 객체만 보호할 경우 s3://bucket/exact-key 형식으로 지정합니다.
PROTECTED_S3_OBJECTS = set(load_s3_string_list("PROTECTED_S3_OBJECTS"))
if any(
    not value.startswith("s3://") or not value[5:].partition("/")[2]
    for value in PROTECTED_S3_OBJECTS
):
    raise ValueError("PROTECTED_S3_OBJECTS must contain s3://bucket/exact-key values")

REQUIRED_PUBLIC_ACCESS_BLOCK_SETTINGS = (
    "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"
)


def s3_dict(value):
    return value if isinstance(value, dict) else {}


def s3_field(mapping, name):
    """CloudTrail과 SDK 필드명의 대소문자 차이를 처리합니다. 값은 변경하지 않습니다."""
    mapping = s3_dict(mapping)
    if name in mapping:
        return mapping[name]
    lowered = name.lower()
    return next((value for key, value in mapping.items()
                 if isinstance(key, str) and key.lower() == lowered), None)


def s3_rows(value):
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]
    return [value] if isinstance(value, dict) else []


def s3_delete_rows(request):
    """DeleteObjects 요청의 삭제 대상 목록. CloudTrail은 objects/object를 섞어 씁니다."""
    delete = s3_dict(s3_field(request, "delete"))
    rows = s3_field(delete, "objects")
    if rows is None:
        rows = s3_field(delete, "object")
    return s3_rows(rows)


def s3_object_is_protected(bucket, key):
    if bucket in PROTECTED_BUCKETS:
        return True
    if key is None:
        return False
    return (
        f"s3://{bucket}/{key}" in PROTECTED_S3_OBJECTS
        or any(key.startswith(prefix) for prefix in PROTECTED_S3_PREFIXES.get(bucket, []))
    )


def extract_s3_targets(normalized_event):
    """일반 목적 S3 버킷/객체를 추출합니다. Access Point ARN은 추측해서 변환하지 않습니다."""
    details = s3_dict(normalized_event.get("details"))
    request = s3_dict(details.get("request_parameters"))
    bucket = s3_field(request, "bucketName")
    bucket = bucket if isinstance(bucket, str) and bucket else None
    buckets = set()
    objects = set()
    if bucket:
        buckets.add(bucket)
        key = s3_field(request, "key")
        if isinstance(key, str):
            objects.add((bucket, key))
        for row in s3_delete_rows(request):
            key = s3_field(row, "key")
            if isinstance(key, str):
                objects.add((bucket, key))

    for resource in normalized_event.get("resources") or []:
        if not isinstance(resource, dict):
            continue
        arn = resource.get("arn") or resource.get("ARN")
        if not isinstance(arn, str):
            continue
        parts = arn.split(":", 5)
        if len(parts) != 6 or parts[0] != "arn" or parts[2] != "s3" or parts[3] or parts[4]:
            continue
        resource_bucket, separator, key = parts[5].partition("/")
        # 요청 대상 버킷이 있으면 다른 버킷의 리소스를 매칭하지 않습니다.
        if not resource_bucket or (bucket and resource_bucket != bucket):
            continue
        buckets.add(resource_bucket)
        if separator:
            objects.add((resource_bucket, key))
    return sorted(buckets), sorted(objects)


def s3_source_ip_condition(team_status):
    """팀 CIDR 판정 결과를 근거 문자열로 옮깁니다."""
    if team_status is True:
        return "SOURCE_IP_INSIDE_TEAM_CIDRS"
    if team_status is False:
        return "SOURCE_IP_OUTSIDE_TEAM_CIDRS"
    return "SOURCE_IP_TEAM_STATUS_UNKNOWN"


def s3_boolean(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "false"}:
        return value.lower() == "true"
    return None


def make_s3_evaluation(rule, conditions, context, classification=None):
    result_class = classification or (rule["classification"] if rule else "NO_MATCH")
    # REVIEW로 낮춰 보낼 때 룰이 별도 표현을 정의했으면 그 값으로 덮어씁니다.
    view = rule or {}
    if rule and classification == "REVIEW":
        view = {**rule, **rule.get("review_variant", {})}
    return {
        "evaluation_schema_version": "1.0",
        "evaluated_at": utc_now(),
        "classification": result_class,
        # S3 룰은 합의한 기본 점수를 유지합니다. 외부 IP는 근거로만 기록합니다.
        "risk_score": view["base_score"] if rule else 0,
        "severity": rule["severity"] if rule else "INFORMATIONAL",
        "human_review_required": result_class in {"REVIEW", "FINDING"},
        "rule_id": rule["rule_id"] if rule else None,
        "title": view["title"] if rule else None,
        "description": view["description"] if rule else None,
        "recommended_action": [rule["recommended_action"]] if rule else [],
        "matched_conditions": conditions,
        "context": context,
    }


def evaluate_s3_event(normalized_event):
    event = normalized_event["event"]
    outcome = normalized_event["outcome"]
    source_ip = s3_dict(normalized_event.get("source")).get("ip")
    team_status = source_ip_team_status(source_ip)
    buckets, objects = extract_s3_targets(normalized_event)
    context = {
        "source_ip": source_ip,
        "source_ip_in_team_cidrs": team_status,
        "detected_bucket_names": buckets,
        "detected_objects": [{"bucket": bucket, "key": key} for bucket, key in objects],
        "protected_buckets": sorted(PROTECTED_BUCKETS),
        "protected_s3_prefixes": PROTECTED_S3_PREFIXES,
        "approval_exception_check": "NOT_IMPLEMENTED",
    }
    conditions = []
    rule = S3_EVENT_RULES.get(event["action"])

    def no_match(reason):
        return make_s3_evaluation(None, conditions + [reason], context)

    if event["service"] != "s3.amazonaws.com":
        return no_match("NOT_S3_SERVICE")
    if outcome.get("status") != "SUCCESS" or outcome.get("error_code"):
        return no_match("API_CALL_NOT_SUCCESSFUL")
    if rule is None:
        return no_match("ACTION_NOT_IN_S3_RULESET")
    if not rule["enabled"] or rule["rule_id"] == "AWS-S3-010":
        context["disabled_rule_id"] = rule["rule_id"]
        return no_match("S3_RULE_DISABLED")
    if not buckets:
        return no_match("S3_TARGET_NOT_IDENTIFIED")

    if rule["rule_id"] in {"AWS-S3-008", "AWS-S3-009"}:
        if team_status is True:
            return no_match("SOURCE_IP_INSIDE_TEAM_CIDRS")
        if team_status is None:
            return no_match("SOURCE_IP_TEAM_STATUS_UNKNOWN")

    action = event["action"]
    object_action = action in {"PutObjectAcl", "DeleteObject", "DeleteObjects", "GetObject"}
    protected_objects = [(bucket, key) for bucket, key in objects
                        if s3_object_is_protected(bucket, key)]
    if object_action:
        # 전체 보호 버킷이면 객체 키가 생략된 CloudTrail 이벤트도 REVIEW 대상으로 유지.
        protected = bool(protected_objects) or any(bucket in PROTECTED_BUCKETS for bucket in buckets)
    else:
        protected = any(bucket in PROTECTED_BUCKETS for bucket in buckets)
    if not protected:
        if object_action and not objects and any(
            bucket in PROTECTED_S3_PREFIXES or any(
                uri.startswith(f"s3://{bucket}/") for uri in PROTECTED_S3_OBJECTS
            ) for bucket in buckets
        ):
            conditions.append("S3_OBJECT_KEY_MISSING")
            # Prefix 판별 불가를 정상으로 버리지 않습니다. 매칭 확정은 아니며 검토로 보냅니다.
            context["protection_scope_confirmed"] = False
            return make_s3_evaluation(rule, conditions + ["PROTECTION_SCOPE_REVIEW_REQUIRED"],
                                      context, "REVIEW")
        return no_match("S3_TARGET_NOT_PROTECTED")
    context["protection_scope_confirmed"] = True
    context["matched_protected_objects"] = [
        {"bucket": bucket, "key": key} for bucket, key in protected_objects
    ]


    conditions.extend(["S3_RULE_MATCHED", "API_CALL_SUCCESS", "PROTECTED_S3_TARGET"])
    conditions.append(s3_source_ip_condition(team_status))
    details = s3_dict(normalized_event.get("details"))
    request = s3_dict(details.get("request_parameters"))

    if action == "PutBucketPublicAccessBlock":
        block = s3_dict(s3_field(request, "PublicAccessBlockConfiguration"))
        settings = {name: s3_boolean(s3_field(block, name))
                    for name in REQUIRED_PUBLIC_ACCESS_BLOCK_SETTINGS}
        context["requested_public_access_block"] = settings
        disabled = [name for name, value in settings.items() if value is False]
        context["disabled_required_settings"] = disabled
        if disabled:
            conditions.append("REQUIRED_PUBLIC_ACCESS_BLOCK_SET_FALSE")
        elif all(value is True for value in settings.values()):
            return no_match("REQUIRED_PUBLIC_ACCESS_BLOCK_ENABLED")
        else:
            return make_s3_evaluation(rule, conditions + ["PUBLIC_ACCESS_BLOCK_CONTENT_UNKNOWN"],
                                      context, "REVIEW")
    elif action == "DeleteBucketPublicAccessBlock":
        conditions.append("REQUIRED_PUBLIC_ACCESS_BLOCK_DELETED")

    if action == "DeleteObjects":
        # CloudTrail은 객체별 응답을 생략할 수 있습니다. HTTP/API 성공 != 모든 객체 삭제 성공.
        response = s3_dict(details.get("response_elements"))
        response = s3_dict(s3_field(response, "DeleteResult")) or response
        deleted = s3_field(response, "Deleted")
        errors = s3_field(response, "Errors")
        if errors is None:
            errors = s3_field(response, "Error")
        deleted_rows, error_rows = s3_rows(deleted), s3_rows(errors)
        context["delete_result"] = {
            "deleted": deleted_rows, "errors": error_rows,
            "object_results_available": bool(deleted_rows or error_rows),
        }
        # 버전별 오류를 키 전체의 실패로 확장하지 않도록 (key, versionId)로 비교.
        requested_rows = s3_delete_rows(request)
        failed = {(s3_field(row, "key"), s3_field(row, "versionId")) for row in error_rows}
        request_bucket = s3_field(request, "bucketName")
        protected_requests = [
            row for row in requested_rows
            if isinstance(s3_field(row, "key"), str)
            and s3_object_is_protected(request_bucket, s3_field(row, "key"))
        ]
        if protected_requests and all(
            (s3_field(row, "key"), s3_field(row, "versionId")) in failed
            for row in protected_requests
        ) and not deleted_rows:
            return no_match("ALL_IDENTIFIED_PROTECTED_DELETES_FAILED")
        conditions.append(
            "BATCH_DELETE_RESULTS_REQUIRE_REVIEW" if deleted_rows or error_rows
            else "OBJECT_DELETE_RESULTS_NOT_CONFIRMED"
        )
    elif action == "DeleteObject":
        conditions.append("SINGLE_OBJECT_DELETE_API_SUCCESS")
        context["requested_version_id"] = s3_field(request, "versionId")

    if rule["classification"] == "REVIEW":
        conditions.append("CONTENT_OR_CONTEXT_REVIEW_REQUIRED")
    return make_s3_evaluation(rule, conditions, context)


def evaluate_security_event(normalized_event):
    if normalized_event["event"]["service"] == "s3.amazonaws.com":
        return evaluate_s3_event(normalized_event)
    return evaluate_cloudtrail_event(normalized_event)


def lambda_handler(event, context):
  # normalized_event가 있으면 벗겨내고, 없으면 정규화 본문으로 간주 
  normalized_event = extract_normalized_event(event)
  # normalized_event 검증 함수 
  validate_normalized_event(normalized_event)

  # 위험도 분석
  evaluation = evaluate_security_event(normalized_event)

  # S3 경로 설계 및 영구 적재 
  saved_key = save_evaluation_result(normalized_event, evaluation)

  result = {
    "statusCode": 200,
    "event_id": normalized_event["event"]["id"],
    "classification": evaluation["classification"],
    "risk_score": evaluation["risk_score"],
    "severity": evaluation["severity"],
    "rule_id": evaluation["rule_id"],
    "saved_bucket": RESULT_BUCKET,
    "saved_key": saved_key,
  }

  print(json.dumps(result, ensure_ascii=False))
  
  return result



