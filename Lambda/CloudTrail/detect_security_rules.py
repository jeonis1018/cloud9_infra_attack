import json
import os
import ipaddress
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

PROTECTED_TRAILS = set(load_json_list_environment("PROTECT_TRAILS", ["Managed-role"]))

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

  for resource in normalized_event.get("resource") or normalized_event.get("recources") or[]:
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
  elif outcome_status != "SUCCESS":
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
  classification = classification_from_score(risk_score)

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
    "recommended_action":(
      matched_rule["recommended_action"] if matched_rule else None,
    ),
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
  event_time = event_data["time"]

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

def lambda_handler(event, context):
  # normalized_event가 있으면 벗겨내고, 없으면 정규화 본문으로 간주 
  normalized_event = extract_normalized_event(event)
  # normalized_event 검증 함수 
  validate_normalized_event(normalized_event)

  # 위험도 분석
  evaluation = evaluate_cloudtrail_event(normalized_event)

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