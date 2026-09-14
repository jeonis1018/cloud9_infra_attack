"""GuardDuty rules extracted from origin/main; CloudTrail/S3 rules remain unchanged."""
import json
import os
from datetime import datetime, timezone
from cloudtrail_s3_rules import (s3, utc_now, source_ip_team_status,
    classification_from_score, extract_trail_names, PROTECTED_TRAILS)
RESULT_BUCKET = os.environ["RESULT_BUCKET"]
NORMAL_PREFIX = os.environ.get("GUARDDUTY_NORMAL_PREFIX", "guardduty/normal").strip("/")
REVIEW_PREFIX = os.environ.get("GUARDDUTY_REVIEW_PREFIX", "guardduty/review").strip("/")
FINDING_PREFIX = os.environ.get("GUARDDUTY_FINDING_PREFIX", "guardduty/findings").strip("/")
GUARDDUTY_TAMPERING_RULES = {
    "UpdateDetector": {
        "rule_id": "AWS-GDT-001",
        "title": "GuardDuty 디텍터 설정 변경",
        "description": (
            "GuardDuty 디텍터 설정이 변경되었습니다. 탐지를 중단시키는 "
            "무력화 행위일 수 있습니다."
        ),
        "base_score": 90,
        "severity": "HIGH",
        "recommended_action": (
            "enable 값과 호출 주체를 확인하고, 디텍터가 꺼진 구간 동안의 "
            "CloudTrail 로그를 별도로 점검하세요."
        ),
    },
    "DeleteDetector": {
        "rule_id": "AWS-GDT-002",
        "title": "GuardDuty 디텍터 삭제",
        "description": (
            "GuardDuty 디텍터가 삭제되어 위협 탐지가 완전히 중단되었습니다."
        ),
        "base_score": 100,
        "severity": "CRITICAL",
        "recommended_action": (
            "삭제 승인 여부를 즉시 확인하고 디텍터를 복구하세요. "
            "삭제 이후 구간은 탐지 공백으로 간주해야 합니다."
        ),
    },
    "CreateFilter": {
        "rule_id": "AWS-GDT-003",
        "title": "GuardDuty 억제 필터 생성",
        "description": (
            "Finding 억제 규칙이 생성되었습니다. 탐지는 유지한 채 "
            "경보만 숨기는 은폐 행위일 수 있습니다."
        ),
        "base_score": 60,
        "severity": "MEDIUM",
        "recommended_action": (
            "필터 조건이 어떤 파인딩을 가리는지 확인하세요."
        ),
    },
    "UpdateFilter": {
        "rule_id": "AWS-GDT-004",
        "title": "GuardDuty 억제 필터 변경",
        "description": (
            "Finding 억제 규칙이 변경되었습니다."
        ),
        "base_score": 60,
        "severity": "MEDIUM",
        "recommended_action": (
            "변경 전후 필터 조건과 변경 승인 내역을 확인하세요."
        ),
    },
}


GUARDDUTY_RULES = {
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS": {
        "rule_id": "AWS-GD-001",
        "title": "EC2 인스턴스 자격 증명 외부 사용",
        "description": (
            "EC2 인스턴스 전용으로 발급된 임시 자격 증명이 AWS 외부 IP에서 "
            "사용되었습니다. 자격 증명 탈취 가능성이 높습니다."
        ),
        "base_score": 95,
        "severity": "CRITICAL",
        "recommended_action": (
            "해당 역할의 기존 세션을 무효화하고, 인스턴스의 IMDS 설정과 "
            "SSRF 취약점을 즉시 점검하세요."
        ),
    },
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS": {
        "rule_id": "AWS-GD-002",
        "title": "EC2 인스턴스 자격 증명 타 계정 사용",
        "description": (
            "EC2 인스턴스 자격 증명이 다른 AWS 계정에서 사용되었습니다."
        ),
        "base_score": 90,
        "severity": "CRITICAL",
        "recommended_action": (
            "호출 계정을 확인하고 해당 역할의 기존 세션을 무효화하세요."
        ),
    },
    "Exfiltration:S3/AnomalousBehavior": {
        "rule_id": "AWS-GD-003",
        "title": "S3 데이터 반출 이상 행위",
        "description": (
            "평소와 다른 규모나 패턴의 S3 객체 반출이 탐지되었습니다."
        ),
        "base_score": 85,
        "severity": "HIGH",
        "recommended_action": (
            "대상 버킷의 접근 로그와 반출된 객체 목록을 확인하세요."
        ),
    },
    "Discovery:S3/AnomalousBehavior": {
        "rule_id": "AWS-GD-004",
        "title": "S3 정찰 이상 행위",
        "description": (
            "버킷 목록 조회 등 평소와 다른 S3 탐색 행위가 탐지되었습니다."
        ),
        "base_score": 60,
        "severity": "MEDIUM",
        "recommended_action": (
            "호출 주체가 정상 업무 범위인지 확인하세요."
        ),
    },
    "CredentialAccess:IAMUser/AnomalousBehavior": {
        "rule_id": "AWS-GD-005",
        "title": "자격 증명 접근 이상 행위",
        "description": (
            "자격 증명 관련 API 호출에서 평소와 다른 패턴이 탐지되었습니다."
        ),
        "base_score": 75,
        "severity": "HIGH",
        "recommended_action": (
            "호출 주체와 대상 자격 증명의 사용 이력을 확인하세요."
        ),
    },
}


def guardduty_severity_baseline(finding_severity):
  # GuardDuty 자체 심각도(1.0~8.9)를 점수와 등급의 기본선으로 환산한다
  if finding_severity is None:
    return 0, "INFORMATIONAL"

  if finding_severity >= 7:
    return 70, "HIGH"

  if finding_severity >= 4:
    return 40, "MEDIUM"

  return 10, "LOW"


def evaluate_guardduty_event(normalized_event):
  event_data = normalized_event["event"]
  source_data = normalized_event.get("source") or {}
  details = normalized_event.get("details") or {}
  finding = details.get("finding") or {}
  target_resource = details.get("target_resource") or {}

  finding_type = event_data["action"]
  finding_severity = finding.get("severity")
  source_ip = source_data.get("ip")

  # 호출자 ip가 팀 내 공인 ip인지 확인
  source_ip_team_cidrs = source_ip_team_status(source_ip)

  matched_rule = None
  matched_conditions = []

  risk_score, severity = guardduty_severity_baseline(finding_severity)
  matched_conditions.append("GUARDDUTY_SEVERITY_BASELINE")

  # 룰셋에 정의된 파인딩 타입이면 기본선 대신 룰 점수를 적용한다
  if finding_type in GUARDDUTY_RULES:
    matched_rule = GUARDDUTY_RULES[finding_type]
    risk_score = max(risk_score, matched_rule["base_score"])
    severity = matched_rule["severity"]
    matched_conditions.append("GUARDDUTY_RULE_MATCHED")

  else:
    matched_conditions.append("FINDING_TYPE_NOT_IN_GUARDDUTY_RULESET")

  # 이미 보관 처리된 파인딩은 재확인 대상임을 표시만 남긴다
  if finding.get("archived") is True:
    matched_conditions.append("FINDING_ARCHIVED")

  # 팀원 IP가 아닌 외부 IP에서 발생했다면 가산점 +10점
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
    "title": matched_rule["title"] if matched_rule else finding.get("title"),
    "description": (
      matched_rule["description"] if matched_rule else finding.get("description")
    ),
    "recommended_action": (
      matched_rule["recommended_action"] if matched_rule else None
    ),
    "matched_conditions": matched_conditions,
    "context":{
      "source_ip": source_ip,
      "source_ip_in_team_cidrs": source_ip_team_cidrs,
      "finding_type": finding_type,
      "guardduty_severity": finding_severity,
      "detector_id": finding.get("detector_id"),
      "target_instance_id": target_resource.get("instance_id"),
      "target_role_name": target_resource.get("role_name"),
    },
  }


TAMPERING_RULES_BY_SERVICE = {"guardduty.amazonaws.com": GUARDDUTY_TAMPERING_RULES}
def evaluate_guardduty_tampering(normalized_event):
  event_data = normalized_event["event"]
  outcome_data = normalized_event["outcome"]
  source_data = normalized_event.get("source") or {}

  action = event_data["action"]
  service = event_data["service"]
  outcome_status = outcome_data.get("status")
  source_ip = source_data.get("ip")

  # UpdateDetector의 enable 값처럼 호출 파라미터로 위험도가 갈리는 경우에 쓴다
  request_parameters = (
    (normalized_event.get("details") or {}).get("request_parameters") or {}
  )

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

  # 호출된 서비스에 맞는 룰셋을 고른다 (CloudTrail 무력화 / GuardDuty 무력화)
  service_ruleset = TAMPERING_RULES_BY_SERVICE.get(service)

  if service_ruleset is None:
    matched_conditions.append("NOT_DETECTION_SERVICE")
  elif outcome_status != "SUCCESS" or outcome_data.get("error_code"):
    matched_conditions.append("API_CALL_NOT_SUCCESSFUL")
  # 룰셋에 등록된 핵심 파괴행동이 아니면 탈락
  elif action not in service_ruleset:
    matched_conditions.append("ACTION_NOT_IN_RULESET")

  # 지정한 보호 Trail이 아니면 탈락
  # GuardDuty 무력화 이벤트에는 Trail이 없으므로 CloudTrail 이벤트에만 적용한다
  elif (
    service == "cloudtrail.amazonaws.com"
    and not set(trail_names).intersection(PROTECTED_TRAILS)
  ):
    matched_conditions.append("TRAIL_NOT_PROTECTED")

  # 룰 적중시 동작 로직
  else:
    # 룰셋 정의대로 기본 점수 및 심각도 부여
    matched_rule = service_ruleset[action]
    risk_score = matched_rule["base_score"]
    severity = matched_rule["severity"]

    matched_conditions.extend(
      [
        "TAMPERING_RULE_MATCHED",
        "API_CALL_SUCCESS",
      ]
    )

    if service == "cloudtrail.amazonaws.com":
      matched_conditions.append("PROTECTED_TRAIL")

    # UpdateDetector는 끄기와 켜기가 같은 이벤트 이름이라 파라미터로 구분한다.
    # 켜기(재활성화)도 버리지 않고 낮은 점수로 남겨야 감시 공백 구간을 계산할 수 있다
    if action == "UpdateDetector":
      enable = request_parameters.get("enable")

      if enable is False:
        matched_conditions.append("GUARDDUTY_DETECTOR_DISABLED")

      elif enable is True:
        risk_score = 35
        severity = "MEDIUM"
        matched_conditions.append("GUARDDUTY_DETECTOR_REENABLED")

      else:
        risk_score = 70
        severity = "HIGH"
        matched_conditions.append("GUARDDUTY_DETECTOR_PARTIAL_UPDATE")

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
      "event_service": service,
      "source_ip": source_ip,
      "source_ip_in_team_cidrs": source_ip_team_cidrs,
      "detected_trail_names": trail_names,
      "protected_trails": sorted(PROTECTED_TRAILS),
      # GuardDuty 무력화 이벤트에서 어느 디텍터가 대상이었는지
      "detector_id": request_parameters.get("detectorId"),
    },
  }

def prefix_from_classification(classification):
  if classification == "FINDING":
    return FINDING_PREFIX

  if classification == "REVIEW":
    return REVIEW_PREFIX

  return NORMAL_PREFIX


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

