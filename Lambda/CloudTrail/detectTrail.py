import json
import os
import time
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# 30분: CloudTrail은 최대 15분 지연 조회라 5분이면 누락 (eventID 중복제거로 안전)
LOOKBACK_MINUTES = int(os.environ.get("LOOKBACK_MINUTES", "30"))
ALERT_BUCKET = os.environ["ALERT_BUCKET"]
ALERT_PREFIX = os.environ.get(
  "ALERT_PREFIX",
  "cloudtrail/alert",
).strip("/")

s3 = boto3.client("s3")

cloudtrail = boto3.client(
    "cloudtrail",
    config=Config(
        retries={
            "max_attempts": 3,
            "mode": "standard",
        }
    ),
)

TARGET_EVENT_NAMES = [
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",
    "PutEventSelectors",
    "PutInsightSelectors",
    # ↓ 추가: GuardDuty 무력화 (# 줄은 구분용 주석일 뿐, 아래 4개 전부 활성 탐지 대상)
    "UpdateDetector",    # enable=false = 탐지 중단 — 이번 공격 시나리오에서 실제 사용됨
    "DeleteDetector",    # 디텍터 삭제 (복구 불가)
    # ↓ 추가: GuardDuty Finding 은폐 — 탐지는 살려두고 경보만 숨기는 행위
    "CreateFilter",
    "UpdateFilter",
]


def classify_event(event_name, request_parameters):
    """
    이벤트 + 파라미터 조합으로 위험도와 행위 종류를 판정한다.
    반환: {"severity": int, "action_kind": str, "note": str | None}

    action_kind: DISABLE | ENABLE | DELETE | MODIFY | SUPPRESS
    severity: 1~10

    enable=true(켜기) 이벤트도 버리지 않고 severity만 낮게 부여한다.
    공격자가 GuardDuty를 껐다 켜서 흔적을 은폐하는 기법(anti-forensics)에서
    켜기 기록이 없으면 감시 공백 구간(blind window)을 계산할 수 없다.
    """
    request_parameters = request_parameters or {}

    if event_name == "UpdateDetector":
        enable = request_parameters.get("enable")
        if enable is False:
            return {
                "severity": 9,
                "action_kind": "DISABLE",
                "note": "GuardDuty 탐지 중단",
            }
        if enable is True:
            return {
                "severity": 5,
                "action_kind": "ENABLE",
                "note": "재활성화 — HITL 승인 기록과 대조 필요",
            }
        # enable 파라미터 없음 = features/dataSources 등 부분 설정 변경
        return {
            "severity": 7,
            "action_kind": "MODIFY",
            "note": "부분 설정 변경 — 개별 기능 비활성화 가능성",
        }

    if event_name == "UpdateTrail":
        # 로깅 범위를 축소하는 변경만 고위험
        narrowing = (
            request_parameters.get("includeGlobalServiceEvents") is False
            or request_parameters.get("isMultiRegionTrail") is False
            or request_parameters.get("enableLogFileValidation") is False
        )
        return {
            "severity": 8 if narrowing else 5,
            "action_kind": "DISABLE" if narrowing else "MODIFY",
            "note": "로깅 범위 축소" if narrowing else "Trail 설정 변경",
        }

    if event_name in ("DeleteTrail", "DeleteDetector"):
        return {
            "severity": 10,
            "action_kind": "DELETE",
            "note": "복구 불가 — 즉시 대응 필요",
        }

    if event_name == "StopLogging":
        return {
            "severity": 9,
            "action_kind": "DISABLE",
            "note": "CloudTrail 로깅 중단",
        }

    if event_name in ("CreateFilter", "UpdateFilter"):
        return {
            "severity": 6,
            "action_kind": "SUPPRESS",
            "note": "Finding 억제 규칙 — 정상 오탐 억제일 수 있음",
        }

    if event_name in ("PutEventSelectors", "PutInsightSelectors"):
        return {
            "severity": 7,
            "action_kind": "MODIFY",
            "note": "로깅 대상 셀렉터 변경",
        }

    return {"severity": 5, "action_kind": "MODIFY", "note": None}

def lookup_events(event_name, start_time, end_time):
    detected_events = []
    next_token = None

    while True:
        request = {
            "LookupAttributes": [
                {
                    "AttributeKey": "EventName",
                    "AttributeValue": event_name,
                }
            ],
            "StartTime": start_time,
            "EndTime": end_time,
            "MaxResults": 50,
        }

        # 다음 페이지 토큰이 존재하면 이어서 조회
        if next_token:
            request["NextToken"] = next_token

        ############# **request 문법 예제 시작 #############
        # **request는 딕셔너리의 키와 값을 함수의 이름 있는 인자로
        # 풀어 전달하는 Python 문법
        #
        # 아래 두 호출은 같은 의미이다.
        #
        # 1. 딕셔너리를 **로 풀어서 전달
        # cloudtrail.lookup_events(**request)
        #
        # 2. 각 인자를 직접 전달
        # cloudtrail.lookup_events(
        #     LookupAttributes=request["LookupAttributes"],
        #     StartTime=request["StartTime"],
        #     EndTime=request["EndTime"],
        #     MaxResults=request["MaxResults"],
        # )
        ############# **request 문법 예제 끝 #############

        response = cloudtrail.lookup_events(**request)

        ############# CloudTrail 응답 구조 예제 시작 #############
        # lookup_events()의 응답은 딕셔너리이며,
        # 조회된 이벤트는 Events 배열에 들어 있다.
        # 다음 페이지가 있으면 NextToken도 함께 반환된다.
        #
        # {
        #     "Events": [
        #         {
        #             "EventId": "...",
        #             "EventName": "StopLogging",
        #             "EventTime": ...,
        #             "CloudTrailEvent": "{...JSON 문자열...}",
        #         }
        #     ],
        #     "NextToken": "다음 페이지 토큰",
        # }
        ############# CloudTrail 응답 구조 예제 끝 #############

        for event in response.get("Events", []):
            raw_event = json.loads(event["CloudTrailEvent"])

            classification = classify_event(
                raw_event.get("eventName"),
                raw_event.get("requestParameters"),
            )

            detected_events.append(
                {
                    "event_time": raw_event.get("eventTime"),
                    "event_id": raw_event.get("eventID") or event.get("EventId"),
                    "event_source": raw_event.get("eventSource"),
                    "event_name": raw_event.get("eventName"),
                    "account_id": raw_event.get("recipientAccountId"),
                    "region": raw_event.get("awsRegion"),
                    "user_identity": raw_event.get("userIdentity"),
                    "source_ip": raw_event.get("sourceIPAddress"),
                    "user_agent": raw_event.get("userAgent"),
                    "request_parameters": raw_event.get("requestParameters"),
                    "error_code": raw_event.get("errorCode"),
                    "error_message": raw_event.get("errorMessage"),
                    "severity": classification["severity"],
                    "action_kind": classification["action_kind"],
                    "classification_note": classification["note"],
                    "target_service": (
                        "guardduty"
                        if "Detector" in (raw_event.get("eventName") or "")
                        or "Filter" in (raw_event.get("eventName") or "")
                        else "cloudtrail"
                    ),
                }
            )

        # 다음 페이지가 있다면 다음 페이지 토큰을 저장
        next_token = response.get("NextToken")

        # 다음 페이지가 없다면 반복문 정지
        if not next_token:
            break

        # API 호출 제한을 고려
        time.sleep(0.6)

    return detected_events


# 구조 
# CloudTrail 변조 이벤트가 없음
# → 아무것도 하지 않음
# 
# CloudTrail 변조 이벤트가 있음
# → eventID로 S3 객체 존재 여부 확인
# 
# 같은 eventID 객체가 없음
# → 새 JSON 파일 저장
# 
# 같은 eventID 객체가 이미 있음
# → 중복으로 판단하고 버림

def lambda_handler(event,context):
  end_time = datetime.now(timezone.utc)

  # 환경 변수의 LOOKBACK_MINUTES 만큼 현재 시각에서 뺌
  start_time = end_time - timedelta(
    minutes=LOOKBACK_MINUTES
  )

  # 탐지 이벤트를 담을 배열
  detected_events = []

  # 위에서 선언한 리스트에서 하나씩 뺌
  # enumerate를 사용하면 순서번호와 값이 함께 나옴 -> index=0, event_name=StopLogging
  for index, event_name in enumerate(TARGET_EVENT_NAMES):
    # 이벤트 조회 결과 합치기
    detected_events.extend(
      lookup_events(
        event_name = event_name, 
        start_time = start_time, 
        end_time = end_time
      )
    )

    # CloudTrail LookupEvent 호출 제한 고려, 마지막 이벤트가 아니라면 다음 API 호출 전에 0.6초 기다린다 
    if index < len(TARGET_EVENT_NAMES) -1:
      time.sleep(0.6)

  saved_count = 0     # saved_count : S3에 새로 저장한 이벤트 수
  skipped_count = 0   # skipped_count : 이미 있어서 건너뛴 이벤트 수 

  for detected_event in detected_events:
    event_id = detected_event["event_id"]

    object_key = (
      f"{ALERT_PREFIX}/"
      f"{event_id}.json"
    )

    # 같은 eventID 파일이 이미 있는지 확인
    try:
      # head_object()는 파일 내용을 다운로드하지 않고 객체가 존재하는지만 확인
      s3.head_object(
        Bucket = ALERT_BUCKET,
        Key = object_key
      )

      # 이미 파일이 있는 경우 
      skipped_count += 1
      continue

    # 객체가 없을 경우 오류 처리
    except ClientError as error:
      status_code = error.response[
        "ResponseMetadata"
      ]["HTTPStatusCode"]

      # 파일이 없다는 오류만 정상 처리
      if status_code != 404:
        raise

    body = json.dumps(
      detected_event,
      ensure_ascii=False,
      indent=2
    )

    s3.put_object(
      Bucket = ALERT_BUCKET,
      Key = object_key,
      Body = body.encode("utf-8"),
      ContentType = "application/json",
      ServerSideEncryption = "AES256"
    )

    saved_count += 1

  return {
    "statusCode": 200,
    "detected_count": len(detected_events),
    "saved_count": saved_count,
    "skipped_count": skipped_count
  }