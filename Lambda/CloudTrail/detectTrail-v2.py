import json
import os
import time
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config

# 코드 로직 
# ============================================================
# 코드 로직

# 1. EventBridge Scheduler가 정해진 주기로 Lambda 호출
# 2. 최근 LOOKBACK_MINUTES 범위의 CloudTrail Event History 조회
# 3. 보안 이벤트 이름에 해당하는 이벤트만 선별
# 4. eventID 기준으로 이번 실행 내 중복 제거
# 5. CloudTrailEvent JSON 문자열을 원본 레코드로 변환
# 6. normalize-cloudtrail-logs-v2 Lambda에 비동기 전달

# 이 Lambda는 S3에 직접 저장하지 않는다.
# 정규화와 저장은 normalize-cloudtrail-logs-v2가 담당한다.
# ============================================================

cloudtrail = boto3.client(
  "cloudtrail",
  config=Config(
        retries={
            "max_attempts": 3,
            "mode": "standard",
        }
    ),
  )

lambda_client = boto3.client("lambda")

# EventBridge Scheduler 1분마다 호출, 로그 5분 조회 
# 중복 시 버림

LOOKBACK_MINUTES = int(
  os.environ.get("LOOKBACK_MINUTES", "5")
)

NORMALIZER_FUNCTION_NAME = os.environ["NORMALIZER_FUNCTION_NAME"]

TARGET_EVENT_NAMES = [
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",
    "PutEventSelectors",
    "PutInsightSelectors",
]

def lookup_events(event_name, start_time, end_time):
  # cloudtrail Event History에서 event_name을 조회하고, 
  # 페이지가 여러개라면, NextToken을 이용하여 처리한다 

  events = []
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
    ############# **request 문법 예제 끝 ############
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
    events.extend(response.get("Events",[]))

    next_token = response.get("NextToken")

    if not next_token:
      break 

    # CloudTrail API 호출 제한을 고려한 짧은 시간 대기
    time.sleep(0.6)

  return events

def get_cloudtrail_record(lookup_event):
  # LookupEvents 응답의 CloudTrailEvent JSON 문자열을 Python 딕셔너리로 변환한다 

  # 원시 로그의 형태
  # {
  #   "EventId": "b1a2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
  #   "EventName": "StopLogging",
  #   "ReadOnly": "false",
  #   "AccessKeyId": "ASIAEXAMPLEKEY999",
  #   "EventTime": datetime.datetime(2026, 9, 11, 4, 30, 0, tzinfo=tzutc()),
  #   "Username": "SecOps-Admin",
  #   "Resources": [],
  #   # 핵심 상세 정보가 JSON 텍스트(문자열)로 묶여 있음
  #   "CloudTrailEvent": "{\"eventVersion\":\"1.08\",\"userIdentity\":{\"type\":\"AssumedRole\",\"principalId\":\"AROAEXAMPLE:SecOps-Admin\",\"arn\":\"arn:aws:sts::123456789012:assumed-role/SecOpsRole/SecOps-Admin\",\"accountId\":\"123456789012\"},\"eventTime\":\"2026-09-11T04:30:00Z\",\"eventSource\":\"cloudtrail.amazonaws.com\",\"eventName\":\"StopLogging\",\"awsRegion\":\"ap-northeast-2\",\"sourceIPAddress\":\"203.0.113.50\",\"requestParameters\":{\"name\":\"arn:aws:cloudtrail:ap-northeast-2:123456789012:trail/Audit-Main-Trail\"},\"eventID\":\"b1a2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d\",\"eventType\":\"AwsApiCall\",\"recipientAccountId\":\"123456789012\"}"
  # }

  raw_event = lookup_event.get("CloudTrailEvent") or lookup_event.get("cloudTrailEvent")

  if not raw_event:
    return None

  if isinstance(raw_event, str):
    return json.loads(raw_event)

  return raw_event


def invoke_normalizer(record, lookup_event_id):
  # 정규화 Lambda에 Event History 형식의 입력을 전달한다

  payload = {
    "record": record,  # 파싱된 실제 CloudTrail 로그 본준
    "lookup_event_id": lookup_event_id,
  }

  # 비동기 호출을 한다
  response = lambda_client.invoke(
    FunctionName = NORMALIZER_FUNCTION_NAME,
    InvocationType = "Event",
    Payload = json.dumps(payload).encode("utf-8"),
  )

  return response

def lambda_handler(event, context):
  # EventBridge Scheduler가 호출하는 Lambda 진입점 

  # 현재 시각부터 5분전까지의 시간 윈도우를 계산한다 -> CloudAPI 지연으로 인한 로그 누락 방지 
  end_time = datetime.now(timezone.utc)
  start_time = end_time - timedelta(minutes=LOOKBACK_MINUTES)

  lookup_events_count = 0
  selected_events = []
  seen_event_ids = set()

  # ["StopLogging", "DeleteTrail", ...] 목록을 하나씩 돌면서 CloudTrail에 조회를 요청한다 
  for index, event_name in enumerate(TARGET_EVENT_NAMES):
    events = lookup_events(
      event_name = event_name,
      start_time = start_time,
      end_time = end_time,  
    )

    lookup_events_count += len(events)

    # 중복 제거 및 데이터 파싱
    # 5분 단위로 조회하면 같은 이벤트가 반복 조회되기 때문에, seen_event_ids 집합을 둔다 
    # event가 seen_event_ids에 있다면, 건너뛴다 
    for lookup_event in events:
      event_id = lookup_event.get("EventId")

      # EventID가 없으면 안전하게 건너 뜀 
      if not event_id:
        continue

      # 이번 Lambda 실행 안에서 같은 이벤트가 다시 나오면 건너 뜀 
      if event_id in seen_event_ids:
        continue

      seen_event_ids.add(event_id)
      record = get_cloudtrail_record(lookup_event)

      if not record:
        continue

      selected_events.append(
        {
          "event_id": event_id,
          "record": record,
        }
      )

    # 여러 이벤트 이름을 연속으로 조회할 때 API 제한 고려
    if index < len(TARGET_EVENT_NAMES) - 1:
      time.sleep(0.6)

  invoked_count = 0
  failed_count = 0

  # 수집된 유일한 로그들을 정규화 Lambda에 InvocationType="Event"로 발송하는 로직
  for selected_event in selected_events:
    try:
      invoke_normalizer(
        record = selected_event["record"],
        lookup_event_id = selected_event["event_id"],
      )

      invoked_count += 1

    except Exception as error:
      failed_count += 1

      print(
            json.dumps(
              {
                  "level": "ERROR",
                  "message": (
                      "Normalizer Lambda invocation failed"
                  ),
                  "event_id": selected_event["event_id"],
                  "error_message": str(error),
              },
              ensure_ascii=False,
            )
          )

  result = {
    "statusCode": 200,
    "lookback_minutes": LOOKBACK_MINUTES,
    "start_time": start_time.isoformat(),
    "end_time": end_time.isoformat(),
    "target_event_names": TARGET_EVENT_NAMES,
    "lookup_events_count": lookup_events_count,
    "deduplicated_event_count": len(selected_events),
    "invoked_count": invoked_count,
    "failed_count": failed_count,
  }

  print(
    json.dumps(
      result,
      ensure_ascii=False,
    )
  )

  return result