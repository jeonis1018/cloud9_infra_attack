# Cloudwatch logs 이벤트 수신
# -> base64 디코딩
# -> GZIP 압축 해제
# -> Cloudtrail JSON 파싱
# -> 공통 필드 추출
# -> Log 출력
# -> S3에 저장

import base64
import gzip
import json
from datetime import datetime, timezone

SCHEMA_VERSION = "2.0"
LOG_TYPE = "cloudtrail"

def utc_now():
  # 현재 UTC 시간을 ISO 8601 형식으로 변환한다.예: 2026-09-10T01:20:30.123456Z
  return(
    datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
  )

def normalize_event_category(value):
  # CloudTrail로그의 eventCategory 값을 공통 표현으로 변환한다. 
  # eventCategory값은 다음과 같다 
  # | eventCategory값 |  콘솔 표기명          | 주요 설명                                           |
  # |-----------------|--------------------|--------------------------------------------------| 
  # | Management      | CloudTrail events  | AWS 리소스의 생성, 삭제, 수정등 제어 평면 작업             |
  # | Data            | CloudTrail events  | S3 객체 접근, Lambda 호출 등 리소스 내부의 데이터 평면 작업  |
  # | NetworkActivity | CloudTrail events  | VPC 엔드포인트를 통하는 프라이빗 네트워크 API 호출 활동      |
  category_map = {
    "Management": "management",
    "Data": "data",
    "NetworkActivity": "network_activity",
  }

  if value is None:
    return None

  # 카테고리에 없는 값인 경우, 소문자 문자열로 변환
  return category_map.get(
    value, str(value).lower()
  )

def resource_id_from_arn(resource_arn):
  # ARN의 마지막 부분을 리소스 ID 후보로 사용한다.
  if not resource_arn:
    return None
  # rsplit은 문자열의 오른쪽부터 지정한 구분자를 기준으로 문자열을 쪼개어 리스트로 반환한다
  if "/" in resource_arn:
    return resource_arn.rsplit("/",1)[-1]
  return resource_arn.rsplit(":", 1)[-1]

def normalize_resource(record):
  """
  CloudTrail 원시 로그의 리소스 정보를 표준화된 딕셔너리 구조로 변환한다.
  
  StopLogging, DeleteTrail 같은 관리 이벤트는 AWS 기본 규격상 'resources' 배열이
  비어 있는 경우가 많으므로, requestParameters.name 필드를 조회해 수동으로 보완해야한다 
  """
  normalized_resources = []
  # 기본 계정 ID 및 리전 추출 (개별 리소스에 누락 시 대체용)
  account_id = record.get("recipientAccountId")
  region = record.get("awsRegion")
  # 1. 기본 resources 배열 파싱 및 표준화
  for resource in record.get("resources") or []:
      # AWS 대소문자 표기 불일치(ARN vs arn) 대응
      resource_arn = resource.get("ARN") or resource.get("arn")
      normalized_resources.append(
          {
              "type": resource.get("type"),
              "id": resource_id_from_arn(resource_arn),
              "arn": resource_arn,
              "account_id": resource.get("accountId") or account_id,
              "region": region,
          }
      )
  # 2. CloudTrail 추적(Trail) 관리 이벤트의 결측 리소스 정보 보완
  event_source = record.get("eventSource")
  event_name = record.get("eventName")
  cloudtrail_management_events = {
      "StopLogging",
      "DeleteTrail",
      "UpdateTrail",
      "PutEventSelectors",
      "PutInsightSelectors",
  }
  # resources 배열이 비어 있고, CloudTrail 자체 설정 변경 이벤트인 경우 실행
  if (
      not normalized_resources
      and event_source == "cloudtrail.amazonaws.com"
      and event_name in cloudtrail_management_events
  ):
      request_parameters = record.get("requestParameters") or {}
      # [참고: requestParameters 로그 예시]
      # 케이스 1 (전체 ARN): {"name": "arn:aws:cloudtrail:ap-northeast-2:123456789012:trail/Main-Trail"}
      # 케이스 2 (단순 이름): {"name": "Main-Trail"}
      trail_name = request_parameters.get("name")
      if trail_name:
          # 입력값이 전체 ARN 형태인지 단순 이름인지 판별하여 처리
          if trail_name.startswith("arn"):
              trail_arn = trail_name
              trail_id = resource_id_from_arn(trail_name)
          else:
              trail_id = trail_name
              # 단순 이름일 경우 표준 ARN 형식으로 조합
              trail_arn = f"arn:aws:cloudtrail:{region}:{account_id}:trail/{trail_name}"
          # 누락되었던 Trail 리소스 정보를 표준 규격으로 직접 생성하여 추가
          normalized_resources.append(
              {
                  "type": "AWS::CloudTrail::Trail",
                  "id": trail_id,
                  "arn": trail_arn,
                  "account_id": account_id,
                  "region": region,
              }
          )
  return normalized_resources

# record : 파싱된 단일 CloudTrail 이벤트 본문
# collection_path : 로그가 어떤 경로를 통해 들어왔는지 나타냄
# collection_source : 수집 주체나 원본 인프라 식별자
# collector : 로그를 수집 및 가공 처리한 엔진 이름 (예 : lambda-cloudtrail-normalizer)
def normalize(record, collection_path, collection_source, collector, 
              log_group = None, log_stream = None, log_event_id = None):
  identity = record.get("userIdentity", {})

  # 루트 계정 및 IAM 계정이 이벤트를 호출한 경우, session_issuer이 남지 않는다 
  # 즉, 임시 자격 증명일때만 남는다 
  session_issuer = (
    identity.get("sessionContext",{}).get("sessionIssuer",{})
  )

  error_code = record.get("errorCode")

  event_id = (
    record.get("eventID") or log_event_id
  )

  if not event_id:
    raise ValueError("CloudTrail event ID is missing")

  if collection_path == "cloudwatch_subscription":
    source_log_type = "cloudwatch"
  else:
    source_log_type = "cloudtrail_event_history"

  return{
    "schema_version": SCHEMA_VERSION,
    "log_type": LOG_TYPE,

    "event":{
      "id": event_id,
      "time": record.get("eventTime"),
      "ingested_at": utc_now(),
      "service":record.get("eventSource"),
      "action": record.get("eventName"),
      "category": normalize_event_category(record.get("eventCategory")),
      "read_only": record.get("readOnly"),
    },

    "cloud":{
      "provider": "aws",
      "account_id": record.get("recipientAccountId"),
      "region": record.get("awsRegion"),
    },

    "actor":{
      "type": identity.get("type"),
      "account_id":identity.get("accountId"),
      "principal_id": identity.get("principalId"),
      "arn": identity.get("arn"),
      "session_issuer_arn": session_issuer.get("arn"),
      "invoked_by": identity.get("invokedBy"),
      "access_key_id": identity.get("accessKeyId"),
    },

    "source":{
      "ip": record.get("sourceIPAddress"),
      "user_agent": record.get("userAgent"),
    },

    "resources":normalize_resource(record),

    "outcome": {
      "status": ("FAILURE" if error_code else "SUCCESS"),
      "error_code": error_code,
      "error_message": record.get("errorMessage")
    },

    "collection":{
      "path": collection_path,
      "source": collection_source,
      "collector": collector,
    },

    "source_log":{
      "type": source_log_type,
      "log_group": log_group,
      "log_stream": log_stream,
      "log_event_id": log_event_id
    },

    "detail":{
      "request_parameters": (record.get("requestParameters") or {}),
      "response_elements": (record.get("responseElements") or {}),
      "additional_event_data": (record.get("additionalEventData") or {})
    }
  }

# CloudWatch Logs 구독 필터 입력을 처리한다 
def handle_cloudwatch_logs(event, context):
  compressed_data = base64.b64decode(event["awslogs"]["data"])
  # 원본 로그 압축을 해제한다 
  #{
  #   "awslogs": {
  #     "data": "H4sICAAAAAAA/1NWssqvKUrMS1Ew0DXSMzY3NzPQNTDSNTKxMLVMTLFMSjMyMTMyNrI0NzQ20gdyU4tLkjPzShRc8osUMvNSi1KLFIxNDc2NzY1NDAwMTAwMzIxNzMz0TI0MDA1NTM0NzU10TQyMTU2MDQ2MjcyNTQ1MTA3NTQ20jE1NDY1NTA00TUx0zc0NDA0Mjcx1bU0sDMzMzcxNDIx0zE1MzU1MTI3NjA31DU3MTczNzM20TI2NDU1NzM3MjM21zc1NDY3MTEwNTYwMTEyMDQ2MjEzMzUxNzEx0Tcx0TE01DE30zMwAA49iO/uAQAA"
  #   }
  # }

  payload = json.loads(gzip.decompress(compressed_data))

  if payload.get("messageType") == "CONTROL_MESSAGE":
    return {
      "statusCode": 200,
      "normalized_count": 0,
      "message": "control message ignored",
    }

  normalized_events = []
  failed_count = 0

  # payload 구조 
  # {
  # "messageType": "DATA_MESSAGE",
  # "owner": "123456789012",
  # "logGroup": "/aws/cloudtrail/management-events",
  # "logStream": "123456789012_CloudTrail_ap-northeast-2",
  # "subscriptionFilters": [
  #   "CloudTrailToLambdaFilter"
  # ],
  # "logEvents": [
  #   {
  #     "id": "38472910481239847192837491823749182374918234",
  #     "timestamp": 1789003230000,
  #     "message": "{\"eventVersion\":\"1.08\",\"userIdentity\":{...},\"eventName\":\"StopLogging\", ...}"
  #   }
  # ]
  #}
  for log_event in payload.get("logEvents", []):
    try:
      record = json.loads(log_event["message"])
      normalized = normalize(
        record = record,
        collection_path = "cloudwatch_subscription",
        collection_source = "cloudwatch",
        collector = context.function_name,
        log_group = payload.get("logGroup"),
        log_stream = payload.get("logStream"),
        log_event_id = log_event.get("id"),
      )

      normalized_events.append(normalized)

      print(
        json.dumps(
          normalized,
          ensure_ascii=False
        )
      )
    except(
      json.JSONDecodeError,
      KeyError,
      TypeError,
      ValueError,
    ) as error:
        failed_count += 1

        print(
          json.dumps(
            {
              "level": "ERROR",
              "message": "CloudTrail Normalization failed",
              "error_message": str(error),
              "log_event_id":(log_event.get("id"))
            },
            ensure_ascii=False,
          )
        )
    return {
      "statusCode": 200,
      "normalized_count": len(normalized_events),
      "failed_count": failed_count,
      # 이 부분은 단독 테스트를 위해서 임시로 반환.
      # 공통 처리 Lambda 연결 시 제거 가능 
      "normalized_events": normalized_events
    }

def handle_event_history(event, context):
  # detect trail Lambda가 전달한 Event Histroy 입력을 처리한다 
  record = event.get("record")

  if not isinstance(record, dict):
    raise ValueError("record must be a CloudTrail event object")

  normalized = normalize(
    record = record,
    collection_path = "cloudtrail_event_history",
    collection_source = "cloudtrail_lookup_events",
    collector = context.function_name,
    # cloudwatch 로그가 아니므로, Loggroup, logstream은 생략된다 
    log_event_id = event.get("lookup_event_id")
  )

  print(
    json.dumps(
      normalized,
      ensure_ascii=False
    )
  )

  return{
    "statusCode": 200,
    "normalized_count": 1,
    # 이 부분은 단독 테스트를 위해서 임시로 반환.
    # 공통 처리 Lambda 연결 시 제거 가능 
    "normalized_events": [normalized]
  }

def lambda_handler(event, context):
  # 입력 구조에 따라 정상 경로와 우회 경로를 구분하고, 각 구조에 함수를 매칭한다 
  if "awslogs" in event:
    return handle_cloudwatch_logs(event, context)

  if (event.get("input_type") == "cloudtrail_event_history"):
    return handle_event_history(event, context)

  raise ValueError("Unsuported Lambda input type")