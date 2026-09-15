# GuardDuty Finding 정규화
# Cloudwatch logs 이벤트 수신
# -> base64 디코딩
# -> GZIP 압축 해제
# -> GuardDuty Finding JSON 파싱
# -> 공통 필드 추출 (CloudTrail 정규화와 동일한 스키마 v1.1)
# -> Log 출력
# -> S3에 저장
#
# 유입 경로: GuardDuty -> EventBridge 룰 -> CloudWatch Logs
#            -> 구독 필터 -> 이 Lambda
# 그래서 logEvents[].message에는 EventBridge 봉투 JSON 전체가 들어온다.

import base64
import gzip
import json
import os
from collections import defaultdict
from datetime import datetime, timezone

import boto3

s3 = boto3.client("s3")

# 버킷
NORMALIZED_BUCKET = os.environ["NORMALIZED_BUCKET"]
# 객체 키 시작 부분
PREFIX = os.environ.get("NORMALIZED_PREFIX", "guardduty").strip("/")


def normalize(record, log_group, log_stream, log_event_id):
    """GuardDuty Finding을 CloudTrail 정규화와 동일한 v1.1 스키마로 매핑."""
    detail = record.get("detail", {})
    resource = detail.get("resource", {})
    access_key = resource.get("accessKeyDetails", {})
    action = detail.get("service", {}).get("action", {}).get("awsApiCallAction", {})
    source_ip = action.get("remoteIpDetails", {}).get("ipAddressV4")
    error_code = action.get("errorCode") or None

    # CloudTrail 쪽 pick_params()와 달리 화이트리스트 함수가 필요 없다.
    # 파인딩 구조에서 필요한 키만 직접 골라 담기 때문에 민감·대용량 값이 섞이지 않는다.
    request_parameters = {
        "detectorId": detail.get("service", {}).get("detectorId"),
        "name": access_key.get("userName"),
    }
    request_parameters = {
        k: v for k, v in request_parameters.items() if v is not None
    } or None

    return {
        "schema_version": "1.1",
        "event_time": detail.get("updatedAt") or record.get("time"),
        "event_id": detail.get("id") or log_event_id,
        "event_source": record.get("source"),
        "event_name": detail.get("type"),
        "account_id": detail.get("accountId"),
        "region": detail.get("region"),
        "principal_arn": access_key.get("principalId"),
        "access_key": access_key.get("accessKeyId"),
        "source_ip": source_ip,
        "user_agent": None,
        "status": "FAIL" if error_code else "SUCCESS",
        "error_code": error_code,
        "raw_log_location": (
            f"cloudwatch://{log_group}/{log_stream}/{log_event_id}"
        ),
        "user_type": access_key.get("userType"),
        "mfa_authenticated": None,
        "is_aws_internal": bool(source_ip and source_ip.endswith(".amazonaws.com")),
        "read_only": None,
        "error_message": detail.get("description"),
        "request_parameters": request_parameters,
        # GuardDuty는 자체 심각도(1~8.9)를 제공하므로 그대로 수용한다
        "severity": detail.get("severity"),
    }


def partition_path(event_time_str, fallback):
    """event_time(ISO8601 Z) 기준 Hive 스타일 파티션 경로."""
    # 파인딩의 updatedAt은 밀리초 단위(...57.988Z), 봉투의 time은 초 단위(...46Z)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            dt = datetime.strptime(event_time_str, fmt) \
                         .replace(tzinfo=timezone.utc)
            break
        except (TypeError, ValueError):
            dt = fallback
    return f"year={dt:%Y}/month={dt:%m}/day={dt:%d}/hour={dt:%H}"


def lambda_handler(event, context):

    # CloudWatch Logs가 Subscription Filter로 로그를 전달할 때 GZIP 압축 후
    # base64 문자열로 인코딩해서 보내므로, 디코딩 -> 압축 해제 -> JSON 변환 순서를 거친다

    # 전달받는 구조 (message 안에 EventBridge 봉투가 문자열로 들어있다)
    # {
    #   "owner": "896986966760",
    #   "logGroup": "/aws/events/cloud9-security/guardduty",
    #   "logStream": "...",
    #   "messageType": "DATA_MESSAGE",
    #   "logEvents": [
    #     {
    #       "id": "123456789",
    #       "timestamp": 1788600000000,
    #       "message": "{\"detail-type\":\"GuardDuty Finding\",\"detail\":{...}}"
    #     }
    #   ]
    # }

    compressed_data = base64.b64decode(event["awslogs"]["data"])
    payload = json.loads(gzip.decompress(compressed_data))

    if payload.get("messageType") == "CONTROL_MESSAGE":
        return {
            "statusCode": 200,
            "message": "control message ignored"
        }

    normalized_events = []

    for log_event in payload.get("logEvents", []):
        try:
            finding_record = json.loads(log_event["message"])

            normalized = normalize(
                record=finding_record,
                log_group=payload.get("logGroup"),
                log_stream=payload.get("logStream"),
                log_event_id=log_event.get("id")
            )

            normalized_events.append(normalized)

            print(json.dumps(normalized, ensure_ascii=False))

        except (json.JSONDecodeError, KeyError) as error:
            print(json.dumps({
                "level": "ERROR",
                "message": "GuardDuty Finding Parsing Failed",
                "error_message": str(error),
                "log_event_id": log_event.get("id")
            }))

    if not normalized_events:
        return {
            "statusCode": 200,
            "normalized_event_count": 0
        }

    now = datetime.now(timezone.utc)

    # 파티션을 Lambda 실행 시각이 아닌 파인딩 발생 시각 기준으로 만들어
    # 지연 도착한 이벤트가 잘못된 시간 파티션에 저장되지 않게 한다
    groups = defaultdict(list)
    for normalized in normalized_events:
        groups[partition_path(normalized["event_time"], now)].append(normalized)

    written_keys = []

    for path, events in groups.items():
        object_key = (
            f"{PREFIX}/{path}/"
            f"guardduty_{now:%Y%m%d%H%M%S}_"
            f"{context.aws_request_id[:12]}.jsonl"
        )

        # 한 줄에 한 이벤트(NDJSON) — Athena 파싱·학습 스트리밍 처리 호환
        body = "\n".join(
            json.dumps(e, ensure_ascii=False) for e in events
        )

        s3.put_object(
            Bucket=NORMALIZED_BUCKET,
            Key=object_key,
            Body=body.encode("utf-8"),
            ContentType="application/x-ndjson",
            ServerSideEncryption="AES256"
        )
        written_keys.append(object_key)

    return {
        "statusCode": 200,
        "normalized_count": len(normalized_events),
        "partition_count": len(groups),
        "s3_keys": written_keys
    }
