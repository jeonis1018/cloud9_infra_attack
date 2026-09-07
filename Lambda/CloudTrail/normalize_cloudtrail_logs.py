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
import os
from datetime import datetime, timezone

import boto3

s3 = boto3.client("s3")

# 버킷 
NORMALIZED_BUCKET = os.environ["NORMALIZED_BUCKET"]
# 객체 키 시작 부분
PREFIX = os.environ.get("NORMALIZED_PREFIX", "cloudtrail").strip("/")

def get_principal_arn(identity):
    return (
        identity.get("arn")
        or identity.get("sessionContext", {})
                   .get("sessionIssuer", {})
                   .get("arn")
        or identity.get("principalId")
        or identity.get("invokedBy")
    )


def normalize(record, log_group, log_stream, log_event_id):
    identity = record.get("userIdentity", {})
    error_code = record.get("errorCode")

    return {
        "schema_version": "1.0",
        "event_time": record.get("eventTime"),
        "event_id": record.get("eventID") or log_event_id,
        "event_source": record.get("eventSource"),
        "event_name": record.get("eventName"),
        "account_id": record.get("recipientAccountId") or identity.get("accountId"),
        "region": record.get("awsRegion"),
        "principal_arn": get_principal_arn(identity),
        "access_key": identity.get("accessKeyId"),
        "source_ip": record.get("sourceIPAddress"),
        "user_agent": record.get("userAgent"),
        "status": "FAIL" if error_code else "SUCCESS",
        "error_code": error_code,
        "raw_log_location": (
            f"cloudwatch://{log_group}/{log_stream}/{log_event_id}"
        ),
        "details": "Will Be Update"
    }


def lambda_handler(event, context):

    # CloudWatch Logs가 Subscription Filter를 통해 Lambda로 로그를 전달할 대 GZI으로
    # 압축 후 base64 문자열로 인코딩해서 전달하기 때문에, 디코딩 -> 압축 해제 -> JSON 변환 형태를 가져야한다

    # Subscription Filter를 통해 전달 받은 코드 구조 
    # {
    #   "owner": "896986966760",
    #   "logGroup": "/aws/cloudtrail/cloud9-security",
    #   "logStream": "896986966760_CloudTrail_ap-northeast-2",
    #   "messageType": "DATA_MESSAGE",
    #   "subscriptionFilters": [
    #     "cloudtrail-normalization-filter"
    #   ],
    #   "logEvents": [
    #     {
    #       "id": "123456789",
    #       "timestamp": 1788600000000,
    #       "message": "{\"eventTime\":\"2026-09-05T12:59:00Z\",\"eventSource\":\"s3.amazonaws.com\",\"eventName\":\"GetObject\"}"
    #     }
    #   ]
    # }


    # event : Lambda가 전달받은 전체 데이더 
    # awslogs : 그 안의 awslogs 항목
    # data : awslogs 안에 있는 base64 문자열
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
            cloudtrail_record = json.loads(log_event["message"])

            normalized = normalize(
                record=cloudtrail_record,
                log_group=payload.get("logGroup"),
                log_stream=payload.get("logStream"),
                log_event_id=log_event.get("id")
            )

            normalized_events.append(normalized)

            print(json.dumps(normalized, ensure_ascii=False))

        except (json.JSONDecodeError, KeyError) as error:
            print(json.dumps({
                "level": "ERROR",
                "message": "CloudTrail log Parsing Failed",
                "error_message": str(error),
                "log_event_id": log_event.get("id")
            }))

    if not normalized_events:
        return {
            "statusCode": 200,
            "normalized_event_count": 0
        }

    now = datetime.now(timezone.utc)

    object_key = (
        f"{PREFIX}/"
        f"year={now:%Y}/month={now:%m}/day={now:%d}/hour={now:%H}/" # 디렉터리 지정
        f"cloudtrail_{now:%Y%m%d%H%M%S}_"
        f"{context.aws_request_id[:12]}.json"
    )

    body = json.dumps(
        normalized_events,
        ensure_ascii=False,
        indent=2
    )
    

    s3.put_object(
        Bucket=NORMALIZED_BUCKET,
        Key=object_key,
        Body=body.encode("utf-8"),
        ContentType="application/json",
        ServerSideEncryption="AES256"
    )

    return {
        "statusCode": 200,
        "normalized_count": len(normalized_events),
        "s3_key": object_key
    }