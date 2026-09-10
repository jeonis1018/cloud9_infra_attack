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
from collections import defaultdict
from datetime import datetime, timezone

import boto3

s3 = boto3.client("s3")

# 버킷 
NORMALIZED_BUCKET = os.environ["NORMALIZED_BUCKET"]
# 객체 키 시작 부분
PREFIX = os.environ.get("NORMALIZED_PREFIX", "cloudtrail").strip("/")

# request_parameters "내부 키" 화이트리스트 — 로그를 거르는 필터가 아님(모든 로그 저장).
# requestParameters는 API마다 내용이 다른 자유형 딕셔너리라 IAM 정책 전문 같은
# 크고 민감한 값이 들어올 수 있어, 분석에 쓰는 키만 남긴다.
# 원본 전체는 raw_log_location으로 CloudWatch Logs에서 역추적 가능.
SAFE_PARAM_KEYS = {
    "bucketName", "key", "detectorId", "name", "trailName",
    "enable", "roleName", "userName", "policyArn", "policyName",
    "includeGlobalServiceEvents", "isMultiRegionTrail",
    "enableLogFileValidation", "serverSideEncryptionConfiguration",
}


def pick_params(request_parameters):
    """민감·대용량 값 유입을 막기 위해 requestParameters 내부의 화이트리스트 키만 추출.
    해당 키가 없으면 이 필드만 None — 이벤트 자체는 그대로 저장된다."""
    if not isinstance(request_parameters, dict):
        return None
    picked = {
        k: v for k, v in request_parameters.items()
        if k in SAFE_PARAM_KEYS
    }
    return picked or None


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
    session_context = identity.get("sessionContext", {})
    source_ip = record.get("sourceIPAddress")

    return {
        "schema_version": "1.1",
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
        "user_type": identity.get("type"),
        "mfa_authenticated": session_context.get("attributes", {})
                                            .get("mfaAuthenticated"),
        "is_aws_internal": bool(source_ip and source_ip.endswith(".amazonaws.com")),
        "read_only": record.get("readOnly"),
        "error_message": record.get("errorMessage"),
        "request_parameters": pick_params(record.get("requestParameters")),
        "severity": None,
    }


def partition_path(event_time_str, fallback):
    """event_time(ISO8601 Z) 기준 Hive 스타일 파티션 경로."""
    try:
        dt = datetime.strptime(event_time_str, "%Y-%m-%dT%H:%M:%SZ") \
                     .replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        dt = fallback
    return f"year={dt:%Y}/month={dt:%m}/day={dt:%d}/hour={dt:%H}"


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

    # 파티션을 Lambda 실행 시각이 아닌 이벤트 발생 시각 기준으로 만들어
    # 지연 도착한 이벤트가 잘못된 시간 파티션에 저장되지 않게 한다
    groups = defaultdict(list)
    for normalized in normalized_events:
        groups[partition_path(normalized["event_time"], now)].append(normalized)

    written_keys = []

    for path, events in groups.items():
        object_key = (
            f"{PREFIX}/{path}/"
            f"cloudtrail_{now:%Y%m%d%H%M%S}_"
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