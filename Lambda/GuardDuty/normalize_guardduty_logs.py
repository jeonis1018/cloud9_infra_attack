# GuardDuty Finding 수신
# -> base64 디코딩 / GZIP 압축 해제 (CloudWatch Logs 경유인 경우)
# -> EventBridge 봉투 JSON 파싱
# -> 공통 필드 추출 (WAF 정규화와 동일한 스키마 2.0)
# -> 로그 출력
# -> S3에 저장 (guardduty/ 프리픽스)
# -> 룰 평가 Lambda 비동기 호출 (환경변수가 설정된 경우에만)
#
# 유입 경로 1: GuardDuty -> EventBridge 룰 -> CloudWatch Logs
#              -> 구독 필터 -> 이 Lambda
#              이 경우 logEvents[].message에 EventBridge 봉투 JSON 전체가
#              문자열로 들어온다.
#
# 유입 경로 2: GuardDuty -> EventBridge 룰 -> 이 Lambda 직접 호출
#              이 경우 event 자체가 EventBridge 봉투다.

import base64
import gzip
import json
import os
from datetime import datetime, timezone

import boto3


s3 = boto3.client("s3")
lambda_client = boto3.client("lambda")

SCHEMA_VERSION = "2.0"
LOG_TYPE = "guardduty"

# 어느 서비스가 만든 이벤트인지 나타내는 식별자
# (WAF 정규화의 event.service 자리와 같은 용도)
EVENT_SERVICE = "guardduty.amazonaws.com"

# WAF 정규화와 같은 버킷을 쓰고, 프리픽스로 폴더를 나눈다
# 예: s3://{bucket}/waf/... , s3://{bucket}/guardduty/...
NORMALIZED_BUCKET = os.environ["NORMALIZED_BUCKET"]
PREFIX = os.environ.get("NORMALIZED_PREFIX", "guardduty").strip("/")

# 정규화 결과를 넘길 룰 평가 Lambda 이름
# 값이 없으면 평가 호출을 건너뛰므로, 평가 Lambda 없이도 정규화만 단독 배포할 수 있다
RULES_FUNCTION_NAME = os.environ.get("RULES_FUNCTION_NAME")


def utc_now():
    # 현재 UTC 시각을 ISO 8601 형식으로 변환한다. 예: 2026-09-17T01:20:30.123456Z
    return (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def normalize_resources(
    access_key_details,
    instance_details,
    account_id,
    region
):
    # GuardDuty는 resourceType에 따라 accessKeyDetails / instanceDetails 처럼
    # 서로 다른 키에 대상이 흩어져 있어서, WAF/CloudTrail과 같은 배열 형태로
    # 직접 재조립해야 한다
    resources = []

    # 탈취 의심 자격 증명 (이번 공격 체인의 핵심 대상)
    access_key_id = access_key_details.get("accessKeyId")

    if access_key_id:
        resources.append({
            "type": "AWS::IAM::AccessKey",
            "id": access_key_id,
            "arn": None,
            "account_id": account_id,
            "region": region
        })

    # 자격 증명이 발급된 EC2 인스턴스
    instance_id = instance_details.get("instanceId")

    if instance_id:
        resources.append({
            "type": "AWS::EC2::Instance",
            "id": instance_id,
            "arn": None,
            "account_id": account_id,
            "region": region
        })

    return resources or None


def build_finding_detail(detail, service):
    return {
        "severity":
            detail.get("severity"),

        "type":
            detail.get("type"),

        "title":
            detail.get("title"),

        "description":
            detail.get("description"),

        "detector_id":
            service.get("detectorId"),

        "finding_arn":
            detail.get("arn"),

        # 같은 파인딩이 반복 관측되면 새 파인딩이 생기지 않고 count가 올라간다
        "count":
            service.get("count"),

        "archived":
            service.get("archived"),

        "feature_name":
            service.get("featureName"),

        "resource_role":
            service.get("resourceRole"),

        "first_seen":
            service.get("eventFirstSeen"),

        "last_seen":
            service.get("eventLastSeen"),
    }


def build_observed_api(action, api_call_action):
    # 파인딩이 관찰한 API 호출 (예: ec2.amazonaws.com / DescribeInstances)
    return {
        "action_type":
            action.get("actionType"),

        "service_name":
            api_call_action.get("serviceName"),

        "api":
            api_call_action.get("api"),

        "caller_type":
            api_call_action.get("callerType"),
    }


def build_remote_ip(remote_ip_details):
    # country / city / organization이 각각 중첩 dict로 오기 때문에 평탄화한다
    country = remote_ip_details.get("country") or {}
    city = remote_ip_details.get("city") or {}
    organization = remote_ip_details.get("organization") or {}

    return {
        "country":
            country.get("countryName"),

        "city":
            city.get("cityName"),

        "organization":
            organization.get("org"),
    }


def build_target_resource(
    resource,
    access_key_details,
    instance_details
):
    iam_instance_profile = (
        instance_details.get("iamInstanceProfile") or {}
    )

    return {
        "resource_type":
            resource.get("resourceType"),

        # 탈취된 자격 증명이 속한 역할 이름
        "role_name":
            access_key_details.get("userName"),

        "instance_id":
            instance_details.get("instanceId"),

        "instance_type":
            instance_details.get("instanceType"),

        "image_id":
            instance_details.get("imageId"),

        "availability_zone":
            instance_details.get("availabilityZone"),

        "iam_instance_profile_arn":
            iam_instance_profile.get("arn"),
    }


# record : 파싱된 단일 EventBridge 봉투 (detail-type = "GuardDuty Finding")
# collection_path : 로그가 어떤 경로를 통해 들어왔는지 나타냄
# collection_source : 수집 주체나 원본 인프라 식별자
# collector : 로그를 수집 및 가공 처리한 엔진 이름
def normalize(
    record,
    collection_path,
    collection_source,
    collector,
    log_group=None,
    log_stream=None,
    log_event_id=None
):
    detail = record.get("detail") or {}

    resource = detail.get("resource") or {}
    access_key_details = resource.get("accessKeyDetails") or {}
    instance_details = resource.get("instanceDetails") or {}

    service = detail.get("service") or {}
    action = service.get("action") or {}
    api_call_action = action.get("awsApiCallAction") or {}
    remote_ip_details = api_call_action.get("remoteIpDetails") or {}

    # 빈 문자열로 오는 경우가 있어 None으로 통일한다
    error_code = api_call_action.get("errorCode") or None

    event_id = detail.get("id") or log_event_id

    # event_id는 S3 객체 키가 되는 값이라 없으면 저장할 수 없다
    if not event_id:
        raise ValueError("GuardDuty finding ID is missing")

    account_id = detail.get("accountId") or record.get("account")
    region = detail.get("region") or record.get("region")

    if collection_path == "cloudwatch_subscription":
        source_log_type = "cloudwatch"
    else:
        source_log_type = "eventbridge"

    return {
        "schema_version": SCHEMA_VERSION,
        "log_type": LOG_TYPE,

        "event": {
            "id": event_id,

            # updatedAt이 파인딩이 마지막으로 갱신된 시각이다
            # (봉투의 time은 전달 시각)
            "time": (
                detail.get("updatedAt")
                or record.get("time")
            ),

            "ingested_at": utc_now(),

            "service": EVENT_SERVICE,

            # CloudTrail의 eventName 자리에 파인딩 타입이 들어간다
            # 예: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS
            "action": detail.get("type"),

            "category": "finding",

            # 탐지 결과이지 API 호출이 아니므로 읽기/쓰기 구분이 없다
            "read_only": None
        },

        "cloud": {
            "provider": "aws",
            "account_id": account_id,
            "region": region
        },

        "actor": {
            "type":
                access_key_details.get("userType"),

            "account_id":
                account_id,

            # principalId에 인스턴스 ID가 함께 들어온다 (예: AROA...:i-0f40...)
            "principal_id":
                access_key_details.get("principalId"),

            # GuardDuty는 호출 주체의 전체 ARN을 제공하지 않는다
            "arn": None,
            "session_issuer_arn": None,
            "invoked_by": None,

            "access_key_id":
                access_key_details.get("accessKeyId")
        },

        "source": {
            "ip": remote_ip_details.get("ipAddressV4"),

            # 파인딩에는 User-Agent가 포함되지 않는다
            "user_agent": None
        },

        "resources": normalize_resources(
            access_key_details,
            instance_details,
            account_id,
            region
        ),

        "outcome": {
            "status": (
                "FAILURE" if error_code else "SUCCESS"
            ),
            "error_code": error_code,
            "error_message": None
        },

        "collection": {
            "path": collection_path,
            "source": collection_source,
            "collector": collector
        },

        "source_log": {
            "type": source_log_type,
            "log_group": log_group,
            "log_stream": log_stream,
            "log_event_id": log_event_id
        },

        # 룰 평가에서 참조하는 값들이라 키 이름을 바꾸지 말 것
        "details": {
            "finding": build_finding_detail(
                detail,
                service
            ),

            "observed_api": build_observed_api(
                action,
                api_call_action
            ),

            "remote_ip": build_remote_ip(
                remote_ip_details
            ),

            "target_resource": build_target_resource(
                resource,
                access_key_details,
                instance_details
            )
        }
    }


def save_normalized_events(normalized_events):
    # 정규화된 파인딩을 파인딩 ID 별로 S3에 저장한다.
    # 파인딩 ID를 객체 키로 사용하므로 같은 파인딩이 갱신되어 다시 들어와도
    # 동일한 객체를 덮어쓴다 (중복 제거)
    now = datetime.now(timezone.utc)

    saved_keys = []

    for normalized_event in normalized_events:
        event_id = (
            normalized_event.get("event", {}).get("id")
        )

        if not event_id:
            print(
                json.dumps({
                    "level": "ERROR",
                    "message":
                        "Cannot save finding without event ID"
                }, ensure_ascii=False)
            )
            continue

        object_key = (
            f"{PREFIX}/"
            f"year={now:%Y}/"
            f"month={now:%m}/"
            f"day={now:%d}/"
            f"hour={now:%H}/"
            f"{event_id}.json"
        )

        body = json.dumps(
            normalized_event,
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

        saved_keys.append(object_key)

    return saved_keys


def invoke_rules_evaluator(normalized_events):
    # 정규화 결과를 룰 평가 Lambda로 넘긴다
    if not RULES_FUNCTION_NAME:
        print(
            json.dumps({
                "level": "WARNING",
                "message":
                    "RULES_FUNCTION_NAME is not set, "
                    "skipping rule evaluation"
            }, ensure_ascii=False)
        )
        return 0

    invoked_count = 0

    for normalized_event in normalized_events:
        payload = {"normalized_event": normalized_event}

        try:
            # 비동기 호출이라 평가가 오래 걸려도 정규화 Lambda는 바로 끝난다
            lambda_client.invoke(
                FunctionName=RULES_FUNCTION_NAME,
                InvocationType="Event",
                Payload=json.dumps(payload).encode("utf-8")
            )

            invoked_count += 1

        # 평가 호출 실패가 이미 끝난 S3 적재를 되돌리지 않도록
        # 이벤트 단위로 처리한다
        except Exception as error:
            print(
                json.dumps({
                    "level": "ERROR",
                    "message":
                        "Rule evaluation invoke failed",
                    "error_message":
                        str(error),
                    "event_id":
                        normalized_event.get("event", {}).get("id")
                }, ensure_ascii=False)
            )

    return invoked_count


def handle_cloudwatch_logs(event, context):
    # CloudWatch Logs 구독 필터 입력을 처리한다
    #
    # payload 구조 (message 안에 EventBridge 봉투가 문자열로 들어있다)
    # {
    #   "messageType": "DATA_MESSAGE",
    #   "owner": "123456789012",
    #   "logGroup": "/aws/events/cloud9-security/guardduty",
    #   "logStream": "...",
    #   "logEvents": [
    #     { "id": "384729104812398471928374", "timestamp": 1789003230000,
    #       "message": "EventBridge 봉투 JSON 문자열" }
    #   ]
    # }
    compressed_data = base64.b64decode(
        event["awslogs"]["data"]
    )

    payload = json.loads(
        gzip.decompress(compressed_data)
    )

    if payload.get("messageType") == "CONTROL_MESSAGE":
        return {
            "statusCode": 200,
            "normalized_count": 0,
            "message": "control message ignored"
        }

    normalized_events = []
    failed_count = 0

    for log_event in payload.get("logEvents", []):
        try:
            record = json.loads(
                log_event["message"]
            )

            normalized = normalize(
                record=record,
                collection_path="cloudwatch_subscription",
                collection_source="cloudwatch",
                collector=context.function_name,
                log_group=payload.get("logGroup"),
                log_stream=payload.get("logStream"),
                log_event_id=log_event.get("id")
            )

            normalized_events.append(normalized)

            print(
                json.dumps(
                    normalized,
                    ensure_ascii=False
                )
            )

        except (
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError
        ) as error:
            failed_count += 1

            print(
                json.dumps({
                    "level": "ERROR",
                    "message":
                        "GuardDuty Normalization failed",
                    "error_message":
                        str(error),
                    "log_event_id":
                        log_event.get("id")
                }, ensure_ascii=False)
            )

    saved_keys = save_normalized_events(normalized_events)
    invoked_count = invoke_rules_evaluator(normalized_events)

    return {
        "statusCode": 200,

        "normalized_count":
            len(normalized_events),

        "failed_count":
            failed_count,

        "saved_count":
            len(saved_keys),

        "saved_keys":
            saved_keys,

        "rule_evaluation_invoked_count":
            invoked_count
    }


def handle_eventbridge(event, context):
    # EventBridge 룰이 이 Lambda를 직접 호출하는 경우를 처리한다
    # (CloudWatch Logs를 경유하지 않는 구성)
    normalized = normalize(
        record=event,
        collection_path="eventbridge_rule",
        collection_source="eventbridge",
        collector=context.function_name
    )

    print(
        json.dumps(
            normalized,
            ensure_ascii=False
        )
    )

    saved_keys = save_normalized_events([normalized])
    invoked_count = invoke_rules_evaluator([normalized])

    return {
        "statusCode": 200,

        "normalized_count": 1,

        "saved_count":
            len(saved_keys),

        "saved_keys":
            saved_keys,

        "rule_evaluation_invoked_count":
            invoked_count
    }


def lambda_handler(event, context):
    # 입력 구조에 따라 CloudWatch Logs 경유와 EventBridge 직접 호출을 구분한다
    if "awslogs" in event:
        return handle_cloudwatch_logs(event, context)

    if event.get("detail-type") == "GuardDuty Finding":
        return handle_eventbridge(event, context)

    raise ValueError("Unsupported Lambda input type")
