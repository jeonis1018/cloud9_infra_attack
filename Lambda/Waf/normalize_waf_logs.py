import base64
import gzip
import json
import os
from datetime import datetime, timezone

import boto3


s3 = boto3.client("s3")

NORMALIZED_BUCKET = os.environ["NORMALIZED_BUCKET"]
PREFIX = os.environ.get("NORMALIZED_PREFIX", "waf").strip("/")

SAFE_WAF_PARAM_KEYS = {
    "http_method",
    "uri",
    "args",
    "country",
    "host",
    "http_version",
    "scheme",

    "terminating_rule_id",
    "terminating_rule_type",

    "managed_rule_group_id",
    "managed_matched_rule_id",
    "managed_matched_rule_action",

    "custom_matched_rule_id",
    "custom_matched_rule_action",

    "match_condition",
    "match_location",
    "matched_field_name",
    "matched_data",

    "rate_based_rule_name",
    "rate_limit_key",
    "max_rate_allowed",
    "evaluation_window_sec",
    "rate_limit_value",

    "ja3_fingerprint",
    "ja4_fingerprint",
}


def pick_waf_params(request_parameters):
    if not isinstance(request_parameters, dict):
        return None

    picked = {
        k: v
        for k, v in request_parameters.items()
        if k in SAFE_WAF_PARAM_KEYS and v is not None
    }

    return picked or None


def get_user_agent(headers):
    if not isinstance(headers, list):
        return None

    for header in headers:
        if header.get("name", "").lower() == "user-agent":
            return header.get("value")

    return None


def parse_webacl_arn(webacl_id):
    if not webacl_id:
        return None, None

    try:
        parts = webacl_id.split(":")
        region = parts[3]
        account_id = parts[4]

        return account_id, region

    except (IndexError, AttributeError):
        return None, None


def get_managed_matched_rule(rule_group_list):
    if not isinstance(rule_group_list, list):
        return None, None, None

    for rule_group in rule_group_list:
        if not isinstance(rule_group, dict):
            continue

        rule_group_id = rule_group.get("ruleGroupId")
        terminating_rule = rule_group.get("terminatingRule")

        if isinstance(terminating_rule, dict):
            return (
                rule_group_id,
                terminating_rule.get("ruleId"),
                terminating_rule.get("action"),
            )

        matching_rules = (
            rule_group.get("nonTerminatingMatchingRules") or []
        )

        for rule in matching_rules:
            if isinstance(rule, dict):
                return (
                    rule_group_id,
                    rule.get("ruleId"),
                    rule.get("action"),
                )

    return None, None, None


def get_custom_matched_rule(record):
    rules = record.get("nonTerminatingMatchingRules")

    if isinstance(rules, list):
        for rule in rules:
            if not isinstance(rule, dict):
                continue

            rule_id = rule.get("ruleId")

            if rule_id and rule_id.startswith("Custom-"):
                return (
                    rule_id,
                    rule.get("action"),
                )

    terminating_rule_id = record.get("terminatingRuleId")

    if (
        terminating_rule_id
        and terminating_rule_id != "Default_Action"
        and not terminating_rule_id.startswith("AWSManaged")
    ):
        return (
            terminating_rule_id,
            record.get("action"),
        )

    return None, None


def first_match_detail(details):
    if not isinstance(details, list):
        return None

    for detail in details:
        if isinstance(detail, dict):
            return detail

    return None


def get_rule_match_detail(
    record,
    managed_rule_group_id,
    custom_rule_id
):
    top_level_rules = (
        record.get("nonTerminatingMatchingRules") or []
    )

    for rule in top_level_rules:
        if not isinstance(rule, dict):
            continue

        rule_id = rule.get("ruleId")

        if rule_id and not rule_id.startswith("Custom-"):
            detail = first_match_detail(
                rule.get("ruleMatchDetails")
            )

            if detail:
                return detail

    for rule in top_level_rules:
        if not isinstance(rule, dict):
            continue

        if rule.get("ruleId") == custom_rule_id:
            detail = first_match_detail(
                rule.get("ruleMatchDetails")
            )

            if detail:
                return detail

    rule_groups = record.get("ruleGroupList") or []

    for rule_group in rule_groups:
        if not isinstance(rule_group, dict):
            continue

        if (
            rule_group.get("ruleGroupId")
            != managed_rule_group_id
        ):
            continue

        terminating_rule = rule_group.get(
            "terminatingRule"
        )

        if isinstance(terminating_rule, dict):
            detail = first_match_detail(
                terminating_rule.get(
                    "ruleMatchDetails"
                )
            )

            if detail:
                return detail

        matching_rules = (
            rule_group.get(
                "nonTerminatingMatchingRules"
            )
            or []
        )

        for rule in matching_rules:
            if not isinstance(rule, dict):
                continue

            detail = first_match_detail(
                rule.get("ruleMatchDetails")
            )

            if detail:
                return detail

    detail = first_match_detail(
        record.get("terminatingRuleMatchDetails")
    )

    if detail:
        return detail

    return {}


def is_rule_matched(record, rule_id):
    if not rule_id:
        return False

    if record.get("terminatingRuleId") == rule_id:
        return True

    for rule in record.get("nonTerminatingMatchingRules") or []:
        if not isinstance(rule, dict):
            continue

        if rule.get("ruleId") == rule_id:
            return True

    return False


def get_rate_based_rule(record):
    rate_based_rule_list = record.get("rateBasedRuleList")

    if not isinstance(rate_based_rule_list, list):
        return {}

    for rule in rate_based_rule_list:
        if not isinstance(rule, dict):
            continue

        rule_name = rule.get("rateBasedRuleName")

        if not is_rule_matched(record, rule_name):
            continue

        return {
            "rate_based_rule_name":
                rule_name,

            "rate_limit_key":
                rule.get("limitKey"),

            "max_rate_allowed":
                rule.get("maxRateAllowed"),

            "evaluation_window_sec":
                rule.get("evaluationWindowSec"),

            "rate_limit_value":
                rule.get("limitValue"),
        }

    return {}


def get_labels(labels):
    if not isinstance(labels, list):
        return None

    picked = [
        label.get("name")
        for label in labels
        if isinstance(label, dict)
        and label.get("name")
    ]

    return picked or None


def get_resources(record, account_id, region):
    resources = []

    webacl_arn = record.get("webaclId")
    http_source_id = record.get("httpSourceId")
    http_source_name = record.get("httpSourceName")

    if webacl_arn:
        webacl_name = None

        try:
            resource_part = webacl_arn.split(":", 5)[5]
            resource_parts = resource_part.split("/")

            if len(resource_parts) >= 3:
                webacl_name = resource_parts[2]

        except (IndexError, AttributeError):
            pass

        resources.append({
            "type": "AWS::WAFv2::WebACL",
            "id": webacl_name or webacl_arn,
            "arn": webacl_arn,
            "account_id": account_id,
            "region": region
        })

    if http_source_id:
        resource_type = (
            "AWS::ElasticLoadBalancingV2::LoadBalancer"
            if http_source_name == "ALB"
            else http_source_name
        )

        resources.append({
            "type": resource_type,
            "id": http_source_id,
            "arn": None,
            "account_id": account_id,
            "region": region
        })

    return resources or None


def convert_timestamp(timestamp):
    if timestamp is None:
        return None

    try:
        return (
            datetime.fromtimestamp(
                timestamp / 1000,
                tz=timezone.utc
            )
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )

    except (TypeError, ValueError, OSError):
        return None


def normalize_waf(
    record,
    log_group,
    log_stream,
    log_event_id
):
    http_request = record.get("httpRequest") or {}
    source_ip = http_request.get("clientIp")

    account_id, region = parse_webacl_arn(
        record.get("webaclId")
    )

    (
        managed_rule_group_id,
        managed_rule_id,
        managed_rule_action,
    ) = get_managed_matched_rule(
        record.get("ruleGroupList")
    )

    (
        custom_rule_id,
        custom_rule_action,
    ) = get_custom_matched_rule(record)

    match_detail = get_rule_match_detail(
        record,
        managed_rule_group_id,
        custom_rule_id
    )

    rate_info = get_rate_based_rule(record)

    waf_detail = {
        "http_method":
            http_request.get("httpMethod"),

        "uri":
            http_request.get("uri"),

        "args":
            http_request.get("args"),

        "country":
            http_request.get("country"),

        "host":
            http_request.get("host"),

        "http_version":
            http_request.get("httpVersion"),

        "scheme":
            http_request.get("scheme"),

        "terminating_rule_id":
            record.get("terminatingRuleId"),

        "terminating_rule_type":
            record.get("terminatingRuleType"),

        "managed_rule_group_id":
            managed_rule_group_id,

        "managed_matched_rule_id":
            managed_rule_id,

        "managed_matched_rule_action":
            managed_rule_action,

        "custom_matched_rule_id":
            custom_rule_id,

        "custom_matched_rule_action":
            custom_rule_action,

        "match_condition":
            match_detail.get("conditionType"),

        "match_location":
            match_detail.get("location"),

        "matched_field_name":
            match_detail.get("matchedFieldName"),

        "matched_data":
            match_detail.get("matchedData"),

        **rate_info,

        "ja3_fingerprint":
            record.get("ja3Fingerprint"),

        "ja4_fingerprint":
            record.get("ja4Fingerprint"),
    }

    return {
        "schema_version": "2.0",
        "log_type": "waf",

        "event": {
            "id": (
                http_request.get("requestId")
                or log_event_id
            ),

            "time": convert_timestamp(
                record.get("timestamp")
            ),

            "ingested_at": (
                datetime.now(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            ),

            "service": "waf.amazonaws.com",
            "action": "HTTPRequest",
            "category": None,
            "read_only": None
        },

        "cloud": {
            "provider": "aws",
            "account_id": account_id,
            "region": region
        },

        "actor": {
            "type": None,
            "account_id": None,
            "principal_id": None,
            "arn": None,
            "session_issuer_arn": None,
            "invoked_by": None,
            "access_key_id": None
        },

        "source": {
            "ip": source_ip,

            "user_agent": get_user_agent(
                http_request.get("headers")
            )
        },

        "resources": get_resources(
            record,
            account_id,
            region
        ),

        "outcome": {
            "action": record.get("action")
        },

        "collection": {
            "path": "cloudwatch_subscription",
            "source": "cloudwatch",
            "collector": "normalize-waf-logs"
        },

        "source_log": {
            "type": "cloudwatch",
            "log_group": log_group,
            "log_stream": log_stream,
            "log_event_id": log_event_id
        },

        "detail": {
            "request_parameters":
                pick_waf_params(waf_detail),

            "labels":
                get_labels(
                    record.get("labels")
                ),

            "severity": None,
            "mitre_technique": None,
            "ai_verdict": None
        }
    }


def lambda_handler(event, context):
    compressed_data = base64.b64decode(
        event["awslogs"]["data"]
    )

    payload = json.loads(
        gzip.decompress(compressed_data)
    )

    if payload.get("messageType") == "CONTROL_MESSAGE":
        return {
            "statusCode": 200,
            "message": "control message ignored"
        }

    normalized_events = []

    for log_event in payload.get("logEvents", []):
        try:
            waf_record = json.loads(
                log_event["message"]
            )

            normalized = normalize_waf(
                record=waf_record,
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
            TypeError
        ) as error:
            print(
                json.dumps({
                    "level": "ERROR",
                    "message":
                        "WAF log Parsing Failed",
                    "error_message":
                        str(error),
                    "log_event_id":
                        log_event.get("id")
                })
            )

    if not normalized_events:
        return {
            "statusCode": 200,
            "normalized_count": 0
        }

    now = datetime.now(timezone.utc)

    object_key = (
        f"{PREFIX}/"
        f"year={now:%Y}/"
        f"month={now:%m}/"
        f"day={now:%d}/"
        f"hour={now:%H}/"
        f"waf_{now:%Y%m%d%H%M%S}_"
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
        "normalized_count":
            len(normalized_events),

        "s3_key":
            object_key
    }
