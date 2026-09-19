"""Native WAF normalization and narrow SSRF detection for the WHS ALB.

This module never changes WAF. Only the normalizer writes its S3 prefix and
only the detector starts response workflows. Importing it performs no I/O.
"""
import base64
import binascii
import gzip
import hashlib
import io
import ipaddress
import json
import os
import re
import time
from urllib.parse import parse_qsl, unquote_plus

ACCOUNT = "896986966760"
REGION = "ap-northeast-2"
BUCKET = "cloud9-security-normalized-logs-896986966760-ap-northeast-2-an"
INPUT_PREFIX = "waf/response/v1/"
EVIDENCE_PREFIX = "evidence/cloudwatch-agent-response/v1/"
WAF_LOG_GROUP = "aws-waf-logs-cloud9-security"
WEB_ACL_ARN = "arn:aws:wafv2:ap-northeast-2:896986966760:regional/webacl/WHS_VPC-WAF/0d04b6a4-be8a-4de8-b094-9c914efceb72"
ALB_ARN = "arn:aws:elasticloadbalancing:ap-northeast-2:896986966760:loadbalancer/app/WHS-ALB/d0ff76940805c393"
ALB_SOURCE_IDS = frozenset((ALB_ARN, "app/WHS-ALB/d0ff76940805c393",
                          ACCOUNT + "-app/WHS-ALB/d0ff76940805c393", "d0ff76940805c393"))
RULE_ID = "WAF-SSRF-v1"
AUTO_BLOCK_RULE = "respond-cloudwatch-agent-logs-block"
DETECTION_RULES = frozenset(("Custom-IMDS-SSRF-QueryArguments", "Custom-IMDS-SSRF-Body"))
MAX_OBJECT_BYTES = 16 * 1024 * 1024
MAX_ROWS = 10000
# The execution time guard provides backpressure; a normal batch containing
# many matches must not become poison merely because it contains >20 matches.
MAX_FINDINGS = MAX_ROWS
MAX_S3_RECORDS = 10
MAX_COMPRESSED = 1024 * 1024
MAX_DECOMPRESSED = 6 * 1024 * 1024
MAX_MESSAGE = 256 * 1024
MAX_MATCHES = 256
_clients = {}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _hex(value, length=64):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{%d}" % length, value) is not None


def _text(value, maximum, code, allow_empty=False):
    require(isinstance(value, str) and len(value.encode("utf-8")) <= maximum
            and (allow_empty or bool(value)) and not any(ord(c) < 32 for c in value), code)
    return value


def parse_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    def constant(_):
        raise ValueError("nonfinite_json")
    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("invalid_json") from None


def public_ip(value):
    """Canonical public unicast address, never X-Forwarded-For or mapped IPv4."""
    if not isinstance(value, str) or len(value) > 64 or "%" in value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if not address.is_global or address.is_multicast or address.is_reserved \
            or address.is_loopback or address.is_link_local or address.is_unspecified \
            or getattr(address, "ipv4_mapped", None) is not None:
        return None
    return str(address)


def parse_allowlist(value):
    require(isinstance(value, str) and len(value) <= 8192, "invalid_allowlist")
    if not value:
        return ()
    parts = value.split(",")
    require(len(parts) <= 256 and all(part.strip() for part in parts), "invalid_allowlist")
    try:
        return tuple(ipaddress.ip_network(part.strip(), strict=True) for part in parts)
    except ValueError:
        raise ValueError("invalid_allowlist") from None


def block_seconds(value=None):
    if value is None:
        value = os.environ.get("BLOCK_SECONDS", "600")
    require(not isinstance(value, bool) and re.fullmatch(r"[0-9]{3,4}", str(value)), "invalid_block_seconds")
    result = int(value)
    require(180 <= result <= 3600, "invalid_block_seconds")
    return result


def _allowlist(value=None):
    if value is None:
        return parse_allowlist(os.environ.get("ALLOWLIST_CIDRS", ""))
    if isinstance(value, str):
        return parse_allowlist(value)
    require(isinstance(value, (list, tuple)) and len(value) <= 256
            and all(isinstance(item, (ipaddress.IPv4Network, ipaddress.IPv6Network)) for item in value),
            "invalid_allowlist")
    return tuple(value)


def is_allowlisted(address, allowlist_cidrs=None):
    ip = ipaddress.ip_address(address)
    return any(ip.version == network.version and ip in network for network in _allowlist(allowlist_cidrs))


def configuration(detector=False):
    fixed = {"EXPECTED_ACCOUNT": ACCOUNT, "AWS_REGION": REGION, "NORMALIZED_BUCKET": BUCKET,
             "NORMALIZED_PREFIX": INPUT_PREFIX, "EVIDENCE_PREFIX": EVIDENCE_PREFIX,
             "WAF_LOG_GROUP": WAF_LOG_GROUP, "WEB_ACL_ARN": WEB_ACL_ARN, "ALB_ARN": ALB_ARN}
    for key, value in fixed.items():
        require(os.environ.get(key) == value, "unexpected_environment_" + key)
    config = {"block_seconds": block_seconds(), "allowlist": _allowlist()}
    if detector:
        queue = os.environ.get("DETECTION_QUEUE_ARN", "")
        machine = os.environ.get("STATE_MACHINE_ARN", "")
        require(re.fullmatch(r"arn:aws:sqs:" + REGION + ":" + ACCOUNT + r":[A-Za-z0-9_-]{1,80}", queue),
                "invalid_queue_arn")
        require(machine == "arn:aws:states:" + REGION + ":" + ACCOUNT + ":stateMachine:respond-cloudwatch-agent-logs",
                "invalid_state_machine_arn")
        config.update(queue_arn=queue, state_machine_arn=machine)
    return config


def client(service):
    if service not in _clients:
        import boto3
        from botocore.config import Config
        _clients[service] = boto3.client(service, region_name=REGION,
            config=Config(connect_timeout=2, read_timeout=3,
                          retries={"mode": "standard", "total_max_attempts": 2}))
    return _clients[service]


def error_code(exc):
    response = getattr(exc, "response", {})
    value = response.get("Error", {}).get("Code") if isinstance(response, dict) else None
    if not value and isinstance(exc, ValueError):
        value = str(exc)
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", value) else "processing_error"


def _source(source, event_id):
    fields = {"account_id", "region", "log_group", "log_stream", "log_event_id", "web_acl_arn",
              "alb_arn", "http_source_id", "synthetic"}
    require(isinstance(source, dict) and set(source) == fields, "invalid_source_fields")
    require(source["account_id"] == ACCOUNT and source["region"] == REGION
            and source["log_group"] == WAF_LOG_GROUP and source["web_acl_arn"] == WEB_ACL_ARN
            and source["alb_arn"] == ALB_ARN and source["http_source_id"] in ALB_SOURCE_IDS,
            "unexpected_source_scope")
    _text(source["log_stream"], 512, "invalid_log_stream")
    event = source["log_event_id"]
    require(isinstance(event, str) and re.fullmatch(r"[0-9]{1,128}|manual-validation-[A-Za-z0-9_-]{1,80}", event),
            "invalid_source_event_id")
    synthetic = event.startswith("manual-validation-")
    require(type(source["synthetic"]) is bool and source["synthetic"] == synthetic, "invalid_synthetic_flag")
    require(event_id == digest([ACCOUNT, REGION, WAF_LOG_GROUP, source["log_stream"], event]),
            "event_identity_mismatch")


def _match(scope, group_id, rule, terminating):
    require(isinstance(rule, dict), "invalid_rule_match")
    rule_id = _text(rule.get("ruleId"), 512, "invalid_rule_id")
    action = rule.get("action")
    require(action in ("ALLOW", "BLOCK", "COUNT", "CAPTCHA", "CHALLENGE"), "invalid_rule_action")
    if group_id is not None:
        _text(group_id, 2048, "invalid_rule_group_id")
    return {"scope": scope, "rule_group_id": group_id, "rule_id": rule_id,
            "action": action, "terminating": terminating}


def _native_matches(native):
    result = []
    terminating = _text(native.get("terminatingRuleId"), 512, "invalid_terminating_rule")
    rule_type = native.get("terminatingRuleType")
    require(rule_type in ("REGULAR", "RATE_BASED", "GROUP", "MANAGED_RULE_GROUP"), "invalid_rule_type")
    if terminating != "Default_Action":
        group = terminating if rule_type in ("GROUP", "MANAGED_RULE_GROUP") else None
        result.append(_match("rule_group" if group else "web_acl", group,
                             {"ruleId": terminating, "action": native["action"]}, True))
    rules = native.get("nonTerminatingMatchingRules", [])
    groups = native.get("ruleGroupList", [])
    require(isinstance(rules, list) and len(rules) <= MAX_MATCHES
            and isinstance(groups, list) and len(groups) <= 100, "invalid_rule_lists")
    result.extend(_match("web_acl", None, rule, False) for rule in rules)
    for group in groups:
        require(isinstance(group, dict), "invalid_rule_group")
        group_id = _text(group.get("ruleGroupId"), 2048, "invalid_rule_group_id")
        terminal = group.get("terminatingRule")
        if terminal is not None:
            result.append(_match("rule_group", group_id, terminal, True))
        nonterminal = group.get("nonTerminatingMatchingRules", [])
        excluded = group.get("excludedRules") or []
        require(isinstance(nonterminal, list) and len(nonterminal) <= MAX_MATCHES
                and isinstance(excluded, list) and len(excluded) <= MAX_MATCHES, "invalid_rule_group_matches")
        result.extend(_match("rule_group", group_id, rule, False) for rule in nonterminal)
        for rule in excluded:
            require(isinstance(rule, dict) and rule.get("exclusionType") == "EXCLUDED_AS_COUNT",
                    "invalid_excluded_rule")
            result.append(_match("rule_group", group_id, {"ruleId": rule.get("ruleId"), "action": "COUNT"}, False))
        require(len(result) <= MAX_MATCHES, "rule_match_limit")
    require(len(result) <= MAX_MATCHES, "rule_match_limit")
    return [parse_json(value) for value in sorted({canonical_bytes(item) for item in result})]


def _probe(args):
    if not isinstance(args, str) or len(args.encode("utf-8")) > 65536:
        return None
    try:
        pairs = parse_qsl(args, keep_blank_values=True, max_num_fields=1024, errors="strict")
    except (ValueError, UnicodeError):
        return None
    probes = [value for key, value in pairs if key == "security_lab_probe"]
    return probes[0] if len(probes) == 1 and _hex(probes[0], 32) else None


def normalize_record(log, payload):
    """Return minimal WAF evidence, or None for a different ACL/ALB."""
    require(isinstance(payload, dict) and payload.get("owner") == ACCOUNT
            and payload.get("logGroup") == WAF_LOG_GROUP, "unexpected_envelope_scope")
    require(isinstance(log, dict), "invalid_log_event")
    message = log.get("message")
    require(isinstance(message, str) and len(message.encode("utf-8")) <= MAX_MESSAGE, "invalid_log_message")
    native = parse_json(message)
    require(isinstance(native, dict), "invalid_waf_record")
    if native.get("webaclId") != WEB_ACL_ARN or native.get("httpSourceName") != "ALB" \
            or native.get("httpSourceId") not in ALB_SOURCE_IDS:
        return None
    require(type(native.get("formatVersion")) is int and native["formatVersion"] == 1, "invalid_waf_format")
    timestamp = native.get("timestamp")
    require(type(timestamp) is int and 0 <= timestamp <= 253402300799999, "invalid_timestamp")
    require(native.get("action") in ("ALLOW", "BLOCK", "CAPTCHA", "CHALLENGE"), "invalid_waf_action")
    request = native.get("httpRequest")
    require(isinstance(request, dict), "invalid_http_request")
    request_id = _text(request.get("requestId"), 512, "invalid_request_id")
    method = request.get("httpMethod")
    require(isinstance(method, str) and re.fullmatch(r"[A-Z][A-Z0-9_-]{0,19}", method), "invalid_http_method")
    log_id = log.get("id")
    source = {"account_id": ACCOUNT, "region": REGION, "log_group": WAF_LOG_GROUP,
              "log_stream": payload.get("logStream"), "log_event_id": log_id,
              "web_acl_arn": WEB_ACL_ARN, "alb_arn": ALB_ARN, "http_source_id": native["httpSourceId"],
              "synthetic": isinstance(log_id, str) and log_id.startswith("manual-validation-")}
    event_id = digest([ACCOUNT, REGION, WAF_LOG_GROUP, source["log_stream"], log_id])
    _source(source, event_id)
    address = public_ip(request.get("clientIp"))
    return {"schema": "cloudwatch-agent.waf.v1", "record_type": "waf_request", "event_id": event_id,
            "event_time": timestamp // 1000, "timestamp_ms": timestamp, "source": source,
            "request_id": request_id, "source_record_sha256": digest(native), "client_ip": address,
            "ip_provenance": "aws_waf_http_request_client_ip",
            "automatic_block_eligible": address is not None and not source["synthetic"],
            "action": native["action"], "matches": _native_matches(native),
            "http_method": method, "probe_id": _probe(request.get("args"))}


def validate_record(record):
    fields = {"schema", "record_type", "event_id", "event_time", "timestamp_ms", "source", "request_id",
              "source_record_sha256", "client_ip", "ip_provenance", "automatic_block_eligible", "action",
              "matches", "http_method", "probe_id"}
    require(isinstance(record, dict) and set(record) == fields and record["schema"] == "cloudwatch-agent.waf.v1"
            and record["record_type"] == "waf_request", "invalid_record_schema")
    _source(record["source"], record["event_id"])
    require(type(record["timestamp_ms"]) is int and 0 <= record["timestamp_ms"] <= 253402300799999
            and type(record["event_time"]) is int and record["event_time"] == record["timestamp_ms"] // 1000,
            "invalid_event_time")
    _text(record["request_id"], 512, "invalid_request_id")
    require(_hex(record["source_record_sha256"]), "invalid_source_record_hash")
    address = public_ip(record["client_ip"])
    require(record["client_ip"] is None or address == record["client_ip"], "invalid_client_ip")
    require(record["ip_provenance"] == "aws_waf_http_request_client_ip"
            and type(record["automatic_block_eligible"]) is bool
            and record["automatic_block_eligible"] == (address is not None and not record["source"]["synthetic"]),
            "invalid_ip_provenance")
    require(record["action"] in ("ALLOW", "BLOCK", "CAPTCHA", "CHALLENGE"), "invalid_waf_action")
    require(isinstance(record["http_method"], str) and re.fullmatch(r"[A-Z][A-Z0-9_-]{0,19}", record["http_method"]),
            "invalid_http_method")
    require(record["probe_id"] is None or _hex(record["probe_id"], 32), "invalid_probe_id")
    matches = record["matches"]
    require(isinstance(matches, list) and len(matches) <= MAX_MATCHES, "invalid_rule_matches")
    for match in matches:
        require(isinstance(match, dict) and set(match) == {"scope", "rule_group_id", "rule_id", "action", "terminating"},
                "invalid_rule_match_fields")
        require(match["scope"] in ("web_acl", "rule_group") and type(match["terminating"]) is bool
                and ((match["scope"] == "web_acl" and match["rule_group_id"] is None)
                     or (match["scope"] == "rule_group" and isinstance(match["rule_group_id"], str))),
                "invalid_rule_match_scope")
        _match(match["scope"], match["rule_group_id"], {"ruleId": match["rule_id"], "action": match["action"]},
               match["terminating"])
    require([canonical_bytes(item) for item in matches] == sorted({canonical_bytes(item) for item in matches}),
            "noncanonical_rule_matches")
    return record


def input_key(key):
    require(isinstance(key, str) and re.fullmatch(re.escape(INPUT_PREFIX) + r"[0-9a-f]{64}\.jsonl", key),
            "unexpected_input_key")
    return key


def _selected_matches(record):
    if any(match["scope"] == "web_acl" and match["rule_id"] == AUTO_BLOCK_RULE
           and match["action"] == "BLOCK" and match["terminating"] for match in record["matches"]):
        return []
    return [match for match in record["matches"] if match["scope"] == "web_acl"
            and match["rule_group_id"] is None and match["rule_id"] in DETECTION_RULES
            and ((match["action"] == "COUNT" and not match["terminating"])
                 or (match["action"] == "BLOCK" and match["terminating"]))]


def _finding(record, key, duration):
    address = ipaddress.ip_address(record["client_ip"])
    return {"schema": "cloudwatch-agent.finding.v1", "finding_id": digest([record["event_id"], RULE_ID]),
            "rule_id": RULE_ID, "event_id": record["event_id"], "event_time": record["event_time"],
            "expires_at": record["event_time"] + duration, "block_seconds": duration,
            "client_ip": str(address), "ip_version": "IPV4" if address.version == 4 else "IPV6",
            "cidr": str(address) + ("/32" if address.version == 4 else "/128"), "probe_id": record["probe_id"],
            "matched_rules": _selected_matches(record), "record_sha256": digest(record), "record": record,
            "input_object": {"bucket": BUCKET, "key": key}}


def finding_from_record(record, key, now=None, block_seconds=None, allowlist_cidrs=None):
    validate_record(record)
    input_key(key)
    duration = globals()["block_seconds"](block_seconds)
    if not record["automatic_block_eligible"] or not _selected_matches(record):
        return None
    if is_allowlisted(record["client_ip"], allowlist_cidrs):
        return None
    now = time.time() if now is None else now
    require(isinstance(now, (int, float)) and not isinstance(now, bool), "invalid_current_time")
    age = now - record["event_time"]
    if not 0 <= age <= min(300, duration - 30):
        return None
    return _finding(record, key, duration)


def validate_finding(finding, block_seconds=None, allowlist_cidrs=None):
    require(isinstance(finding, dict), "invalid_finding")
    record = validate_record(finding.get("record"))
    require(record["automatic_block_eligible"] and bool(_selected_matches(record)), "ineligible_finding")
    require(not is_allowlisted(record["client_ip"], allowlist_cidrs), "allowlisted_client")
    obj = finding.get("input_object")
    require(isinstance(obj, dict) and set(obj) == {"bucket", "key"} and obj["bucket"] == BUCKET,
            "invalid_input_object")
    key = input_key(obj["key"])
    expected = _finding(record, key, globals()["block_seconds"](block_seconds))
    require(canonical_bytes(finding) == canonical_bytes(expected), "finding_contract_mismatch")
    return finding


def decode_envelope(event):
    encoded = event.get("awslogs", {}).get("data") if isinstance(event, dict) else None
    require(isinstance(encoded, str) and len(encoded) <= 4 * ((MAX_COMPRESSED + 2) // 3), "invalid_subscription_data")
    try:
        compressed = base64.b64decode(encoded, validate=True)
        require(len(compressed) <= MAX_COMPRESSED, "compressed_size_limit")
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
            data = stream.read(MAX_DECOMPRESSED + 1)
    except (ValueError, binascii.Error, OSError, EOFError):
        raise ValueError("invalid_compressed_envelope") from None
    require(len(data) <= MAX_DECOMPRESSED, "decompressed_size_limit")
    payload = parse_json(data)
    require(isinstance(payload, dict), "invalid_envelope")
    return payload


def normalize_handler(event, context):
    configuration()
    payload = decode_envelope(event)
    if payload.get("messageType") == "CONTROL_MESSAGE":
        return {"status": "control", "record_count": 0}
    require(payload.get("messageType") == "DATA_MESSAGE", "unexpected_message_type")
    require(payload.get("owner") == ACCOUNT and payload.get("logGroup") == WAF_LOG_GROUP, "unexpected_envelope_scope")
    logs = payload.get("logEvents")
    require(isinstance(logs, list) and len(logs) <= MAX_ROWS, "invalid_log_count")
    records = [normalize_record(log, payload) for log in logs]
    rows = sorted((record for record in records if record is not None), key=lambda record: record["event_id"])
    require(len({record["event_id"] for record in rows}) == len(rows), "duplicate_source_event")
    if not rows:
        return {"status": "ignored", "record_count": 0, "received": len(logs)}
    data = b"".join(canonical_bytes(record) + b"\n" for record in rows)
    require(len(data) <= MAX_OBJECT_BYTES, "normalized_object_limit")
    key = INPUT_PREFIX + hashlib.sha256(data).hexdigest() + ".jsonl"
    status = "written"
    try:
        client("s3").put_object(Bucket=BUCKET, Key=key, Body=data, ContentType="application/x-ndjson",
                                 IfNoneMatch="*", ExpectedBucketOwner=ACCOUNT)
    except Exception as exc:
        if error_code(exc) not in ("PreconditionFailed", "412"):
            raise
        status = "duplicate"
    result = {"status": status, "received": len(logs), "record_count": len(rows),
              "scoped_out": len(logs) - len(rows), "bucket": BUCKET, "key": key}
    print(json.dumps(result, sort_keys=True))
    return result


def read_object(key, maximum=MAX_OBJECT_BYTES):
    response = client("s3").get_object(Bucket=BUCKET, Key=key, ExpectedBucketOwner=ACCOUNT)
    stream = response["Body"]
    try:
        require(type(response.get("ContentLength")) is int and 0 < response["ContentLength"] <= maximum,
                "object_size_limit")
        data = stream.read(maximum + 1)
        require(isinstance(data, bytes) and 0 < len(data) <= maximum
                and len(data) == response["ContentLength"], "invalid_object_length")
        return data
    finally:
        stream.close()


def findings_from_object(data, key, now=None, block_seconds=None, allowlist_cidrs=None):
    input_key(key)
    require(isinstance(data, bytes) and 0 < len(data) <= MAX_OBJECT_BYTES, "object_size_limit")
    require(hashlib.sha256(data).hexdigest() == key[len(INPUT_PREFIX):-6], "object_content_hash_mismatch")
    require(data.endswith(b"\n"), "incomplete_jsonl")
    lines = data.splitlines()
    require(0 < len(lines) <= MAX_ROWS, "row_count_limit")
    findings, seen = [], set()
    now = time.time() if now is None else now
    for line in lines:
        record = parse_json(line)
        finding = finding_from_record(record, key, now, block_seconds, allowlist_cidrs)
        require(record["event_id"] not in seen, "duplicate_object_event")
        seen.add(record["event_id"])
        if finding is not None:
            findings.append(finding)
            require(len(findings) <= MAX_FINDINGS, "finding_count_limit")
    return findings


def _message_keys(message, config):
    require(message.get("eventSource") == "aws:sqs" and message.get("eventSourceARN") == config["queue_arn"]
            and message.get("awsRegion") == REGION, "unexpected_queue_source")
    body = message.get("body")
    require(isinstance(body, str) and len(body.encode("utf-8")) <= 1024 * 1024, "invalid_queue_body")
    notification = parse_json(body)
    require(isinstance(notification, dict), "invalid_s3_notification")
    if notification.get("Event") == "s3:TestEvent":
        require(notification.get("Service") == "Amazon S3" and notification.get("Bucket") == BUCKET,
                "unexpected_s3_test_event")
        return []
    records = notification.get("Records")
    require(isinstance(records, list) and 1 <= len(records) <= MAX_S3_RECORDS, "invalid_s3_record_count")
    keys = []
    for record in records:
        require(isinstance(record, dict) and isinstance(record.get("eventVersion"), str)
                and re.fullmatch(r"2\.[0-9]+", record["eventVersion"]), "unsupported_s3_event_version")
        require(record.get("eventSource") == "aws:s3" and record.get("awsRegion") == REGION
                and record.get("eventName") in ("ObjectCreated:Put", "ObjectCreated:Post", "ObjectCreated:Copy",
                                                "ObjectCreated:CompleteMultipartUpload"), "unexpected_s3_event")
        s3 = record.get("s3")
        require(isinstance(s3, dict) and isinstance(s3.get("bucket"), dict)
                and s3["bucket"].get("name") == BUCKET and s3["bucket"].get("arn") == "arn:aws:s3:::" + BUCKET,
                "unexpected_s3_bucket")
        obj = s3.get("object")
        require(isinstance(obj, dict) and isinstance(obj.get("key"), str) and len(obj["key"]) <= 1024,
                "invalid_s3_object")
        try:
            key = input_key(unquote_plus(obj["key"], errors="strict"))
        except UnicodeError:
            raise ValueError("invalid_s3_key_encoding") from None
        if key not in keys:
            keys.append(key)
    return keys


def execution_arn(finding_id, machine_arn=None):
    require(_hex(finding_id), "invalid_finding_id")
    machine_arn = machine_arn or "arn:aws:states:" + REGION + ":" + ACCOUNT + ":stateMachine:respond-cloudwatch-agent-logs"
    return machine_arn.replace(":stateMachine:", ":execution:") + ":" + finding_id


def _remaining(context):
    if context is not None and hasattr(context, "get_remaining_time_in_millis"):
        require(context.get_remaining_time_in_millis() >= 8000, "insufficient_remaining_time")


def _identity(finding):
    validate_finding(finding)
    return canonical_bytes({key: value for key, value in finding.items() if key != "input_object"})


def _start(finding, config):
    states = client("stepfunctions")
    expected = execution_arn(finding["finding_id"], config["state_machine_arn"])
    try:
        response = states.start_execution(stateMachineArn=config["state_machine_arn"], name=finding["finding_id"],
                                          input=canonical_bytes(finding).decode("utf-8"))
        require(response.get("executionArn") == expected, "unexpected_started_execution")
        return "accepted"
    except Exception as exc:
        if error_code(exc) != "ExecutionAlreadyExists":
            raise
    existing = states.describe_execution(executionArn=expected)
    require(existing.get("executionArn") == expected and existing.get("stateMachineArn") == config["state_machine_arn"],
            "unexpected_existing_execution")
    require(_identity(parse_json(existing.get("input", ""))) == _identity(finding), "execution_identity_conflict")
    require(existing.get("status") in ("RUNNING", "SUCCEEDED"), "previous_execution_unsuccessful")
    return "duplicate"


def detect_handler(event, context):
    config = configuration(detector=True)
    messages = event.get("Records") if isinstance(event, dict) else None
    require(isinstance(messages, list) and 1 <= len(messages) <= 10, "invalid_sqs_records")
    ids = [message.get("messageId") if isinstance(message, dict) else None for message in messages]
    require(all(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value) for value in ids)
            and len(set(ids)) == len(ids), "invalid_sqs_message_ids")
    failures, reasons = [], set()
    summary = {"messages": len(messages), "objects": 0, "findings": 0, "accepted": 0, "duplicate": 0}
    for message in messages:
        try:
            findings = {}
            for key in _message_keys(message, config):
                _remaining(context)
                found = findings_from_object(read_object(key), key, block_seconds=config["block_seconds"],
                                             allowlist_cidrs=config["allowlist"])
                summary["objects"] += 1
                for finding in found:
                    prior = findings.get(finding["finding_id"])
                    require(prior is None or _identity(prior) == _identity(finding), "message_finding_conflict")
                    findings.setdefault(finding["finding_id"], finding)
                require(len(findings) <= MAX_FINDINGS, "finding_count_limit")
            summary["findings"] += len(findings)
            for finding in findings.values():
                _remaining(context)
                summary[_start(finding, config)] += 1
        except Exception as exc:
            failures.append({"itemIdentifier": message["messageId"]})
            reasons.add(error_code(exc))
    print(json.dumps({**summary, "failed_messages": len(failures), "failure_codes": sorted(reasons)}, sort_keys=True))
    return {"batchItemFailures": failures}
