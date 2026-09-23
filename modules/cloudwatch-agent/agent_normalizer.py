"""Normalize the team's legacy journal access logs; never infer a client IP.

Required environment: EXPECTED_ACCOUNT, LOG_GROUP, ALLOWED_LOG_STREAMS,
NORMALIZED_BUCKET, AWS_REGION. Optional AGENT_NORMALIZED_PREFIX overrides NORMALIZED_PREFIX=cloudwatch-agent/v1.
Only S3 is written. boto3 is loaded on the first actual storage operation.
"""
import base64
import binascii
from datetime import datetime, timezone
import gzip
import hashlib
import io
import ipaddress
import json
import os
import re


SCHEMA = "team.web.v1"
APP_UNIT = "vuln-webapp.service"
MAX_COMPRESSED_BYTES = 1024 * 1024
MAX_DECOMPRESSED_BYTES = 6 * 1024 * 1024
MAX_MESSAGE_BYTES = 64 * 1024
MAX_ACCESS_BYTES = 8192
MAX_EVENTS = 10000
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ACCESS = re.compile(
    r'^(?P<peer>\S+)\s+-\s+-\s+\[[^\]\r\n]{1,80}\]\s+"'
    r'(?P<method>[A-Z][A-Z0-9_-]{0,19})\s+(?P<target>.+)\s+'
    r'HTTP/(?P<protocol>[0-9]+\.[0-9]+)"\s+(?P<status>[0-9]{3})\s+(?:[0-9]+|-)\s*$'
)
_s3 = None


class NormalizationError(ValueError):
    """A single record is unsupported; the reason never includes raw metadata."""


def configuration():
    required = ("EXPECTED_ACCOUNT", "LOG_GROUP", "ALLOWED_LOG_STREAMS", "NORMALIZED_BUCKET", "AWS_REGION")
    result = {}
    for name in required:
        value = os.environ.get(name, "").strip()
        if not value:
            raise ValueError("missing_environment_" + name)
        result[name] = value
    if not re.fullmatch(r"[0-9]{12}", result["EXPECTED_ACCOUNT"]):
        raise ValueError("invalid_expected_account")
    if len(result["LOG_GROUP"]) > 512:
        raise ValueError("invalid_log_group")
    streams = result["ALLOWED_LOG_STREAMS"].split(",")
    if not 1 <= len(streams) <= 16 or any(not item.strip() or len(item.strip()) > 512 for item in streams):
        raise ValueError("invalid_allowed_log_streams")
    result["ALLOWED_LOG_STREAMS"] = frozenset(item.strip() for item in streams)
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", result["NORMALIZED_BUCKET"]):
        raise ValueError("invalid_normalized_bucket")
    prefix = os.environ.get("AGENT_NORMALIZED_PREFIX", os.environ.get("NORMALIZED_PREFIX", "cloudwatch-agent/v1")).strip().rstrip("/")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9/_-]{0,127}", prefix):
        raise ValueError("invalid_normalized_prefix")
    result["NORMALIZED_PREFIX"] = prefix
    return result


def decode_envelope(event):
    try:
        encoded = event["awslogs"]["data"]
    except (KeyError, TypeError):
        raise ValueError("missing_cloudwatch_subscription_data") from None
    if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_COMPRESSED_BYTES + 2) // 3):
        raise ValueError("invalid_or_oversize_encoded_payload")
    try:
        compressed = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("invalid_base64_payload") from None
    if len(compressed) > MAX_COMPRESSED_BYTES:
        raise ValueError("compressed_payload_exceeds_limit")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
            decoded = stream.read(MAX_DECOMPRESSED_BYTES + 1)
    except (OSError, EOFError):
        raise ValueError("invalid_gzip_payload") from None
    if len(decoded) > MAX_DECOMPRESSED_BYTES:
        raise ValueError("decompressed_payload_exceeds_limit")
    try:
        payload = json.loads(decoded)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("invalid_envelope_json") from None
    if not isinstance(payload, dict):
        raise ValueError("invalid_envelope_object")
    return payload


def iso_timestamp(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 253402300799999:
        raise NormalizationError("invalid_event_timestamp")
    try:
        return datetime.fromtimestamp(value / 1000, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError):
        raise NormalizationError("invalid_event_timestamp") from None


def access_from_journal(message, evidence):
    if not isinstance(message, str):
        raise NormalizationError("invalid_message_type")
    try:
        message_size = len(message.encode("utf-8"))
    except UnicodeError:
        raise NormalizationError("invalid_message_encoding") from None
    if message_size > MAX_MESSAGE_BYTES:
        raise NormalizationError("message_exceeds_limit")
    try:
        value = json.loads(message)
    except (ValueError, RecursionError):
        raise NormalizationError("invalid_journal_json") from None
    body = value.get("body") if isinstance(value, dict) else None
    if not isinstance(body, dict):
        raise NormalizationError("missing_journal_body")
    if body.get("_SYSTEMD_UNIT") != APP_UNIT:
        raise NormalizationError("unexpected_systemd_unit")
    line = body.get("MESSAGE")
    if not isinstance(line, str):
        raise NormalizationError("missing_access_line")
    try:
        encoded = line.encode("utf-8")
    except UnicodeError:
        raise NormalizationError("invalid_access_line_encoding") from None
    evidence["access_line"] = encoded[:MAX_ACCESS_BYTES].decode("utf-8", errors="ignore")
    evidence["truncated"] = len(encoded) > MAX_ACCESS_BYTES
    if evidence["truncated"]:
        raise NormalizationError("access_line_exceeds_limit")
    clean = ANSI.sub("", line)
    if "\n" in clean or "\r" in clean:
        raise NormalizationError("multiline_access_line")
    match = ACCESS.fullmatch(clean)
    if not match:
        raise NormalizationError("unsupported_access_line")
    try:
        peer = str(ipaddress.ip_address(match["peer"]))
    except ValueError:
        raise NormalizationError("invalid_transport_peer_ip") from None
    status = int(match["status"])
    if not 100 <= status <= 599:
        raise NormalizationError("invalid_http_status")
    return peer, {"method": match["method"], "raw_target": match["target"],
                  "protocol": "HTTP/" + match["protocol"], "status_code": status}


def normalize_record(log, payload, config):
    log_id = log.get("id") if isinstance(log, dict) else None
    if not isinstance(log_id, str) or not log_id or len(log_id.encode("utf-8")) > 512:
        # CloudWatch assigns IDs. Without one, preserve delivery by failing the
        # invocation instead of inventing a source identity and dropping data.
        raise ValueError("missing_or_invalid_cloudwatch_log_event_id")
    identity = [payload["owner"], config["AWS_REGION"], payload["logGroup"], payload["logStream"], log_id]
    event_id = hashlib.sha256(json.dumps(identity, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    source = {"account_id": payload["owner"], "region": config["AWS_REGION"],
              "log_group": payload["logGroup"], "log_stream": payload["logStream"],
              "log_event_id": log_id, "systemd_unit": None,
              "synthetic": log_id.startswith("manual-validation-")}
    record = {"schema": SCHEMA, "record_type": "normalization_error", "event_id": event_id,
              "timestamp": None, "source": source, "transport_peer_ip": None,
              "client_ip": None, "ip_provenance": "unverified_proxy_peer",
              "automatic_block_eligible": False,
              "evidence": {"access_line": None, "truncated": False}}
    try:
        record["timestamp"] = iso_timestamp(log.get("timestamp"))
        peer, http = access_from_journal(log.get("message"), record["evidence"])
    except NormalizationError as exc:
        if record["evidence"]["access_line"] is not None:
            source["systemd_unit"] = APP_UNIT
        record["reason"] = str(exc)
        return record
    source["systemd_unit"] = APP_UNIT
    record.update({"record_type": "web_request", "transport_peer_ip": peer, "http": http})
    return record


def storage_client():
    global _s3
    if _s3 is None:
        import boto3
        from botocore.config import Config
        _s3 = boto3.client("s3", config=Config(connect_timeout=3, read_timeout=5,
                                              retries={"mode": "standard", "total_max_attempts": 3}))
    return _s3


def handler(event, context):
    payload = decode_envelope(event)
    if payload.get("messageType") == "CONTROL_MESSAGE":
        return {"status": "control", "received": 0, "normalized": 0, "skipped": 0,
                "error_records": 0, "record_count": 0, "bucket": None, "key": None}
    if payload.get("messageType") != "DATA_MESSAGE":
        raise ValueError("unexpected_message_type")
    config = configuration()
    if payload.get("owner") != config["EXPECTED_ACCOUNT"]:
        raise ValueError("unexpected_source_account")
    if payload.get("logGroup") != config["LOG_GROUP"]:
        raise ValueError("unexpected_log_group")
    logs = payload.get("logEvents")
    if not isinstance(logs, list) or len(logs) > MAX_EVENTS:
        raise ValueError("invalid_or_oversize_log_events")
    summary = {"status": "ignored", "received": len(logs), "normalized": 0, "skipped": 0,
               "error_records": 0, "record_count": 0, "bucket": None, "key": None}
    if payload.get("logStream") not in config["ALLOWED_LOG_STREAMS"]:
        return {**summary, "reason": "non_application_stream"}
    if not logs:
        return {**summary, "reason": "empty_batch"}
    records = [normalize_record(log, payload, config) for log in logs]
    if len({record["event_id"] for record in records}) != len(records):
        raise ValueError("duplicate_log_event_id_in_batch")
    records.sort(key=lambda record: record["event_id"])
    lines = []
    size = 0
    for record in records:
        line = (json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        size += len(line)
        if size > MAX_OUTPUT_BYTES:
            raise ValueError("normalized_batch_exceeds_limit")
        lines.append(line)
    body = b"".join(lines)
    batch_id = hashlib.sha256(body).hexdigest()
    key = config["NORMALIZED_PREFIX"] + "/" + batch_id + ".jsonl"
    normalized = sum(record["record_type"] == "web_request" for record in records)
    summary.update({"status": "written", "normalized": normalized,
                    "skipped": len(records) - normalized, "error_records": len(records) - normalized,
                    "record_count": len(records), "bucket": config["NORMALIZED_BUCKET"], "key": key})
    try:
        storage_client().put_object(Bucket=config["NORMALIZED_BUCKET"], Key=key, Body=body,
                                    ContentType="application/x-ndjson", IfNoneMatch="*",
                                    ExpectedBucketOwner=config["EXPECTED_ACCOUNT"])
    except Exception as exc:
        response = getattr(exc, "response", {})
        code = response.get("Error", {}).get("Code")
        status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if code in ("PreconditionFailed", "412") or status == 412:
            summary["status"] = "duplicate"
        else:
            raise
    # Never print request payloads or journal metadata into the function's logs.
    print(json.dumps(summary, sort_keys=True))
    return summary
