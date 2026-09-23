"""Single-writer WAF leases. The deployment MUST reserve concurrency at one.

DynamoDB is the durable desired state; WAF is reconciled from a strongly read,
bounded scan. TTL cleans old audit state and never determines release timing.
"""
from datetime import datetime, timezone
import ipaddress
import json
import os
import re
import time

import pipeline


MAX_STATE_RECORDS = 10000
MAX_SCAN_PAGES = 50
SCAN_PAGE_SIZE = 200
MAX_ACTIVE_IPS = 1000
MAX_EVIDENCE_BYTES = 128 * 1024
MAX_AUDITS_PER_RECONCILE = 25
MAX_WAF_ATTEMPTS = 4
RULE_NAME = "respond-cloudwatch-agent-logs-block"
_clients = None


class ResponseRetryableError(RuntimeError):
    """A transient SDK/concurrency failure that the workflow may retry."""


def retryable(exc):
    codes = {"WAFOptimisticLockException", "WAFUnavailableEntityException", "WAFInternalErrorException",
             "ThrottlingException", "Throttling", "TooManyRequestsException", "ProvisionedThroughputExceededException",
             "RequestLimitExceeded", "ConditionalCheckFailedException", "TransactionConflictException",
             "SlowDown", "RequestTimeout", "RequestTimeoutException", "InternalError", "ServiceUnavailable",
             "OperationAborted", "ConditionalRequestConflict", "409"}
    response = getattr(exc, "response", {})
    return (str(response.get("Error", {}).get("Code")) in codes
            or response.get("ResponseMetadata", {}).get("HTTPStatusCode") in {409, 500, 502, 503, 504}
            or type(exc).__name__ in {"ConnectionClosedError", "ConnectTimeoutError", "EndpointConnectionError", "ReadTimeoutError"})


def configuration():
    pipeline.configuration()  # Pin account, region, bucket, source ACL/ALB and prefixes.
    names = ("EXPECTED_ACCOUNT", "AWS_REGION", "NORMALIZED_BUCKET", "STATE_TABLE",
             "IPV4_SET_ID", "IPV4_SET_NAME", "IPV6_SET_ID", "IPV6_SET_NAME",
             "WEB_ACL_ARN", "ALB_ARN", "NORMALIZED_PREFIX", "WAF_LOG_GROUP")
    config = {name: os.environ.get(name, "").strip() for name in names}
    if not all(config.values()) or not re.fullmatch(r"[0-9]{12}", config["EXPECTED_ACCOUNT"]):
        raise ValueError("missing_or_invalid_response_configuration")
    config["BLOCK_SECONDS"] = int(os.environ.get("BLOCK_SECONDS", "600"))
    if not 180 <= config["BLOCK_SECONDS"] <= 3600:
        raise ValueError("block_seconds_out_of_range")
    config["EVIDENCE_PREFIX"] = os.environ.get("EVIDENCE_PREFIX", "evidence/cloudwatch-agent-response/v1").strip().rstrip("/")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9/_-]{0,127}", config["EVIDENCE_PREFIX"]):
        raise ValueError("invalid_evidence_prefix")
    config["ALLOWLIST_CIDRS"] = os.environ.get("ALLOWLIST_CIDRS", "")
    config["ALLOWLIST_NETWORKS"] = pipeline.parse_allowlist(config["ALLOWLIST_CIDRS"])
    if config["IPV4_SET_NAME"] != "respond-cloudwatch-agent-logs-ipv4" or config["IPV6_SET_NAME"] != "respond-cloudwatch-agent-logs-ipv6":
        raise ValueError("unowned_ip_set_name")
    if config["STATE_TABLE"] != "respond-cloudwatch-agent-logs-state":
        raise ValueError("unowned_state_table")
    return config


def clients(config):
    global _clients
    if _clients is None:
        import boto3
        from botocore.config import Config
        sdk = Config(connect_timeout=3, read_timeout=5, retries={"mode": "standard", "total_max_attempts": 3})
        _clients = {name: boto3.client(service, region_name=config["AWS_REGION"], config=sdk)
                    for name, service in (("ddb", "dynamodb"), ("waf", "wafv2"), ("s3", "s3"))}
    return _clients


def evidence_key(finding_id, action, prefix=None):
    if not re.fullmatch(r"[0-9a-f]{64}", finding_id) or action not in {"block", "release"}:
        raise ValueError("invalid_evidence_identity")
    prefix = (prefix or os.environ.get("EVIDENCE_PREFIX", "evidence/cloudwatch-agent-response/v1")).rstrip("/")
    return f"{prefix}/{finding_id}/{action}.json"


def iso_time(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def aws_error(exc, *codes):
    response = getattr(exc, "response", {})
    return str(response.get("Error", {}).get("Code")) in codes


class ResponseRuntime:
    def __init__(self, config, service_clients, now=None):
        self.config = config
        self.ddb, self.waf, self.s3 = (service_clients[name] for name in ("ddb", "waf", "s3"))
        self.now = int(time.time()) if now is None else int(now)

    def eligible(self, cidr):
        try:
            network = ipaddress.ip_network(cidr, strict=True)
            ip = network.network_address
            if network.prefixlen != network.max_prefixlen or pipeline.public_ip(str(ip)) is None:
                return False
            return not any(ip.version == allowed.version and ip in allowed
                           for allowed in self.config["ALLOWLIST_NETWORKS"])
        except (ValueError, TypeError):
            return False

    @staticmethod
    def decode_item(item):
        if not item:
            return None
        try:
            result = {"cidr": item["cidr"]["S"], "expires_at": int(item["expires_at"]["N"]),
                      "purge_at": int(item["purge_at"]["N"]), "revision": int(item["revision"]["N"]),
                      "desired_state": item["desired_state"]["S"],
                      "finding": pipeline.parse_json(item["finding_json"]["S"]),
                      "block_evidence_written": item.get("block_evidence_written", {}).get("BOOL", False),
                      "release_evidence_written": item.get("release_evidence_written", {}).get("BOOL", False),
                      "release_reason": item.get("release_reason", {}).get("S", "expired")}
            if (result["desired_state"] not in {"BLOCKED", "RELEASED"} or result["revision"] < 1
                    or result["purge_at"] != result["expires_at"] + 86400
                    or not isinstance(result["finding"], dict)):
                raise ValueError("invalid_state_fields")
            return result
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("invalid_response_state_item") from exc

    def get_item(self, cidr):
        response = self.ddb.get_item(TableName=self.config["STATE_TABLE"], Key={"cidr": {"S": cidr}}, ConsistentRead=True)
        return self.decode_item(response.get("Item"))

    def put_item(self, desired, previous):
        item = dict(desired, revision=(previous["revision"] + 1 if previous else 1))
        finding_json = pipeline.canonical_bytes(item["finding"])
        if len(finding_json) > MAX_EVIDENCE_BYTES // 2:
            raise ValueError("finding_exceeds_state_size_limit")
        wire = {"cidr": {"S": item["cidr"]}, "expires_at": {"N": str(item["expires_at"])},
                "purge_at": {"N": str(item["expires_at"] + 86400)}, "revision": {"N": str(item["revision"])},
                "desired_state": {"S": item["desired_state"]}, "finding_json": {"S": finding_json.decode()},
                "block_evidence_written": {"BOOL": item.get("block_evidence_written", False)},
                "release_evidence_written": {"BOOL": item.get("release_evidence_written", False)},
                "release_reason": {"S": item.get("release_reason", "expired")}}
        args = {"TableName": self.config["STATE_TABLE"], "Item": wire}
        if previous:
            args.update(ConditionExpression="#revision = :previous_revision", ExpressionAttributeNames={"#revision": "revision"},
                        ExpressionAttributeValues={":previous_revision": {"N": str(previous["revision"])}})
        else:
            args["ConditionExpression"] = "attribute_not_exists(cidr)"
        self.ddb.put_item(**args)
        item["purge_at"] = item["expires_at"] + 86400
        return item

    def scan_state(self):
        result, cursor, seen = [], None, set()
        for _ in range(MAX_SCAN_PAGES):
            args = {"TableName": self.config["STATE_TABLE"], "ConsistentRead": True, "Limit": SCAN_PAGE_SIZE}
            if cursor:
                args["ExclusiveStartKey"] = cursor
            response = self.ddb.scan(**args)
            result.extend(self.decode_item(item) for item in response.get("Items", []))
            if len(result) > MAX_STATE_RECORDS:
                raise ValueError("state_record_limit_exceeded")
            cursor = response.get("LastEvaluatedKey")
            if not cursor:
                return result
            marker = pipeline.canonical_bytes(cursor)
            if marker in seen or len(result) >= MAX_STATE_RECORDS:
                raise ValueError("state_scan_incomplete")
            seen.add(marker)
        raise ValueError("state_scan_page_limit_exceeded")

    def validate_state(self, items):
        for item in items:
            finding = self.validate(item["finding"], releasing=True)
            if (finding["cidr"] != item["cidr"] or item["expires_at"] != finding["expires_at"]
                    or finding["event_time"] > self.now):
                raise ValueError("state_finding_identity_mismatch")
        return items

    def sync_ip_set(self, version, addresses):
        prefix = "IPV4" if version == 4 else "IPV6"
        name, set_id = self.config[prefix + "_SET_NAME"], self.config[prefix + "_SET_ID"]
        expected_arn = f'arn:aws:wafv2:{self.config["AWS_REGION"]}:{self.config["EXPECTED_ACCOUNT"]}:regional/ipset/{name}/{set_id}'
        addresses = sorted(addresses)
        for attempt in range(MAX_WAF_ATTEMPTS):
            response = self.waf.get_ip_set(Name=name, Scope="REGIONAL", Id=set_id)
            current = response.get("IPSet", {})
            if (current.get("Name") != name or current.get("Id") != set_id or current.get("ARN") != expected_arn
                    or current.get("IPAddressVersion") != prefix or not response.get("LockToken")):
                raise ValueError("waf_ip_set_identity_mismatch")
            if sorted(current.get("Addresses", [])) == addresses:
                return False
            try:
                self.waf.update_ip_set(Name=name, Scope="REGIONAL", Id=set_id,
                                       Addresses=addresses, LockToken=response["LockToken"])
                return True
            except Exception as exc:
                if not aws_error(exc, "WAFOptimisticLockException") or attempt + 1 == MAX_WAF_ATTEMPTS:
                    raise
                time.sleep(0.05 * (attempt + 1))
        raise RuntimeError("waf_update_attempts_exhausted")

    def write_evidence(self, finding, action, status, effective_expiry, reason):
        immutable = {"schema": "cloudwatch-agent.response.v1", "action": action, "finding": finding,
                     "finding_id": finding["finding_id"], "cidr": finding["cidr"],
                     "requested_expires_at": finding["expires_at"], "web_acl_arn": self.config["WEB_ACL_ARN"],
                     "alb_arn": self.config["ALB_ARN"], "rule_name": RULE_NAME}
        record = {**immutable, "status": status, "effective_expires_at": effective_expiry,
                  "expires_at": effective_expiry, "observed_at": self.now, "reason": reason}
        body = pipeline.canonical_bytes(record)
        if len(body) > MAX_EVIDENCE_BYTES:
            raise ValueError("response_evidence_size_limit_exceeded")
        key = evidence_key(finding["finding_id"], action, self.config["EVIDENCE_PREFIX"])
        try:
            self.s3.put_object(Bucket=self.config["NORMALIZED_BUCKET"], Key=key, Body=body,
                               ContentType="application/json", ServerSideEncryption="AES256",
                               ExpectedBucketOwner=self.config["EXPECTED_ACCOUNT"], IfNoneMatch="*")
        except Exception as exc:
            if not aws_error(exc, "PreconditionFailed", "412") and getattr(exc, "response", {}).get("ResponseMetadata", {}).get("HTTPStatusCode") != 412:
                raise
            response = self.s3.get_object(Bucket=self.config["NORMALIZED_BUCKET"], Key=key,
                                          ExpectedBucketOwner=self.config["EXPECTED_ACCOUNT"])
            stream = response["Body"]
            try:
                old_body = stream.read(MAX_EVIDENCE_BYTES + 1)
            finally:
                stream.close()
            if len(old_body) > MAX_EVIDENCE_BYTES:
                raise ValueError("existing_response_evidence_too_large")
            try:
                old = pipeline.parse_json(old_body)
                valid = (all(pipeline.canonical_bytes(old.get(field)) == pipeline.canonical_bytes(value)
                             for field, value in immutable.items())
                         and old.get("status") in ({"BLOCKED", "SKIPPED"} if action == "block" else {"RELEASED"})
                         and type(old.get("effective_expires_at")) is int
                         and old["effective_expires_at"] >= finding["expires_at"]
                         and old.get("expires_at") == old["effective_expires_at"]
                         and type(old.get("observed_at")) is int)
            except (ValueError, TypeError, AttributeError):
                valid = False
            if not valid:
                raise ValueError("response_evidence_integrity_conflict")
        return key

    def validate(self, finding, releasing=False):
        original_seconds = finding.get("block_seconds") if isinstance(finding, dict) else None
        validated = pipeline.validate_finding(finding,
            block_seconds=original_seconds if releasing else self.config["BLOCK_SECONDS"],
            allowlist_cidrs=() if releasing else self.config["ALLOWLIST_NETWORKS"])
        if not isinstance(validated, dict):
            raise ValueError("finding_validation_did_not_return_canonical_finding")
        if not releasing and not self.eligible(validated["cidr"]):
            raise ValueError("ineligible_block_address")
        # Check the full evidence size before persisting a block intent.
        if len(pipeline.canonical_bytes(validated)) > MAX_EVIDENCE_BYTES // 2:
            raise ValueError("finding_exceeds_state_size_limit")
        return validated

    def reconcile(self):
        items = self.validate_state(self.scan_state())
        active = {4: set(), 6: set()}
        updated = []
        for item in items:
            eligible = self.eligible(item["cidr"])
            if item["desired_state"] == "BLOCKED" and item["expires_at"] > self.now and eligible:
                active[ipaddress.ip_network(item["cidr"]).version].add(item["cidr"])
            elif item["desired_state"] == "BLOCKED":
                # Persist removal intent before WAF. A later allowlist change
                # must not reactivate a previously released lease.
                desired = dict(item, desired_state="RELEASED", release_evidence_written=False,
                               release_reason="expired" if item["expires_at"] <= self.now else "address_no_longer_eligible")
                item = self.put_item(desired, item)
            updated.append(item)
        if sum(map(len, active.values())) > MAX_ACTIVE_IPS:
            raise ValueError("active_ip_capacity_exceeded")
        changed4 = self.sync_ip_set(4, active[4])
        changed6 = self.sync_ip_set(6, active[6])
        audits = 0
        pending = 0
        for item in updated:
            action = "block" if item["desired_state"] == "BLOCKED" else "release"
            flag = action + "_evidence_written"
            if item.get(flag):
                continue
            if audits >= MAX_AUDITS_PER_RECONCILE:
                pending += 1
                continue
            finding = self.validate(item["finding"], releasing=True)
            if finding["cidr"] != item["cidr"] or item["expires_at"] < finding["expires_at"]:
                raise ValueError("state_finding_identity_mismatch")
            self.write_evidence(finding, action, "BLOCKED" if action == "block" else "RELEASED",
                                item["expires_at"], "desired_state_synchronized" if action == "block" else item["release_reason"])
            self.put_item(dict(item, **{flag: True}), item)
            audits += 1
        result = {"status": "RECONCILED", "active_ipv4": len(active[4]), "active_ipv6": len(active[6]),
                  "ip_sets_updated": int(changed4) + int(changed6), "evidence_written": audits,
                  "pending_evidence": pending, "state_records": len(items)}
        print(json.dumps({"component": "cloudwatch-agent-response", "action": "reconcile", **result}, sort_keys=True))
        return result

    @staticmethod
    def result(finding, status, expiry, blocked):
        return {"status": status, "finding_id": finding["finding_id"], "cidr": finding["cidr"],
                "expires_at": expiry, "wait_until": iso_time(expiry), "blocked": blocked}

    def block(self, supplied):
        finding = self.validate(supplied)
        requested = finding["expires_at"]
        if finding["event_time"] > self.now:
            raise ValueError("future_finding_not_actionable")
        if requested <= self.now:
            self.write_evidence(finding, "block", "SKIPPED", requested, "event_lease_already_expired")
            return {**self.result(finding, "SKIPPED", requested, False), "reason": "event_lease_already_expired"}
        previous = self.get_item(finding["cidr"])
        snapshot = self.validate_state(self.scan_state())
        if previous is None and len(snapshot) >= MAX_STATE_RECORDS:
            raise ValueError("state_record_capacity_exceeded")
        active = {item["cidr"] for item in snapshot if item["desired_state"] == "BLOCKED"
                  and item["expires_at"] > self.now and self.eligible(item["cidr"])}
        if len(active | {finding["cidr"]}) > MAX_ACTIVE_IPS:
            raise ValueError("active_ip_capacity_exceeded")
        if previous:
            self.validate_state([previous])
        old_active = previous is not None and previous["desired_state"] == "BLOCKED"
        expiry = max(requested, previous["expires_at"] if old_active else 0)
        keep_previous_finding = old_active and previous["expires_at"] > requested
        same_finding = old_active and previous["finding"].get("finding_id") == finding["finding_id"]
        desired = {"cidr": finding["cidr"], "expires_at": expiry, "desired_state": "BLOCKED",
                   "finding": previous["finding"] if keep_previous_finding else finding,
                   "block_evidence_written": previous.get("block_evidence_written", False) if keep_previous_finding or same_finding else False,
                   "release_evidence_written": False, "release_reason": "expired"}
        self.put_item(desired, previous)
        self.reconcile()
        self.write_evidence(finding, "block", "BLOCKED", expiry, "desired_state_synchronized")
        return self.result(finding, "BLOCKED", expiry, True)

    def release(self, supplied, cidr=None):
        finding = self.validate(supplied, releasing=True)
        if cidr is not None and cidr != finding["cidr"]:
            raise ValueError("release_cidr_does_not_match_finding")
        self.reconcile()
        current = self.get_item(finding["cidr"])
        if (current and current["desired_state"] == "BLOCKED" and current["expires_at"] > self.now
                and self.eligible(current["cidr"])):
            return self.result(finding, "WAITING", current["expires_at"], True)
        expiry = max(finding["expires_at"], current["expires_at"] if current else 0)
        self.write_evidence(finding, "release", "RELEASED", expiry,
                            current.get("release_reason", "expired") if current else "no_active_lease")
        return self.result(finding, "RELEASED", expiry, False)


def handler(event, context):
    action = event.get("action") if isinstance(event, dict) else None
    if action is None and isinstance(event, dict) and event.get("source") == "aws.events":
        action = "reconcile"
    try:
        config = configuration()
        runtime = ResponseRuntime(config, clients(config))
        if action == "block":
            result = runtime.block(event.get("finding"))
        elif action == "release":
            result = runtime.release(event.get("finding"), event.get("cidr"))
        elif action == "reconcile":
            return runtime.reconcile()
        else:
            raise ValueError("unsupported_response_action")
        print(json.dumps({"component": "cloudwatch-agent-response", "action": action, **result}, sort_keys=True))
        return result
    except Exception as exc:
        print(json.dumps({"component": "cloudwatch-agent-response", "action": action if action in {"block", "release", "reconcile"} else "invalid",
                          "status": "ERROR", "error_type": type(exc).__name__}, sort_keys=True))
        if retryable(exc):
            raise ResponseRetryableError("response_sdk_or_concurrency_failure") from exc
        raise
