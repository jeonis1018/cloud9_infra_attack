#!/usr/bin/env python3
"""Manage only this project's entries inside the existing shared WAF/S3 objects.

Terraform owns the lifecycle via terraform_data. Config travels in an environment
variable, never through shell interpolation. All writes keep private snapshots.
"""
import argparse
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from urllib.parse import unquote_plus

from aws_cli import AWSCLI, AWSCLIError, DeploymentError

ACCOUNT = "896986966760"
REGION = "ap-northeast-2"
BUCKET = "cloud9-security-normalized-logs-896986966760-ap-northeast-2-an"
ACL_NAME = "WHS_VPC-WAF"
ACL_ID = "0d04b6a4-be8a-4de8-b094-9c914efceb72"
ACL_ARN = f"arn:aws:wafv2:{REGION}:{ACCOUNT}:regional/webacl/{ACL_NAME}/{ACL_ID}"
ALB_ARN = f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/WHS-ALB/d0ff76940805c393"
RULE_NAME = "respond-cloudwatch-agent-logs-block"
NOTIFICATION_ID = "detect-cloudwatch-agent-logs"
QUEUE_ARN = f"arn:aws:sqs:{REGION}:{ACCOUNT}:detect-cloudwatch-agent-logs"
PREFIX = "waf/response/v1/"
ACL_MUTABLE = {"Name", "Id", "DefaultAction", "Description", "Rules", "VisibilityConfig",
               "DataProtectionConfig", "CustomResponseBodies", "CaptchaConfig", "ChallengeConfig",
               "TokenDomains", "AssociationConfig", "OnSourceDDoSProtectionConfig", "ApplicationConfig", "MonetizationConfig"}
ACL_READONLY = {"ARN", "Capacity", "PreProcessFirewallManagerRuleGroups", "PostProcessFirewallManagerRuleGroups",
                "ManagedByFirewallManager", "LabelNamespace", "RetrofittedByFirewallManager"}
NOTIFICATION_KEYS = {"QueueConfigurations", "TopicConfigurations", "LambdaFunctionConfigurations", "EventBridgeConfiguration"}


def require(ok, message):
    if not ok:
        raise DeploymentError(message)


def canonical(value):
    if isinstance(value, dict):
        return {key: canonical(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return sorted((canonical(item) for item in value), key=lambda x: json.dumps(x, sort_keys=True))
    return value


def validate_config(config, kind):
    require(kind in {"notification", "waf-rule"}, "Unknown integration kind.")
    require(isinstance(config, dict), "Integration configuration must be an object.")
    expected = {"account_id": ACCOUNT, "region": REGION}
    if kind == "notification":
        expected.update(bucket=BUCKET, queue_arn=QUEUE_ARN, notification_id=NOTIFICATION_ID,
                        input_prefix=PREFIX, suffix=".jsonl")
    else:
        expected.update(web_acl_arn=ACL_ARN, alb_arn=ALB_ARN, rule_name=RULE_NAME, priority=0)
        for version in ("ipv4", "ipv6"):
            arn = config.get(version + "_set_arn", "")
            pattern = rf"arn:aws:wafv2:{REGION}:{ACCOUNT}:regional/ipset/respond-cloudwatch-agent-logs-{version}/[a-f0-9]{{8}}-(?:[a-f0-9]{{4}}-){{3}}[a-f0-9]{{12}}"
            require(isinstance(arn, str) and re.fullmatch(pattern, arn), "Unexpected response IP set ARN.")
        require(type(config.get("priority")) is int, "The response rule priority must be zero.")
    require(all(config.get(key) == value for key, value in expected.items()), "Integration scope differs from the approved team resources.")
    permitted = set(expected) | ({"ipv4_set_arn", "ipv6_set_arn"} if kind == "waf-rule" else set())
    require(set(config) == permitted, "Integration configuration contains unexpected fields.")
    return config


def notification(config):
    return {"Id": config["notification_id"], "QueueArn": config["queue_arn"], "Events": ["s3:ObjectCreated:*"],
            "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": config["input_prefix"]},
                                                {"Name": "suffix", "Value": config["suffix"]}]}}}


def canonical_notifications(current):
    require(isinstance(current, dict) and not (set(current) - NOTIFICATION_KEYS), "Unsupported S3 notification configuration.")
    result = copy.deepcopy(current)
    for kind, entries in result.items():
        if kind == "EventBridgeConfiguration":
            require(entries == {}, "Unsupported EventBridge notification fields.")
            continue
        require(isinstance(entries, list), "Invalid notification entries.")
        for entry in entries:
            require(isinstance(entry, dict), "Invalid notification entry.")
            try:
                rules = entry.get("Filter", {}).get("Key", {}).get("FilterRules", [])
            except (TypeError, AttributeError):
                raise DeploymentError("Invalid notification filter.") from None
            require(isinstance(rules, list), "Invalid notification filters.")
            seen = set()
            for rule in rules:
                require(isinstance(rule, dict) and set(rule) == {"Name", "Value"}
                        and isinstance(rule["Name"], str) and isinstance(rule["Value"], str), "Invalid notification filter rule.")
                name = rule["Name"].lower()
                require(name in {"prefix", "suffix"} and name not in seen, "Unknown or duplicate notification filter name.")
                seen.add(name)
                rule["Name"] = name
    return canonical(result)


def merge_notifications(current, config, detach=False):
    normalized = canonical_notifications(current)
    own = canonical_notifications({"QueueConfigurations": [notification(config)]})["QueueConfigurations"][0]
    count = 0
    for kind, entries in normalized.items():
        if kind == "EventBridgeConfiguration":
            continue
        for entry in entries:
            if entry.get("Id") == config["notification_id"]:
                count += 1
                require(kind == "QueueConfigurations" and entry == own, "Owned S3 notification was changed; refusing to overwrite it.")
            elif not detach and any(e == "s3:*" or e.startswith("s3:ObjectCreated:") for e in entry.get("Events", [])):
                filters = {r["Name"]: unquote_plus(r["Value"]) for r in entry.get("Filter", {}).get("Key", {}).get("FilterRules", [])}
                prefix, suffix = filters.get("prefix", ""), filters.get("suffix", "")
                require(not ((config["input_prefix"].startswith(prefix) or prefix.startswith(config["input_prefix"]))
                             and (config["suffix"].endswith(suffix) or suffix.endswith(config["suffix"]))),
                        "Another ObjectCreated notification overlaps this project's input prefix.")
    require(count <= 1, "Duplicate owned S3 notification IDs.")
    result = copy.deepcopy(current)
    if detach and count:
        result["QueueConfigurations"] = [e for e in result["QueueConfigurations"] if e.get("Id") != config["notification_id"]]
        if not result["QueueConfigurations"]:
            del result["QueueConfigurations"]
    elif not detach and not count:
        result.setdefault("QueueConfigurations", []).append(notification(config))
    return result


def owned_rule(config):
    return {"Name": config["rule_name"], "Priority": config["priority"], "Action": {"Block": {}},
            "Statement": {"OrStatement": {"Statements": [
                {"IPSetReferenceStatement": {"ARN": config["ipv4_set_arn"]}},
                {"IPSetReferenceStatement": {"ARN": config["ipv6_set_arn"]}}]}},
            "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                                 "MetricName": config["rule_name"]}}


def merge_acl(current, config, detach=False):
    acl = current.get("WebACL", {})
    require(acl.get("Name") == ACL_NAME and acl.get("Id") == ACL_ID and acl.get("ARN") == ACL_ARN
            and current.get("LockToken"), "Unexpected existing Web ACL identity.")
    require(not (set(acl) - ACL_MUTABLE - ACL_READONLY), "Unknown Web ACL fields; preserving configuration requires a helper update.")
    require(not any(acl.get(k) for k in ("ManagedByFirewallManager", "RetrofittedByFirewallManager",
                                       "PreProcessFirewallManagerRuleGroups", "PostProcessFirewallManagerRuleGroups")),
            "Firewall Manager owns this ACL; cannot change its rules.")
    rules = copy.deepcopy(acl.get("Rules", []))
    matches = [rule for rule in rules if rule.get("Name") == config["rule_name"]]
    require(len(matches) <= 1 and (not matches or canonical(matches[0]) == canonical(owned_rule(config))),
            "The owned WAF rule has unexpected settings.")
    if detach:
        rules = [rule for rule in rules if rule.get("Name") != config["rule_name"]]
    elif not matches:
        require(all(rule.get("Priority") != config["priority"] for rule in rules),
                "WAF priority zero is occupied; no existing rule was renumbered. Finish legacy teardown and inspect the ACL.")
        rules.append(owned_rule(config))
    result = {key: copy.deepcopy(value) for key, value in acl.items() if key in ACL_MUTABLE}
    result.update(Rules=rules, Scope="REGIONAL", LockToken=current["LockToken"])
    return result


class Integrations:
    def __init__(self, aws, audit_dir=None):
        self.aws = aws
        self.audit_dir = Path(audit_dir) if audit_dir else None

    def audit(self, name, data):
        if self.audit_dir is None:
            base = Path(os.environ.get("INTEGRATION_AUDIT_DIR", str(Path.home() / "cloudwatch-agent-response-terraform-audit")))
            base.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.audit_dir = Path(tempfile.mkdtemp(prefix="integration-", dir=base))
        self.audit_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.audit_dir / name
        with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        return path

    def identity(self):
        require(self.aws.call("sts", "get-caller-identity").get("Account") == ACCOUNT, "Wrong AWS account.")

    def get_notifications(self):
        return self.aws.call("s3api", "get-bucket-notification-configuration", "--bucket", BUCKET, "--expected-bucket-owner", ACCOUNT)

    def change_notification(self, config, detach=False, check=False):
        validate_config(config, "notification")
        self.identity()
        before = self.get_notifications()
        after = merge_notifications(before, config, detach)
        if check:
            require(canonical_notifications(before) == canonical_notifications(after), "S3 notification is missing.")
            return
        self.audit("s3-before.json", before)
        path = self.audit("s3-intended.json", after)
        if canonical_notifications(before) != canonical_notifications(after):
            require(canonical_notifications(self.get_notifications()) == canonical_notifications(before),
                    "S3 configuration changed concurrently; retry after coordinating with its owner.")
            self.aws.call("s3api", "put-bucket-notification-configuration", "--bucket", BUCKET,
                          "--expected-bucket-owner", ACCOUNT, "--notification-configuration", "file://" + str(path))
        actual = self.get_notifications()
        self.audit("s3-after.json", actual)
        require(canonical_notifications(actual) == canonical_notifications(after), "S3 notification verification failed.")

    def get_acl(self):
        return self.aws.call("wafv2", "get-web-acl", "--scope", "REGIONAL", "--name", ACL_NAME, "--id", ACL_ID)

    def change_waf(self, config, detach=False, check=False):
        validate_config(config, "waf-rule")
        self.identity()
        associated = self.aws.call("wafv2", "get-web-acl-for-resource", "--resource-arn", ALB_ARN).get("WebACL", {})
        require(associated.get("ARN") == ACL_ARN, "The ALB Web ACL association changed.")
        if not detach:
            resources = self.aws.call("wafv2", "list-resources-for-web-acl", "--web-acl-arn", ACL_ARN,
                                      "--resource-type", "APPLICATION_LOAD_BALANCER").get("ResourceArns", [])
            require(set(resources) == {ALB_ARN}, "The Web ACL is shared with another ALB.")
            for version in ("ipv4", "ipv6"):
                arn = config[version + "_set_arn"]
                name, identity = arn.rsplit("/", 2)[-2:]
                ipset = self.aws.call("wafv2", "get-ip-set", "--scope", "REGIONAL", "--name", name, "--id", identity).get("IPSet", {})
                require(ipset.get("ARN") == arn and ipset.get("IPAddressVersion") == version.upper(), "Unexpected response IP set.")
        for attempt in range(5):
            before = self.get_acl()
            after = merge_acl(before, config, detach)
            same = canonical(before["WebACL"].get("Rules", [])) == canonical(after["Rules"])
            if check:
                require(same, "The WAF response rule is missing.")
                return
            self.audit(f"waf-before-{attempt}.json", before)
            path = self.audit(f"waf-intended-{attempt}.json", after)
            if not same:
                try:
                    self.aws.call("wafv2", "update-web-acl", "--cli-input-json", "file://" + str(path))
                except AWSCLIError as exc:
                    if exc.code != "WAFOptimisticLockException":
                        raise
                    time.sleep(0.2 * (attempt + 1))
                    continue
            actual = self.get_acl()
            self.audit(f"waf-after-{attempt}.json", actual)
            expected = {key: value for key, value in after.items() if key not in {"Scope", "LockToken"}}
            observed = {key: value for key, value in actual.get("WebACL", {}).items() if key in ACL_MUTABLE}
            require(canonical(expected) == canonical(observed), "WAF configuration differs after the update; inspect private snapshots.")
            return
        raise DeploymentError("WAF lock contention did not clear; no blind overwrite was attempted.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=[a + "-" + k for a in ("attach", "detach", "check") for k in ("notification", "waf-rule")])
    args = parser.parse_args(argv)
    try:
        raw = os.environ.get("INTEGRATION_CONFIG", "")
        require(0 < len(raw) <= 16384, "INTEGRATION_CONFIG is missing or too large.")
        action, kind = args.operation.split("-", 1)
        config = validate_config(json.loads(raw), kind)
        runner = Integrations(AWSCLI())
        method = runner.change_notification if kind == "notification" else runner.change_waf
        method(config, detach=action == "detach", check=action == "check")
        print(json.dumps({"operation": args.operation, "status": "VERIFIED", "audit_dir": str(runner.audit_dir) if runner.audit_dir else None}))
        return 0
    except Exception as exc:
        print("ERROR: " + (str(exc) if isinstance(exc, DeploymentError) else type(exc).__name__), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
