import copy
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock, patch

# AWS에 접속하지 않습니다. 저장 호출은 Mock으로 확인합니다.
fake_s3 = Mock()
fake_boto3 = types.SimpleNamespace(client=Mock(return_value=fake_s3))
spec = importlib.util.spec_from_file_location("detector", Path(__file__).with_name("detect_security_rules.py"))
detector = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"boto3": fake_boto3}), patch.dict(os.environ, {
    "RESULT_BUCKET": "test-results",
    "PROTECTED_BUCKETS": '["protected-bucket"]',
    "PROTECTED_S3_PREFIXES": '{"prefix-bucket":["critical/"]}',
    "PROTECTED_S3_OBJECTS": '["s3://object-bucket/one.txt"]',
    "TEAM_CIDRS": '["203.0.113.0/24"]',
    "PROTECTED_TRAILS": '["test-trail"]',
}, clear=True):
    spec.loader.exec_module(detector)

def event(action, bucket="protected-bucket", key=None, ip="198.51.100.20"):
    request = {"bucketName": bucket}
    if key is not None:
        request["key"] = key
    return {
        "schema_version": "2.0", "log_type": "cloudtrail",
        "event": {"id": "test-event", "time": "2026-09-14T03:00:00Z",
                  "service": "s3.amazonaws.com", "action": action},
        "cloud": {"provider": "aws", "account_id": "123456789012", "region": "ap-northeast-2"},
        "source": {"ip": ip},
        "resources": [],
        "outcome": {"status": "SUCCESS", "error_code": None},
        "details": {"request_parameters": request, "response_elements": {}},
    }

def evaluate(value):
    detector.validate_normalized_event(value)
    return detector.evaluate_security_event(value)

class S3Tests(unittest.TestCase):
    def test_all_active_event_mappings(self):
        count = 0
        for rule_id, rule in detector.S3_RULES.items():
            if not rule["enabled"]:
                continue
            for action in rule["events"]:
                with self.subTest(rule=rule_id, action=action):
                    value = event(action, key="critical/test.txt")
                    if action == "PutBucketPublicAccessBlock":
                        value["details"]["request_parameters"]["PublicAccessBlockConfiguration"] = {
                            "BlockPublicAcls": False
                        }
                    result = evaluate(value)
                    self.assertEqual(result["rule_id"], rule_id)
                    self.assertEqual(result["risk_score"], rule["base_score"])
                    self.assertEqual(result["classification"], rule["classification"])
                    self.assertEqual(result["severity"], rule["severity"])
                    count += 1
        self.assertEqual(count, 14)

    def test_every_active_action_ignores_api_failure(self):
        for rule in detector.S3_RULES.values():
            if not rule["enabled"]:
                continue
            for action in rule["events"]:
                with self.subTest(action=action):
                    value = event(action)
                    value["outcome"] = {"status": "FAILURE", "error_code": "AccessDenied"}
                    self.assertEqual(evaluate(value)["classification"], "NO_MATCH")

    def test_error_code_overrides_success(self):
        value = event("DeleteBucket")
        value["outcome"]["error_code"] = "AccessDenied"
        self.assertEqual(evaluate(value)["classification"], "NO_MATCH")

    def test_unprotected_targets(self):
        for action in ("DeleteBucket", "GetObject", "PutObjectAcl", "DeleteObjects"):
            with self.subTest(action=action):
                self.assertEqual(evaluate(event(action, bucket="other", key="x"))["classification"], "NO_MATCH")

    def test_team_ip_does_not_bypass_destructive_actions(self):
        self.assertEqual(evaluate(event("DeleteBucket", ip="203.0.113.9"))["classification"], "FINDING")
        self.assertEqual(evaluate(event("DeleteBucketPolicy", ip="203.0.113.9"))["classification"], "REVIEW")

    def test_read_ip_states(self):
        for action in ("GetObject", "ListObjects", "ListObjectsV2"):
            for ip, expected in (
                ("203.0.113.9", "NO_MATCH"), ("198.51.100.9", "REVIEW"),
                ("AWS Internal", "NO_MATCH"), (None, "NO_MATCH"),
            ):
                with self.subTest(action=action, ip=ip):
                    self.assertEqual(evaluate(event(action, key="x", ip=ip))["classification"], expected)

    def test_empty_cidr_is_unknown(self):
        with patch.object(detector, "TEAM_CIDRS", []):
            result = evaluate(event("GetObject", key="x"))
            self.assertIsNone(result["context"]["source_ip_in_team_cidrs"])
            self.assertEqual(result["classification"], "NO_MATCH")

    def test_ipv6(self):
        with patch.object(detector, "TEAM_CIDRS", [ipaddress.ip_network("2001:db8::/32")]):
            self.assertEqual(evaluate(event("GetObject", key="x", ip="2001:db8::1"))["classification"], "NO_MATCH")
            self.assertEqual(evaluate(event("GetObject", key="x", ip="2001:db9::1"))["classification"], "REVIEW")

    def test_prefix_and_exact_object(self):
        for bucket, key, expected in (
            ("prefix-bucket", "critical/a", "REVIEW"),
            ("prefix-bucket", "criticality/a", "NO_MATCH"),
            ("prefix-bucket", "other/a", "NO_MATCH"),
            ("object-bucket", "one.txt", "REVIEW"),
            ("object-bucket", "one.txt.backup", "NO_MATCH"),
        ):
            with self.subTest(bucket=bucket, key=key):
                self.assertEqual(evaluate(event("DeleteObject", bucket, key))["classification"], expected)

    def test_prefix_missing_key_goes_to_review(self):
        result = evaluate(event("DeleteObjects", "prefix-bucket"))
        self.assertEqual(result["classification"], "REVIEW")
        self.assertIn("S3_OBJECT_KEY_MISSING", result["matched_conditions"])
        self.assertFalse(result["context"]["protection_scope_confirmed"])
        self.assertEqual(result["risk_score"], 65)

    def test_prefix_scope_does_not_protect_bucket_settings(self):
        self.assertEqual(evaluate(event("DeleteBucket", "prefix-bucket"))["classification"], "NO_MATCH")

    def test_resource_arn_fallback(self):
        value = event("GetObject")
        value["details"]["request_parameters"] = {}
        value["resources"] = [{"type": "AWS::S3::Object", "arn": "arn:aws:s3:::prefix-bucket/critical/a"}]
        self.assertEqual(evaluate(value)["classification"], "REVIEW")

    def test_different_resource_bucket_cannot_override_request(self):
        value = event("DeleteObject", "other", "a")
        value["resources"] = [{"arn": "arn:aws:s3:::protected-bucket/a"}]
        self.assertEqual(evaluate(value)["classification"], "NO_MATCH")

    def test_access_point_arn_not_inferred(self):
        value = event("GetObject")
        value["details"]["request_parameters"] = {}
        value["resources"] = [{"arn": "arn:aws:s3:ap-northeast-2:123456789012:accesspoint/a/object/x"}]
        result = evaluate(value)
        self.assertIn("S3_TARGET_NOT_IDENTIFIED", result["matched_conditions"])

    def test_bpa_all_enabled_is_not_finding(self):
        for casing in ("sdk", "cloudtrail"):
            value = event("PutBucketPublicAccessBlock")
            block = {name if casing == "sdk" else name[0].lower() + name[1:]: True
                     for name in detector.REQUIRED_PUBLIC_ACCESS_BLOCK_SETTINGS}
            value["details"]["request_parameters"]["PublicAccessBlockConfiguration"] = block
            self.assertEqual(evaluate(value)["classification"], "NO_MATCH")

    def test_bpa_each_disabled_is_finding(self):
        for setting in detector.REQUIRED_PUBLIC_ACCESS_BLOCK_SETTINGS:
            with self.subTest(setting=setting):
                value = event("PutBucketPublicAccessBlock")
                block = {name: True for name in detector.REQUIRED_PUBLIC_ACCESS_BLOCK_SETTINGS}
                block[setting] = "false"
                value["details"]["request_parameters"]["publicAccessBlockConfiguration"] = block
                self.assertEqual(evaluate(value)["classification"], "FINDING")

    def test_bpa_unknown_is_review(self):
        for block in (None, {}, {"BlockPublicAcls": "invalid"}, {"BlockPublicAcls": True}):
            with self.subTest(block=block):
                value = event("PutBucketPublicAccessBlock")
                value["details"]["request_parameters"]["PublicAccessBlockConfiguration"] = block
                result = evaluate(value)
                self.assertEqual((result["classification"], result["risk_score"]), ("REVIEW", 70))
                self.assertIn("PUBLIC_ACCESS_BLOCK_CONTENT_UNKNOWN", result["matched_conditions"])

    def test_ssec_disabled_even_when_marker_present(self):
        for action in ("PutObject", "CopyObject"):
            value = event(action, key="x")
            value["details"]["additional_event_data"] = {"SSEApplied": "SSE_C"}
            self.assertIn("S3_RULE_DISABLED", evaluate(value)["matched_conditions"])

    def test_reserved_ssec_cannot_be_enabled_without_implementation(self):
        with patch.dict(detector.S3_RULES["AWS-S3-010"], {"enabled": True}):
            self.assertEqual(evaluate(event("CopyObject", key="x"))["classification"], "NO_MATCH")

    def test_get_object_metadata_not_content_rule(self):
        for action in ("GetObjectAcl", "GetObjectTagging", "HeadObject"):
            self.assertEqual(evaluate(event(action, key="x"))["classification"], "NO_MATCH")

    def test_batch_delete_unknown_does_not_claim_all_deleted(self):
        result = evaluate(event("DeleteObjects"))
        self.assertEqual(result["classification"], "REVIEW")
        self.assertIn("OBJECT_DELETE_RESULTS_NOT_CONFIRMED", result["matched_conditions"])
        self.assertFalse(result["context"]["delete_result"]["object_results_available"])

    def test_batch_partial_results(self):
        value = event("DeleteObjects", "prefix-bucket")
        value["details"]["request_parameters"]["delete"] = {
            "objects": [{"key": "critical/a"}, {"key": "critical/b"}]
        }
        value["details"]["response_elements"] = {
            "Deleted": [{"Key": "critical/a"}],
            "Errors": [{"Key": "critical/b", "Code": "AccessDenied"}],
        }
        result = evaluate(value)
        self.assertEqual(result["classification"], "REVIEW")
        self.assertTrue(result["context"]["delete_result"]["object_results_available"])

    def test_batch_all_identified_failed(self):
        value = event("DeleteObjects", "prefix-bucket")
        value["details"]["request_parameters"]["delete"] = {"objects": [{"key": "critical/a", "versionId": "v1"}]}
        value["details"]["response_elements"] = {"Errors": [{"Key": "critical/a", "VersionId": "v1", "Code": "AccessDenied"}]}
        self.assertEqual(evaluate(value)["classification"], "NO_MATCH")
        value["details"]["response_elements"]["Errors"][0]["VersionId"] = "v2"
        self.assertEqual(evaluate(value)["classification"], "REVIEW")

    def test_review_never_promoted_for_external_ip(self):
        for action in ("PutBucketPolicy", "PutBucketAcl", "PutBucketEncryption"):
            result = evaluate(event(action))
            self.assertEqual((result["classification"], result["risk_score"]), ("REVIEW", 70))

    def test_handler_and_all_storage_branches(self):
        for action, ip, prefix in (
            ("DeleteBucket", "198.51.100.1", detector.FINDING_PREFIX),
            ("GetObject", "198.51.100.1", detector.REVIEW_PREFIX),
            ("GetObject", "203.0.113.1", detector.NORMAL_PREFIX),
        ):
            with self.subTest(action=action, ip=ip):
                fake_s3.reset_mock()
                value = event(action, key="x", ip=ip)
                result = detector.lambda_handler({"normalized_event": value}, None)
                fake_s3.put_object.assert_called_once()
                call = fake_s3.put_object.call_args.kwargs
                document = json.loads(call["Body"].decode("utf-8"))
                self.assertEqual(document["normalized_event"], value)
                self.assertTrue(result["saved_key"].startswith(prefix + "/year=2026/month=09/day=14/hour=03/"))
                self.assertEqual(call["ServerSideEncryption"], "AES256")
                self.assertIsInstance(document["evaluation"]["recommended_action"], list)

    def test_input_not_mutated(self):
        value = event("PutBucketPolicy")
        before = copy.deepcopy(value)
        evaluate(value)
        self.assertEqual(value, before)

    def test_invalid_schema_rejected(self):
        value = event("DeleteBucket")
        value["schema_version"] = "1.0"
        with self.assertRaises(ValueError):
            detector.lambda_handler(value, None)

    def test_missing_time_uses_fallback(self):
        value = event("DeleteBucket")
        del value["event"]["time"]
        self.assertIn("test-event/AWS-S3-001.json", detector.build_result_key(value, evaluate(value)))

    def test_cloudtrail_rules_and_resources_regression(self):
        # 기본 픽스처 IP(198.51.100.20)는 TEAM_CIDRS 밖이라 +10점이 붙는다.
        # PutEventSelectors는 70+10=80으로 FINDING 임계값에 도달한다.
        for action, classification in (
            ("StopLogging", "FINDING"), ("DeleteTrail", "FINDING"),
            ("UpdateTrail", "REVIEW"), ("PutEventSelectors", "FINDING"),
            ("PutInsightSelectors", "REVIEW"),
        ):
            with self.subTest(action=action):
                value = event(action)
                value["event"]["service"] = "cloudtrail.amazonaws.com"
                value["details"]["request_parameters"] = {}
                value["resources"] = [{"type": "AWS::CloudTrail::Trail",
                                      "arn": "arn:aws:cloudtrail:ap-northeast-2:123456789012:trail/test-trail"}]
                self.assertEqual(evaluate(value)["classification"], classification)

if __name__ == "__main__":
    unittest.main(verbosity=2)

