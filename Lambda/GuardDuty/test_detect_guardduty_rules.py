import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock, patch


fake_s3 = Mock()
fake_boto3 = types.SimpleNamespace(client=Mock(return_value=fake_s3))
spec = importlib.util.spec_from_file_location(
    "guardduty_detector",
    Path(__file__).with_name("detect_guardduty_rules.py"),
)
detector = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"boto3": fake_boto3}), patch.dict(os.environ, {
    "RESULT_BUCKET": "test-results",
    "TEAM_CIDRS": '["203.0.113.0/24"]',
}, clear=True):
    spec.loader.exec_module(detector)


def finding(finding_type="Exfiltration:S3/AnomalousBehavior", severity=8):
    return {
        "schema_version": "2.0",
        "log_type": "guardduty",
        "event": {
            "id": "finding-1",
            "time": "2026-09-15T00:00:00Z",
            "service": "guardduty.amazonaws.com",
            "action": finding_type,
        },
        "cloud": {
            "provider": "aws",
            "account_id": "896986966760",
            "region": "ap-northeast-2",
        },
        "source": {"ip": "198.51.100.10"},
        "resources": [],
        "outcome": {"status": "SUCCESS", "error_code": None},
        "details": {
            "finding": {"severity": severity, "detector_id": "detector-1"},
            "target_resource": {"instance_id": "i-test"},
        },
    }


def tampering(action="UpdateDetector", enable=False):
    value = finding()
    value["log_type"] = "cloudtrail"
    value["event"]["id"] = "event-1"
    value["event"]["action"] = action
    value["details"] = {"request_parameters": {
        "detectorId": "detector-1",
        "enable": enable,
    }}
    return value


class GuardDutyTests(unittest.TestCase):
    def test_known_finding_rule(self):
        result = detector.evaluate_security_event(finding())
        self.assertEqual(result["rule_id"], "AWS-GD-003")
        self.assertEqual(result["classification"], "FINDING")

    def test_unknown_finding_uses_guardduty_severity(self):
        result = detector.evaluate_security_event(finding("Other:Service/Unknown", 5))
        self.assertIsNone(result["rule_id"])
        self.assertEqual(result["classification"], "REVIEW")

    def test_detector_disable_and_reenable(self):
        disabled = detector.evaluate_security_event(tampering(enable=False))
        enabled = detector.evaluate_security_event(tampering(enable=True))
        self.assertEqual(disabled["rule_id"], "AWS-GDT-001")
        self.assertEqual(disabled["classification"], "FINDING")
        self.assertEqual(enabled["classification"], "REVIEW")

    def test_failed_tampering_call_is_no_match(self):
        value = tampering("DeleteDetector")
        value["outcome"] = {"status": "FAILURE", "error_code": "AccessDenied"}
        self.assertEqual(
            detector.evaluate_security_event(value)["classification"],
            "NO_MATCH",
        )

    def test_handler_saves_under_guardduty_prefix(self):
        fake_s3.reset_mock()
        value = finding()
        before = copy.deepcopy(value)
        result = detector.lambda_handler({"normalized_event": value}, None)
        self.assertEqual(value, before)
        self.assertTrue(result["saved_key"].startswith("guardduty/findings/"))
        fake_s3.put_object.assert_called_once()
        document = json.loads(fake_s3.put_object.call_args.kwargs["Body"])
        self.assertEqual(document["normalized_event"], value)

    def test_rejects_cloudtrail_service(self):
        value = finding()
        value["event"]["service"] = "cloudtrail.amazonaws.com"
        with self.assertRaises(ValueError):
            detector.lambda_handler(value, None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
