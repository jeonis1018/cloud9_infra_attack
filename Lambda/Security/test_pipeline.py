"""Offline integration tests using the exact detector ZIP source mappings."""
import base64
import copy
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        package = Path(self.tmp.name)
        config = (ROOT / 'envs/security/lambdas.tf').read_text()
        block = config.split('data "archive_file" "detector" {')[1].split('data "archive_file" "tampering"')[0]
        for source, filename in re.findall(r'content\s*=\s*file\("\$\{path.module\}/([^\"]+)"\)\s*filename\s*=\s*"([^\"]+)"', block):
            (package / filename).write_text((ROOT / 'envs/security' / source).read_text())
        self.assertEqual({p.name for p in package.iterdir()}, {'lambda_function.py', 'cloudtrail_s3_rules.py', 'guardduty_rules.py'})
        self.s3 = Mock()
        self.invoke = Mock()
        self.invoke.invoke.return_value = {'StatusCode': 202}
        self.enterContext(patch.dict(os.environ, {
            'RESULT_BUCKET': 'results', 'NORMALIZED_BUCKET': 'results',
            'DETECTOR_FUNCTION_NAME': 'detector', 'RULES_FUNCTION_NAME': 'detector',
            'PROTECTED_TRAILS': '["test-trail"]', 'PROTECTED_BUCKETS': '["protected-bucket"]',
            'TEAM_CIDRS': '[]', 'FINDING_PREFIX': 'cloudtrail/findings',
        }, clear=True))
        self.enterContext(patch.dict(sys.modules, {'boto3': types.SimpleNamespace(client=lambda s: self.s3 if s == 's3' else self.invoke)}))
        self.enterContext(redirect_stdout(io.StringIO()))
        self.ct = self.load('cloudtrail_s3_rules', package / 'cloudtrail_s3_rules.py')
        self.gd = self.load('guardduty_rules', package / 'guardduty_rules.py')
        self.router = self.load('lambda_function', package / 'lambda_function.py')
        self.ctn = self.load('ct_normalizer_test', ROOT / 'Lambda/CloudTrail/normalize-cloudtrail-logs-v2.py')
        self.gdn = self.load('gd_normalizer_test', ROOT / 'Lambda/GuardDuty/normalize-guardduty-logs-v2.py')
        self.context = types.SimpleNamespace(function_name='normalizer-test')

    def load(self, name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    def raw(self, action, service='s3.amazonaws.com', **params):
        return {'eventID': 'evt', 'eventTime': '2026-09-15T00:00:00Z',
                'eventName': action, 'eventSource': service, 'awsRegion': 'ap-northeast-2',
                'recipientAccountId': '896986966760', 'requestParameters': params}

    def route_raw(self, raw):
        event = self.ctn.normalize(raw, 'test', 'test', 'test')
        before = copy.deepcopy(event)
        result = self.router.lambda_handler({'normalized_event': event}, None)
        self.assertEqual(event, before)
        return result

    def test_cloudtrail_and_s3_routes(self):
        for raw, rule, prefix in [
            (self.raw('StopLogging', 'cloudtrail.amazonaws.com', name='test-trail'), 'AWS-CT-001', 'cloudtrail/findings/'),
            (self.raw('DeleteBucket', bucketName='protected-bucket'), 'AWS-S3-001', 'cloudtrail/findings/'),
            (self.raw('DeleteBucketPolicy', bucketName='protected-bucket'), 'AWS-S3-003', 'cloudtrail/review/'),
            (self.raw('DeleteBucket', bucketName='other'), None, 'cloudtrail/normal/'),
        ]:
            with self.subTest(rule=rule):
                result = self.route_raw(raw)
                self.assertEqual(result['rule_id'], rule)
                self.assertTrue(result['saved_key'].startswith(prefix))

    def test_guardduty_tampering(self):
        for enabled, expected in [(False, 'FINDING'), (True, 'REVIEW')]:
            result = self.route_raw(self.raw('UpdateDetector', 'guardduty.amazonaws.com', enable=enabled))
            self.assertEqual(result['rule_id'], 'AWS-GDT-001')
            self.assertEqual(result['classification'], expected)
            self.assertTrue(result['saved_key'].startswith('guardduty/'))
        raw = self.raw('DeleteDetector', 'guardduty.amazonaws.com')
        raw['errorCode'] = 'AccessDenied'
        self.assertEqual(self.route_raw(raw)['classification'], 'NO_MATCH')

    def test_guardduty_normalizer_to_router(self):
        finding = {'source': 'aws.guardduty', 'detail-type': 'GuardDuty Finding',
                   'account': '896986966760', 'region': 'ap-northeast-2',
                   'detail': {'id': 'finding-1', 'updatedAt': '2026-09-15T00:00:00Z',
                              'type': 'Exfiltration:S3/AnomalousBehavior', 'severity': 8}}
        payload = {'messageType': 'DATA_MESSAGE', 'logEvents': [{'id': 'log1', 'message': json.dumps(finding)}]}
        compressed = {'awslogs': {'data': base64.b64encode(gzip.compress(json.dumps(payload).encode())).decode()}}
        for event in [finding, compressed]:
            self.gdn.lambda_handler(event, self.context)
            args = self.invoke.invoke.call_args.kwargs
            self.assertEqual(args['FunctionName'], 'detector')
            self.assertEqual(args['InvocationType'], 'Event')
            result = self.router.lambda_handler(json.loads(args['Payload']), None)
            self.assertEqual(result['rule_id'], 'AWS-GD-003')
            self.assertTrue(result['saved_key'].startswith('guardduty/findings/'))
            self.assertEqual(self.s3.put_object.call_args.kwargs['Bucket'], 'results')

    def test_cloudtrail_normalizer_to_router(self):
        record = self.raw('DeleteBucket', bucketName='protected-bucket')
        self.ctn.lambda_handler({'input_type': 'cloudtrail_event_history', 'record': record}, self.context)
        result = self.router.lambda_handler(json.loads(self.invoke.invoke.call_args.kwargs['Payload']), None)
        self.assertEqual(result['rule_id'], 'AWS-S3-001')

    def test_reject_unknown_log_type_and_schema(self):
        event = self.ctn.normalize(self.raw('DeleteBucket'), 'test', 'test', 'test')
        for field, value in [('log_type', 'other'), ('schema_version', '1.0')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.router.lambda_handler(dict(event, **{field: value}), None)


if __name__ == '__main__':
    unittest.main()
