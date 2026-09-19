"""One Lambda entry point for Agent journal and native WAF subscriptions.

Routing uses the bounded subscription envelope and never changes process
environment variables. Each implementation validates its own source contract.
"""
import os

import agent_normalizer
import pipeline

AGENT_LOG_GROUP = "/aws/events/cloud9-security/cloudwatch-agent"


def handler(event, context):
    payload = agent_normalizer.decode_envelope(event)
    if payload.get("messageType") == "CONTROL_MESSAGE":
        return {"status": "control", "record_count": 0}
    if payload.get("messageType") != "DATA_MESSAGE":
        raise ValueError("unexpected_message_type")
    if os.environ.get("EXPECTED_ACCOUNT") != pipeline.ACCOUNT or payload.get("owner") != pipeline.ACCOUNT:
        raise ValueError("unexpected_source_account")
    group = payload.get("logGroup")
    if group == AGENT_LOG_GROUP:
        return agent_normalizer.handler(event, context)
    if group == pipeline.WAF_LOG_GROUP:
        return pipeline.normalize_handler(event, context)
    raise ValueError("unexpected_log_group")
