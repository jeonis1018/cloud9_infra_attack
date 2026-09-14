"""Shared entry point. Route by log type, then CloudTrail event service."""
import json
import cloudtrail_s3_rules as cloudtrail
import guardduty_rules as guardduty


def lambda_handler(event, context):
    normalized_event = cloudtrail.extract_normalized_event(event)
    log_type = normalized_event.get("log_type")
    if log_type not in {"cloudtrail", "guardduty"}:
        raise ValueError("Unsupported or missing log_type")
    # Reuse schema validation without changing the original event or validator.
    validation_event = dict(normalized_event, log_type="cloudtrail")
    cloudtrail.validate_normalized_event(validation_event)
    service = normalized_event["event"]["service"]
    if log_type == "guardduty":
        if service != "guardduty.amazonaws.com":
            raise ValueError("GuardDuty log must have guardduty.amazonaws.com service")
        evaluation = guardduty.evaluate_guardduty_event(normalized_event)
    elif service == "guardduty.amazonaws.com":
        evaluation = guardduty.evaluate_guardduty_tampering(normalized_event)
    else:
        return cloudtrail.lambda_handler(event, context)
    saved_key = guardduty.save_evaluation_result(normalized_event, evaluation)
    result = {
        "statusCode": 200, "log_type": log_type,
        "event_id": normalized_event["event"]["id"],
        "classification": evaluation["classification"],
        "risk_score": evaluation["risk_score"], "severity": evaluation["severity"],
        "rule_id": evaluation["rule_id"],
        "saved_bucket": guardduty.RESULT_BUCKET, "saved_key": saved_key,
    }
    print(json.dumps(result, ensure_ascii=False))
    return result
