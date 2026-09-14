# CloudTrail security stack

This Terraform root creates the security pipeline in AWS account `896986966760`, Region `ap-northeast-2`:

`CloudTrail (multi-region, management + attack-bucket S3 object data events) → /aws/cloudtrail/cloud9-security → CloudWatch Logs subscription → normalize-cloudtrail-logs-v2 → normalized S3 objects + detect_security_rules → normal/review/findings S3 objects`

It also creates `EventBridge Scheduler (every minute) → detect-cloudtrail-tampering → normalize-cloudtrail-logs-v2 → detect_security_rules`. The tampering Lambda looks back five minutes using CloudTrail Event History, so it can see relevant management events when the Trail delivery path is stopped. The scheduler may reprocess an event during several consecutive runs; the existing event-ID-based S3 key makes results overwrite by event ID/rule ID, but Lambda invocations and logs can repeat.

## Prerequisites

- The existing Terraform backend bucket `cloud943-attack-tfstate` must exist and be accessible. An S3 backend cannot create its own bucket during `terraform init`.
- Configure valid AWS credentials for account `896986966760`. The repo's attack roots and this root currently use the placeholder profile `cloud943` in their backend blocks. Change those backend profile fields or supply `-backend-config="profile=<PROFILE>"` during init. Set `aws_profile` to the same account's profile. Confirm with `aws sts get-caller-identity --profile <PROFILE>` before applying. The security AWS provider refuses any account other than `896986966760`.
- Apply the selected existing attack root (`envs/before` or `envs/after`) **once after the added outputs.tf is present**, so its remote state exposes `attack_target_bucket_name` and `attack_target_bucket_arn`. Select that root via `attack_environment`; the security stack does not create a second attack bucket.
- The deployment identity needs permission to create S3 buckets/policies, CloudTrail, CloudWatch Logs/subscription filters, Lambda, IAM roles/policies, Scheduler, and to read both S3 state objects. If IAM requires a permissions boundary, set `permissions_boundary_arn` and verify the boundary permits the actions used by these roles.

Example, after credentials and the attack-state outputs are ready:

```sh
cd envs/security
terraform init -backend-config="profile=<PROFILE>"
terraform plan -var="aws_profile=<PROFILE>" -var="attack_environment=before" -out=security.tfplan
terraform apply security.tfplan
terraform output
```

If `terraform init` previously used another backend configuration, use `terraform init -reconfigure -backend-config="profile=<PROFILE>"`. Review the plan before applying. If any of the intended resources already exist outside this state, import them first; creating duplicate resources with the same names will fail. Do not apply both `before` and `after` security stacks against the same account: they would manage the same named resources.

## What Terraform sets

- Trail: `cloud9-security-multi-region`, continuous logging, management events plus S3 object data events only for the attack bucket exported by the selected attack root. This creates a separate, private, AES256-encrypted raw CloudTrail S3 bucket.
- CloudWatch Logs group: `/aws/cloudtrail/cloud9-security`, 30-day retention; subscription filter forwards CloudTrail, S3, EC2, IAM, STS, sign-in, and SSM event sources. The filter is intentionally broad so later service rules can be added without losing these logs. CloudTrail management events and S3 data events can incur charges.
- Three Python 3.14 Lambdas, their execution roles and least-scope policies, CloudWatch Logs invocation permission, and a one-minute Scheduler invocation role/schedule.
- Results bucket: `cloud9-security-normalized-logs-896986966760-ap-northeast-2-an`. The normalizer currently also saves normalized events under `cloudtrail/year=...`; detector results go under `cloudtrail/normal`, `cloudtrail/review`, or `cloudtrail/findings`. Detector protection settings use the exported attack bucket and this new Trail name. Check `team_cidrs` before deployment.

## Verification

```sh
aws cloudtrail get-trail-status --name cloud9-security-multi-region --region ap-northeast-2 --profile <PROFILE>
aws logs describe-subscription-filters --log-group-name /aws/cloudtrail/cloud9-security --region ap-northeast-2 --profile <PROFILE>
aws scheduler get-schedule --name detect-cloudtrail-tampering-every-minute --region ap-northeast-2 --profile <PROFILE>
```

Then run a **non-destructive** CloudTrail management action and check normalizer/detector CloudWatch Logs plus S3 result objects. Test the S3 rules in a dedicated disposable attack bucket. Do not stop or delete the protective Trail merely to verify initial deployment. The S3 rule tests in `Lambda/CloudTrail/test_detect_security_rules.py` run locally with `python3 -m unittest -q test_detect_security_rules` from that directory.

## Current limits

- Terraform syntax and Python unit tests are validated locally; live AWS `plan`, `apply`, and end-to-end delivery still require working target-account credentials and populated attack-stack remote-state outputs.
- S3-010 (SSE-C object write/copy detection) is reserved but disabled; CloudTrail metadata alone does not prove a successful ransomware-style overwrite. Approval exceptions and automatic remediation are not implemented. A `FINDING` means a rule matched, not that an incident is confirmed.
- Lambda asynchronous invocation acceptance is not proof that the detector completed; monitor both Lambda error metrics and the S3 result object.

## Shared detector wiring (2026-09-15)

The detector ZIP now contains `lambda_function.py` (router), `cloudtrail_s3_rules.py`
(the unchanged CloudTrail/S3 implementation), and `guardduty_rules.py` (extracted
from the locally available origin/main). The 32 divergent commits were not merged.
CloudTrail normalizer still uses DETECTOR_FUNCTION_NAME; GuardDuty normalizer uses
RULES_FUNCTION_NAME. Both send {"normalized_event": ...} with schema_version 2.0.

GuardDuty Finding -> EventBridge -> CloudWatch Logs -> GuardDuty normalizer -> shared
detector -> guardduty/{normal,review,findings}. GuardDuty management API events keep
log_type=cloudtrail and route by event.service=guardduty.amazonaws.com to the
GuardDuty tampering evaluator. CloudTrail/S3 evaluation and paths remain unchanged.

GuardDuty detector enablement is a prerequisite, not created here. Delivery is in
ap-northeast-2 only. Import already existing module resources before apply; do not
manage the same GuardDuty delivery resources from another Terraform state.
Run terraform init -backend=false for offline validation after adding the module;
backend authentication and remote-state checks are still needed before plan/apply.
The five-minute Event History fallback still covers only the five CloudTrail actions.
GuardDuty normalizer currently logs invocation failures without raising; no DLQ or
end-to-end AWS delivery verification has been added. GuardDuty rule thresholds and
filter semantics were retained and require the owner's review before deployment.
