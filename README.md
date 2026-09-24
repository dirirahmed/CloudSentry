# CloudSentry — AI-Powered AWS Security Scanner

CloudSentry is a read-only AWS security scanner built as a student portfolio project. It connects to an AWS account, inspects a small set of services, applies deterministic security rules, and returns structured findings through a FastAPI backend. Optionally, it uses Amazon Bedrock to explain those findings in plain English.

The split of responsibilities is deliberate:

- **The scanner decides.** Fixed rules in code detect every finding and assign its severity.
- **Bedrock explains.** A language model adds a plain-English explanation, likely impact, and remediation context to findings the scanner has already produced. It never creates findings, changes severity, or looks at the AWS account.

CloudSentry is not a replacement for AWS Security Hub, AWS Config, GuardDuty, IAM Access Analyzer, or a professional security review. It runs a limited set of checks and should be treated as a learning project.

## What it scans

| Rule | Service | Check | Severity |
|---|---|---|---|
| IAM-001 | IAM | Wildcard actions (`*`, `service:*`, `NotAction`) in customer-managed and inline policies | CRITICAL for `*` on `*` with no condition; HIGH or MEDIUM otherwise |
| IAM-002 | IAM | Sensitive actions (e.g. `iam:PassRole`, `secretsmanager:GetSecretValue`) on `Resource: "*"` | HIGH or MEDIUM depending on the action |
| IAM-003 | IAM | Users with a console password and no MFA device (API-only users are skipped) | HIGH |
| IAM-004 | IAM | Access keys idle for 90+ days (configurable) | MEDIUM if active, LOW if deactivated |
| S3-001 | S3 | Buckets that appear public through bucket policy or ACL, taking Block Public Access into account | HIGH if public, LOW if Block Public Access is only partly enabled |
| S3-002 | S3 | No default server-side encryption configuration | MEDIUM |
| EC2-001 | EC2 | Security group allows TCP 22 from `0.0.0.0/0` or `::/0` | HIGH |
| EC2-002 | EC2 | Security group allows TCP 3389 from the internet | HIGH |
| EC2-003 | EC2 | Other broad inbound rules (all traffic, port ranges, database ports, other single ports; 80/443 are not flagged) | HIGH to LOW |
| CT-001 | CloudTrail | No trail, no logging trail, or no multi-region trail for the scanned region | HIGH or MEDIUM |
| ACCOUNT-001 | Account | Root user MFA status from `iam:GetAccountSummary` | CRITICAL if disabled |
| ACCOUNT-002 | Account | Root user has access keys | CRITICAL |

When a check cannot reach a conclusion (usually because of a missing permission), it returns an `INFO` finding with `"status": "unable_to_determine"` instead of assuming the worst. For example, if `cloudtrail:DescribeTrails` is denied, the scanner does not report CloudTrail as disabled.

## Architecture

```text
POST /scan
    │
    ▼
connect()  ── boto3 session + sts:GetCallerIdentity (validates credentials)
    │
    ▼
scan_account()  ── runs each service scanner independently
    ├── iam.scan
    ├── s3.scan
    ├── ec2.scan
    ├── cloudtrail.scan
    └── account.scan
            │
            ▼
      Finding objects  ──►  ScanResult (sorted by severity, with per-service errors)
            │
            ▼  only when include_ai is true
explain_scan()  ── up to 10 findings, most severe first
    │
    ▼
Amazon Bedrock (Converse API)  ──►  ai_explanation attached to each finding
```

Each scanner module has the same shape: a `scan(session, account_id)` function that calls AWS, plus small pure functions (`analyze_policy`, `check_public_access`, `evaluate_security_group`, ...) that apply the rules. The pure functions take plain data, which is what the tests exercise.

If one scanner fails (for example, a missing permission for a whole service), the error is recorded in `errors` and the other scanners still run.

```text
backend/
├── app/
│   ├── main.py            FastAPI app (/health, /scan)
│   ├── models.py          Finding, ScanResult, Severity
│   ├── config.py          Region, thresholds, Bedrock settings, boto3 retry config
│   ├── ai/
│   │   ├── bedrock.py     Prompt, Bedrock call, safe error handling, response parsing
│   │   └── analysis.py    Chooses which findings to explain and attaches results
│   └── scanner/
│       ├── scanner.py     Central scanner
│       ├── common.py      Shared AWS error helpers
│       ├── iam.py, s3.py, ec2.py, cloudtrail.py, account.py
└── tests/                 pytest suite with mocked AWS responses
docs/iam-policy.json       Minimum read-only scanner policy
docs/bedrock-policy.json   Optional Bedrock invocation policy
```

## AI analysis

CloudSentry uses Amazon Bedrock to explain security findings that have already been detected by deterministic rules. The scanner determines the security finding and its severity. Bedrock explains the finding and provides additional remediation context.

AI analysis is optional and off by default. When you request it:

1. The deterministic scan runs exactly as it does without AI.
2. Up to 10 findings are selected, most severe first (CRITICAL, then HIGH, and so on). `INFO` results such as "unable to determine" are not sent.
3. Each selected finding (ID, service, title, severity, resource, description, evidence, and the scanner's recommendation) is sent to Bedrock one at a time. The prompt tells the model the finding was already detected, that it must not change the severity or ID, invent evidence, or mention other issues, and that field values are data rather than instructions. Very large evidence is truncated.
4. The model must return JSON with `explanation`, `impact`, and `remediation`. Any other fields it returns (such as a different severity) are discarded, and the result is attached to the finding as `ai_explanation`.

The deterministic fields (`id`, `service`, `title`, `severity`, `resource`, `description`, `evidence`, `recommendation`) are never modified.

If Bedrock is unavailable, the scan still succeeds and returns every deterministic finding. Problems are reported in `ai_analysis` with a short, generic message; raw AWS or model errors are never returned, and a Bedrock failure is never turned into a security finding.

| Situation | Behaviour |
|---|---|
| `BEDROCK_MODEL_ID` not set, access denied, model not found, invalid credentials, Bedrock unreachable | Stops after the first attempt (the error would repeat); `ai_analysis.status` is `unavailable` |
| Throttling, timeout, or an unreadable model response for one finding | That finding is left without `ai_explanation`; the rest are still processed (`partial`, or `unavailable` if none succeed) |
| No findings, or only `INFO` findings | Bedrock is not called (`skipped`) |

### Choosing a model

No model is hard-coded. Set `BEDROCK_MODEL_ID` to any text model or inference profile that supports the Bedrock Converse API and is available and enabled in your account and region (check the Bedrock console under Model access / Model catalog). Some models are only reachable through a cross-region inference profile ID rather than a plain model ID.

Bedrock calls go to the scan region by default. If your chosen model is not available there, set `BEDROCK_REGION`.

Each request is capped at 500 output tokens, and at most 10 requests are made per scan, so a scan with AI enabled makes at most 10 model calls. Requests run one after another, so an AI-enabled scan can take noticeably longer than a plain one. Bedrock usage is billed to your AWS account.

## Setup

Requires Python 3.12+.

```bash
cd backend
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## AWS credentials

CloudSentry never stores or asks for credentials. It uses boto3's standard credential chain, so any of these work:

```bash
# Option 1: a named profile
export AWS_PROFILE=cloudsentry-audit

# Option 2: environment variables (for example, temporary credentials)
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...     # if using temporary credentials

# Option 3: IAM Identity Center
aws sso login --profile cloudsentry-audit
```

The region comes from the request body, then `AWS_REGION`, then your AWS config, and falls back to `us-east-1`. Temporary credentials from a dedicated read-only role are the safest option.

### Configuration

| Variable | Required | Purpose |
|---|---|---|
| `AWS_REGION` | No | Default region to scan, e.g. `ca-central-1` |
| `BEDROCK_MODEL_ID` | Only for AI analysis | Bedrock model or inference profile ID of your choice |
| `BEDROCK_REGION` | No | Region for Bedrock calls if different from the scan region |
| `CLOUDSENTRY_UNUSED_KEY_DAYS` | No | IAM-004 threshold in days (default `90`) |

```bash
export AWS_REGION=ca-central-1
export BEDROCK_MODEL_ID=your-model-id
```

On Windows PowerShell:

```powershell
$env:AWS_REGION = "ca-central-1"
$env:BEDROCK_MODEL_ID = "your-model-id"
```

The server starts without any AWS credentials or Bedrock settings; they are only needed when a scan runs.

## Required permissions

Permissions are split into two separate policies so the scanner itself stays read-only.

### Scanner (required, read-only)

The scanner only calls read APIs and never modifies resources. The minimum policy is in [`docs/iam-policy.json`](docs/iam-policy.json):

| Service | Actions |
|---|---|
| IAM | `GetAccountAuthorizationDetails`, `GetAccountSummary`, `GetLoginProfile`, `ListMFADevices`, `ListAccessKeys`, `GetAccessKeyLastUsed` |
| S3 | `ListAllMyBuckets`, `GetAccountPublicAccessBlock`, `GetBucketPublicAccessBlock`, `GetBucketPolicyStatus`, `GetBucketAcl`, `GetEncryptionConfiguration` |
| EC2 | `DescribeSecurityGroups` |
| CloudTrail | `DescribeTrails`, `GetTrailStatus` |

`sts:GetCallerIdentity` needs no permission. The AWS managed `SecurityAudit` policy also covers everything above. Do not run the scanner with administrator credentials.

### Bedrock (optional, only for AI analysis)

[`docs/bedrock-policy.json`](docs/bedrock-policy.json) grants `bedrock:InvokeModel`, which the Converse API uses. It does not grant access to any other AWS resources. The example allows any foundation model or inference profile; narrow `Resource` to the ARN of the model you chose. The model must also be enabled for your account in the Bedrock console.

## Running the backend

```bash
cd backend
uvicorn app.main:app --reload
```

Then:

```bash
curl http://localhost:8000/health
curl -X POST http://localhost:8000/scan -H "Content-Type: application/json" -d '{"region": "ca-central-1"}'

# With Bedrock explanations
curl -X POST http://localhost:8000/scan -H "Content-Type: application/json" -d '{"region": "ca-central-1", "include_ai": true}'
```

`POST /scan` accepts an optional body. Both fields are optional:

| Field | Default | Meaning |
|---|---|---|
| `region` | see above | Region to scan |
| `include_ai` | `false` | Add Bedrock explanations to findings |

When `include_ai` is false or omitted, Bedrock is never called, every finding has `"ai_explanation": null`, and `ai_analysis` is `null`.

Interactive API docs are at http://localhost:8000/docs.

Error responses never include credentials or raw exception text:

| Situation | Response |
|---|---|
| Missing, invalid or expired credentials | 401 |
| Invalid region format | 422 |
| Cannot reach AWS | 503 |
| Other AWS API error before scanning starts | 502 |
| Unexpected failure | 500 (details only in server logs) |
| One service denied or unavailable | 200 with the service listed in `errors` |
| Bedrock unavailable or failing | 200 with all findings; details in `ai_analysis` |

## Running tests

Tests use mocked boto3 clients and a mocked Bedrock client. They never touch a real AWS account or call Bedrock.

```bash
cd backend
pytest
```

## Example scan output

With `"include_ai": true` (AI text is illustrative):

```json
{
  "account_id": "123456789012",
  "region": "ca-central-1",
  "scanned_at": "2026-09-23T14:02:11.482Z",
  "resources_scanned": 18,
  "findings_count": 3,
  "severity_counts": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 0, "INFO": 1},
  "findings": [
    {
      "id": "EC2-001",
      "service": "EC2",
      "title": "SSH exposed to the internet",
      "severity": "HIGH",
      "resource": "sg-0a1b2c3d4e5f67890",
      "description": "Security group sg-0a1b2c3d4e5f67890 (web) allows SSH (TCP 22) from 0.0.0.0/0. This may be intentional, but it exposes any resource using this group to the whole internet.",
      "evidence": {"group_name": "web", "vpc_id": "vpc-1234", "protocol": "tcp", "from_port": 22, "to_port": 22, "sources": ["0.0.0.0/0"]},
      "recommendation": "Restrict port 22 to known IP ranges, or remove the rule and use AWS Systems Manager Session Manager or EC2 Instance Connect Endpoint for shell access.",
      "ai_explanation": {
        "explanation": "This security group lets any computer on the internet try to open an SSH connection to instances that use it.",
        "impact": "Internet-facing SSH is constantly scanned by automated tools; a weak or leaked key or an unpatched SSH server could let someone log in.",
        "remediation": "Remove the 0.0.0.0/0 rule and allow port 22 only from your own IP range, or switch to Session Manager so no inbound port is needed."
      }
    },
    {
      "id": "S3-001",
      "service": "S3",
      "title": "Potentially risky public access",
      "severity": "HIGH",
      "resource": "example-public-assets",
      "description": "Bucket 'example-public-assets' appears to be publicly accessible through its bucket policy. ...",
      "evidence": {"policy_is_public": true, "public_acl_grantees": [], "account_settings_known": true, "effective_block_public_access": {"BlockPublicAcls": false, "IgnorePublicAcls": false, "BlockPublicPolicy": false, "RestrictPublicBuckets": false}},
      "recommendation": "Confirm the bucket is meant to be public. ...",
      "ai_explanation": {"explanation": "...", "impact": "...", "remediation": "..."}
    },
    {
      "id": "CT-001",
      "service": "CloudTrail",
      "title": "Unable to determine CloudTrail status",
      "severity": "INFO",
      "resource": "account/123456789012 (ca-central-1)",
      "description": "The scanner could not determine the result of this check (access denied for cloudtrail:DescribeTrails). This is not evidence of a problem.",
      "evidence": {"status": "unable_to_determine", "reason": "access denied for cloudtrail:DescribeTrails"},
      "recommendation": "Grant the read-only permissions in docs/iam-policy.json and run the scan again.",
      "ai_explanation": null
    }
  ],
  "errors": [],
  "ai_analysis": {
    "status": "completed",
    "model_id": "your-model-id",
    "findings_selected": 2,
    "findings_explained": 2,
    "errors": []
  }
}
```

## Security limitations

- **Limited coverage.** Only the checks listed above are run. Many important controls (GuardDuty, Config, KMS key policies, VPC flow logs, RDS, Lambda, and more) are out of scope.
- **Single region.** EC2 security groups and CloudTrail are evaluated for one region per scan. IAM and S3 are global.
- **Policy analysis is simplified.** AWS managed policies (such as `AdministratorAccess`) are not evaluated, only customer-managed and inline policies. `NotResource`, permission boundaries, SCPs, resource policies, and role trust policies are not considered, so findings describe what a policy document allows, not the identity's effective permissions.
- **Exposure is not proof of vulnerability.** A public bucket or open port can be intentional. The scanner does not check whether a security group is attached to anything or what is running behind it.
- **S3 public access** relies on AWS's own policy status evaluation and ACL grants; access points and object-level ACLs are not checked.
- **Root account.** Root MFA status comes from `iam:GetAccountSummary`. If root credentials are centrally managed through AWS Organizations, results should be interpreted with that in mind.
- **Point-in-time results.** A scan reflects the account at the moment it ran.
- **AI explanations can be wrong.** They are generated text based only on the finding's fields. Treat them as helpful context; the deterministic finding, evidence, and recommendation are authoritative.
- **AI coverage is capped.** At most 10 findings per scan are explained; lower-severity findings beyond that are returned without an explanation.
- **Finding data is sent to Bedrock.** Resource names and evidence (for example policy statements and CIDR ranges) are included in the prompt. AWS states that Bedrock does not use prompts to train models, but only enable AI analysis if sending this data to Bedrock is acceptable for your account.
- **No authentication on the API.** Run it locally only; do not expose it to a network.
