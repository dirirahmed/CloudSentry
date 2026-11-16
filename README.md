# CloudSentry — AI-Powered AWS Security Scanner

[![CI](https://github.com/dirirahmed/CloudSentry/actions/workflows/ci.yml/badge.svg)](https://github.com/dirirahmed/CloudSentry/actions/workflows/ci.yml)

## 1. Project overview

CloudSentry is a read-only AWS security scanner built as a student portfolio project. A web dashboard lets you pick a region and run a scan; a FastAPI backend inspects IAM, S3, EC2 security groups, CloudTrail and root account settings, applies deterministic security rules, and returns structured findings. Optionally, Amazon Bedrock adds a plain-English explanation to each finding.

CloudSentry is not a replacement for AWS Security Hub, AWS Config, GuardDuty, IAM Access Analyzer, or a professional security review. It runs a limited set of checks and should be treated as a learning project.

## 2. Features

- Twelve deterministic checks across IAM, S3, EC2, CloudTrail and the root account, each with a fixed severity
- Read-only: the scanner never modifies AWS resources
- Safe handling of missing permissions: a check that cannot conclude returns an `INFO` "unable to determine" result instead of assuming the worst
- Optional Bedrock explanations (explanation, impact, remediation) for up to 10 of the most severe findings
- Web dashboard: severity breakdown with filtering, findings list, finding details with evidence, and AI analysis shown separately from scanner results
- Clear loading, empty, no-findings, error, backend-unavailable and AI-unavailable states
- Public demo on AWS that stays online at no cost within the AWS always-free limits (CloudFront, S3 and Lambda), deployed with one script; or a private EC2 deployment

## 3. Architecture

```text
Browser
   │
   ▼
React / Vite dashboard  ── calls /api/scan (same origin)
   │
   ▼
Local:        Vite dev proxy ── strips /api ──► FastAPI on localhost:8000
Public demo:  CloudFront ── /api/* ──► Lambda function URL (FastAPI through Mangum)
                         └─ /*     ──► private S3 bucket (built dashboard)
Private EC2:  nginx ── strips /api ──► FastAPI on localhost:8000
   │
   ▼
FastAPI backend (the same app in every setup)
   │
   ├──► Deterministic scanner ── boto3 ──► AWS APIs (IAM, S3, EC2, CloudTrail)   [read-only]
   │         │
   │         ▼
   │     Findings + severity  (source of truth)
   │
   └──► Optional: Amazon Bedrock (Converse API) ──► ai_explanation attached to findings
```

Inside the backend, `connect()` validates credentials with `sts:GetCallerIdentity`, then `scan_account()` runs each service scanner independently. A scanner that fails is reported in `errors` without stopping the others. When `include_ai` is true, `explain_scan()` sends the selected findings to Bedrock one at a time and attaches the results.

The browser only ever talks to the backend. AWS credentials stay on the server.

## 4. Deterministic scanning vs AI explanation

- **The scanner decides.** Fixed rules in code detect every finding and assign its severity. The same account always produces the same findings.
- **Bedrock explains.** A language model adds context to findings the scanner has already produced. It never creates findings, changes severity or IDs, or looks at the AWS account.

How AI analysis works when `include_ai` is true:

1. The deterministic scan runs exactly as it does without AI.
2. Up to 10 findings are selected, most severe first. `INFO` results are not sent.
3. Each selected finding (ID, service, title, severity, resource, description, evidence, and the scanner's recommendation) is sent to Bedrock. The prompt states that the finding was already detected, that the model must not change the severity or ID, invent evidence, or mention other issues, and that field values are data rather than instructions. Very large evidence is truncated.
4. The model must return JSON with `explanation`, `impact` and `remediation`. Any other fields it returns are discarded.

The deterministic fields (`id`, `service`, `title`, `severity`, `resource`, `description`, `evidence`, `recommendation`) are never modified. In the dashboard, AI text appears in a separate, clearly labelled "AI analysis" panel below the scanner result.

If Bedrock is unavailable, the scan still succeeds and returns every deterministic finding. The problem is reported in `ai_analysis` with a short, generic message:

| Situation | Behaviour |
|---|---|
| `BEDROCK_MODEL_ID` not set, access denied, model not found, invalid credentials, Bedrock unreachable | Stops after the first attempt (the error would repeat); status `unavailable` |
| Throttling, timeout, or an unreadable model response for one finding | That finding has no `ai_explanation`; the rest are still processed (`partial`, or `unavailable` if none succeed) |
| No findings, or only `INFO` findings | Bedrock is not called (`skipped`) |

## 5. Supported AWS checks

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

When a check cannot reach a conclusion (usually because of a missing permission), it returns an `INFO` finding with `"status": "unable_to_determine"`. For example, if `cloudtrail:DescribeTrails` is denied, CloudSentry does not report CloudTrail as disabled.

## 6. Tech stack

| Part | Technology |
|---|---|
| Scanner and API | Python 3.12, FastAPI, Pydantic, boto3 |
| AI explanations | Amazon Bedrock Converse API (model of your choice) |
| Dashboard | React 19, TypeScript, Vite, plain CSS |
| Tests | pytest (backend), Vitest with jsdom (frontend) |
| Deployment | Public demo: CloudFront, S3 and Lambda, defined in one CloudFormation template. Private option: one EC2 instance with nginx and systemd |

## 7. Local setup

Requirements: Python 3.12+, Node.js 20.19+ or 22.12+, and AWS credentials for the account you want to scan.

```bash
git clone https://github.com/dirirahmed/CloudSentry.git
cd CloudSentry

# Backend
cd backend
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cd ..

# Frontend
cd frontend
npm install
```

### AWS credentials

CloudSentry never stores or asks for credentials. The backend uses boto3's standard credential chain, so any of these work:

```bash
export AWS_PROFILE=cloudsentry-audit                 # a named profile
aws sso login --profile cloudsentry-audit           # IAM Identity Center
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...   # temporary credentials
```

Temporary credentials for a dedicated read-only role are the safest option. Do not use administrator credentials.

### Required AWS permissions

Permissions are split so the scanner stays read-only.

**Scanner (required, read-only)** — [`docs/iam-policy.json`](docs/iam-policy.json):

| Service | Actions |
|---|---|
| IAM | `GetAccountAuthorizationDetails`, `GetAccountSummary`, `GetLoginProfile`, `ListMFADevices`, `ListAccessKeys`, `GetAccessKeyLastUsed` |
| S3 | `ListAllMyBuckets`, `GetAccountPublicAccessBlock`, `GetBucketPublicAccessBlock`, `GetBucketPolicyStatus`, `GetBucketAcl`, `GetEncryptionConfiguration` |
| EC2 | `DescribeSecurityGroups` |
| CloudTrail | `DescribeTrails`, `GetTrailStatus` |

`sts:GetCallerIdentity` needs no permission. The AWS managed `SecurityAudit` policy also covers everything above.

**Bedrock (optional)** — [`docs/bedrock-policy.json`](docs/bedrock-policy.json) grants only `bedrock:InvokeModel`, which the Converse API uses. Narrow `Resource` to the ARN of the model you choose, and make sure that model is enabled for your account in the Bedrock console.

## 8. Environment variables

Backend (set in your shell locally, or in `/etc/cloudsentry.env` on EC2):

| Variable | Required | Purpose |
|---|---|---|
| `AWS_REGION` | No | Default region to scan, e.g. `ca-central-1` (falls back to your AWS config, then `us-east-1`) |
| `BEDROCK_MODEL_ID` | Only for AI analysis | Bedrock model or inference profile ID of your choice |
| `BEDROCK_REGION` | No | Region for Bedrock calls if different from the scan region |
| `CLOUDSENTRY_UNUSED_KEY_DAYS` | No | IAM-004 threshold in days (default `90`) |

Frontend (see [`frontend/.env.example`](frontend/.env.example)):

| Variable | Default | Purpose |
|---|---|---|
| `VITE_API_URL` | `/api` | Base path of the API as seen from the browser |
| `VITE_DEMO_MODE` | `false` | `true` builds the public demo: a banner explains the sandbox account and the AI toggle is replaced by a note |

Every `VITE_` variable is embedded in the public JavaScript bundle. Never put credentials in the frontend.

**Choosing a Bedrock model:** no model is hard-coded. Set `BEDROCK_MODEL_ID` to any text model or inference profile that supports the Converse API and is available in your account and region (see the Bedrock console's model catalog). Some models are only reachable through a cross-region inference profile ID. Each request is capped at 500 output tokens, at most 10 requests are made per scan, and Bedrock usage is billed to your AWS account.

## 9. Running the backend

```bash
cd backend
uvicorn app.main:app --reload        # Windows: py -m uvicorn app.main:app --reload
```

The server starts without AWS credentials or Bedrock settings; they are only needed when a scan runs. Interactive API docs are at <http://localhost:8000/docs>.

| Endpoint | Purpose |
|---|---|
| `GET /health` | Returns `{"status": "ok"}` |
| `POST /scan` | Body (all optional): `{"region": "ca-central-1", "include_ai": false}` |

The response contains `account_id`, `region`, `scanned_at`, `resources_scanned`, `findings_count`, `severity_counts`, `findings` (each with the deterministic fields and `ai_explanation`, which is `null` unless AI added one), `errors` (services that could not be scanned) and `ai_analysis` (`null` when AI was not requested).

| Situation | Response |
|---|---|
| Missing, invalid or expired credentials | 401 |
| Invalid region format | 422 |
| Cannot reach AWS | 503 |
| Other AWS API error before scanning starts | 502 |
| Unexpected failure | 500 (details only in server logs) |
| One service denied or unavailable | 200, with the service listed in `errors` |
| Bedrock unavailable or failing | 200, with all findings; details in `ai_analysis` |

Error responses never include credentials or raw exception text.

## 10. Running the frontend

With the backend running on port 8000, in a second terminal:

```bash
cd frontend
npm run dev
```

Open <http://127.0.0.1:5173>. The Vite dev server forwards `/api/*` to `http://127.0.0.1:8000`, so the browser sees one origin and the backend needs no CORS configuration.

```bash
npm run build      # type-check and build to frontend/dist
npm run preview    # serve the production build locally (also proxies /api)
```

## 11. AWS deployment

There are two ways to run CloudSentry on AWS:

- **Option A, public demo:** a live link anyone can open, for example from a resume. It scans a dedicated sandbox account and costs nothing within the AWS always-free limits.
- **Option B, private instance:** only you can reach it. Use it to scan a real account, with AI analysis if you want it.

### Option A: Public demo (serverless)

[`deploy/serverless/template.yaml`](deploy/serverless/template.yaml) defines everything as one CloudFormation stack, and [`deploy/serverless/deploy.sh`](deploy/serverless/deploy.sh) builds and deploys it from AWS CloudShell. Nothing needs to be installed on your computer.

| Part | What it is |
|---|---|
| CloudFront distribution | The public HTTPS address. Serves the dashboard and forwards `/api/*` to Lambda |
| Private S3 bucket | Holds the built dashboard. Only this CloudFront distribution can read it |
| Lambda function | The same FastAPI app, run through [Mangum](https://github.com/Kludex/mangum). Its function URL uses IAM auth, so only CloudFront can call it (origin access control) |
| Lambda role | The read-only scanner permissions from `docs/iam-policy.json`, plus permission to write logs. No Bedrock access |
| Demo resources | Three IAM policies, three security groups, an empty VPC and an empty bucket, each insecure on purpose so the scanner has something to find. None of them is attached to anything, so they expose nothing |
| Budget alert (optional) | Emails you as soon as the account is charged anything |

**Why a sandbox account?** The public demo has no login, so anyone who opens it can scan whichever account it runs in and see the results. Deploy it only in a separate, empty AWS account, never in an account with real resources.

**Cost:** CloudFront, Lambda and CloudWatch Logs all have monthly allowances in the AWS always-free tier, and a portfolio demo uses a tiny fraction of them. The dashboard is under 1 MB in S3. AI analysis is turned off, so there are no Bedrock charges. Set `ALERT_EMAIL` so that any unexpected charge reaches you quickly.

These steps have not been run end to end yet. CloudFormation rolls back on its own if a step fails.

**1. Create a sandbox account.** In your main AWS account, open **AWS Organizations**, then **Add an AWS account** → **Create an AWS account**. Name it, for example, `cloudsentry-sandbox`, and give it an email address you control that is not already used by an AWS account (with Gmail, `you+cloudsentry@gmail.com` works).

**2. Sign in to it.** From the account menu in the top right of the console, choose **Switch role**, enter the new account's 12-digit ID and the role name `OrganizationAccountAccessRole`, and confirm. Pick your region in the top bar (for example **Canada (Central)**).

**3. Deploy from CloudShell.** Open **CloudShell** (the terminal icon in the top bar) and run:

```bash
cd /tmp && git clone https://github.com/dirirahmed/CloudSentry.git && cd CloudSentry
ALERT_EMAIL=you@example.com bash deploy/serverless/deploy.sh
```

The script packages the backend for Lambda, deploys the stack (about 5–10 minutes the first time), builds the dashboard and uploads it. It finishes by printing the address, which looks like `https://d1234abcd.cloudfront.net`. A new CloudFront address can take a few more minutes to start answering.

**4. Check it.** Open the address and run a scan. You should see the planted findings: a CRITICAL wildcard admin policy (IAM-001); HIGH findings for an `iam:PassRole` policy (IAM-002) and for open SSH and RDP (EC2-001, EC2-002); MEDIUM findings for an `s3:*` policy (IAM-001) and an open PostgreSQL port (EC2-003); and a LOW finding for a bucket with only partial Block Public Access (S3-001). If the account has no CloudTrail trail you will also see CT-001, and the root account check (ACCOUNT-001) reports what AWS returns for the new account.

**Updating after a push:** open CloudShell in the sandbox account and run the two commands from step 3 again. CloudShell clears `/tmp` between sessions, so cloning again is expected.

**Removing it:** run `bash deploy/serverless/teardown.sh` from the cloned repository. It empties the dashboard bucket, deletes the stack (CloudFront takes 10–20 minutes) and removes the bucket that held the Lambda package.

### Option B: Private EC2 instance

This option is a single EC2 instance that serves the dashboard with nginx and runs the API with systemd. It has **no inbound ports open**; you reach it through an AWS Systems Manager port-forwarding session. The configuration is in [`deploy/`](deploy/).

Use it to scan a real account with AI analysis enabled: the API has no authentication, so it must not be public when it can scan an account you care about.

These steps have not been run end to end yet. Treat them as a starting point and check each step's output.

**Prerequisites:** the AWS CLI v2 with credentials that can create IAM roles and EC2 instances, and the [Session Manager plugin](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html) installed locally.

**1. Create the instance role** (from the repository root):

```bash
aws iam create-role --role-name CloudSentryEC2Role \
  --assume-role-policy-document file://deploy/ec2-trust-policy.json
aws iam attach-role-policy --role-name CloudSentryEC2Role \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
aws iam put-role-policy --role-name CloudSentryEC2Role \
  --policy-name CloudSentryScannerReadOnly --policy-document file://docs/iam-policy.json
# Optional, only for AI analysis:
aws iam put-role-policy --role-name CloudSentryEC2Role \
  --policy-name CloudSentryBedrockInvoke --policy-document file://docs/bedrock-policy.json

aws iam create-instance-profile --instance-profile-name CloudSentryEC2Profile
aws iam add-role-to-instance-profile --instance-profile-name CloudSentryEC2Profile \
  --role-name CloudSentryEC2Role
```

`AmazonSSMManagedInstanceCore` is the AWS managed policy that lets Session Manager reach the instance. The role gets no write access to your resources.

**2. Launch the instance** in the EC2 console:

- AMI: Ubuntu Server 24.04 LTS; instance type `t3.small` (a `t3.micro` may run out of memory during `npm install`)
- Key pair: none (Session Manager replaces SSH)
- Network: a subnet with outbound internet access (for example, the default VPC with a public IP), and a new security group with **all inbound rules removed**
- Advanced details: IAM instance profile `CloudSentryEC2Profile`, metadata version "V2 only"

**3. Install CloudSentry** (wait a few minutes for the instance to register with Systems Manager):

```bash
aws ssm start-session --target i-0123456789abcdef0
```

Then, in the session:

```bash
sudo apt-get update && sudo apt-get install -y git
sudo git clone https://github.com/dirirahmed/CloudSentry.git /opt/cloudsentry
sudo bash /opt/cloudsentry/deploy/setup-ec2.sh
sudo nano /etc/cloudsentry.env          # set AWS_REGION and, optionally, BEDROCK_MODEL_ID
sudo systemctl restart cloudsentry
curl -s localhost/api/health            # expect {"status":"ok"}
```

The setup script installs Python, Node.js 22, nginx and the app, builds the dashboard, and starts the `cloudsentry` service (listening on `127.0.0.1:8000`) behind nginx. The backend gets short-lived credentials from the instance role; no access keys are stored on the instance.

**4. Open the dashboard** from your computer:

```bash
aws ssm start-session --target i-0123456789abcdef0 \
  --document-name AWS-StartPortForwardingSession \
  --parameters "portNumber"=["80"],"localPortNumber"=["8080"]
```

Leave that running and open <http://localhost:8080>.

**Updating:** start a session and run `sudo bash /opt/cloudsentry/deploy/setup-ec2.sh` again.

**Tearing down:** terminate the instance, then remove the instance profile and role (`remove-role-from-instance-profile`, `delete-instance-profile`, `delete-role-policy`, `detach-role-policy`, `delete-role`).

Costs: the EC2 instance is billed while it runs, and Bedrock is billed per request. Stop the instance when you are not using it.

## 12. Security considerations

- **Credentials never reach the browser.** The dashboard only calls the CloudSentry API. The backend uses the standard AWS credential chain locally, the function's role on Lambda, and the instance role on EC2.
- **Public only where it is safe.** The API has no authentication. The public demo is therefore limited to a sandbox account with a read-only role and no Bedrock access. Its Lambda function and S3 bucket only accept requests from its CloudFront distribution (origin access control). Locally the API listens on `localhost`, and on EC2 it is reachable only through a Session Manager tunnel.
- **Least privilege.** The scanner policy is read-only. The Bedrock policy only allows `bedrock:InvokeModel`. Neither grants access to modify resources.
- **Safe errors.** API errors return short, generic messages; details stay in server logs. The dashboard shows only those messages, never stack traces.
- **Untrusted text is rendered as text.** Resource names, evidence and AI output are displayed as plain text (React escapes them), and CloudFront (or nginx on EC2) sends a strict Content Security Policy.
- **Finding data goes to Bedrock when AI is enabled.** Resource names and evidence (for example policy statements and CIDR ranges) are included in prompts. AWS states that Bedrock does not use prompts to train models, but only enable AI analysis if sending this data to Bedrock is acceptable for your account.

## 13. Limitations

- **Limited coverage.** Only the checks listed above are run. GuardDuty, Config, KMS key policies, VPC flow logs, RDS, Lambda and many other controls are out of scope.
- **One region per scan.** EC2 security groups and CloudTrail are evaluated for the chosen region. IAM and S3 are global.
- **Simplified policy analysis.** AWS managed policies (such as `AdministratorAccess`) are not evaluated. `NotResource`, permission boundaries, SCPs, resource policies and role trust policies are not considered, so findings describe what a policy document allows, not an identity's effective permissions.
- **Exposure is not proof of vulnerability.** A public bucket or open port can be intentional. The scanner does not check whether a security group is attached to anything.
- **S3 public access** relies on AWS's own policy status evaluation and ACL grants; access points and object ACLs are not checked.
- **Root account** MFA status comes from `iam:GetAccountSummary`; interpret it with care if root credentials are centrally managed through AWS Organizations.
- **AI explanations can be wrong** and cover at most 10 findings per scan. The deterministic finding is authoritative.
- **No accounts, history or scheduling.** Each scan is a single synchronous request; results are not stored. On the public demo a scan must finish within 60 seconds (the CloudFront and Lambda limit); on EC2 the limit is 300 seconds.
- **No authentication.** Keep the API private unless it can only scan a sandbox account, as in the public demo.
- **No per-visitor rate limit on the public demo.** That would need AWS WAF, which is not free. Scans cost nothing within the free tier, and the budget alert catches unusual use.

## 14. Testing

Backend tests use mocked boto3 and Bedrock clients and never touch a real AWS account. They also run the Lambda entry point with sample function URL events:

```bash
cd backend
py -m pytest          # or: python -m pytest
```

Frontend tests use Vitest with jsdom and a mocked `fetch`; they cover the API client and the dashboard's states (empty, loading, results, AI analysis, AI unavailable, no findings, scan error, backend unavailable, rate-limited, invalid region, and the public demo mode):

```bash
cd frontend
npm test
npm run build         # also type-checks
```

### Continuous integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push to `main` and on pull requests. It runs the backend tests on Python 3.12, the frontend tests and production build on Node.js 22, and checks the deployment files with cfn-lint and ShellCheck. The workflow has no AWS credentials and only read access to the repository; every AWS and Bedrock call in the tests is mocked.

## 15. Project structure

```text
CloudSentry/
├── .github/workflows/ci.yml     Tests, build and deployment checks on every push and pull request
├── backend/
│   ├── app/
│   │   ├── main.py              FastAPI app (/health, /scan)
│   │   ├── lambda_handler.py    Runs the same app on AWS Lambda (public demo)
│   │   ├── models.py            Finding, ScanResult, Severity, AI models
│   │   ├── config.py            Region, thresholds, Bedrock settings
│   │   ├── scanner/             Deterministic checks: iam, s3, ec2, cloudtrail, account
│   │   └── ai/                  Bedrock prompt, call and parsing; finding selection
│   ├── tests/                   pytest suite (mocked AWS and Bedrock)
│   ├── requirements.txt
│   └── requirements-lambda.txt  What the Lambda package needs
├── frontend/
│   ├── src/
│   │   ├── App.tsx              Page layout and scan state
│   │   ├── api.ts               API client and error handling
│   │   ├── types.ts             Types matching the backend models
│   │   ├── components/          Controls, summary, findings list, details, AI panel, states
│   │   ├── styles.css
│   │   └── *.test.ts(x)         Vitest tests (test data lives in src/test/)
│   ├── .env.example
│   ├── package.json
│   └── vite.config.ts           Dev proxy: /api -> 127.0.0.1:8000
├── deploy/
│   ├── serverless/              Public demo: CloudFormation template, deploy and teardown scripts
│   ├── setup-ec2.sh             Private EC2 option: installs/updates CloudSentry on Ubuntu 24.04
│   ├── nginx.conf               Serves the dashboard, proxies /api
│   ├── cloudsentry.service      systemd unit for the API
│   ├── cloudsentry.env.example  Backend settings on the instance
│   └── ec2-trust-policy.json    Trust policy for the instance role
├── docs/
│   ├── iam-policy.json          Read-only scanner permissions
│   └── bedrock-policy.json      Optional Bedrock invocation permission
└── README.md
```
