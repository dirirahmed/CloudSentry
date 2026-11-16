#!/usr/bin/env bash
# Deploys (or updates) the CloudSentry public demo: Lambda API + S3 dashboard + CloudFront.
# Run it in AWS CloudShell, signed in to the sandbox account, from the repository root:
#
#   ALERT_EMAIL=you@example.com bash deploy/serverless/deploy.sh
#
# Optional settings: STACK_NAME (default cloudsentry-demo), ALERT_EMAIL (monthly cost alert).
set -euo pipefail

STACK_NAME="${STACK_NAME:-cloudsentry-demo}"
ALERT_EMAIL="${ALERT_EMAIL:-}"
REGION="${AWS_REGION:-$(aws configure get region)}"
export AWS_REGION="$REGION"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
ARTIFACT_BUCKET="cloudsentry-artifacts-$ACCOUNT_ID-$REGION"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

[ -f deploy/serverless/template.yaml ] || { echo "Run this from the CloudSentry repository root." >&2; exit 1; }
echo "Deploying stack $STACK_NAME to account $ACCOUNT_ID in $REGION"

# --- Node.js for the dashboard build (Vite needs 20.19+ or 22.12+)
node_ok() {
  command -v node >/dev/null && node -e '
    const [major, minor] = process.versions.node.split(".").map(Number);
    process.exit((major === 20 && minor >= 19) || (major === 22 && minor >= 12) || major > 22 ? 0 : 1);'
}
if ! node_ok; then
  case "$(uname -m)" in x86_64) ARCH=x64 ;; aarch64) ARCH=arm64 ;; *) echo "Unsupported CPU" >&2; exit 1 ;; esac
  NODE_DIR=/tmp/node22
  if [ ! -x "$NODE_DIR/bin/node" ]; then
    echo "Installing Node.js 22 in $NODE_DIR"
    BASE=https://nodejs.org/dist/latest-v22.x
    TARBALL="$(curl -fsSL "$BASE/SHASUMS256.txt" | awk -v a="linux-$ARCH.tar.xz" '$2 ~ a"$" {print $2}')"
    curl -fsSL -o "/tmp/$TARBALL" "$BASE/$TARBALL"
    (cd /tmp && curl -fsSL "$BASE/SHASUMS256.txt" | grep " $TARBALL\$" | sha256sum -c -)
    mkdir -p "$NODE_DIR"
    tar -xJf "/tmp/$TARBALL" -C "$NODE_DIR" --strip-components=1
  fi
  export PATH="$NODE_DIR/bin:$PATH"
fi

# --- 1. Lambda package: the backend app plus the libraries Lambda doesn't already have
echo "Building the Lambda package"
python3 -m pip install --quiet --target "$BUILD_DIR/lambda" \
  --platform manylinux2014_x86_64 --platform manylinux_2_28_x86_64 \
  --implementation cp --python-version 3.12 --only-binary=:all: \
  -r backend/requirements-lambda.txt
cp -r backend/app "$BUILD_DIR/lambda/app"
find "$BUILD_DIR/lambda" -name __pycache__ -type d -prune -exec rm -rf {} +
python3 -c "import shutil, sys; shutil.make_archive(sys.argv[1], 'zip', sys.argv[2])" "$BUILD_DIR/lambda" "$BUILD_DIR/lambda"
CODE_KEY="lambda/cloudsentry-$(sha256sum "$BUILD_DIR/lambda.zip" | cut -c1-16).zip"

if ! aws s3api head-bucket --bucket "$ARTIFACT_BUCKET" 2>/dev/null; then
  aws s3 mb "s3://$ARTIFACT_BUCKET" --region "$REGION"
fi
aws s3 cp "$BUILD_DIR/lambda.zip" "s3://$ARTIFACT_BUCKET/$CODE_KEY" --only-show-errors

# --- 2. Infrastructure
echo "Deploying the CloudFormation stack (the first run takes about 5-10 minutes)"
aws cloudformation deploy \
  --stack-name "$STACK_NAME" \
  --template-file deploy/serverless/template.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset \
  --parameter-overrides "CodeBucket=$ARTIFACT_BUCKET" "CodeKey=$CODE_KEY" "AlertEmail=$ALERT_EMAIL"

output() {
  aws cloudformation describe-stacks --stack-name "$STACK_NAME" \
    --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text
}
SITE_BUCKET="$(output SiteBucket)"
DISTRIBUTION_ID="$(output DistributionId)"
DASHBOARD_URL="$(output DashboardUrl)"

# --- 3. Dashboard
echo "Building the dashboard"
(cd frontend && npm ci --no-audit --no-fund && VITE_DEMO_MODE=true npm run build)

echo "Uploading the dashboard"
aws s3 sync frontend/dist "s3://$SITE_BUCKET" --delete --only-show-errors \
  --exclude index.html --cache-control "public,max-age=31536000,immutable"
aws s3 cp frontend/dist/index.html "s3://$SITE_BUCKET/index.html" --only-show-errors \
  --cache-control "no-cache"
aws cloudfront create-invalidation --distribution-id "$DISTRIBUTION_ID" --paths "/*" >/dev/null

echo
echo "Done. CloudSentry is live at: $DASHBOARD_URL"
echo "(A brand-new CloudFront address can take a few more minutes to start answering.)"
