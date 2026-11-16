#!/usr/bin/env bash
# Removes the CloudSentry public demo and everything deploy.sh created.
# Run it in AWS CloudShell, signed in to the sandbox account:
#
#   bash deploy/serverless/teardown.sh
set -euo pipefail

STACK_NAME="${STACK_NAME:-cloudsentry-demo}"
REGION="${AWS_REGION:-$(aws configure get region)}"
export AWS_REGION="$REGION"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
ARTIFACT_BUCKET="cloudsentry-artifacts-$ACCOUNT_ID-$REGION"

SITE_BUCKET="$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" \
  --query "Stacks[0].Outputs[?OutputKey=='SiteBucket'].OutputValue" --output text 2>/dev/null || true)"

# CloudFormation cannot delete a bucket that still has files in it.
if [ -n "$SITE_BUCKET" ] && [ "$SITE_BUCKET" != "None" ]; then
  aws s3 rm "s3://$SITE_BUCKET" --recursive --only-show-errors
fi

echo "Deleting stack $STACK_NAME (CloudFront takes 10-20 minutes to remove)"
aws cloudformation delete-stack --stack-name "$STACK_NAME"
aws cloudformation wait stack-delete-complete --stack-name "$STACK_NAME"

if aws s3api head-bucket --bucket "$ARTIFACT_BUCKET" 2>/dev/null; then
  aws s3 rb "s3://$ARTIFACT_BUCKET" --force
fi

echo "CloudSentry demo removed."
