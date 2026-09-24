import os

from botocore.config import Config

# Credentials are never read here: boto3 resolves them through its standard chain
# (environment variables, AWS_PROFILE / shared config, SSO, instance or container roles).
AWS_REGION = os.getenv("AWS_REGION")
FALLBACK_REGION = "us-east-1"

UNUSED_ACCESS_KEY_DAYS = int(os.getenv("CLOUDSENTRY_UNUSED_KEY_DAYS", "90"))

BOTO_CONFIG = Config(
    retries={"max_attempts": 3, "mode": "standard"},
    connect_timeout=5,
    read_timeout=30,
)

# Optional Bedrock analysis. No model is assumed: choose one available in your account and region.
BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "").strip() or None
BEDROCK_REGION = os.getenv("BEDROCK_REGION", "").strip() or None  # defaults to the scan region

AI_MAX_FINDINGS = 10
AI_MAX_TOKENS = 500

BEDROCK_CONFIG = Config(
    retries={"max_attempts": 2, "mode": "standard"},
    connect_timeout=5,
    read_timeout=30,
)
