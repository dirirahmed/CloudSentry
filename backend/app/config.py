import os

from botocore.config import Config

# Credentials are never read here: boto3 resolves them through its standard chain
# (environment variables, AWS_PROFILE / shared config, SSO, instance or container roles).
AWS_REGION = os.getenv("AWS_REGION")
FALLBACK_REGION = "us-east-1"

UNUSED_ACCESS_KEY_DAYS = int(os.getenv("CLOUDGUARD_UNUSED_KEY_DAYS", "90"))

BOTO_CONFIG = Config(
    retries={"max_attempts": 3, "mode": "standard"},
    connect_timeout=5,
    read_timeout=30,
)
