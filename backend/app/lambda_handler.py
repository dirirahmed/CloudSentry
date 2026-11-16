"""AWS Lambda entry point for the public demo (deploy/serverless/template.yaml).

CloudFront forwards /api/* to the function URL; Mangum strips the /api prefix and runs the
same FastAPI app used locally, so /api/scan reaches POST /scan.
"""

from mangum import Mangum

from app.main import app

handler = Mangum(app, lifespan="off", api_gateway_base_path="/api")
