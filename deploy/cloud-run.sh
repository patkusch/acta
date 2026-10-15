#!/bin/sh
# Usage: deploy/cloud-run.sh <service> <image>
# Needs GCP_PROJECT and GCP_REGION. Deploys the Acta checker, which holds no secrets.
set -eu
gcloud run deploy "$1" --image "$2" --project "$GCP_PROJECT" --region "$GCP_REGION" \
  --allow-unauthenticated --port 8080 --memory 256Mi --max-instances 2 --quiet
