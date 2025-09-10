#!/bin/sh -x
# Deploy the current Go app to Google Cloud run
set -eux -o pipefail

PROJECT=${GCP_PROJECT:=ready-to-review}
REGISTRY="${PROJECT}"
REGION="us-central1"

APP_NAME=$(basename $(go mod graph | head -n 1 | cut -d" " -f1))
APP_USER="${APP_NAME}@${PROJECT}.iam.gserviceaccount.com"
APP_IMAGE="gcr.io/${REGISTRY}/${APP_NAME}"

gcloud iam service-accounts list --project "${PROJECT}" | grep -q "${APP_USER}" ||
	gcloud iam service-accounts create "${APP_NAME}" --project "${PROJECT}"

export KO_DOCKER_REPO="${APP_IMAGE}"
gcloud run deploy "${APP_NAME}" \
	--image="$(ko publish .)" \
	--region="${REGION}" \
	--service-account="${APP_USER}" \
	--project "${PROJECT}"
