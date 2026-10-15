#!/bin/sh
# Usage: scripts/ci-step.sh <agent> <stage> "<action>" [--failed]
# Writes one step into .acta-run/ using the recorder key held as a CI file variable,
# so no job ever stores the key in the artifact.
set -eu
mkdir -p .acta-run
[ -n "${ACTA_RECORDER_KEY:-}" ] && cp "$ACTA_RECORDER_KEY" .acta-run/recorder.key && chmod 600 .acta-run/recorder.key
agent=$1; stage=$2; action=$3; shift 3
node bin/acta.mjs step .acta-run --agent "$agent" --stage "$stage" --action "$action" --ref "${CI_PIPELINE_URL:-local}" "$@"
rm -f .acta-run/recorder.key
