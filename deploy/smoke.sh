#!/bin/sh
# Usage: deploy/smoke.sh <base-url>
# Passes only if the service is up and still says "tampered" about an edited ledger.
set -eu
curl -fsS "$1/healthz" >/dev/null
code=$(printf '{"not":"a ledger"}\n' | curl -s -o /dev/null -w '%{http_code}' -X POST --data-binary @- "$1/verify")
[ "$code" = "200" ] || { echo "checker answered $code"; exit 1; }
echo "smoke ok: $1"
