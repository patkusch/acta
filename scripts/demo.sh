#!/bin/sh
# A 60-second demo with no accounts: play a whole lifecycle into a ledger,
# check it, edit one line, check it again.
set -eu
cd "$(dirname "$0")/.."
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
a="node bin/acta.mjs"
step() { $a step "$d/run" --agent "$1" --stage "$2" --action "$3" --ref "demo"; }

echo "== issue #7 arrives; agents take it from here =="
step issue-to-mr plan      "split issue 7 into two tasks"
step issue-to-mr create    "opened merge request 5"
step ci-pipeline verify    "typecheck, tests and attack table passed"
step security-fixer secure "upgraded a vulnerable dependency"
step ci-pipeline package   "built the container image"
step ci-pipeline release   "deployed to staging, smoke check passed"
step ci-pipeline release   "deployed to production"
step release-watcher monitor "production healthy after 5 minutes"
step release-watcher govern "commented the summary on issue 7"
$a step "$d/run" --close
cp "$d/run/recorder.pub" "$d/trusted.pub"

echo; echo "== the record, as written =="
$a show "$d/run"
echo; echo "== check it against a key kept elsewhere =="
$a verify "$d/run" --key "$d/trusted.pub" || true

echo; echo "== now someone edits the story: the security fix 'never happened' =="
sed -i.bak 's/upgraded a vulnerable dependency/nothing needed fixing/' "$d/run/ledger.jsonl"
$a verify "$d/run" --key "$d/trusted.pub" || true
