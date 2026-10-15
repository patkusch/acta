# Acta on GitLab: the post-code lifecycle, on the record

Built for the GitLab Transcend hackathon (Path B: an existing MIT project, with the automation and deploy added on or after 5 October 2026).

**What it does.** You open an issue. Agents plan it, open a merge request, fix what the security scans find, ship it through staging to production, watch it after release, and comment the result on the issue. Every action goes into an Acta ledger, so afterwards anyone can check the story was not edited.

| Stage | Who does it | Record |
|:--|:--|:--|
| plan | `issue-to-mr` flow | `acta step --stage plan` |
| create | `issue-to-mr` flow | `--stage create` |
| verify | `test` job (types, tests, attack table) | `ci-step.sh` |
| package | `package` job builds the container | |
| secure | SAST, secret and dependency scans, then `security-fixer` flow | `--stage secure` |
| release | `deploy_staging`, `deploy_production` to Cloud Run | |
| configure | `deploy/` and `.gitlab-ci.yml` change only through merge requests | |
| monitor | smoke jobs, then `release-watcher` flow | `--stage monitor` |
| govern | `govern` job closes and verifies the ledger | `--stage govern` |

**What was added in the submission period** (everything below is new since 5 October): `acta step`, `acta serve`, `Dockerfile`, `.gitlab-ci.yml`, `deploy/`, `scripts/ci-step.sh`, `.gitlab/duo/flows/`, this page.

## Set-up you must do by hand
1. Import this repo into GitLab (MIT licence stays).
2. In GitLab, enable the three flows from `.gitlab/duo/flows/` (AI > Flows > New flow) with the triggers named in each file.
3. CI variables: `ACTA_RECORDER_KEY` (file; from `acta init`), `GCP_PROJECT`, `GCP_SA_KEY` (file), `STAGING_URL`, `PRODUCTION_URL`.
4. Keep a copy of `recorder.pub` somewhere the agents cannot write; that copy is what makes a verdict `verified`.

## Not yet verified
The flow files have not been run on GitLab and may need field changes to pass the v1 validator. The pipeline has not been run on GitLab. Nothing has been deployed.

## Try it without any account

```bash
sh scripts/demo.sh
```

Plays nine agent steps into a ledger, checks it, edits one line, and checks again.
