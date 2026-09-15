# terradrift

**A free, open-source Terraform drift detection tool for AWS — a maintained alternative to driftctl (unmaintained since December 2023).**

`terradrift` compares your Terraform state against live AWS resources and tells you exactly what changed outside of Terraform — the security group rule someone added "just for now," the S3 bucket that got un-locked by a console click, the IAM trust policy that quietly widened. It focuses on the drift that actually causes incidents, not an exhaustive diff of every attribute on every resource type.

```
$ terradrift --terraform-dir ./infra --region us-east-1

========================================================================
  TERRADRIFT
========================================================================
  Drift findings  : 5
  High: 3   Medium: 2   Low: 0
========================================================================

  [HIGH] aws_security_group.database  (aws_security_group)
    live id  : sg-0a1b2c3d4e5f67890
    field    : ingress
    expected : (not in Terraform state)
    actual   : tcp:5432-5432 from 0.0.0.0/0
```

That's a real class of finding this tool exists to catch: a database port opened to the entire internet, outside of code review, with no CloudTrail alarm to notice it.

## Install

```bash
pip install terradrift
```

Or run from source:

```bash
git clone https://github.com/azeem261/terradrift
cd terradrift
pip install -e .
```

## Quickstart

```bash
# Against a live Terraform working directory
terradrift --terraform-dir ./infra --region us-east-1

# Against a saved `terraform show -json` output (e.g. in CI, where you don't want live state access twice)
terraform show -json > state.json
terradrift --state-json state.json --region us-east-1

# Write an HTML report
terradrift --terraform-dir ./infra --region us-east-1 --html report.html
```

Exits with status `1` if any high-severity drift is found — plug it straight into CI to fail a pipeline on dangerous drift, not just report it.

## What it checks

| Resource | Detects |
|---|---|
| `aws_security_group` | Ingress rules added or removed outside Terraform — CIDR, IPv6, security-group references, and prefix lists all covered; flags `0.0.0.0/0` rules as high severity |
| `aws_s3_bucket_public_access_block` | Any of the four block-public settings drifted from what Terraform expects |
| `aws_s3_bucket_versioning` | Versioning silently disabled outside Terraform |
| `aws_s3_bucket_server_side_encryption_configuration` | Default encryption removed or changed outside Terraform |
| `aws_iam_role` | Trust (assume-role) policy differs from state — catches privilege-escalation-shaped drift that a permissions-only review misses |
| `aws_db_instance` | RDS flipped to publicly accessible, or storage encryption doesn't match state |
| `aws_cloudtrail` | Trail exists but logging was stopped outside Terraform — invisible to `terraform plan`, and the one finding that undermines your ability to investigate every other finding here |

More resource types are a natural extension — see `Contributing` below. Each check is chosen because it's a class of drift that's silent (no application symptom, no `terraform plan` diff) and genuinely dangerous — not because it's easy to add.

## Why not driftctl?

driftctl (Snyk) has had no feature release since December 2023 and is effectively unmaintained. `terradrift` exists because that gap is real — people are still searching for a working alternative, and the ones that exist are either broader/heavier (full infra-coverage tools) or narrower. This one is deliberately small, readable, and focused on the drift that's actually dangerous, so you can read the entire checks/ directory in ten minutes and trust exactly what it does.

## Requirements

- Python 3.10+
- Terraform CLI on PATH (only if using `--terraform-dir`; not needed with `--state-json`)
- AWS credentials with read access to the resource types you're checking (`ec2:DescribeSecurityGroups`, `s3:GetPublicAccessBlock`, `iam:GetRole`) — see `docs/iam-policy.json`

100% read-only. `terradrift` cannot modify anything in your AWS account.

## Use it as a GitHub Action

No local install needed — drop this into a workflow:

```yaml
- uses: azeem261/terradrift@v1
  with:
    terraform-dir: ./infra
    region: us-east-1
    slack-webhook-url: ${{ secrets.SLACK_WEBHOOK_URL }}   # optional
    html-report: report.html                               # optional
```

Runs on every push or on a schedule (add a `schedule:` trigger to your workflow), fails the job on high-severity drift by default (`fail-on-high: false` to just report instead), and posts a severity-ranked summary to Slack when `slack-webhook-url` is set. Needs AWS credentials already configured earlier in the job (OIDC recommended — see `docs/iam-policy.json` for the minimal permissions).

## Contributing

PRs adding a new check follow the same shape as the three in `terradrift/checks/` — a pure function taking state resources + a boto3 client, returning `DriftFinding`s, with a test in `tests/` using `moto`. Open an issue first for anything beyond a new resource-type check.

## CI/CD integration

Free and open source, MIT licensed — use it in CI however you like. A ready-made GitHub Action + Slack alerting wrapper is available separately for teams who want it turnkey rather than wiring it up themselves: see `docs/ci-pro-pack.md`.

## License

MIT — see `LICENSE`. Not affiliated with HashiCorp, Snyk, or driftctl.
