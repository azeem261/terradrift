#!/usr/bin/env python3
"""
Runs terradrift and posts a formatted summary to a Slack incoming webhook.
Requires: pip install terradrift (the free core tool this pack wraps).

Usage:
    python notify_slack.py --terraform-dir ./infra --region us-east-1 \\
        --slack-webhook-url "$SLACK_WEBHOOK_URL"

Exits 1 if any high-severity drift was found (same convention as terradrift
itself), so a CI job can fail the build on dangerous drift.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request

import boto3
from terradrift.checks.iam_role import check_iam_role_trust_policies
from terradrift.checks.s3_public_access import check_s3_public_access_block
from terradrift.checks.security_group import check_security_groups
from terradrift.state import load_state_resources, resources_of_type


def run_checks(terraform_dir, state_json, region, profile):
    resources = load_state_resources(state_json, terraform_dir)
    session = boto3.Session(profile_name=profile)

    findings = []
    sgs = resources_of_type(resources, "aws_security_group")
    if sgs:
        findings += check_security_groups(sgs, session.client("ec2", region_name=region))
    pabs = resources_of_type(resources, "aws_s3_bucket_public_access_block")
    if pabs:
        findings += check_s3_public_access_block(pabs, session.client("s3", region_name=region))
    roles = resources_of_type(resources, "aws_iam_role")
    if roles:
        findings += check_iam_role_trust_policies(roles, session.client("iam", region_name=region))
    return findings


def build_slack_payload(findings, context_label):
    if not findings:
        return {
            "text": f":white_check_mark: *terradrift* — no drift found ({context_label})"
        }

    by_sev = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    emoji = ":rotating_light:" if by_sev["high"] else ":warning:"
    lines = [
        f"{emoji} *terradrift* found {len(findings)} drift finding(s) — {context_label}",
        f"High: {by_sev['high']}  Medium: {by_sev['medium']}  Low: {by_sev['low']}",
        "",
    ]
    # Lead with the highest-severity findings, capped so the message stays readable
    ordered = sorted(findings, key=lambda f: {"high": 0, "medium": 1, "low": 2}.get(f.severity, 9))
    for f in ordered[:8]:
        lines.append(f"• [{f.severity.upper()}] `{f.resource_address}` — {f.field}: expected `{f.expected}`, got `{f.actual}`")
    if len(findings) > 8:
        lines.append(f"...and {len(findings) - 8} more.")

    return {"text": "\n".join(lines)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--terraform-dir", default=None)
    parser.add_argument("--state-json", default=None)
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile", default=None)
    parser.add_argument("--slack-webhook-url", required=True)
    parser.add_argument("--context-label", default="scheduled check",
                         help="Shown in the Slack message, e.g. a repo/branch name.")
    args = parser.parse_args()

    if not args.terraform_dir and not args.state_json:
        print("Pass either --terraform-dir or --state-json.", file=sys.stderr)
        return 1

    findings = run_checks(args.terraform_dir, args.state_json, args.region, args.profile)
    payload = build_slack_payload(findings, args.context_label)

    req = urllib.request.Request(
        args.slack_webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        if resp.status != 200:
            print(f"Slack webhook returned status {resp.status}", file=sys.stderr)
            return 1

    print(f"Posted {len(findings)} finding(s) to Slack.")
    return 1 if any(f.severity == "high" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
