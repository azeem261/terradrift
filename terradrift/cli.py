#!/usr/bin/env python3
"""
terradrift — detect drift between Terraform state and live AWS resources.

A free, open-source alternative to driftctl (unmaintained since Dec 2023),
focused on the drift that actually causes incidents: security group rules,
S3 public access/versioning/encryption, IAM role trust policies, RDS
public accessibility/encryption, and CloudTrail logging status.

Usage:
    terradrift --terraform-dir ./infra --region us-east-1
    terradrift --state-json plan.json --region us-east-1 --html report.html
"""

from __future__ import annotations

import argparse
import sys

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from .checks.cloudtrail import check_cloudtrail_logging
from .checks.iam_role import check_iam_role_trust_policies
from .checks.rds import check_rds_instances
from .checks.s3_config import check_s3_encryption, check_s3_versioning
from .checks.s3_public_access import check_s3_public_access_block
from .checks.security_group import check_security_groups
from .report import print_console_report, write_html_report
from .state import load_state_resources, resources_of_type


def main() -> int:
    parser = argparse.ArgumentParser(description="terradrift — Terraform vs. live AWS drift detection")
    parser.add_argument("--terraform-dir", default=None,
                         help="Directory to run `terraform show -json` in. Mutually exclusive with --state-json.")
    parser.add_argument("--state-json", default=None,
                         help="Path to a file already containing `terraform show -json` output.")
    parser.add_argument("--region", required=True, help="AWS region to check live resources in.")
    parser.add_argument("--profile", default=None, help="AWS CLI profile to use.")
    parser.add_argument("--html", default=None, help="Write an HTML report to this path.")
    args = parser.parse_args()

    if not args.terraform_dir and not args.state_json:
        print("Pass either --terraform-dir or --state-json.", file=sys.stderr)
        return 1

    try:
        resources = load_state_resources(args.state_json, args.terraform_dir)
    except Exception as e:  # noqa: BLE001 — surfacing to the user either way
        print(f"Could not read Terraform state: {e}", file=sys.stderr)
        return 1

    try:
        session = boto3.Session(profile_name=args.profile)
        session.client("sts").get_caller_identity()
    except NoCredentialsError:
        print("No AWS credentials found. Run `aws configure` or pass --profile.", file=sys.stderr)
        return 1
    except ClientError as e:
        print(f"Could not authenticate to AWS: {e}", file=sys.stderr)
        return 1

    findings = []

    sgs = resources_of_type(resources, "aws_security_group")
    if sgs:
        ec2 = session.client("ec2", region_name=args.region)
        findings += check_security_groups(sgs, ec2)

    pabs = resources_of_type(resources, "aws_s3_bucket_public_access_block")
    if pabs:
        s3 = session.client("s3", region_name=args.region)
        findings += check_s3_public_access_block(pabs, s3)

    roles = resources_of_type(resources, "aws_iam_role")
    if roles:
        iam = session.client("iam", region_name=args.region)
        findings += check_iam_role_trust_policies(roles, iam)

    versionings = resources_of_type(resources, "aws_s3_bucket_versioning")
    if versionings:
        s3 = session.client("s3", region_name=args.region)
        findings += check_s3_versioning(versionings, s3)

    encryptions = resources_of_type(resources, "aws_s3_bucket_server_side_encryption_configuration")
    if encryptions:
        s3 = session.client("s3", region_name=args.region)
        findings += check_s3_encryption(encryptions, s3)

    dbs = resources_of_type(resources, "aws_db_instance")
    if dbs:
        rds = session.client("rds", region_name=args.region)
        findings += check_rds_instances(dbs, rds)

    trails = resources_of_type(resources, "aws_cloudtrail")
    if trails:
        cloudtrail = session.client("cloudtrail", region_name=args.region)
        findings += check_cloudtrail_logging(trails, cloudtrail)

    print_console_report(findings)

    if args.html:
        write_html_report(findings, args.html)
        print(f"HTML report written to {args.html}", file=sys.stderr)

    return 1 if any(f.severity == "high" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
