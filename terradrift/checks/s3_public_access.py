from __future__ import annotations

from ..findings import DriftFinding

_FIELDS = [
    ("block_public_acls", "BlockPublicAcls"),
    ("block_public_policy", "BlockPublicPolicy"),
    ("ignore_public_acls", "IgnorePublicAcls"),
    ("restrict_public_buckets", "RestrictPublicBuckets"),
]


def check_s3_public_access_block(state_resources: list[dict], s3_client) -> list[DriftFinding]:
    """Compares each aws_s3_bucket_public_access_block in state against the
    bucket's live setting. This is the single highest-value check in the
    whole tool: a bucket that was locked down in Terraform but had public
    access silently re-enabled via the console (or by an application's own
    IAM permissions) is one of the most common real-world S3 breach causes,
    and it produces zero CloudTrail alarm on its own."""
    findings = []

    for state_pab in state_resources:
        bucket = state_pab["values"].get("bucket")
        if not bucket:
            continue

        try:
            live = s3_client.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        except s3_client.exceptions.ClientError:
            findings.append(
                DriftFinding(
                    resource_type="aws_s3_bucket_public_access_block",
                    resource_address=state_pab["address"],
                    live_id=bucket,
                    field="existence",
                    expected="public access block configured",
                    actual="no public access block found on the live bucket",
                    severity="high",
                    details={"note": "State expects this bucket locked down, but AWS reports no block config at all."},
                )
            )
            continue

        for tf_field, aws_field in _FIELDS:
            expected = state_pab["values"].get(tf_field)
            actual = live.get(aws_field)
            if expected is not None and expected != actual:
                findings.append(
                    DriftFinding(
                        resource_type="aws_s3_bucket_public_access_block",
                        resource_address=state_pab["address"],
                        live_id=bucket,
                        field=tf_field,
                        expected=expected,
                        actual=actual,
                        severity="high" if expected is True and actual is False else "medium",
                    )
                )

    return findings
