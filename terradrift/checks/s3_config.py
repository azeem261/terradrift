from __future__ import annotations

from ..findings import DriftFinding


def check_s3_versioning(state_resources: list[dict], s3_client) -> list[DriftFinding]:
    """Compares each aws_s3_bucket_versioning in state against the live
    bucket. Versioning quietly disabled outside Terraform means your
    "we can always restore an overwritten/deleted object" assumption is
    silently false — usually discovered exactly when you need it."""
    findings = []

    for state_v in state_resources:
        bucket = state_v["values"].get("bucket")
        expected_status = None
        for block in state_v["values"].get("versioning_configuration", []):
            expected_status = block.get("status")
        if not bucket or not expected_status:
            continue

        live = s3_client.get_bucket_versioning(Bucket=bucket)
        actual_status = live.get("Status", "Disabled")

        if expected_status != actual_status:
            findings.append(
                DriftFinding(
                    resource_type="aws_s3_bucket_versioning",
                    resource_address=state_v["address"],
                    live_id=bucket,
                    field="versioning_configuration.status",
                    expected=expected_status,
                    actual=actual_status,
                    severity="medium",
                )
            )

    return findings


def check_s3_encryption(state_resources: list[dict], s3_client) -> list[DriftFinding]:
    """Compares each aws_s3_bucket_server_side_encryption_configuration in
    state against the live bucket — flags a bucket that Terraform expects
    encrypted-at-rest but that AWS reports has no encryption configured at
    all (default-encryption was removed outside Terraform)."""
    findings = []

    for state_enc in state_resources:
        bucket = state_enc["values"].get("bucket")
        if not bucket:
            continue

        try:
            live = s3_client.get_bucket_encryption(Bucket=bucket)
            live_rules = live.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            actual_algorithm = None
            if live_rules:
                actual_algorithm = live_rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
        except s3_client.exceptions.ClientError:
            actual_algorithm = None  # no encryption configuration at all

        expected_algorithm = None
        for rule in state_enc["values"].get("rule", []):
            default = rule.get("apply_server_side_encryption_by_default", [])
            if default:
                expected_algorithm = default[0].get("sse_algorithm")

        if expected_algorithm and expected_algorithm != actual_algorithm:
            findings.append(
                DriftFinding(
                    resource_type="aws_s3_bucket_server_side_encryption_configuration",
                    resource_address=state_enc["address"],
                    live_id=bucket,
                    field="rule.apply_server_side_encryption_by_default.sse_algorithm",
                    expected=expected_algorithm,
                    actual=actual_algorithm or "(no encryption configured)",
                    severity="high" if actual_algorithm is None else "medium",
                )
            )

    return findings
