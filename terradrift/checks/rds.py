from __future__ import annotations

from ..findings import DriftFinding


def check_rds_instances(state_dbs: list[dict], rds_client) -> list[DriftFinding]:
    """Compares each aws_db_instance in state against live AWS for the two
    settings that turn a routine database into a real incident when they
    drift silently: public accessibility and storage encryption. Both are
    the kind of change that can happen via a single console click, produce
    no application-level symptom, and sit unnoticed until a security
    review or a breach finds it."""
    findings = []

    for state_db in state_dbs:
        db_id = state_db["values"].get("identifier") or state_db["values"].get("id")
        if not db_id:
            continue

        try:
            live = rds_client.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
        except rds_client.exceptions.DBInstanceNotFoundFault:
            findings.append(
                DriftFinding(
                    resource_type="aws_db_instance",
                    resource_address=state_db["address"],
                    live_id=db_id,
                    field="existence",
                    expected="exists",
                    actual="not found in AWS",
                    severity="high",
                    details={"note": "In state but no longer exists in AWS."},
                )
            )
            continue

        expected_public = state_db["values"].get("publicly_accessible")
        actual_public = live.get("PubliclyAccessible")
        if expected_public is not None and expected_public != actual_public:
            findings.append(
                DriftFinding(
                    resource_type="aws_db_instance",
                    resource_address=state_db["address"],
                    live_id=db_id,
                    field="publicly_accessible",
                    expected=expected_public,
                    actual=actual_public,
                    severity="high" if actual_public is True else "medium",
                    details={"note": "A database flipped to publicly accessible outside Terraform is a direct exposure risk."},
                )
            )

        expected_encrypted = state_db["values"].get("storage_encrypted")
        actual_encrypted = live.get("StorageEncrypted")
        if expected_encrypted is not None and expected_encrypted != actual_encrypted:
            findings.append(
                DriftFinding(
                    resource_type="aws_db_instance",
                    resource_address=state_db["address"],
                    live_id=db_id,
                    field="storage_encrypted",
                    expected=expected_encrypted,
                    actual=actual_encrypted,
                    severity="high",
                    details={"note": "Storage encryption can only be set at creation — this drift means the live DB was never what Terraform believes it is, not a runtime toggle."},
                )
            )

    return findings
