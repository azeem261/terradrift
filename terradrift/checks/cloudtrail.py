from __future__ import annotations

from ..findings import DriftFinding


def check_cloudtrail_logging(state_trails: list[dict], cloudtrail_client) -> list[DriftFinding]:
    """Compares each aws_cloudtrail in state against live AWS for whether
    logging is actually turned on. A trail can exist (so `terraform plan`
    shows no changes) while logging is stopped — `aws cloudtrail
    stop-logging` outside Terraform leaves the resource itself untouched.
    That's the single most dangerous kind of drift in this whole tool: it
    silently disables the audit trail you'd need to investigate every
    other finding here."""
    findings = []

    for state_trail in state_trails:
        name = state_trail["values"].get("name")
        if not name:
            continue

        try:
            status = cloudtrail_client.get_trail_status(Name=name)
        except cloudtrail_client.exceptions.TrailNotFoundException:
            findings.append(
                DriftFinding(
                    resource_type="aws_cloudtrail",
                    resource_address=state_trail["address"],
                    live_id=name,
                    field="existence",
                    expected="exists",
                    actual="not found in AWS",
                    severity="high",
                )
            )
            continue

        is_logging = status.get("IsLogging", False)
        if not is_logging:
            findings.append(
                DriftFinding(
                    resource_type="aws_cloudtrail",
                    resource_address=state_trail["address"],
                    live_id=name,
                    field="is_logging",
                    expected=True,
                    actual=False,
                    severity="high",
                    details={"note": "Trail exists but logging is stopped — this is invisible to `terraform plan`."},
                )
            )

    return findings
