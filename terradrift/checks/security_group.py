from __future__ import annotations

from ..findings import DriftFinding


def _normalize_rules(rules: list[dict]) -> set[tuple]:
    """Reduce a security group's rule list to a comparable set of
    (protocol, from_port, to_port, cidr) tuples — ignores rule ordering and
    AWS's own internal rule IDs, which differ between state and live but
    don't represent real drift."""
    normalized = set()
    for rule in rules:
        protocol = rule.get("IpProtocol") or rule.get("protocol", "-1")
        from_port = rule.get("FromPort", rule.get("from_port", 0))
        to_port = rule.get("ToPort", rule.get("to_port", 0))
        cidrs = rule.get("cidr_blocks") or [
            r.get("CidrIp") for r in rule.get("IpRanges", []) if r.get("CidrIp")
        ]
        for cidr in cidrs or [None]:
            normalized.add((protocol, from_port, to_port, cidr))
    return normalized


def check_security_groups(state_sgs: list[dict], ec2_client) -> list[DriftFinding]:
    """Compares each aws_security_group in Terraform state against its live
    AWS rules. Flags added/removed ingress rules — the highest-risk kind of
    drift, since a rule added outside Terraform (e.g. "just for now" via the
    console) is exactly how 0.0.0.0/0 access to a database quietly happens."""
    findings = []

    for state_sg in state_sgs:
        sg_id = state_sg["values"].get("id")
        if not sg_id:
            continue  # not yet applied — nothing live to compare against

        try:
            live = ec2_client.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
        except ec2_client.exceptions.ClientError:
            findings.append(
                DriftFinding(
                    resource_type="aws_security_group",
                    resource_address=state_sg["address"],
                    live_id=sg_id,
                    field="existence",
                    expected="exists",
                    actual="not found in AWS",
                    severity="high",
                    details={"note": "In state but no longer exists in AWS — someone deleted it outside Terraform."},
                )
            )
            continue

        expected_ingress = _normalize_rules(state_sg["values"].get("ingress", []))
        actual_ingress = _normalize_rules(live.get("IpPermissions", []))

        added = actual_ingress - expected_ingress
        removed = expected_ingress - actual_ingress

        for rule in added:
            protocol, from_port, to_port, cidr = rule
            findings.append(
                DriftFinding(
                    resource_type="aws_security_group",
                    resource_address=state_sg["address"],
                    live_id=sg_id,
                    field="ingress",
                    expected="(not in Terraform state)",
                    actual=f"{protocol}:{from_port}-{to_port} from {cidr}",
                    severity="high" if cidr == "0.0.0.0/0" else "medium",
                    details={"direction": "added outside Terraform"},
                )
            )
        for rule in removed:
            protocol, from_port, to_port, cidr = rule
            findings.append(
                DriftFinding(
                    resource_type="aws_security_group",
                    resource_address=state_sg["address"],
                    live_id=sg_id,
                    field="ingress",
                    expected=f"{protocol}:{from_port}-{to_port} from {cidr}",
                    actual="(missing from live AWS)",
                    severity="medium",
                    details={"direction": "removed outside Terraform"},
                )
            )

    return findings
