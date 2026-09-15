from __future__ import annotations

from ..findings import DriftFinding


def _normalize_rules(rules: list[dict]) -> set[tuple]:
    """Reduce a security group's rule list to a comparable set of
    (protocol, from_port, to_port, source_type, source_value) tuples —
    ignores rule ordering and AWS's own internal rule IDs, which differ
    between state and live but don't represent real drift.

    Covers all four source types a rule can actually have: a plain CIDR,
    an IPv6 CIDR, a reference to another security group, or a managed
    prefix list. Earlier versions of this check only looked at CIDR
    blocks, which made it completely blind to the very common pattern of
    one security group referencing another (e.g. "allow from the
    app-tier SG") — that's fixed here, not worked around.
    """
    normalized = set()
    for rule in rules:
        protocol = rule.get("IpProtocol") or rule.get("protocol", "-1")
        from_port = rule.get("FromPort", rule.get("from_port", 0))
        to_port = rule.get("ToPort", rule.get("to_port", 0))

        sources: list[tuple[str, str]] = []

        # CIDR (IPv4) — live shape: IpRanges[].CidrIp / state shape: cidr_blocks
        for cidr in rule.get("cidr_blocks") or []:
            sources.append(("cidr", cidr))
        for r in rule.get("IpRanges", []):
            if r.get("CidrIp"):
                sources.append(("cidr", r["CidrIp"]))

        # IPv6 CIDR
        for cidr6 in rule.get("ipv6_cidr_blocks") or []:
            sources.append(("cidr6", cidr6))
        for r in rule.get("Ipv6Ranges", []):
            if r.get("CidrIpv6"):
                sources.append(("cidr6", r["CidrIpv6"]))

        # Security-group-to-security-group reference
        for sg_ref in rule.get("security_groups") or []:
            sources.append(("sg", sg_ref))
        for pair in rule.get("UserIdGroupPairs", []):
            if pair.get("GroupId"):
                sources.append(("sg", pair["GroupId"]))

        # "self" — a rule allowing traffic from the security group itself
        if rule.get("self"):
            sources.append(("self", "true"))

        # Managed prefix lists
        for pl in rule.get("prefix_list_ids") or []:
            sources.append(("prefix_list", pl))
        for pl in rule.get("PrefixListIds", []):
            if pl.get("PrefixListId"):
                sources.append(("prefix_list", pl["PrefixListId"]))

        for source_type, source_value in sources or [("cidr", None)]:
            normalized.add((protocol, from_port, to_port, source_type, source_value))

    return normalized


def _describe_source(source_type: str, source_value: str) -> str:
    return {
        "cidr": f"from {source_value}",
        "cidr6": f"from {source_value} (IPv6)",
        "sg": f"from security group {source_value}",
        "self": "from itself (self-reference)",
        "prefix_list": f"from prefix list {source_value}",
    }.get(source_type, f"from {source_value}")


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
            protocol, from_port, to_port, source_type, source_value = rule
            findings.append(
                DriftFinding(
                    resource_type="aws_security_group",
                    resource_address=state_sg["address"],
                    live_id=sg_id,
                    field="ingress",
                    expected="(not in Terraform state)",
                    actual=f"{protocol}:{from_port}-{to_port} {_describe_source(source_type, source_value)}",
                    severity="high" if source_type == "cidr" and source_value == "0.0.0.0/0" else "medium",
                    details={"direction": "added outside Terraform"},
                )
            )
        for rule in removed:
            protocol, from_port, to_port, source_type, source_value = rule
            findings.append(
                DriftFinding(
                    resource_type="aws_security_group",
                    resource_address=state_sg["address"],
                    live_id=sg_id,
                    field="ingress",
                    expected=f"{protocol}:{from_port}-{to_port} {_describe_source(source_type, source_value)}",
                    actual="(missing from live AWS)",
                    severity="medium",
                    details={"direction": "removed outside Terraform"},
                )
            )

    return findings
