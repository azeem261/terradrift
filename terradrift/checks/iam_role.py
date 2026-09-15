from __future__ import annotations

import json
from urllib.parse import unquote

from ..findings import DriftFinding


def _normalize_policy(policy) -> dict:
    if isinstance(policy, str):
        return json.loads(unquote(policy))
    return policy


def check_iam_role_trust_policies(state_roles: list[dict], iam_client) -> list[DriftFinding]:
    """Compares each aws_iam_role's assume-role (trust) policy in state
    against the live role. A trust policy widened outside Terraform — e.g.
    someone adding a second trusted principal directly in the console to
    unblock themselves — is a real, common privilege-escalation path that
    normal permission-boundary reviews don't catch, because the role's
    *permissions* policy didn't change at all."""
    findings = []

    for state_role in state_roles:
        role_name = state_role["values"].get("name")
        if not role_name:
            continue

        try:
            live = iam_client.get_role(RoleName=role_name)["Role"]
        except iam_client.exceptions.NoSuchEntityException:
            findings.append(
                DriftFinding(
                    resource_type="aws_iam_role",
                    resource_address=state_role["address"],
                    live_id=role_name,
                    field="existence",
                    expected="exists",
                    actual="not found in AWS",
                    severity="high",
                )
            )
            continue

        expected_policy = state_role["values"].get("assume_role_policy")
        actual_policy = live.get("AssumeRolePolicyDocument")
        if expected_policy is None:
            continue

        try:
            expected_norm = _normalize_policy(expected_policy)
            actual_norm = _normalize_policy(actual_policy)
        except (json.JSONDecodeError, TypeError):
            continue  # malformed policy JSON — not this check's job to validate JSON shape

        if expected_norm != actual_norm:
            findings.append(
                DriftFinding(
                    resource_type="aws_iam_role",
                    resource_address=state_role["address"],
                    live_id=role_name,
                    field="assume_role_policy",
                    expected=expected_norm,
                    actual=actual_norm,
                    severity="high",
                    details={"note": "Trust policy differs from Terraform state — check who can assume this role."},
                )
            )

    return findings
