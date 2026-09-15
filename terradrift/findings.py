from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DriftFinding:
    resource_type: str      # "aws_security_group", "aws_s3_bucket_public_access_block", "aws_iam_role"
    resource_address: str   # the Terraform address, e.g. aws_security_group.web
    live_id: str             # the real AWS resource id, e.g. sg-0123456789abcdef0
    field: str                # which attribute drifted, e.g. "ingress[0].cidr_blocks"
    expected: object          # what Terraform state says it should be
    actual: object            # what AWS actually reports
    severity: str = "medium"  # "high" | "medium" | "low" — set per-check based on real risk
    details: dict = field(default_factory=dict)
