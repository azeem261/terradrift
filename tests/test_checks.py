import boto3
from moto import mock_aws

from terradrift.checks.s3_public_access import check_s3_public_access_block
from terradrift.checks.security_group import check_security_groups


@mock_aws
def test_security_group_drift_detects_added_rule():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)
    sg_id = sg["GroupId"]

    # Terraform state says: only port 443 from anywhere
    state_sgs = [{
        "address": "aws_security_group.web",
        "values": {
            "id": sg_id,
            "ingress": [{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]}],
        },
    }]

    # But live AWS also has port 22 open — drift added outside Terraform
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )

    findings = check_security_groups(state_sgs, ec2)

    assert len(findings) == 1
    assert findings[0].field == "ingress"
    assert findings[0].severity == "high"  # 0.0.0.0/0 on port 22 = high
    assert "22" in findings[0].actual


@mock_aws
def test_security_group_no_drift_when_matching():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="clean", Description="clean", VpcId=vpc)
    sg_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )

    state_sgs = [{
        "address": "aws_security_group.clean",
        "values": {
            "id": sg_id,
            "ingress": [{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]}],
        },
    }]

    findings = check_security_groups(state_sgs, ec2)
    assert findings == []


@mock_aws
def test_security_group_reference_drift_is_detected():
    """Regression test for the real gap found in review: the original
    check only compared CIDR blocks, so a rule referencing another
    security group (a very common real-world pattern, e.g. "allow from
    the app-tier SG") was invisible to it — neither an added nor a
    removed SG-reference rule would ever show up as drift. This proves
    it now does."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    db_sg = ec2.create_security_group(GroupName="db", Description="db", VpcId=vpc)
    db_sg_id = db_sg["GroupId"]
    other_sg = ec2.create_security_group(GroupName="mystery-app", Description="mystery", VpcId=vpc)
    other_sg_id = other_sg["GroupId"]

    # Terraform state expects no ingress at all
    state_sgs = [{
        "address": "aws_security_group.db",
        "values": {"id": db_sg_id, "ingress": []},
    }]

    # Live AWS has a rule referencing a completely different SG — added outside Terraform
    ec2.authorize_security_group_ingress(
        GroupId=db_sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
            "UserIdGroupPairs": [{"GroupId": other_sg_id}],
        }],
    )

    findings = check_security_groups(state_sgs, ec2)

    assert len(findings) == 1
    assert findings[0].field == "ingress"
    assert other_sg_id in findings[0].actual
    assert "security group" in findings[0].actual


@mock_aws
def test_s3_public_access_block_drift():
    s3 = boto3.client("s3", region_name="us-east-1")
    bucket = "my-test-bucket-terradrift"
    s3.create_bucket(Bucket=bucket)
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,  # drifted from what Terraform expects
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    state_resources = [{
        "address": "aws_s3_bucket_public_access_block.this",
        "values": {
            "bucket": bucket,
            "block_public_acls": True,
            "block_public_policy": True,
            "ignore_public_acls": True,
            "restrict_public_buckets": True,
        },
    }]

    findings = check_s3_public_access_block(state_resources, s3)

    assert len(findings) == 1
    assert findings[0].field == "block_public_acls"
    assert findings[0].severity == "high"
    assert findings[0].expected is True
    assert findings[0].actual is False
