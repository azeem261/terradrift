import boto3
from moto import mock_aws

from terradrift.checks.cloudtrail import check_cloudtrail_logging
from terradrift.checks.rds import check_rds_instances
from terradrift.checks.s3_config import check_s3_encryption, check_s3_versioning


@mock_aws
def test_rds_publicly_accessible_drift():
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="prod-db",
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        MasterUsername="admin",
        MasterUserPassword="supersecret123",
        AllocatedStorage=20,
        PubliclyAccessible=True,  # drifted from what Terraform expects
        StorageEncrypted=True,
    )

    state_dbs = [{
        "address": "aws_db_instance.prod",
        "values": {"identifier": "prod-db", "publicly_accessible": False, "storage_encrypted": True},
    }]

    findings = check_rds_instances(state_dbs, rds)

    assert len(findings) == 1
    assert findings[0].field == "publicly_accessible"
    assert findings[0].severity == "high"
    assert findings[0].expected is False
    assert findings[0].actual is True


@mock_aws
def test_rds_no_drift_when_matching():
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="clean-db",
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        MasterUsername="admin",
        MasterUserPassword="supersecret123",
        AllocatedStorage=20,
        PubliclyAccessible=False,
        StorageEncrypted=True,
    )

    state_dbs = [{
        "address": "aws_db_instance.clean",
        "values": {"identifier": "clean-db", "publicly_accessible": False, "storage_encrypted": True},
    }]

    findings = check_rds_instances(state_dbs, rds)
    assert findings == []


@mock_aws
def test_s3_versioning_drift():
    s3 = boto3.client("s3", region_name="us-east-1")
    bucket = "versioned-bucket-terradrift"
    s3.create_bucket(Bucket=bucket)
    # Live: versioning never enabled (state expects "Enabled")

    state_resources = [{
        "address": "aws_s3_bucket_versioning.this",
        "values": {"bucket": bucket, "versioning_configuration": [{"status": "Enabled"}]},
    }]

    findings = check_s3_versioning(state_resources, s3)

    assert len(findings) == 1
    assert findings[0].field == "versioning_configuration.status"
    assert findings[0].expected == "Enabled"
    assert findings[0].actual == "Disabled"


@mock_aws
def test_s3_encryption_drift_missing_entirely():
    s3 = boto3.client("s3", region_name="us-east-1")
    bucket = "unencrypted-bucket-terradrift"
    s3.create_bucket(Bucket=bucket)
    # No encryption configuration set on the live bucket at all

    state_resources = [{
        "address": "aws_s3_bucket_server_side_encryption_configuration.this",
        "values": {
            "bucket": bucket,
            "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}],
        },
    }]

    findings = check_s3_encryption(state_resources, s3)

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].expected == "aws:kms"
    assert "no encryption" in findings[0].actual


@mock_aws
def test_cloudtrail_logging_stopped_is_drift():
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    s3 = boto3.client("s3", region_name="us-east-1")
    bucket = "cloudtrail-bucket-terradrift"
    s3.create_bucket(Bucket=bucket)
    s3.put_bucket_policy(Bucket=bucket, Policy="{}")  # moto doesn't strictly validate this

    ct.create_trail(Name="org-trail", S3BucketName=bucket)
    ct.start_logging(Name="org-trail")
    ct.stop_logging(Name="org-trail")  # drift: state expects logging on, live has it stopped

    state_trails = [{
        "address": "aws_cloudtrail.org",
        "values": {"name": "org-trail"},
    }]

    findings = check_cloudtrail_logging(state_trails, ct)

    assert len(findings) == 1
    assert findings[0].field == "is_logging"
    assert findings[0].severity == "high"
    assert findings[0].actual is False
