"""
AUTHOR: Ninad Lunge
EMAIL: ninad.lunge@comprinno.net
DATE: 2025-05-20
"""

import pytest
from unittest.mock import MagicMock
from library.aws.checks.s3.s3_bucket_lifecycle_policy_enabled import s3_bucket_lifecycle_policy_enabled
from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata, Remediation, RemediationCode, RemediationRecommendation

def build_check_metadata() -> CheckMetadata:
    return CheckMetadata(
        Provider="aws",
        CheckID="s3_bucket_lifecycle_policy_enabled",
        CheckTitle="Ensure S3 buckets have lifecycle policies enabled",
        CheckType=["Data Protection"],
        ServiceName="s3",
        SubServiceName="",
        ResourceIdTemplate="arn:aws:s3:::{bucket_name}",
        Severity="Medium",
        ResourceType="AWS::S3::Bucket",
        Risk="Without lifecycle policies, S3 objects may accumulate unnecessarily, increasing storage costs.",
        RelatedUrl="https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html",
        Remediation=Remediation(
            Code=RemediationCode(
                CLI="aws s3api put-bucket-lifecycle-configuration ...",
                NativeIaC="",
                Other="",
                Terraform="resource \"aws_s3_bucket_lifecycle_configuration\" ..."
            ),
            Recommendation=RemediationRecommendation(
                Text="Enable lifecycle policies on S3 buckets to automatically expire or transition objects.",
                Url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html"
            )
        ),
        Description="Checks whether S3 buckets have lifecycle policies configured."
    )

@pytest.fixture
def mock_s3_client(monkeypatch):
    mock_client = MagicMock()
    monkeypatch.setattr("boto3.Session.client", lambda self, service_name: mock_client)
    return mock_client


def test_check_with_lifecycle_policy(mock_s3_client):
    # Setup mock
    mock_s3_client.list_buckets.return_value = {
        "Buckets": [{"Name": "test-bucket"}]
    }
    mock_s3_client.get_bucket_lifecycle_configuration.return_value = {
        "Rules": [
            {
                "ID": "expire-rule",
                "Status": "Enabled",
                "Filter": {"Prefix": ""},
                "Expiration": {"Days": 30}
            }
        ]
    }

    check = s3_bucket_lifecycle_policy_enabled(metadata=build_check_metadata())
    report = check.execute(MagicMock())

    assert report.status != CheckStatus.FAILED
    assert report.resource_ids_status[0].status == CheckStatus.PASSED


def test_check_without_lifecycle_policy(mock_s3_client):
    mock_s3_client.list_buckets.return_value = {
        "Buckets": [{"Name": "no-policy-bucket"}]
    }
    mock_s3_client.get_bucket_lifecycle_configuration.side_effect = \
        mock_s3_client.exceptions.ClientError(
            {"Error": {"Code": "NoSuchLifecycleConfiguration", "Message": "No lifecycle configuration"}},
            "get_bucket_lifecycle_configuration"
        )

    check = s3_bucket_lifecycle_policy_enabled(metadata=build_check_metadata())
    report = check.execute(MagicMock())

    assert report.status == CheckStatus.FAILED
    assert report.resource_ids_status[0].status == CheckStatus.FAILED


def test_check_with_no_buckets(mock_s3_client):
    mock_s3_client.list_buckets.return_value = {"Buckets": []}

    check = s3_bucket_lifecycle_policy_enabled(metadata=build_check_metadata())
    report = check.execute(MagicMock())

    assert report.status == CheckStatus.NOT_APPLICABLE