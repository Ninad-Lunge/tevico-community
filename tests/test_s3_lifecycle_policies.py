"""
Test suite for the s3_bucket_lifecycle_policy_enabled check.

AUTHOR: Ninad Lunge
EMAIL: ninad.lunge@comprinno.net
DATE: 2025-05-20
"""

import boto3
from botocore.stub import Stubber
from botocore.exceptions import ClientError, BotoCoreError, EndpointConnectionError

from library.aws.checks.s3.s3_bucket_lifecycle_policy_enabled import s3_bucket_lifecycle_policy_enabled
from tevico.engine.entities.report.check_model import (
    CheckMetadata, Remediation, RemediationCode, RemediationRecommendation, CheckStatus
)


def build_check_metadata(
    check_id="s3_bucket_lifecycle_policy_enabled",
    check_title="Ensure S3 buckets have lifecycle policies enabled",
    service_name="s3"
) -> CheckMetadata:
    """Constructs CheckMetadata for unit testing."""
    return CheckMetadata(
        Provider="aws",
        CheckID=check_id,
        CheckTitle=check_title,
        CheckType=["Data Protection"],
        ServiceName=service_name,
        SubServiceName="",
        ResourceIdTemplate="arn:aws:s3:::{bucket_name}",
        Severity="Medium",
        ResourceType="AWS::S3::Bucket",
        Risk="Without lifecycle policies, S3 objects may accumulate unnecessarily, increasing storage costs.",
        RelatedUrl="https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html",
        Remediation=Remediation(
            Code=RemediationCode(
                CLI="aws s3api put-bucket-lifecycle-configuration ...",
                Terraform="resource \"aws_s3_bucket_lifecycle_configuration\" ..."
            ),
            Recommendation=RemediationRecommendation(
                Text="Enable lifecycle policies on S3 buckets to automatically expire or transition objects.",
                Url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html"
            )
        ),
        Description="Checks whether S3 buckets have lifecycle policies configured."
    )


class DummySession:
    """Dummy session wrapper to inject stubbed S3 client."""
    def __init__(self, client):
        self._client = client

    def client(self, service_name):
        return self._client


def test_bucket_with_lifecycle_policy():
    """Test that a bucket with lifecycle policy is marked PASSED."""
    s3 = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(s3)

    stubber.add_response("list_buckets", {
        "Buckets": [{"Name": "test-bucket"}]
    })
    stubber.add_response("get_bucket_lifecycle_configuration", {
        "Rules": [
            {"ID": "rule1", "Status": "Enabled", "Expiration": {"Days": 30}}
        ]
    }, {"Bucket": "test-bucket"})

    stubber.activate()
    check = s3_bucket_lifecycle_policy_enabled(metadata=build_check_metadata())
    report = check.execute(DummySession(s3))  # type: ignore[arg-type]

    assert report.status == CheckStatus.PASSED
    assert report.resource_ids_status[0].status == CheckStatus.PASSED


def test_bucket_without_lifecycle_policy():
    """Test that a bucket with no lifecycle policy is marked FAILED."""
    s3 = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(s3)

    stubber.add_response("list_buckets", {
        "Buckets": [{"Name": "no-policy-bucket"}]
    })
    stubber.add_client_error(
        "get_bucket_lifecycle_configuration",
        service_error_code="NoSuchLifecycleConfiguration",
        service_message="No lifecycle configuration",
        http_status_code=404,
        expected_params={"Bucket": "no-policy-bucket"}
    )

    stubber.activate()
    check = s3_bucket_lifecycle_policy_enabled(metadata=build_check_metadata())
    report = check.execute(DummySession(s3))  # type: ignore[arg-type]

    assert report.status == CheckStatus.FAILED
    assert report.resource_ids_status[0].status == CheckStatus.FAILED


def test_check_with_no_buckets():
    """Test that NOT_APPLICABLE is returned when no buckets exist."""
    s3 = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(s3)

    stubber.add_response("list_buckets", {"Buckets": []})
    stubber.activate()

    check = s3_bucket_lifecycle_policy_enabled(metadata=build_check_metadata())
    report = check.execute(DummySession(s3))  # type: ignore[arg-type]
 
    assert report.status == CheckStatus.NOT_APPLICABLE
    assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE


def test_check_with_boto_error():
    """Test that UNKNOWN status is returned on boto3 client error."""
    class FailingSession:
        def client(self, service_name):
            raise EndpointConnectionError(endpoint_url="https://s3.amazonaws.com")

    check = s3_bucket_lifecycle_policy_enabled(metadata=build_check_metadata())
    report = check.execute(FailingSession())  # type: ignore[arg-type]

    assert report.status == CheckStatus.UNKNOWN
    assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN


def test_check_with_unexpected_client_error():
    """Test that unexpected client errors are marked as UNKNOWN."""
    s3 = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(s3)

    stubber.add_response("list_buckets", {
        "Buckets": [{"Name": "error-bucket"}]
    })
    stubber.add_client_error(
        "get_bucket_lifecycle_configuration",
        service_error_code="AccessDenied",
        service_message="Access Denied",
        http_status_code=403,
        expected_params={"Bucket": "error-bucket"}
    )

    stubber.activate()

    check = s3_bucket_lifecycle_policy_enabled(metadata=build_check_metadata())
    report = check.execute(DummySession(s3))  # type: ignore[arg-type]

    assert report.status == CheckStatus.UNKNOWN
    assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN