"""
AUTHOR: Ninad Lunge
EMAIL: ninad.lunge@comprinno.net
DATE: 2025-05-20
"""

import pytest
from unittest.mock import MagicMock
from botocore.exceptions import EndpointConnectionError

from library.aws.checks.ebs.ebs_volume_lifecycle_policy_enabled import ebs_volume_lifecycle_policy_enabled
from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata, Remediation, RemediationCode, RemediationRecommendation


@pytest.fixture
def mock_dlm_client(monkeypatch):
    mock_client = MagicMock()
    monkeypatch.setattr("boto3.Session.client", lambda self, service_name: mock_client)
    return mock_client


def build_check_metadata() -> CheckMetadata:
    return CheckMetadata(
        Provider="aws",
        CheckID="ebs_volume_lifecycle_policy_enabled",
        CheckTitle="Ensure EBS volumes are covered by a Data Lifecycle Manager policy",
        CheckType=["Backup", "Cost Optimization"],
        ServiceName="ec2",
        SubServiceName="ebs",
        ResourceIdTemplate="arn:aws:dlm:region:account-id:policy/policy-id",
        Severity="Medium",
        ResourceType="AWS::EC2::Volume",
        Risk="Without lifecycle policies, EBS volumes may lack backups or become costly due to unmanaged snapshots.",
        RelatedUrl="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/snapshot-lifecycle.html",
        Remediation=Remediation(
            Code=RemediationCode(
                CLI="aws dlm create-lifecycle-policy ...",
                NativeIaC="",
                Other="",
                Terraform="resource \"aws_dlm_lifecycle_policy\" ..."
            ),
            Recommendation=RemediationRecommendation(
                Text="Enable Data Lifecycle Manager (DLM) policies for EBS volumes to automate snapshot management.",
                Url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/snapshot-lifecycle.html"
            )
        ),
        Description="Checks if DLM policies are configured and enabled to manage the lifecycle of EBS volumes."
    )


def test_check_with_dlm_policy(mock_dlm_client):
    mock_dlm_client.get_lifecycle_policies.return_value = {
        "Policies": [
            {
                "PolicyId": "test-policy",
                "PolicyDetails": {
                    "ResourceTypes": ["VOLUME"],
                    "TargetTags": [{"Key": "backup", "Value": "daily"}]
                },
                "State": "ENABLED"
            }
        ]
    }

    check = ebs_volume_lifecycle_policy_enabled(metadata=build_check_metadata())
    report = check.execute(MagicMock())

    assert report.status == CheckStatus.PASSED
    assert report.resource_ids_status[0].status == CheckStatus.PASSED


def test_check_without_dlm_policy(mock_dlm_client):
    mock_dlm_client.get_lifecycle_policies.return_value = {
        "Policies": []
    }

    check = ebs_volume_lifecycle_policy_enabled(metadata=build_check_metadata())
    mock_session = MagicMock()
    mock_session.client.return_value = mock_dlm_client
    report = check.execute(mock_session)

    assert report.status == CheckStatus.FAILED
    assert report.resource_ids_status[0].status == CheckStatus.FAILED


def test_check_error_handling(mock_dlm_client):
    mock_dlm_client.get_lifecycle_policies.side_effect = Exception("Unexpected error")

    check = ebs_volume_lifecycle_policy_enabled(metadata=build_check_metadata())
    
    mock_session = MagicMock()
    mock_session.client.return_value = mock_dlm_client
    report = check.execute(mock_session)

    assert report.status == CheckStatus.UNKNOWN


def test_check_with_boto_client_error(monkeypatch):
    """Test that UNKNOWN status is returned if boto3 client creation fails."""
    class FailingSession:
        def client(self, service_name):
            raise EndpointConnectionError(endpoint_url="https://ec2.amazonaws.com")

    check = ebs_volume_lifecycle_policy_enabled(metadata=build_check_metadata())
    report = check.execute(FailingSession()) # type: ignore[arg-type]

    assert report.status == CheckStatus.UNKNOWN
    assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
    assert "Failed to create DLM client" in (report.resource_ids_status[0].summary or "")