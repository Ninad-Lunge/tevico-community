"""
AUTHOR: Ninad Lunge
EMAIL: ninad.lunge@comprinno.net
DATE: 2025-05-20
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from tevico.engine.entities.report.check_model import (
    CheckReport,
    CheckStatus,
    GeneralResource,
    ResourceStatus,
)
from tevico.engine.entities.check.check import Check


class ebs_volume_lifecycle_policy_enabled(Check):
    """Check that verifies EBS volumes are covered by at least one DLM lifecycle policy."""

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=self.__class__.__name__)
        report.resource_ids_status = []

        # 1. Try to construct the DLM client
        try:
            dlm_client = connection.client("dlm")
        except (BotoCoreError, ClientError) as e:
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Failed to create DLM client.",
                    exception=str(e),
                )
            )
            report.status = CheckStatus.UNKNOWN
            return report

        # 2. Attempt to retrieve lifecycle policies
        try:
            response = dlm_client.get_lifecycle_policies()
            policies = response.get("Policies", [])
            if policies:
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.PASSED,
                        summary="At least one DLM lifecycle policy is enabled.",
                    )
                )
            else:
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.FAILED,
                        summary="No DLM lifecycle policies found.",
                    )
                )

        except (BotoCoreError, ClientError, Exception) as e:
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Error retrieving DLM lifecycle policies.",
                    exception=str(e),
                )
            )

        # 3. Aggregate overall status
        statuses = [r.status for r in report.resource_ids_status]
        if any(s == CheckStatus.FAILED for s in statuses):
            report.status = CheckStatus.FAILED
        elif any(s == CheckStatus.UNKNOWN for s in statuses):
            report.status = CheckStatus.UNKNOWN
        else:
            report.status = CheckStatus.PASSED

        return report
