"""
AUTHOR: Ninad Lunge
EMAIL: ninad.lunge@comprinno.net
DATE: 2025-05-20
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class ebs_volume_lifecycle_policy_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        dlm_client = connection.client('dlm')
        ec2_client = connection.client('ec2')
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            policies_response = dlm_client.get_lifecycle_policies()
            policies = policies_response.get("Policies", [])

            if not policies:
                report.status = CheckStatus.FAILED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.FAILED,
                        summary="No EBS lifecycle policies found."
                    )
                )
                return report

            volumes_response = ec2_client.describe_volumes()
            volumes = volumes_response.get("Volumes", [])

            if not volumes:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No EBS volumes found."
                    )
                )
                return report

            for volume in volumes:
                volume_id = volume["VolumeId"]
                volume_arn = f"arn:aws:ec2:::volume/{volume_id}"
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=AwsResource(arn=volume_arn),
                        status=CheckStatus.PASSED,
                        summary=f"EBS volume {volume_id} is under lifecycle management (based on presence of policies)."
                    )
                )

        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Failed to check EBS lifecycle policies.",
                    exception=str(e)
                )
            )

        return report