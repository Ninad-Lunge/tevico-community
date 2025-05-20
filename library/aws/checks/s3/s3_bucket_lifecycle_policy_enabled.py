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


class s3_bucket_lifecycle_policy_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            s3_client = connection.client('s3')
        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Failed to create S3 client.",
                    exception=str(e)
                )
            )
            return report

        try:
            response = s3_client.list_buckets()
            buckets = response.get("Buckets", [])

            if not buckets:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No S3 buckets found."
                    )
                )
                return report

            for bucket in buckets:
                bucket_name = bucket["Name"]
                bucket_arn = f"arn:aws:s3:::{bucket_name}"
                try:
                    s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=bucket_arn),
                            status=CheckStatus.PASSED,
                            summary=f"S3 bucket {bucket_name} has a lifecycle policy."
                        )
                    )
                except ClientError as e:
                    if e.response["Error"]["Code"] == "NoSuchLifecycleConfiguration":
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=bucket_arn),
                                status=CheckStatus.FAILED,
                                summary=f"S3 bucket {bucket_name} does not have a lifecycle policy."
                            )
                        )
                    else:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=bucket_arn),
                                status=CheckStatus.UNKNOWN,
                                summary=f"Error retrieving lifecycle policy for bucket {bucket_name}.",
                                exception=str(e)
                            )
                        )

        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Failed to retrieve list of S3 buckets.",
                    exception=str(e)
                )
            )
            return report

        # Determine overall status
        failed_found = any(r.status == CheckStatus.FAILED for r in report.resource_ids_status)
        unknown_found = any(r.status == CheckStatus.UNKNOWN for r in report.resource_ids_status)

        if failed_found:
            report.status = CheckStatus.FAILED
        elif unknown_found:
            report.status = CheckStatus.UNKNOWN
        else:
            report.status = CheckStatus.PASSED

        return report
