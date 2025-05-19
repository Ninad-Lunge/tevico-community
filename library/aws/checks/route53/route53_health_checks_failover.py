"""
AUTHOR: Ninad Lunge
EMAIL: ninad.lunge@comprinno.net
DATE: 2025-05-19
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class route53_health_checks_failover(Check):
    """Check Route 53 Health Checks and whether failover policies are in place."""

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            route53 = connection.client("route53")

            # Fetch all health checks
            health_checks_resp = route53.list_health_checks()
            health_checks = health_checks_resp.get("HealthChecks", [])

            # Fetch all record sets to identify failover policies
            hosted_zones = route53.list_hosted_zones().get("HostedZones", [])
            failover_health_ids = set()

            for zone in hosted_zones:
                records = route53.list_resource_record_sets(HostedZoneId=zone["Id"])
                for record in records.get("ResourceRecordSets", []):
                    if record.get("Failover") and "HealthCheckId" in record:
                        failover_health_ids.add(record["HealthCheckId"])

            if not health_checks:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No Route 53 health checks configured in this account."
                    )
                )
                return report

            found_unlinked = False
            for hc in health_checks:
                hc_id = hc["Id"]
                hc_name = hc.get("CallerReference", hc_id)
                if hc_id not in failover_health_ids:
                    found_unlinked = True
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=hc_id),
                            status=CheckStatus.FAILED,
                            summary=f"Health Check {hc_name} is not associated with any failover routing policy."
                        )
                    )
                else:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=hc_id),
                            status=CheckStatus.PASSED,
                            summary=f"Health Check {hc_name} is associated with a failover routing policy."
                        )
                    )

            report.status = CheckStatus.FAILED if found_unlinked else CheckStatus.PASSED

        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Error checking Route 53 health checks and failover routing.",
                    exception=str(e)
                )
            )

        return report