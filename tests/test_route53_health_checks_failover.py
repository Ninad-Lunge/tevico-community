"""
Test suite for the route53_health_checks_failover check.

AUTHOR: Ninad Lunge
EMAIL: ninad.lunge@comprinno.net
DATE: 2025-05-19
"""

import boto3
from botocore.stub import Stubber

from library.aws.checks.route53.route53_health_checks_failover import route53_health_checks_failover
from tevico.engine.entities.report.check_model import (
    CheckMetadata, Remediation, RemediationCode, RemediationRecommendation,
    CheckStatus
)


def build_check_metadata() -> CheckMetadata:
    return CheckMetadata(
        Provider="aws",
        CheckID="route53_health_checks_failover",
        CheckTitle="Route 53 Health Checks should be linked with failover policies",
        CheckType=["Reliability"],
        ServiceName="Route 53",
        SubServiceName="Health Checks",
        ResourceIdTemplate="{Id}",
        Severity="High",
        ResourceType="AWS::Route53::HealthCheck",
        Risk="Unlinked health checks won't trigger failover.",
        RelatedUrl="https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html",
        Remediation=Remediation(
            Code=RemediationCode(CLI="aws route53 change-resource-record-sets ..."),
            Recommendation=RemediationRecommendation(
                Text="Link health checks to failover routing policies.",
                Url="https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html"
            )
        ),
        Description="Checks whether Route 53 health checks are associated with failover routing policies."
    )


class DummySession:
    def __init__(self, client):
        self._client = client

    def client(self, service_name):
        return self._client


def test_all_health_checks_linked():
    route53 = boto3.client("route53", region_name="us-east-1")
    stubber = Stubber(route53)

    stubber.add_response("list_health_checks", {
        "HealthChecks": [
            {
                "Id": "hc1",
                "CallerReference": "check-1",
                "HealthCheckConfig": {
                    "IPAddress": "192.0.2.1",
                    "Port": 80,
                    "Type": "HTTP",
                    "ResourcePath": "/",
                    "RequestInterval": 30,
                    "FailureThreshold": 3
                },
                "HealthCheckVersion": 1
            }
        ],
        "Marker": "marker",
        "IsTruncated": False,
        "MaxItems": "100"
    })

    stubber.add_response("list_hosted_zones", {
        "HostedZones": [
            {
                "Id": "/hostedzone/Z1",
                "Name": "example.com.",
                "CallerReference": "unique-string",
                "Config": {"PrivateZone": False},
                "ResourceRecordSetCount": 1
            }
        ],
        "Marker": "marker",
        "IsTruncated": False,
        "MaxItems": "100"
    })

    stubber.add_response("list_resource_record_sets", {
        "ResourceRecordSets": [
            {"Name": "example.com.", "Type": "A", "Failover": "PRIMARY", "HealthCheckId": "hc1"}
        ],
        "IsTruncated": False,
        "MaxItems": "100",
    })

    stubber.activate()
    check = route53_health_checks_failover(metadata=build_check_metadata())
    report = check.execute(connection=DummySession(route53))  # type: ignore[arg-type]

    assert report.status == CheckStatus.PASSED
    assert report.resource_ids_status[0].status == CheckStatus.PASSED
    stubber.deactivate()


def test_some_health_checks_unlinked():
    route53 = boto3.client("route53", region_name="us-east-1")
    stubber = Stubber(route53)

    stubber.add_response("list_health_checks", {
        "HealthChecks": [
            {
                "Id": "hc1",
                "CallerReference": "check-1",
                "HealthCheckConfig": {
                    "IPAddress": "192.0.2.1",
                    "Port": 80,
                    "Type": "HTTP",
                    "ResourcePath": "/",
                    "RequestInterval": 30,
                    "FailureThreshold": 3
                },
                "HealthCheckVersion": 1
            },
            {
                "Id": "hc2",
                "CallerReference": "check-2",
                "HealthCheckConfig": {
                    "IPAddress": "192.0.2.2",
                    "Port": 80,
                    "Type": "HTTP",
                    "ResourcePath": "/",
                    "RequestInterval": 30,
                    "FailureThreshold": 3
                },
                "HealthCheckVersion": 1
            }
        ],
        "Marker": "marker",
        "IsTruncated": False,
        "MaxItems": "100"
    })

    stubber.add_response("list_hosted_zones", {
        "HostedZones": [
            {
                "Id": "/hostedzone/Z1",
                "Name": "example.com.",
                "CallerReference": "unique-string",
                "Config": {"PrivateZone": False},
                "ResourceRecordSetCount": 1
            }
        ],
        "Marker": "marker",
        "IsTruncated": False,
        "MaxItems": "100"
    })

    stubber.add_response("list_resource_record_sets", {
        "ResourceRecordSets": [
            {"Name": "example.com.", "Type": "A", "Failover": "PRIMARY", "HealthCheckId": "hc1"}
        ],
        "IsTruncated": False,
        "MaxItems": "100"
    })

    stubber.activate()
    check = route53_health_checks_failover(metadata=build_check_metadata())
    report = check.execute(connection=DummySession(route53))  # type: ignore[arg-type]

    assert report.status == CheckStatus.FAILED
    assert any(r.status == CheckStatus.FAILED for r in report.resource_ids_status)
    stubber.deactivate()


def test_health_checks_but_no_hosted_zones():
    route53 = boto3.client("route53", region_name="us-east-1")
    stubber = Stubber(route53)

    stubber.add_response("list_health_checks", {
        "HealthChecks": [
            {
                "Id": "hc1",
                "CallerReference": "check-1",
                "HealthCheckConfig": {
                    "IPAddress": "192.0.2.1",
                    "Port": 80,
                    "Type": "HTTP",
                    "ResourcePath": "/",
                    "RequestInterval": 30,
                    "FailureThreshold": 3,
                },
                "HealthCheckVersion": 1,
            },
            {
                "Id": "hc2",
                "CallerReference": "check-2",
                "HealthCheckConfig": {
                    "IPAddress": "192.0.2.2",
                    "Port": 80,
                    "Type": "HTTP",
                    "ResourcePath": "/",
                    "RequestInterval": 30,
                    "FailureThreshold": 3,
                },
                "HealthCheckVersion": 1,
            }
        ],
        "Marker": "marker",
        "IsTruncated": False,
        "MaxItems": "100"
    })

    stubber.add_response("list_hosted_zones", {
        "HostedZones": [],
        "Marker": "marker",
        "IsTruncated": False,
        "MaxItems": "100"
    })

    stubber.activate()
    check = route53_health_checks_failover(metadata=build_check_metadata())
    report = check.execute(connection=DummySession(route53))  # type: ignore[arg-type]

    assert report.status == CheckStatus.FAILED
    assert all(r.status == CheckStatus.FAILED for r in report.resource_ids_status)
    stubber.deactivate()