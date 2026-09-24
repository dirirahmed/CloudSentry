from unittest.mock import MagicMock

from app.models import Severity
from app.scanner import ec2
from tests.helpers import fake_session


def security_group(*permissions, group_id="sg-0123456789abcdef0"):
    return {"GroupId": group_id, "GroupName": "web", "VpcId": "vpc-1", "IpPermissions": list(permissions)}


def rule(from_port, cidr="0.0.0.0/0", protocol="tcp", to_port=None):
    permission = {
        "IpProtocol": protocol,
        "FromPort": from_port,
        "ToPort": from_port if to_port is None else to_port,
        "IpRanges": [],
        "Ipv6Ranges": [],
    }
    if ":" in cidr:
        permission["Ipv6Ranges"].append({"CidrIpv6": cidr})
    else:
        permission["IpRanges"].append({"CidrIp": cidr})
    return permission


def summary(group):
    return [(f.id, f.severity) for f in ec2.evaluate_security_group(group)]


def test_ssh_open_to_the_internet_is_high():
    assert summary(security_group(rule(22))) == [("EC2-001", Severity.HIGH)]


def test_ssh_open_over_ipv6_is_high():
    assert summary(security_group(rule(22, cidr="::/0"))) == [("EC2-001", Severity.HIGH)]


def test_ssh_restricted_to_a_cidr_passes():
    assert summary(security_group(rule(22, cidr="203.0.113.10/32"))) == []


def test_rdp_open_to_the_internet_is_high():
    assert summary(security_group(rule(3389))) == [("EC2-002", Severity.HIGH)]


def test_safe_security_group_passes():
    group = security_group(rule(443), rule(80), rule(22, cidr="10.0.0.0/8"))
    assert summary(group) == []


def test_all_traffic_from_the_internet_is_a_single_high_finding():
    group = security_group({"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]})
    assert summary(group) == [("EC2-003", Severity.HIGH)]


def test_database_port_is_medium():
    findings = ec2.evaluate_security_group(security_group(rule(5432)))
    assert [(f.id, f.severity) for f in findings] == [("EC2-003", Severity.MEDIUM)]
    assert "PostgreSQL" in findings[0].title


def test_other_single_port_is_low():
    assert summary(security_group(rule(8080))) == [("EC2-003", Severity.LOW)]


def test_port_range_is_medium():
    assert summary(security_group(rule(8000, to_port=8100))) == [("EC2-003", Severity.MEDIUM)]


def test_full_tcp_range_reports_ssh_rdp_and_range():
    assert summary(security_group(rule(0, to_port=65535))) == [
        ("EC2-001", Severity.HIGH),
        ("EC2-002", Severity.HIGH),
        ("EC2-003", Severity.HIGH),
    ]


def test_icmp_is_not_evaluated():
    assert summary(security_group(rule(-1, protocol="icmp"))) == []


def test_descriptions_are_neutral():
    finding = ec2.evaluate_security_group(security_group(rule(22)))[0]
    assert "may be intentional" in finding.description
    assert finding.evidence["sources"] == ["0.0.0.0/0"]


def test_scan_uses_paginated_security_groups():
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [
        {"SecurityGroups": [security_group(rule(22), group_id="sg-open")]},
        {"SecurityGroups": [security_group(rule(443), group_id="sg-web")]},
    ]
    result = ec2.scan(fake_session(ec2=client), "123456789012")

    assert [(f.id, f.resource) for f in result.findings] == [("EC2-001", "sg-open")]
    assert result.resources_scanned == 2
    client.get_paginator.assert_called_once_with("describe_security_groups")
