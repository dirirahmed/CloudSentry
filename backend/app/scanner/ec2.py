import boto3

from app.config import BOTO_CONFIG
from app.models import Finding, ServiceScan, Severity

SERVICE = "EC2"

WORLD_CIDRS = {"0.0.0.0/0", "::/0"}
PROTOCOLS = {"tcp": "tcp", "6": "tcp", "udp": "udp", "17": "udp"}
COMMON_PUBLIC_PORTS = {80, 443}
SENSITIVE_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    1433: "SQL Server",
    3306: "MySQL",
    5432: "PostgreSQL",
    5601: "Kibana",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}


def _world_sources(permission: dict) -> list[str]:
    cidrs = [r["CidrIp"] for r in permission.get("IpRanges", [])]
    cidrs += [r["CidrIpv6"] for r in permission.get("Ipv6Ranges", [])]
    return [c for c in cidrs if c in WORLD_CIDRS]


def _finding(rule_id: str, severity: Severity, title: str, group: dict, evidence: dict, detail: str, fix: str) -> Finding:
    return Finding(
        id=rule_id,
        service=SERVICE,
        title=title,
        severity=severity,
        resource=group["GroupId"],
        description=f"Security group {group['GroupId']} ({group.get('GroupName', '')}) allows {detail} from "
        f"{', '.join(evidence['sources'])}. This may be intentional, but it exposes any resource using this "
        "group to the whole internet.",
        evidence=evidence,
        recommendation=fix,
    )


def _evaluate_permission(group: dict, permission: dict, sources: list[str]) -> list[Finding]:
    raw_protocol = str(permission.get("IpProtocol", "")).lower()
    evidence = {
        "group_name": group.get("GroupName"),
        "vpc_id": group.get("VpcId"),
        "protocol": raw_protocol,
        "from_port": permission.get("FromPort"),
        "to_port": permission.get("ToPort"),
        "sources": sources,
    }
    restrict = "Confirm the exposure is required. Restrict the source to known IP ranges or other security groups, " \
               "and limit the rule to the ports the service actually uses."

    if raw_protocol == "-1":
        return [_finding("EC2-003", Severity.HIGH, "All inbound traffic allowed from the internet",
                         group, evidence, "all protocols and ports", restrict)]

    protocol = PROTOCOLS.get(raw_protocol)
    if protocol is None:  # ICMP and other protocols are not evaluated
        return []

    low, high = permission.get("FromPort", 0), permission.get("ToPort", 65535)
    ports = f"{protocol.upper()} {low}" if low == high else f"{protocol.upper()} {low}-{high}"
    findings = []

    if protocol == "tcp" and low <= 22 <= high:
        findings.append(_finding(
            "EC2-001", Severity.HIGH, "SSH exposed to the internet", group, evidence, f"SSH ({ports})",
            "Restrict port 22 to known IP ranges, or remove the rule and use AWS Systems Manager Session Manager "
            "or EC2 Instance Connect Endpoint for shell access.",
        ))
    if protocol == "tcp" and low <= 3389 <= high:
        findings.append(_finding(
            "EC2-002", Severity.HIGH, "RDP exposed to the internet", group, evidence, f"RDP ({ports})",
            "Restrict port 3389 to known IP ranges, or use Systems Manager Fleet Manager, a VPN, or a bastion host.",
        ))

    if high > low:
        severity = Severity.HIGH if (low, high) == (0, 65535) else Severity.MEDIUM
        findings.append(_finding("EC2-003", severity, "Port range open to the internet", group, evidence, ports, restrict))
    elif not findings and low in SENSITIVE_PORTS:
        findings.append(_finding("EC2-003", Severity.MEDIUM, f"{SENSITIVE_PORTS[low]} port open to the internet",
                                 group, evidence, ports, restrict))
    elif not findings and low not in COMMON_PUBLIC_PORTS:
        findings.append(_finding("EC2-003", Severity.LOW, "Port open to the internet", group, evidence, ports, restrict))

    return findings


def evaluate_security_group(group: dict) -> list[Finding]:
    findings = []
    for permission in group.get("IpPermissions", []):
        if sources := _world_sources(permission):
            findings += _evaluate_permission(group, permission, sources)
    return findings


def scan(session: boto3.Session, account_id: str) -> ServiceScan:
    client = session.client("ec2", config=BOTO_CONFIG)
    paginator = client.get_paginator("describe_security_groups")
    groups = [group for page in paginator.paginate() for group in page["SecurityGroups"]]
    findings = [finding for group in groups for finding in evaluate_security_group(group)]
    return ServiceScan(findings=findings, resources_scanned=len(groups))
