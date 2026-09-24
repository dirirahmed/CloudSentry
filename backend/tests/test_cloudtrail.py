from unittest.mock import MagicMock

from app.models import Severity
from app.scanner import cloudtrail
from tests.helpers import client_error, fake_session

RESOURCE = "account/123456789012 (ca-central-1)"


def trail(multi_region=True, is_logging=True):
    return {"name": "main", "multi_region": multi_region, "is_logging": is_logging}


def summary(trails):
    return [(f.id, f.severity) for f in cloudtrail.evaluate_trails(trails, RESOURCE)]


def test_no_trails_is_high():
    assert summary([]) == [("CT-001", Severity.HIGH)]


def test_trails_not_logging_is_high():
    assert summary([trail(is_logging=False)]) == [("CT-001", Severity.HIGH)]


def test_logging_multi_region_trail_passes():
    assert summary([trail(), trail(multi_region=False, is_logging=False)]) == []


def test_only_single_region_logging_is_medium():
    assert summary([trail(multi_region=False)]) == [("CT-001", Severity.MEDIUM)]


def test_unknown_trail_status_is_info_not_high():
    assert summary([trail(is_logging=None)]) == [("CT-001", Severity.INFO)]


def test_scan_access_denied_is_unable_to_determine():
    client = MagicMock()
    client.describe_trails.side_effect = client_error("AccessDeniedException", "DescribeTrails")

    result = cloudtrail.scan(fake_session(region="ca-central-1", cloudtrail=client), "123456789012")

    assert [(f.id, f.severity) for f in result.findings] == [("CT-001", Severity.INFO)]
    assert "disabled" not in result.findings[0].title.lower()


def test_scan_reads_trail_status():
    client = MagicMock()
    client.describe_trails.return_value = {
        "trailList": [{"Name": "org-trail", "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail",
                       "HomeRegion": "us-east-1", "IsMultiRegionTrail": True, "IsOrganizationTrail": True}]
    }
    client.get_trail_status.return_value = {"IsLogging": True}

    result = cloudtrail.scan(fake_session(region="ca-central-1", cloudtrail=client), "123456789012")

    assert result.findings == []
    assert result.resources_scanned == 1
    client.describe_trails.assert_called_once_with(includeShadowTrails=True)
