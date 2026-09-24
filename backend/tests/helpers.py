from unittest.mock import MagicMock

from botocore.exceptions import ClientError


def client_error(code: str, operation: str = "Operation") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "test error"}}, operation)


def fake_session(region: str = "us-east-1", **clients) -> MagicMock:
    """A stand-in for boto3.Session whose client(name) returns the given mock clients."""
    session = MagicMock()
    session.region_name = region
    session.client.side_effect = lambda name, **kwargs: clients[name]
    return session
