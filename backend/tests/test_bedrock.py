import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import NoCredentialsError, ReadTimeoutError

from app.ai import bedrock
from app.ai.bedrock import AIUnavailableError, BedrockService, build_prompt, parse_explanation
from app.models import Finding, Severity
from tests.helpers import client_error

MODEL_ID = "test-model-id"
EXPLANATION = {
    "explanation": "SSH is reachable from any IP address.",
    "impact": "Attackers can attempt to brute-force SSH logins.",
    "remediation": "Limit port 22 to trusted IP ranges or use Session Manager.",
}


def make_finding(**overrides):
    fields = dict(
        id="EC2-001", service="EC2", title="SSH exposed to the internet", severity=Severity.HIGH,
        resource="sg-123456", description="Security group allows SSH from 0.0.0.0/0.",
        evidence={"from_port": 22, "sources": ["0.0.0.0/0"]}, recommendation="Restrict port 22.",
    )
    return Finding(**{**fields, **overrides})


def converse_response(text):
    return {"output": {"message": {"role": "assistant", "content": [{"text": text}]}}, "stopReason": "end_turn"}


def service_returning(text):
    client = MagicMock()
    client.converse.return_value = converse_response(text)
    return BedrockService(model_id=MODEL_ID, client=client), client


# Successful explanation

def test_explain_finding_returns_parsed_explanation():
    service, client = service_returning(json.dumps(EXPLANATION))

    explanation = service.explain_finding(make_finding())

    assert explanation.model_dump() == EXPLANATION
    kwargs = client.converse.call_args.kwargs
    assert kwargs["modelId"] == MODEL_ID
    assert kwargs["inferenceConfig"]["maxTokens"] == bedrock.AI_MAX_TOKENS


def test_system_prompt_states_the_scanner_is_the_source_of_truth():
    service, client = service_returning(json.dumps(EXPLANATION))
    service.explain_finding(make_finding())

    system = client.converse.call_args.kwargs["system"][0]["text"]
    assert "already been detected by CloudSentry's deterministic rules" in system
    assert "Do not change, dispute or re-rate the severity" in system
    assert "Do not invent evidence" in system


def test_prompt_contains_the_structured_finding():
    prompt = build_prompt(make_finding())
    data = json.loads(prompt.split("\n", 1)[1])

    assert data == {
        "id": "EC2-001",
        "service": "EC2",
        "title": "SSH exposed to the internet",
        "severity": "HIGH",
        "resource": "sg-123456",
        "description": "Security group allows SSH from 0.0.0.0/0.",
        "evidence": {"from_port": 22, "sources": ["0.0.0.0/0"]},
        "recommendation": "Restrict port 22.",
    }


def test_large_evidence_is_truncated():
    prompt = build_prompt(make_finding(evidence={"statements": ["x" * 10_000]}))
    assert "...(truncated)" in prompt
    assert len(prompt) < 5_000


# Response parsing

def test_parse_plain_json():
    assert parse_explanation(json.dumps(EXPLANATION)).impact == EXPLANATION["impact"]


def test_parse_json_wrapped_in_code_fence_and_text():
    text = "Here is the analysis:\n```json\n" + json.dumps(EXPLANATION) + "\n```"
    assert parse_explanation(text).model_dump() == EXPLANATION


def test_parse_ignores_fields_the_model_should_not_set():
    text = json.dumps({**EXPLANATION, "severity": "LOW", "id": "HACKED-001"})
    assert parse_explanation(text).model_dump() == EXPLANATION


# Malformed responses

@pytest.mark.parametrize(
    "text",
    [
        "I cannot help with that.",
        '{"explanation": "only one field"}',
        '{"explanation": "", "impact": "i", "remediation": "r"}',
        '{"explanation": "cut off because of the token lim',
        "{not json}",
    ],
)
def test_malformed_response_raises_safe_error(text):
    service, _ = service_returning(text)

    with pytest.raises(AIUnavailableError) as error:
        service.explain_finding(make_finding())

    assert str(error.value) == bedrock.MALFORMED
    assert not error.value.fatal


def test_empty_response_content_is_malformed():
    client = MagicMock()
    client.converse.return_value = {"output": {"message": {"role": "assistant", "content": []}}}

    with pytest.raises(AIUnavailableError, match="could not be read"):
        BedrockService(model_id=MODEL_ID, client=client).explain_finding(make_finding())


# Bedrock API failures

@pytest.mark.parametrize(
    "exc, message, fatal",
    [
        (client_error("AccessDeniedException", "Converse"), bedrock.ACCESS_DENIED, True),
        (client_error("ResourceNotFoundException", "Converse"), bedrock.MODEL_UNAVAILABLE, True),
        (client_error("ValidationException", "Converse"), bedrock.MODEL_REJECTED, True),
        (client_error("UnrecognizedClientException", "Converse"), bedrock.CREDENTIALS, True),
        (client_error("ThrottlingException", "Converse"), bedrock.THROTTLED, False),
        (client_error("InternalServerException", "Converse"), bedrock.REQUEST_FAILED, False),
        (ReadTimeoutError(endpoint_url="https://bedrock-runtime.example"), bedrock.TIMEOUT, False),
        (NoCredentialsError(), bedrock.CREDENTIALS, True),
    ],
)
def test_bedrock_failures_become_safe_errors(exc, message, fatal):
    client = MagicMock()
    client.converse.side_effect = exc

    with pytest.raises(AIUnavailableError) as error:
        BedrockService(model_id=MODEL_ID, client=client).explain_finding(make_finding())

    assert str(error.value) == message
    assert error.value.fatal is fatal
    assert "test error" not in str(error.value)  # raw AWS message is never passed through


# Configuration

def test_missing_model_id_does_not_call_bedrock():
    client = MagicMock()

    with pytest.raises(AIUnavailableError) as error:
        BedrockService(model_id=None, client=client).explain_finding(make_finding())

    assert str(error.value) == bedrock.NOT_CONFIGURED
    assert error.value.fatal
    client.converse.assert_not_called()
