"""Trust-boundary input validation (AgentRequest / ToolCall)."""
import pytest

from aegis import AgentRequest, Source, ToolCall
from aegis.errors import AegisValidationError


@pytest.mark.parametrize("kwargs", [
    {"agent_id": "", "role": "ops"},
    {"agent_id": "   ", "role": "ops"},
    {"agent_id": "a", "role": ""},
    {"agent_id": "a", "role": "ops", "content": ["not", "a", "string"]},
    {"agent_id": "a", "role": "ops", "content": {"x": 1}},
    {"agent_id": "a", "role": "ops", "source": "not-a-real-source"},
    {"agent_id": "a", "role": "ops", "tool_call": {"name": "web_search"}},  # dict, not ToolCall
])
def test_invalid_requests_raise(kwargs):
    with pytest.raises(AegisValidationError):
        AgentRequest(**kwargs)


def test_str_source_is_coerced():
    r = AgentRequest("a", "ops", source="web")
    assert r.source is Source.WEB


def test_none_content_becomes_empty():
    r = AgentRequest("a", "ops", content=None)
    assert r.content == ""


def test_toolcall_validation():
    with pytest.raises(AegisValidationError):
        ToolCall("")
    with pytest.raises(AegisValidationError):
        ToolCall("web_search", args=["bad"])  # args must be dict
    tc = ToolCall("web_search", None)
    assert tc.args == {}


def test_request_ids_are_unique():
    ids = {AgentRequest("a", "ops").request_id for _ in range(1000)}
    assert len(ids) == 1000
