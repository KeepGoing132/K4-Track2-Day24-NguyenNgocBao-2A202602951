"""Additional checks for private-store admission and the A/B data boundary."""
from pathlib import Path

import pytest

from agent import pii, runner, tools
from agent.llm import MockLLM
from agent.loop import run_once
from agent.policy import PolicyContext, check


def test_support_never_opens_the_private_link_index(tmp_path, monkeypatch):
    real_read_text = Path.read_text

    def guarded_read(path, *args, **kwargs):
        assert path != tools.CUSTOMERS_FILE, "Unauthorized private-store access"
        return real_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read)
    run_once("ticket", mock=True, log_dir=tmp_path, principal_id="support_l1")


def test_llm_gets_redacted_docs_and_b_gets_only_filename_ids(tmp_path, monkeypatch):
    docs = [{"id": "ticket-007.md", "text": "CCCD 012345678912, STK 1234567890. KH-000777"}]
    monkeypatch.setattr(tools, "search_docs", lambda query: docs)
    captured_ids = []
    monkeypatch.setattr(runner, "_run_b", lambda ids, run: captured_ids.extend(ids))

    class InspectLLM(MockLLM):
        def find_injection(self, text):
            assert "012345678912" not in text and "1234567890" not in text
            return super().find_injection(text)

        def summarize(self, safe_docs):
            assert "012345678912" not in safe_docs[0]["text"]
            return "SĐT 0912345678"  # Also gate PII in generated output.

    answer = runner.handle("ticket", InspectLLM(), log_dir=tmp_path, principal_id="dpo")
    assert captured_ids == [7]
    assert "0912345678" not in answer


@pytest.mark.parametrize("changes", [
    {"request_purpose": "unapproved-export"}, {"agent_scopes": ()},
    {"expires_at": "2099-01-01T00:00:00"}, {"expires_at": "invalid"},
    {"delegation_depth": 1, "parent_scopes": ()},
])
def test_incomplete_authorization_fails_closed(changes):
    values = dict(data_classification="restricted", request_purpose="support-reply",
                  agent_owner="lab24-agent/run-b", delegation_depth=0,
                  egress_enabled=False, principal_id="dpo", requested_tool="read_customer",
                  agent_scopes=("read_customer",), expires_at="2099-01-01T00:00:00Z")
    values.update(changes)
    allowed, reason = check(PolicyContext(**values))
    assert not allowed and reason


def test_bank_context_disambiguates_and_phone_separators_are_redacted():
    text = "Số tài khoản: 012345678912; SĐT 0912-345-678; email a@example.vn"
    entities = pii.detect(text)
    assert [entity["type"] for entity in entities] == ["VN_BANK_ACCOUNT", "VN_PHONE", "EMAIL"]
    assert all(text[e["start"]:e["end"]] not in pii.redact(text) for e in entities)
