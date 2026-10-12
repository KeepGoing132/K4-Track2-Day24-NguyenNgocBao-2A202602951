"""Regression for appending to valid JSONL with no final line terminator."""
import json

from agent import ledger


def test_append_preserves_chain_when_last_newline_is_missing(tmp_path):
    path = tmp_path / "ledger.jsonl"
    entry = {
        "ts": "2026-10-12T00:00:00Z", "agent_id": "audit", "run_id": "audit",
        "tool": "search_docs", "args_hash": "test", "classification": "internal",
        "decision": "allow", "reason": "Authorized synthetic regression test",
    }
    first = ledger.append(entry, path)
    original = path.read_bytes().rstrip(b"\r\n")
    path.write_bytes(original)
    assert ledger.verify(path)

    second = ledger.append(entry, path)

    assert path.read_bytes().startswith(original)
    assert len(path.read_text(encoding="utf-8").splitlines()) == 2
    assert second["prev_hash"] == first["hash"]
    assert json.loads(path.read_text(encoding="utf-8").splitlines()[0]) == first
    assert ledger.verify(path)
