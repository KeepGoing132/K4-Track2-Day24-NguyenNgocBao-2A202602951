"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

from pathlib import Path
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from uuid import uuid4

from agent import ledger, pii, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""

_TICKET_FILE = re.compile(r"ticket-([0-9]+)(?:b)?\.md")
_PARENT_SCOPES = ("search_docs", "read_customer")


@dataclass(frozen=True)
class _Run:
    agent_id: str
    run_id: str
    principal_id: str
    scopes: tuple[str, ...]
    expires_at: str
    ledger_path: Path


def _authorize(run: _Run, tool: str, args: dict, classification: str,
               purpose: str, *, egress: bool = False) -> bool:
    """Write the decision before execution; ledger failure stops the call."""
    allowed, reason = policy.check(policy.PolicyContext(
        data_classification=classification, request_purpose=purpose,
        agent_owner=run.agent_id, delegation_depth=1, egress_enabled=egress,
        principal_id=run.principal_id, requested_tool=tool,
        agent_scopes=run.scopes, parent_scopes=_PARENT_SCOPES,
        expires_at=run.expires_at,
    ))
    ledger.append({
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": run.agent_id, "run_id": run.run_id,
        "on_behalf_of": run.principal_id, "expires_at": run.expires_at,
        "tool": tool, "args_hash": hashlib.sha256(
            json.dumps(args, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest(), "classification": classification,
        "decision": "allow" if allowed else "deny", "reason": reason,
    }, run.ledger_path)
    return allowed


def _run_a(message: str, llm, run: _Run) -> tuple[list[int], str]:
    if not _authorize(run, "search_docs", {"query": message}, "internal", "summarize-tickets"):
        return [], "Không có quyền tìm kiếm ticket."
    docs = tools.search_docs(message)
    safe_docs = [{"id": doc["id"], "text": pii.redact(doc["text"])} for doc in docs]
    injection = llm.find_injection("\n\n".join(doc["text"] for doc in safe_docs))
    if injection is not None:
        # Audit the proposed exfiltration in A; never forward attacker commands,
        # URLs or customer IDs to B. This proposal has no private record body.
        allowed = _authorize(run, "http_post", {
            "url": injection.target_url, "customer_ids": injection.customer_ids,
            "operation": "proposed restricted-record export",
        }, "restricted", "support-reply", egress=True)
        if allowed:
            raise RuntimeError("Policy unexpectedly permitted a restricted export")
    ticket_ids = sorted({int(match.group(1)) for doc in docs
                         if (match := _TICKET_FILE.fullmatch(doc["id"]))})
    return ticket_ids, pii.redact(llm.summarize(safe_docs))


def _run_b(ticket_ids: list[int], run: _Run) -> None:
    """Private stage: receives ticket IDs only and has no LLM or egress tool."""
    if any(type(ticket_id) is not int or ticket_id < 0 for ticket_id in ticket_ids):
        raise ValueError("Run B accepts only nonnegative integer ticket IDs")
    if not ticket_ids:
        return
    # The link index is colocated with private records in this lab. Authorize
    # its access too, so support_l1 never opens the private JSON at all.
    if not _authorize(run, "read_customer", {
        "operation": "resolve trusted customer links", "ticket_ids": ticket_ids,
    }, "restricted", "support-reply"):
        return
    linked = set(ticket_ids)
    customer_ids = sorted({record["customer_id"] for record in
                           json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
                           if linked.intersection(record.get("related_tickets", []))})
    for customer_id in customer_ids:
        if _authorize(run, "read_customer", {"customer_id": customer_id},
                      "restricted", "support-reply"):
            tools.read_customer(customer_id)


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    path = Path(log_dir) / "ledger.jsonl" if log_dir is not None else DEFAULT_LEDGER_PATH
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    run_a = _Run("lab24-agent/run-a", str(uuid4()), principal_id,
                 ("search_docs",), expiry, path)
    run_b = _Run("lab24-agent/run-b", str(uuid4()), principal_id,
                 ("read_customer",), expiry, path)
    ticket_ids, answer = _run_a(message, llm, run_a)
    _run_b(ticket_ids, run_b)
    return answer
