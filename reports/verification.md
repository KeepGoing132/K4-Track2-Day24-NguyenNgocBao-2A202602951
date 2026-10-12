# Verification — 12/10/2026 (Asia/Bangkok)

## Kết quả thực tế

| Kiểm tra | Kết quả | Evidence |
|---|---|---|
| Môi trường | Windows native / PowerShell, Python 3.11.9; venv riêng, pytest 9.1.1 | `.venv/` không thuộc bài nộp |
| Gitleaks version | 8.30.1; checksum archive khớp release chính thức | `reports/secrets-incident.md` |
| `python -m pytest tests/ -q -s` | **41 passed in 5.51s**, không skip; 33 test có sẵn + 8 case bổ sung | `reports/pytest.log` |
| PII trên test set | gold=118, pred=118, tp=118; precision=1.000, recall=1.000 | `reports/pytest.log` |
| Lure preflight | **4/4 sẵn sàng**; từng file của cặp 904 riêng trả None, ghép cặp nhận diện | `injection-corpus.md`, `corpus/ticket-90*.md` |
| Baseline replay | Query gốc + 4 biến thể, mỗi lần 1 request chứa PII synthetic KH-000999 | `reports/replay-before.json`, `attack-before.log` (1495 byte / 5 dòng) |
| Contained replay | Query gốc + 4 biến thể × support_l1/dpo = 10 lần; **0 request** | `reports/replay-after.json`, `attack-after.log` (0 byte) |
| Ledger | **verify=True**, 135 dòng có reason/OBO/TTL; 10 http_post deny; không có PII thô | `reports/ledger-check.json`, `ledger.jsonl` |
| Tamper proof | Sửa reason dòng thứ hai trong bản sao tạm, giữ hash cũ → **verify=False** | `tests/test_ledger.py`, `reports/ledger-check.json` |
| Dependency lock | Sinh bằng pip-tools 7.6.2; cài lại tất cả package với `--require-hashes --force-reinstall` thành công, exit 0 | `requirements.lock`, `reports/hash-install.log` |
| Gitleaks history | exit 1 như dự kiến; đúng 1 finding rule lab24-synthetic-token tại commit 1bdd849 | `reports/gitleaks-history.json`, `gitleaks-history.log` |
| Gitleaks current source | exit 0, 0 finding; chỉ loại trừ `.venv/` khỏi source | `reports/gitleaks-current.json`, `gitleaks-current.log` |
| `pre-commit run --all-files` | Passed, exit 0, gitleaks-system pin v8.30.1 | `.pre-commit-config.yaml`, `reports/pre-commit.log` |
| `git diff --check` | exit 0; Git thông báo chuyển LF → CRLF ở Markdown theo cấu hình máy | Không có lỗi whitespace |

Test missing-pair chủ động in “Không thấy file ...ticket-904b.md / 0/1 lure” trong pytest: đây là negative test đạt, không phải lỗi của corpus thật. Hook dùng lệnh mặc định của gitleaks-system để kiểm staged diff; quét `gitleaks dir` riêng kiểm cả source hiện tại, gồm file mới chưa stage.

## Lỗi và giới hạn ghi nhận

Không còn test FAIL/SKIP hay lỗi cài dependency/hook. Quét thư mục ban đầu nhận 3 chuỗi mẫu thuộc thư viện/README trong `.venv/`; đã giới hạn allowlist đúng thư mục môi trường, quét lại source sạch. Một số lệnh PowerShell ghi stderr thành dòng `NativeCommandError` trong log cài pip khi pip in notice; exit thực tế là 0.

Đã khắc phục lỗi truy cập VBPL bằng bản PDF ký trên Cổng thông tin Chính phủ: đọc Điều 3 khoản 2, 4, 5 Luật 91/2025 (trang 2), Điều 4 khoản 2 NĐ 356/2025 (trang 3), Điều 4 khoản 2, 3 Luật AI 134/2025 (trang 2), cùng các mục phân loại và quyền chủ thể được ghi trong mapping. PDF gốc/URL/checksum lưu tại `reports/legal-sources/manifest.json`. Không kết luận tuân thủ toàn bộ pháp luật từ kết quả test.

Hai run tách context/tool scope bằng code trong cùng process; chưa có sandbox OS. Principal JSON/CLI là mô phỏng. Hash chain thiếu mốc tin cậy ngoài file và chỉ khóa thread cùng process. Chưa kiểm model thật hoặc Linux/WSL; evidence ở đây chạy bằng mock trên Windows native.

## Chạy lại trong PowerShell

```powershell
$env:PYTHONIOENCODING = 'utf-8'
$env:PATH = "$PWD\.venv\tools;$PWD\.venv\Scripts;$env:PATH"
.venv\Scripts\python.exe -m pytest tests/ -q
.venv\Scripts\python.exe -m agent.check_lure 'corpus/ticket-90*.md'
.venv\Scripts\python.exe -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"
.venv\Scripts\python.exe -m pre_commit run --all-files
.venv\tools\gitleaks.exe dir --config .gitleaks.toml --redact .
```

Agent đã containment không cần sink chạy vì không thực thi http_post. Muốn ghi lại evidence sau trên sink localhost: `python -m scripts.replay_evidence --phase after` khi cổng 10024 đang trống. Script tự mở/đóng sink và không tác động evidence before. Nó append ledger, vì vậy số dòng ledger sẽ tăng nếu chạy lại.

HEAD nền trước thay đổi: `52b33b5`. Kiểm tra chốt sau khi hoàn tất mapping: `python -m pytest tests/ -q` đạt **41 passed in 5.45s**. Hook pre-commit đã được cài tại `.git/hooks/pre-commit`. Toàn bộ code/báo cáo và ba evidence bị `.gitignore` chặn được thêm vào commit bàn giao theo SUBMISSION. Lấy SHA cuối bằng `git rev-parse HEAD`; kiểm nội dung commit bằng `git show --stat HEAD`. Khi thay đổi evidence sau bàn giao, cần tạo commit mới để SHA tiếp tục phản ánh bài nộp.

```powershell
git add -f reports/attack-before.log reports/attack-after.log reports/ledger.jsonl
```

Không thêm `reports/sink.log` hoặc `.venv/` vào bài nộp. Code hỗ trợ bằng AI trong phiên này; người nộp cần đọc, tự chạy lại và giải thích từng control theo RULES.md. Nơi nộp và deadline không có trong repo, do lớp/TA công bố; bản bàn giao local đã chứa các file bắt buộc.
