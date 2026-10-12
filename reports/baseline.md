# Baseline — checkpoint 1

1. `_naive_loop()` (`agent/loop.py:27`) chưa tạo agent_id/run_id, TTL hay kiểm quyền OBO; dù CLI nhận `--as`, baseline không dùng principal để quyết định tool call.
2. `_naive_loop()` gọi `read_customer` (`agent/loop.py:39`) rồi `http_post` (`agent/loop.py:44`) theo chỉ thị trích từ nội dung ticket, không qua policy; allowlist trong `agent/tools.py:77` chỉ giới hạn đích localhost, không cho phép xuất PII theo quyền người dùng.
3. `reports/attack-before.log:1` là request thật tới `/reconcile` chứa CCCD, SĐT, STK tổng hợp của KH-000999; `sink/sink.py:47` ghi request này và `reports/replay-before.json` ghi kết quả của query gốc cùng 4 lure riêng biệt.
