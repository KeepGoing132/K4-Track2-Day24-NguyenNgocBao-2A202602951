# Secret giả trong lịch sử Git — checkpoint 4

- Scanner: Gitleaks **8.30.1**, binary Windows x64 từ release chính thức. SHA256 archive khớp checksum công bố: `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e`.
- Commit: `1bdd849922156c868a5ee9293d68f5b72e242d2c` (`1bdd849`), file `lab-fake-secret.txt:1`, rule `lab24-synthetic-token`. File bị xoá ở commit `ece6ca4`; token vẫn có trong lịch sử.
- Lệnh `gitleaks git --config .gitleaks.toml --redact --verbose --report-format json --report-path reports/gitleaks-history.json .` trả **exit 1**, đúng **1 finding**. Evidence JSON đã redact, không sao chép giá trị token vào báo cáo.
- Đây là token tổng hợp, vô hiệu thuộc bài lab; không có credential thật được tạo hay sử dụng.
- Quét thư mục ban đầu tìm 3 chuỗi mẫu trong `.venv/` (mã thư viện setuptools và README đi kèm binary Gitleaks). `.gitleaks.toml` loại trừ đúng thư mục môi trường không thuộc bài nộp; giữ nguyên rule bắt token trong source/lịch sử. Kết quả quét source hiện tại xem `reports/gitleaks-current.json` và `reports/verification.md`.
- Nếu là credential thật: thu hồi/rotate ngay tại nhà cung cấp, kiểm tra truy cập trái phép, cập nhật nơi sử dụng và xử lý các bản sao/lịch sử theo quy trình sự cố. Xoá file khỏi HEAD không vô hiệu hoá credential đã lộ.
- Hook pin `rev: v8.30.1` và dependency lock kèm SHA256 làm phiên bản cài đặt tái lập, nhưng không thu hồi credential, không chứng minh dependency không có lỗ hổng, cũng không ngăn người có quyền sửa cả hook/lock.

Nguồn binary: [Gitleaks v8.30.1](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1). Công cụ đặt trong `.venv/tools/`, không thêm binary vào Git.
