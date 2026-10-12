# Nguồn pháp luật đã đối chiếu

`manifest.json` ghi ba URL PDF ký chính thức của Chính phủ, ngày truy cập, số trang và SHA256 của bản đã đọc. Các trang liên quan được render từ PDF gốc và xem trực tiếp vì PDF không có text layer.

| Văn bản | Trang PDF đã đọc | Điều/khoản được sử dụng trong mapping |
|---|---|---|
| Luật 91/2025/QH15 | 2–3 | Điều 2 khoản 11; Điều 3 khoản 2, 4, 5; Điều 4 |
| NĐ 356/2025/NĐ-CP | 2–3 | Điều 3 khoản 1, 7; Điều 4 khoản 1 điểm k, khoản 2 |
| Luật AI 134/2025/QH15 | 2–3 | Điều 4 khoản 2, 3 |

Ảnh và PDF nằm trong cache `.venv/legal-review/`, không thêm vào bài nộp. Chỉ dùng nội dung pháp luật cần thiết để đối chiếu control; dữ liệu tấn công và log vẫn là synthetic theo RULES.md.

Để kiểm bản tải lại, dùng `Get-FileHash -Algorithm SHA256` hoặc `sha256sum`, đối chiếu giá trị trong manifest. Chỉ đối chiếu các điều/khoản được liệt kê; báo cáo không khẳng định toàn hệ thống đã đạt tất cả nghĩa vụ pháp lý.
