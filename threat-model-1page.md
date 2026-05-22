# Lab 8 - Threat model 1 trang

## 1. Tài sản cần bảo vệ

- **Nội dung bản tin (Plaintext):** Thông điệp gốc cần giữ bí mật tuyệt đối trên đường truyền.
- **Khóa phiên đối xứng (DES Session Key):** Khóa dùng để mã hóa trực tiếp bản tin, nếu lộ sẽ lộ toàn bộ nội dung.
- **Khóa riêng RSA của Receiver (Receiver Private Key):** Thành phần cốt lõi để giải mã DES Session Key, phải được lưu trữ an toàn ở local và không được chia sẻ.
- **Tính toàn vẹn của gói tin (Packet Integrity):** Đảm bảo cấu trúc gói tin nhị phân không bị xáo trộn hoặc chèn mã độc trên luồng Socket.

## 2. Đối tượng tấn công giả định

- **Kẻ tấn công đứng giữa mạng (Adversary/MitM):** Có khả năng nghe lén (Sniffing), bắt giữ gói tin hoặc cố tình chỉnh sửa, giả mạo các byte dữ liệu nhị phân trên đường truyền TCP Socket.
- **Giới hạn:** Kẻ tấn công không chiếm được quyền điều khiển máy vật lý và không sở hữu khóa riêng RSA Private Key của Receiver.

## 3. Rủi ro và cơ chế giảm thiểu

| Rủi ro (Threats) | Cơ chế giảm thiểu trong Lab 8 | Vị trí xử lý trong Code |
|---|---|---|
| Kẻ địch nghe lén đọc trộm Plaintext | Sử dụng thuật toán đối xứng **DES-CBC** kết hợp Vector khởi tạo (IV) ngẫu nhiên để mã hóa nội dung. | `secure_transfer_utils.py` / `encrypt_des_cbc` |
| Bị lộ DES Session Key khi truyền cùng gói tin | Sử dụng thuật toán bất đối xứng mạnh **RSA-OAEP** để mã hóa bọc bảo vệ khóa DES bằng Public Key của Receiver. | `secure_transfer_utils.py` / `encrypt_des_key_rsa` |
| Kẻ địch cố tình can thiệp làm sai lệch dữ liệu | Áp dụng hàm băm **SHA-256** của plaintext gốc đi kèm gói tin. Receiver tính toán lại và đối chiếu để phát hiện can thiệp. | `secure_transfer_utils.py` / `open_receiver_payload` |
| Gửi packet sai định dạng phá vỡ luồng Socket | Đóng gói theo cấu trúc nhị phân nghiêm ngặt với Header độ dài cố định 4-byte mạng (`big-endian`) giúp hàm parse bắt lỗi chính xác. | `secure_transfer_utils.py` / `recv_exact` |

## 4. Hạn chế còn tồn tại

- **Không gian khóa yếu:** Thuật toán DES có kích thước khóa danh nghĩa 64-bit (hiệu dụng chỉ 56-bit), dễ dàng bị phá mã bạo lực (Brute-force) ngày nay.
- **Thiếu tính xác thực nguồn gốc (Authentication):** Hệ thống mới chỉ đảm bảo bí mật cho Receiver chứ chưa giúp Receiver kiểm tra xem gói tin đó có đúng là do Sender hợp pháp gửi hay không (Kẻ tấn công hoàn toàn có thể lấy RSA Public Key công khai của Receiver để tự đóng gói một gói tin giả mạo).
- **Tấn công phát lại (Replay Attack):** Kẻ tấn công có thể bắt trọn vẹn một gói tin hợp pháp cũ rồi gửi lại lên Socket để đánh lừa Receiver thực thi lại hành động.
- **Quản lý khóa (Key Management):** Chưa có cơ chế thu hồi khóa hay quy định thời hạn hiệu lực cho cặp khóa RSA.
## 5. Hướng cải tiến

1. **Nâng cấp thuật toán đối xứng:** Thay thế hoàn toàn mã dịch DES sang **AES-GCM** (Authenticated Encryption with Associated Data - AEAD) để vừa bảo mật vừa xác thực dữ liệu ở tầng mã hóa khối, loại bỏ việc băm SHA-256 rời rạc.
2. **Tích hợp chữ ký số (Digital Signature):** Yêu cầu Sender ký lên mã băm bằng khóa riêng RSA Private Key của Sender giúp Receiver kiểm tra tính chống từ chối (Non-repudiation).
3. **Chống Replay Attack:** Bổ sung thêm trường dữ liệu `Timestamp` (thời gian thực) hoặc số ngẫu nhiên chỉ dùng một lần `Nonce` vào bên trong cấu trúc gói tin được bảo vệ.
