# 🔐 Secure File Transfer System (Đề tài 6 Nâng cấp)

## 🎯 Giới thiệu bài toán

Hệ thống này được xây dựng để mô phỏng quy trình **gửi và nhận file an toàn** trong môi trường mạng hạn chế băng thông, được nâng cấp toàn diện theo yêu cầu bảo mật của **Đề tài 6: Secure Assignment Chunk Transfer**.

### Quy trình cũ vs Quy trình nâng cấp:

| Đặc điểm | Hệ thống cũ (Khóa trước) | Hệ thống nâng cấp (Đề tài 6) |
|---|---|---|
| **Mã hóa đối xứng** | DES / CBC (Khóa 8-byte, yếu) | **AES-256-GCM** (Khóa 32-byte, AEAD xác thực) |
| **Trao đổi khóa** | RSA 1024-bit (PKCS#1 v1.5) | **RSA-2048 OAEP** (SHA-256, chống Bleichenbacher) |
| **Chữ ký số** | RSA / SHA-512 (PKCS#1 v1.5) | **RSA-PSS** (SHA-256, salt ngẫu nhiên) |
| **Xác thực toàn vẹn** | SHA-512 thuần | **HMAC-SHA256 & AES-GCM Authentication Tag** |
| **Mật khẩu người dùng**| SHA-256 thuần (không salt) | **Bcrypt** (Cost factor 12, tự động sinh salt) |
| **Chống Replay Attack**| Không hỗ trợ | **Replay Guard** (Kiểm tra nonce + TTL + Timestamp age) |
| **Nhật ký bảo mật** | Chỉ in console dạng thô | **Security Logger** (Ghi tệp `logs/security.log`, chuẩn UTC) |
| **Cơ chế truyền** | Chia cố định 3 phần | **Linh hoạt số phần (Chunks) & Hỗ trợ Resume** |

---

## 🛠️ Kỹ thuật và công nghệ sử dụng

| Thành phần | Công nghệ |
|------------|-----------|
| **Ngôn ngữ lập trình** | Python 3.11+ |
| **Framework web** | Flask |
| **Mã hóa đối xứng** | AES-256-GCM |
| **Mã hóa khóa phiên** | RSA-2048 OAEP (SHA-256) |
| **Ký số** | RSA-PSS (SHA-256) |
| **Hàm băm & Xác thực**| HMAC-SHA256 & SHA-256 |
| **Mật khẩu** | Bcrypt (cost 12) |
| **Frontend** | HTML5, CSS3, Vanilla Javascript & Bootstrap 5 |
| **Trao đổi dữ liệu** | JSON qua Socket TCP |

---

## ✨ Các chức năng chính

1. **Đăng ký, đăng nhập người dùng an toàn**
   - Tài khoản được lưu trữ an toàn bằng **bcrypt** chống tấn công Rainbow Table.
2. **Handshake an toàn**
   - Đồng thuận khởi động phiên gửi nhận file qua Socket TCP.
3. **Mã hóa khóa phiên lai (Hybrid Cryptosystem)**
   - Sinh khóa phiên AES-256 ngẫu nhiên cho mỗi giao dịch.
   - Mã hóa khóa phiên bằng RSA-2048 OAEP.
4. **Phân đoạn và Mã hóa Chunks**
   - File được chia thành nhiều phần linh hoạt.
   - Mỗi phần được mã hóa bằng AES-256-GCM, tính HMAC-SHA256 và ký số RSA-PSS.
   - Định dạng gói tin chunk gửi qua Socket:
     ```json
     {
       "file_id": "<UUID>",
       "chunk_id": "<UUID>",
       "sequence_number": "<int>",
       "total_chunks": "<int>",
       "nonce": "<Base64>",
       "timestamp": "<ISO-8601>",
       "cipher": "<Base64>",
       "tag": "<Base64>",
       "hmac": "<Hex>",
       "sig": "<Signature_Base64>"
     }
     ```
5. **Cơ chế Replay Guard & Phục hồi (Resume)**
   - Server kiểm tra chặn các gói tin trùng lặp nonce hoặc timestamp quá hạn (5 phút).
   - Nếu thiếu chunk hoặc mất gói tin, server gửi yêu cầu NACK cụ thể để client truyền lại đúng chunk bị thiếu.
6. **Nhật ký bảo mật (Audit Logs)**
   - Mọi sự kiện đăng nhập, mã hóa, lỗi, tấn công replay đều được lưu tại `logs/security.log`.

---

## 🖥️ Giao diện và Hoạt động

Mọi giao diện hiển thị thông số bảo mật chi tiết, cấu trúc gói tin trực quan của các giao dịch đã được đồng bộ hóa hoàn toàn với cấu hình mật mã nâng cấp mới nhất.

---

## 🚀 Hướng dẫn Cài đặt & Chạy Chương trình

### 1. Yêu cầu hệ thống
* Python 3.11+
* Hệ điều hành: Windows, macOS, hoặc Linux

### 2. Cài đặt thư viện phụ thuộc
Di chuyển vào thư mục dự án `BTL_ATTT` và chạy lệnh sau để cài đặt các thư viện cần thiết:
```bash
pip install -r requirements.txt
```

Các thư viện chính được cài đặt bao gồm:
* `Flask`: Web Framework
* `pycryptodome`: Thư viện mật mã (AES, RSA, HMAC)
* `bcrypt`: Băm mật khẩu người dùng
* `pytest`: Công cụ chạy kiểm thử tự động

### 3. Khởi chạy ứng dụng
Chạy tệp `app.py` bằng Python:
```bash
python app.py
```

Ứng dụng sẽ tự động:
1. Tạo các thư mục lưu trữ cần thiết (`uploads/`, `encrypted_files/`, `decrypted_files/`, `keys/`, `logs/`, `data/`).
2. Khởi tạo cơ sở dữ liệu giả lập (`users.json`, `admin.json`).
3. Tự động sinh khóa hệ thống RSA-2048 nếu chưa tồn tại.
4. Khởi chạy **Socket Server** chạy nền ở cổng `9999`.
5. Khởi chạy ứng dụng **Web Flask** ở địa chỉ: [http://localhost:5000](http://localhost:5000).

### 4. Chạy kiểm thử bảo mật (Security Tests)
Để chạy toàn bộ 16 trường hợp kiểm thử tự động (Unit & Integration tests) và kiểm tra tính toàn vẹn của mã nguồn, chạy lệnh:
```bash
pytest
```
hoặc:
```bash
python -m pytest tests/
```

