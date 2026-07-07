# 🔐 Secure File Transfer System (Đề tài 6 Nâng cấp)

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.3.3-000000?style=flat&logo=flask&logoColor=white)
![AES-256-GCM](https://img.shields.io/badge/AES--256--GCM-✓-green?style=flat)
![RSA-2048](https://img.shields.io/badge/RSA--2048-OAEP%20%2B%20PSS-green?style=flat)
![bcrypt](https://img.shields.io/badge/Password-bcrypt%20cost%2012-green?style=flat)
![Tests](https://img.shields.io/badge/Tests-16%20passed-brightgreen?style=flat&logo=pytest)

---

## 🎯 Giới thiệu bài toán

Hệ thống này được xây dựng để mô phỏng quy trình **gửi và nhận file an toàn** trong môi trường mạng hạn chế băng thông, được nâng cấp toàn diện theo yêu cầu bảo mật của **Đề tài 6: Secure Assignment Chunk Transfer**.

### Quy trình cũ vs Quy trình nâng cấp

| Đặc điểm | Hệ thống cũ (Khóa trước) | Hệ thống nâng cấp (Đề tài 6) |
|---|---|---|
| **Mã hóa đối xứng** | DES / CBC (Khóa 8-byte, yếu) | **AES-256-GCM** (Khóa 32-byte, AEAD xác thực) |
| **Trao đổi khóa** | RSA 1024-bit (PKCS#1 v1.5) | **RSA-2048 OAEP** (SHA-256, chống Bleichenbacher) |
| **Chữ ký số** | RSA / SHA-512 (PKCS#1 v1.5) | **RSA-PSS** (SHA-256, salt ngẫu nhiên) |
| **Xác thực toàn vẹn** | SHA-512 thuần | **HMAC-SHA256 & AES-GCM Authentication Tag** |
| **Mật khẩu người dùng** | SHA-256 thuần (không salt) | **Bcrypt** (Cost factor 12, tự động sinh salt) |
| **Chống Replay Attack** | Không hỗ trợ | **Replay Guard** (Kiểm tra nonce + TTL + Timestamp age) |
| **Nhật ký bảo mật** | Chỉ in console dạng thô | **Security Logger** (Ghi tệp `logs/security.log`, chuẩn UTC) |
| **Cơ chế truyền** | Chia cố định 3 phần | **Linh hoạt số phần (Chunks) & Hỗ trợ Resume** |

---

## 🛠️ Kỹ thuật và công nghệ sử dụng

| Thành phần | Công nghệ |
|------------|-----------|
| **Ngôn ngữ lập trình** | Python 3.11+ |
| **Framework web** | Flask 2.3.3 |
| **Mã hóa đối xứng** | AES-256-GCM |
| **Mã hóa khóa phiên** | RSA-2048 OAEP (SHA-256) |
| **Ký số** | RSA-PSS (SHA-256) |
| **Hàm băm & Xác thực** | HMAC-SHA256 & SHA-256 |
| **Mật khẩu** | Bcrypt (cost 12) |
| **Frontend** | HTML5, CSS3, Vanilla Javascript & Bootstrap 5 |
| **Trao đổi dữ liệu** | JSON qua Socket TCP (cổng 9999) |
| **Thư viện mật mã** | pycryptodome 3.19.0 |

---

## ✨ Các chức năng chính

1. **Đăng ký, đăng nhập người dùng an toàn**
   - Tài khoản được lưu trữ an toàn bằng **bcrypt** chống tấn công Rainbow Table.
2. **Quản lý khóa RSA-2048**
   - Người dùng tự tạo cặp khóa RSA-2048 hoặc tải lên khóa công khai có sẵn.
3. **Handshake an toàn**
   - Đồng thuận khởi động phiên gửi nhận file qua Socket TCP.
4. **Mã hóa khóa phiên lai (Hybrid Cryptosystem)**
   - Sinh khóa phiên AES-256 ngẫu nhiên cho mỗi giao dịch.
   - Mã hóa khóa phiên bằng RSA-2048 OAEP.
5. **Phân đoạn và Mã hóa Chunks**
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
6. **Cơ chế Replay Guard & Phục hồi (Resume)**
   - Server kiểm tra chặn các gói tin trùng lặp nonce hoặc timestamp quá hạn (5 phút).
   - Nếu thiếu chunk, server gửi NACK để client truyền lại đúng chunk bị thiếu.
7. **Nhật ký bảo mật (Audit Logs)**
   - Mọi sự kiện đăng nhập, mã hóa, lỗi, tấn công replay đều được lưu tại `logs/security.log`.
8. **Trang quản trị Admin**
   - Xem toàn bộ giao dịch, danh sách người dùng, thống kê hệ thống.
   - Tải xuống file đã giải mã.

---

## 🏗️ Kiến trúc hệ thống

```
Người dùng (Trình duyệt)
        │  HTTP (Port 5000)
        ▼
┌─────────────────────┐
│   Flask Web App     │  ← app.py
│  (Routes & Views)   │
└────────┬────────────┘
         │ Socket TCP localhost:9999
         ▼
┌─────────────────────┐      ┌──────────────────────────┐
│   Socket Server     │      │     Crypto Modules       │
│  (SocketServer)     │─────►│  ┌─ AESGCMHandler        │
│                     │      │  ├─ RSAHandler (2048)     │
│  1. Handshake       │      │  ├─ HMACHandler           │
│  2. Verify Manifest │      │  ├─ ReplayGuard           │
│  3. Verify Chunks   │      │  └─ FileProcessor         │
│  4. Reconstruct     │      └──────────────────────────┘
└─────────────────────┘
```

---

## 📁 Cấu trúc thư mục

```
BTL_NHẬP MÔN ATBMTT/
│
├── app.py                    # Ứng dụng chính: Flask routes + Socket Server
├── security_logger.py        # Module ghi nhật ký bảo mật
├── requirements.txt          # Danh sách thư viện Python
│
├── crypto/                   # Package mật mã học
│   ├── __init__.py
│   ├── aes_gcm_handler.py    # AES-256-GCM: mã hóa/giải mã chunk
│   ├── rsa_handler.py        # RSA-2048 OAEP (mã hóa) + PSS (ký số)
│   ├── hmac_handler.py       # HMAC-SHA256: xác thực thông điệp
│   ├── hash_handler.py       # SHA-512: hàm băm
│   ├── replay_guard.py       # Chống Replay Attack (nonce + timestamp)
│   ├── file_processor.py     # Chia/ghép file, tạo manifest, mã hóa chunk
│   └── des_handler.py        # DES/CBC (Legacy - chỉ để so sánh)
│
├── templates/                # Giao diện HTML
│   ├── base.html             # Layout chung
│   ├── index.html            # Trang chủ
│   ├── login.html            # Đăng nhập người dùng
│   ├── register.html         # Đăng ký người dùng
│   ├── dashboard.html        # Bảng điều khiển người dùng
│   ├── upload.html           # Upload & gửi file
│   ├── keys.html             # Quản lý khóa RSA-2048
│   ├── history.html          # Lịch sử giao dịch
│   ├── admin_login.html      # Đăng nhập admin
│   ├── admin_dashboard.html  # Bảng điều khiển admin
│   ├── admin_users.html      # Quản lý người dùng (admin)
│   └── admin_transactions.html  # Quản lý giao dịch (admin)
│
├── static/                   # Tài nguyên tĩnh (CSS, JS, hình ảnh)
│   └── images/
│
├── tests/                    # Kiểm thử tự động
│   └── test_security.py      # 16 test cases (Unit & Integration)
│
├── sample_data/              # Dữ liệu mẫu để test
│   └── assignment.txt
│
│   ── Các thư mục tự động tạo khi chạy (KHÔNG commit lên Git) ──
├── keys/                     # Khóa RSA hệ thống (tự sinh)
├── data/                     # users.json, transactions.json, admin.json
├── logs/                     # security.log
├── uploads/                  # File tạm khi upload
├── encrypted_files/          # File đã mã hóa (JSON)
└── decrypted_files/          # File đã giải mã
```

---

## 🚀 Hướng dẫn Cài đặt & Chạy

### 1. Yêu cầu hệ thống
- Python **3.11+**
- Hệ điều hành: Windows, macOS, hoặc Linux

### 2. Cài đặt thư viện

```bash
cd "BTL_NHẬP MÔN ATBMTT"
pip install -r requirements.txt
```

### 3. Khởi chạy ứng dụng

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

