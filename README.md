
# 🔐 Secure File Transfer System (Đề tài 6 Nâng cấp)

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.3.3-000000?style=flat&logo=flask&logoColor=white)
![AES-256-GCM](https://img.shields.io/badge/AES--256--GCM-✓-green?style=flat)
![RSA-2048](https://img.shields.io/badge/RSA--2048-OAEP%20%2B%20PSS-green?style=flat)
![bcrypt](https://img.shields.io/badge/Password-bcrypt%20cost%2012-green?style=flat)
![Tests](https://img.shields.io/badge/Tests-6%20kịch_bản-brightgreen?style=flat)

---

## 🎯 Giới thiệu bài toán

Hệ thống này được xây dựng để mô phỏng quy trình **gửi và nhận file an toàn** trong môi trường mạng hạn chế băng thông, được nâng cấp toàn diện theo yêu cầu bảo mật của **Đề tài 6: Secure Assignment Chunk Transfer - FIT4012**.

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

## ✨ Chức năng nền (Core Features)

| # | Chức năng | Mô tả |
|---|-----------|-------|
| 1 | **Chia file thành Chunks** | File được chia thành nhiều phần nhỏ linh hoạt để truyền qua mạng băng thông hẹp |
| 2 | **Gửi từng chunk qua Socket TCP** | Mỗi chunk được gửi riêng lẻ qua kết nối TCP thực sự (port 9999), mô phỏng môi trường mạng thực tế |
| 3 | **Ghép lại file hoàn chỉnh** | Server nhận đủ chunks, sắp xếp theo `sequence_number` và nối lại thành file gốc |
| 4 | **Kiểm tra file sau khi ghép** | So sánh SHA-256 hash của file ghép với hash gốc trong Manifest — đảm bảo toàn vẹn 100% |

---

## 🔒 Yêu cầu bảo mật đã đạt

| # | Yêu cầu | Trạng thái |
|---|---------|-----------|
| 1 | Mỗi chunk có `file_id`, `chunk_id`, `sequence_number`, `total_chunks`, `nonce`, `tag` | ✅ ĐẠT |
| 2 | Mỗi chunk được mã hóa & xác thực riêng biệt (AES-256-GCM + HMAC + RSA-PSS) | ✅ ĐẠT |
| 3 | Có Manifest mô tả toàn bộ file (file_hash, total_chunks, sender, timestamp) | ✅ ĐẠT |
| 4 | Phát hiện thiếu chunk, trùng chunk, đảo thứ tự, chunk bị sửa | ✅ ĐẠT |
| 5 | Cơ chế Resume — tự động yêu cầu gửi lại chunk bị thiếu | ✅ ĐẠT |

---

## 🧪 Kiểm thử bắt buộc (Mandatory Test Cases)

Hệ thống cung cấp **Bảng điều khiển kiểm thử** tại Admin Dashboard, cho phép chạy 6 kịch bản kiểm thử bắt buộc trên **file thật đã upload**.

| TC | Kịch bản | Kết quả mong đợi | Trạng thái |
|----|----------|-----------------|-----------|
| TC01 | Gửi file hợp lệ | `[PASS] Nhận đủ 3 chunks hợp lệ` | ✅ PASS |
| TC02 | Làm mất một chunk | `[FAIL] Thiếu chunk: [X]` — Hệ thống báo cụ thể chunk nào bị mất | ✅ PASS |
| TC03 | Gửi trùng một chunk | `[FAIL] Trùng chunk: [X]` — Lọc bỏ bản sao, giữ lại 1 | ✅ PASS |
| TC04 | Đảo thứ tự chunk | Phát hiện đảo thứ tự, tự sắp xếp lại `[1, 2, 3]` | ✅ PASS |
| TC05 | Sửa nội dung một chunk | `[FAIL] HMAC/AES-GCM chan dung — nội dung bị sửa đổi!` | ✅ PASS |
| TC06 | Kiểm tra hash file sau ghép | So sánh SHA-256 — Hash khớp 100% hoặc báo [FAIL] nếu sai | ✅ PASS |

### Định dạng gói tin Chunk (JSON)

```json
{
  "file_id": "<UUID>",
  "chunk_id": "<UUID>",
  "sequence_number": 1,
  "total_chunks": 3,
  "nonce": "<Base64>",
  "timestamp": "2026-07-07T08:37:39.605919+00:00",
  "cipher": "<Base64 — Nội dung mã hóa AES-256-GCM>",
  "tag": "<Base64 — Authentication Tag GCM>",
  "hmac": "<Hex — HMAC-SHA256 của chunk>",
  "sig": "<Base64 — Chữ ký RSA-PSS>"
}
```

### Định dạng Manifest mẫu

```json
{
  "manifest": {
    "file_id": "<UUID>",
    "original_filename": "File_Mau_Demo.txt",
    "total_chunks": 3,
    "total_size": 4000,
    "file_hash": "<SHA-256 của file gốc>",
    "sender": "namkhanh2",
    "nonce": "<Hex>",
    "timestamp": "2026-07-07T08:37:39.515000+00:00",
    "session_id": "<UUID>"
  },
  "manifest_signature": "<RSA-PSS Signature — Base64>",
  "encrypted_session_key": "<RSA-OAEP Encrypted AES Key — Base64>",
  "chunks": [ "...3 chunk objects..." ]
}
```

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
│  (Thread riêng)     │─────►│  ┌─ AESGCMHandler        │
│                     │      │  ├─ RSAHandler (2048)     │
│  1. Handshake       │      │  ├─ HMACHandler           │
│  2. Verify Manifest │      │  ├─ ReplayGuard           │
│  3. Verify Chunks   │      │  └─ FileProcessor         │
│  4. Reconstruct     │      └──────────────────────────┘
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│  Admin Dashboard    │  ← Bảng kiểm thử 6 kịch bản
│  /admin/tests       │     (Chạy trên file thật)
└─────────────────────┘
```

---

## 📁 Cấu trúc thư mục

```
BTL_NHẬP MÔN ATBMTT/
│
├── app.py                    # Ứng dụng chính: Flask routes + Socket Server + Test API
├── security_logger.py        # Module ghi nhật ký bảo mật
├── requirements.txt          # Danh sách thư viện Python
├── kiem_thu_bat_buoc.py      # Script kiểm thử CLI (6 kịch bản)
│
├── crypto/                   # Package mật mã học
│   ├── aes_gcm_handler.py    # AES-256-GCM: mã hóa/giải mã chunk
│   ├── rsa_handler.py        # RSA-2048 OAEP (mã hóa) + PSS (ký số)
│   ├── hmac_handler.py       # HMAC-SHA256: xác thực thông điệp
│   ├── hash_handler.py       # SHA-256: hàm băm
│   ├── replay_guard.py       # Chống Replay Attack (nonce + timestamp)
│   ├── file_processor.py     # Chia/ghép file, tạo manifest, mã hóa chunk
│   └── des_handler.py        # DES/CBC (Legacy - chỉ để so sánh)
│
├── templates/                # Giao diện HTML
│   ├── base.html             # Layout chung
│   ├── upload.html           # Upload & gửi file
│   ├── admin_dashboard.html  # Bảng điều khiển admin
│   ├── admin_tests.html      # 🆕 Trang kiểm thử 6 kịch bản bắt buộc
│   └── ...
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
# Windows
set PYTHONIOENCODING=utf-8
python app.py

# macOS / Linux
PYTHONIOENCODING=utf-8 python app.py
```

Ứng dụng sẽ tự động:
1. Tạo các thư mục lưu trữ cần thiết.
2. Tự động sinh khóa hệ thống RSA-2048 nếu chưa tồn tại.
3. Khởi chạy **Socket Server** chạy nền ở cổng `9999`.
4. Khởi chạy ứng dụng **Web Flask** ở địa chỉ: [http://localhost:5000](http://localhost:5000).

### 4. Chạy kiểm thử bắt buộc (qua Web)

1. Đăng nhập bằng tài khoản **Admin**
2. Vào **Admin Dashboard** → bấm **"Mở bảng Điều khiển Kiểm thử"**
3. Chọn file giao dịch đã upload từ dropdown
4. Bấm **"BẮT ĐẦU CHẠY KIỂM THỬ"** → 6 kịch bản chạy tự động và in kết quả ra màn hình

VIDEO DEMO: https://drive.google.com/file/d/1tQl1NqPBkKoC6bVBRXTee-yy52s45ABV/view
