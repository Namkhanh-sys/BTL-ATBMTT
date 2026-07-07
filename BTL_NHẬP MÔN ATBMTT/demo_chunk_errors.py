import os
import json
import copy
from crypto.file_processor import FileProcessor
from crypto.rsa_handler import RSAHandler

def run_demo():
    print("=== DEMO: KIỂM TRA LỖI TRUYỀN TẢI CHUNK ===\n")
    
    fp = FileProcessor()
    rsa = RSAHandler()
    
    # 1. Khởi tạo dữ liệu giả lập
    system_priv, system_pub = rsa.generate_key_pair()
    user_priv, user_pub = rsa.generate_key_pair()
    
    file_content = b"Day la noi dung file rat quan trong can duoc bao mat tuyet doi. Bao gom 1234567890."
    with open("dummy.txt", "wb") as f:
        f.write(file_content)
    print(f"[*] Đang xử lý file mẫu: {len(file_content)} bytes")
    
    # 2. Xử lý file (tạo manifest, mã hóa thành các chunks)
    result = fp.process_file_for_sending(
        file_path="dummy.txt", 
        username="test_user", 
        system_public_key_pem=system_pub, 
        user_private_key_pem=user_priv
    )
    # Ghi đè file content vì process_file_for_sending đọc từ file, ta sửa lại manifest cho khớp
    # (Vì process_file_for_sending gọi open() nên trong demo ta làm cách gọn hơn: dùng hàm gốc)
    manifest = fp.create_manifest("dummy.txt", file_content, "test_user", num_chunks=4)
    session_key = fp.aes_handler.generate_key()
    original_chunks = fp.encrypt_chunks(file_content, manifest, session_key, user_priv)
    
    print(f"[*] Đã chia thành {len(original_chunks)} chunks (được mã hóa AES-GCM an toàn).\n")

    # --- KỊCH BẢN 1: BỊ ĐẢO THỨ TỰ ---
    print(">> KỊCH BẢN 1: Mạng bị lag, các chunk đến lộn xộn (đảo thứ tự)")
    shuffled_chunks = [original_chunks[3], original_chunks[0], original_chunks[2], original_chunks[1]]
    val_result = fp.validate_received_chunks(manifest, shuffled_chunks)
    print(f"   Kết quả kiểm tra: {val_result['errors']}\n")

    # --- KỊCH BẢN 2: THIẾU CHUNK ---
    print(">> KỊCH BẢN 2: Bị rớt mạng, mất chunk số 2")
    missing_chunks = [original_chunks[0], original_chunks[2], original_chunks[3]]
    val_result = fp.validate_received_chunks(manifest, missing_chunks)
    print(f"   Kết quả kiểm tra: {val_result['errors']}\n")

    # --- KỊCH BẢN 3: TRÙNG CHUNK ---
    print(">> KỊCH BẢN 3: Lỗi mạng gửi đúp chunk số 1")
    duplicate_chunks = [original_chunks[0], original_chunks[0], original_chunks[1], original_chunks[2], original_chunks[3]]
    val_result = fp.validate_received_chunks(manifest, duplicate_chunks)
    print(f"   Kết quả kiểm tra: {val_result['errors']}\n")

    # --- KỊCH BẢN 4: CHUNK BỊ SỬA ĐỔI (HACKER CAN THIỆP) ---
    print(">> KỊCH BẢN 4: Hacker bắt được chunk 1 và cố tình sửa nội dung")
    tampered_chunks = copy.deepcopy(original_chunks)
    
    # Giả vờ sửa 1 byte trong dữ liệu đã mã hóa của chunk 1
    import base64
    tampered_data = bytearray(base64.b64decode(tampered_chunks[0]['cipher']))
    tampered_data[5] = tampered_data[5] ^ 0xFF # Đảo bit làm sai lệch data
    tampered_chunks[0]['cipher'] = base64.b64encode(tampered_data).decode()
    
    # Thử giải mã chunk bị sửa
    decrypted_result = fp.verify_and_decrypt_chunk(tampered_chunks[0], session_key, user_pub)
    if not decrypted_result['success']:
        print(f"   AES-GCM chặn đứng! Không thể giải mã vì Tag không khớp: {decrypted_result['error']}\n")
    else:
        print("   Giải mã thành công (Lỗi! Đáng lẽ phải thất bại)")

if __name__ == "__main__":
    run_demo()
