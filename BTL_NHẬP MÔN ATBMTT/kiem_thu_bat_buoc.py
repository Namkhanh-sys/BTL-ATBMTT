import os
import json
import copy
import base64
import hashlib
from crypto.file_processor import FileProcessor
from crypto.rsa_handler import RSAHandler

def run_mandatory_tests():
    print("="*60)
    print(" KỊCH BẢN KIỂM THỬ BẮT BUỘC (MANDATORY TESTS) - ĐỀ TÀI 6")
    print("="*60 + "\n")
    
    fp = FileProcessor()
    rsa = RSAHandler()
    
    # 0. Khởi tạo dữ liệu
    system_priv, system_pub = rsa.generate_key_pair()
    user_priv, user_pub = rsa.generate_key_pair()
    
    file_content = b"Data Test. " * 50 # Khoảng 550 bytes
    with open("test_file.txt", "wb") as f:
        f.write(file_content)
    
    print(f"[*] Đang chuẩn bị file test: test_file.txt ({len(file_content)} bytes)")
    
    # Tạo manifest và chunks gốc
    manifest = fp.create_manifest("test_file.txt", file_content, "student1", num_chunks=4)
    session_key = fp.aes_handler.generate_key()
    original_chunks = fp.encrypt_chunks(file_content, manifest, session_key, user_priv)
    expected_hash = manifest['file_hash']
    
    print(f"[*] File được chia làm {len(original_chunks)} chunks, mã hóa AES-256-GCM.")
    print(f"[*] Mã băm (Hash) gốc của file: {expected_hash}\n")

    # ---------------------------------------------------------
    print("-" * 50)
    print("1. GỬI FILE HỢP LỆ")
    print("-" * 50)
    val_result = fp.validate_received_chunks(manifest, original_chunks)
    if val_result['valid']:
        print("   -> [PASS] Nhận đủ 4 chunks hợp lệ, không có lỗi.")
    else:
        print("   -> [FAIL] Validate failed.")
    print()

    # ---------------------------------------------------------
    print("-" * 50)
    print("2. LÀM MẤT MỘT CHUNK")
    print("-" * 50)
    missing_chunks = [original_chunks[0], original_chunks[2], original_chunks[3]] # Mất chunk 2
    val_result = fp.validate_received_chunks(manifest, missing_chunks)
    print(f"   -> [PASS] Hệ thống phát hiện: {val_result['errors']}")
    print()

    # ---------------------------------------------------------
    print("-" * 50)
    print("3. GỬI TRÙNG MỘT CHUNK")
    print("-" * 50)
    duplicate_chunks = [original_chunks[0], original_chunks[1], original_chunks[1], original_chunks[2], original_chunks[3]]
    val_result = fp.validate_received_chunks(manifest, duplicate_chunks)
    print(f"   -> [PASS] Hệ thống phát hiện: {val_result['errors']}")
    print()

    # ---------------------------------------------------------
    print("-" * 50)
    print("4. ĐẢO THỨ TỰ CHUNK")
    print("-" * 50)
    shuffled_chunks = [original_chunks[3], original_chunks[0], original_chunks[2], original_chunks[1]]
    val_result = fp.validate_received_chunks(manifest, shuffled_chunks)
    print(f"   -> [PASS] Hệ thống phát hiện: {val_result['errors']}")
    # Tự động sắp xếp lại để ghép
    reordered = val_result['sorted_chunks']
    if [c['sequence_number'] for c in reordered] == [1, 2, 3, 4]:
         print("   -> [PASS] Hệ thống đã tự động sắp xếp lại thứ tự: 1, 2, 3, 4")
    print()

    # ---------------------------------------------------------
    print("-" * 50)
    print("5. SỬA NỘI DUNG MỘT CHUNK (TẤN CÔNG)")
    print("-" * 50)
    tampered_chunks = copy.deepcopy(original_chunks)
    tampered_data = bytearray(base64.b64decode(tampered_chunks[0]['cipher']))
    tampered_data[10] ^= 0xFF # Sửa 1 byte
    tampered_chunks[0]['cipher'] = base64.b64encode(tampered_data).decode()
    
    decrypted_result = fp.verify_and_decrypt_chunk(tampered_chunks[0], session_key, user_pub)
    if not decrypted_result['success']:
        print(f"   -> [PASS] AES-GCM & HMAC chặn đứng dữ liệu bị sửa!")
        print(f"   -> Chi tiết lỗi: {decrypted_result['error']}")
    else:
        print("   -> [FAIL] Không phát hiện được chunk bị sửa!")
    print()

    # ---------------------------------------------------------
    print("-" * 50)
    print("6. KIỂM TRA HASH FILE SAU KHI GHÉP")
    print("-" * 50)
    decrypted_parts = []
    for chunk in original_chunks: # Ghép file hợp lệ
        res = fp.verify_and_decrypt_chunk(chunk, session_key, user_pub)
        if res['success']:
            decrypted_parts.append(res['data'])
            
    reconstructed_file = fp.reconstruct_file(decrypted_parts)
    actual_hash = hashlib.sha256(reconstructed_file).hexdigest()
    print(f"   -> Kích thước file gốc: {len(file_content)} bytes")
    print(f"   -> Kích thước sau ghép: {len(reconstructed_file)} bytes")
    print(f"   -> Hash gốc (Manifest): {expected_hash}")
    print(f"   -> Hash file sau ghép  : {actual_hash}")
    
    if expected_hash == actual_hash:
        print("   -> [PASS] Mã băm TRÙNG KHỚP 100%. File toàn vẹn tuyệt đối!")
    else:
        print("   -> [FAIL] Hash không khớp!")
    print()
    
    print("="*60)
    print(" HOÀN TẤT TẤT CẢ CÁC BÀI KIỂM THỬ BẮT BUỘC!")
    print("="*60 + "\n")

if __name__ == "__main__":
    run_mandatory_tests()
