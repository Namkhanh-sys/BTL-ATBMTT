"""
AES-GCM Handler - Mã hóa xác thực AES-256-GCM
NÂNG CẤP: Thay thế DES/CBC (yếu, 56-bit) bằng AES-256-GCM (256-bit, AEAD)

Ưu điểm AES-GCM so với DES/CBC:
- Key 256-bit thay vì 56-bit effective của DES
- Tích hợp Authentication Tag (không cần hash riêng)
- Chống tampering tích hợp (AEAD - Authenticated Encryption with Associated Data)
- Nonce 96-bit ngẫu nhiên thay vì IV 64-bit của DES
"""

from Crypto.Cipher import AES
import secrets


class AESGCMHandler:
    """
    AES-256-GCM Handler
    - Key size: 32 bytes (256 bits)
    - Nonce size: 12 bytes (96 bits) - chuẩn GCM
    - Tag size: 16 bytes (128 bits) - xác thực dữ liệu
    """

    KEY_SIZE = 32    # 256-bit AES key
    NONCE_SIZE = 12  # 96-bit nonce (chuẩn GCM)
    TAG_SIZE = 16    # 128-bit authentication tag

    def generate_key(self):
        """
        Tạo AES-256 key ngẫu nhiên (32 bytes).
        Thay thế DESHandler.generate_session_key() (8 bytes, yếu).
        Returns:
            bytes: 32-byte AES key
        """
        return secrets.token_bytes(self.KEY_SIZE)

    def generate_nonce(self):
        """
        Tạo nonce ngẫu nhiên 12 bytes (96-bit) cho GCM.
        Mỗi nonce chỉ được dùng MỘT LẦN với cùng một key.
        Returns:
            bytes: 12-byte nonce
        """
        return secrets.token_bytes(self.NONCE_SIZE)

    def encrypt(self, plaintext: bytes, key: bytes, aad: bytes = None) -> dict:
        """
        Mã hóa dữ liệu bằng AES-256-GCM.
        NÂNG CẤP: Thay thế DES.encrypt() - tích hợp xác thực tag.

        Args:
            plaintext: Dữ liệu cần mã hóa
            key: AES-256 key (32 bytes)
            aad: Additional Authenticated Data (tùy chọn, không bị mã hóa nhưng được xác thực)

        Returns:
            dict: {'nonce': bytes, 'ciphertext': bytes, 'tag': bytes}

        Raises:
            ValueError: Nếu key không đúng kích thước
        """
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key phải là {self.KEY_SIZE} bytes (AES-256), nhận {len(key)} bytes")

        nonce = self.generate_nonce()
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        if aad:
            cipher.update(aad)

        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        return {
            'nonce': nonce,
            'ciphertext': ciphertext,
            'tag': tag
        }

    def decrypt(self, ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes,
                aad: bytes = None) -> bytes:
        """
        Giải mã và xác thực dữ liệu AES-256-GCM.
        NÂNG CẤP: Tự động verify tag - phát hiện dữ liệu bị sửa đổi.

        Args:
            ciphertext: Dữ liệu đã mã hóa
            key: AES-256 key (32 bytes)
            nonce: Nonce 12 bytes
            tag: Authentication tag 16 bytes
            aad: Additional Authenticated Data (phải khớp với lúc mã hóa)

        Returns:
            bytes: Dữ liệu gốc

        Raises:
            ValueError: Nếu xác thực tag thất bại (dữ liệu bị sửa đổi)
        """
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key phải là {self.KEY_SIZE} bytes (AES-256)")

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        if aad:
            cipher.update(aad)

        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext
        except ValueError:
            # Tag không khớp → dữ liệu bị sửa đổi hoặc key sai
            raise ValueError("AES-GCM authentication failed: dữ liệu bị sửa đổi hoặc key không đúng")

    def encrypt_chunk(self, chunk_data: bytes, key: bytes, associated_data: bytes = None) -> dict:
        """
        Mã hóa một chunk file.
        Thay thế DESHandler.encrypt_file_part().

        Args:
            chunk_data: Nội dung chunk cần mã hóa
            key: AES-256 session key
            associated_data: Dữ liệu liên kết (ví dụ: chunk metadata JSON)

        Returns:
            dict: {'nonce': bytes, 'ciphertext': bytes, 'tag': bytes}
        """
        return self.encrypt(chunk_data, key, aad=associated_data)

    def decrypt_chunk(self, ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes,
                      associated_data: bytes = None) -> bytes:
        """
        Giải mã một chunk file.
        Thay thế DESHandler.decrypt_file_part().

        Args:
            ciphertext: Nội dung chunk đã mã hóa
            key: AES-256 session key
            nonce: Nonce của chunk
            tag: Authentication tag của chunk
            associated_data: Dữ liệu liên kết (phải khớp với lúc mã hóa)

        Returns:
            bytes: Nội dung chunk gốc

        Raises:
            ValueError: Nếu chunk bị sửa đổi hoặc key sai
        """
        return self.decrypt(ciphertext, key, nonce, tag, aad=associated_data)
