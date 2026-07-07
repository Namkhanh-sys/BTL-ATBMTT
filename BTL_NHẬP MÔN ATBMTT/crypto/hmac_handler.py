"""
HMAC Handler - Xác thực thông điệp bằng HMAC-SHA256
NÂNG CẤP: Thêm mới - hệ thống cũ không có HMAC

HMAC (Hash-based Message Authentication Code) khác với SHA-512 thuần:
- SHA-512 thuần: Ai cũng có thể tính lại hash → không xác thực được nguồn gửi
- HMAC-SHA256: Cần biết secret key → xác thực được nguồn gửi và toàn vẹn
"""

import hmac
import hashlib
import secrets


class HMACHandler:
    """
    HMAC-SHA256 cho xác thực thông điệp.
    Dùng cho: xác thực từng chunk, xác thực manifest, verify session.
    """

    HASH_ALGO = 'sha256'
    DIGEST_SIZE = 32  # SHA-256 = 32 bytes = 256 bits

    def generate_hmac_key(self, key_size: int = 32) -> bytes:
        """
        Tạo HMAC key ngẫu nhiên.
        Args:
            key_size: Kích thước key tính bằng bytes (mặc định 32 = 256-bit)
        Returns:
            bytes: HMAC key ngẫu nhiên
        """
        return secrets.token_bytes(key_size)

    def compute(self, data: bytes, key: bytes) -> bytes:
        """
        Tính HMAC-SHA256 của dữ liệu.
        NÂNG CẤP: Thay thế SHA-512 thuần (không có key) trong hash_handler.

        Args:
            data: Dữ liệu cần xác thực
            key: HMAC secret key

        Returns:
            bytes: HMAC-SHA256 digest (32 bytes)
        """
        mac = hmac.new(key, data, hashlib.sha256)
        return mac.digest()

    def compute_hex(self, data: bytes, key: bytes) -> str:
        """
        Tính HMAC-SHA256 và trả về dạng hex string.
        Args:
            data: Dữ liệu cần xác thực
            key: HMAC secret key
        Returns:
            str: HMAC-SHA256 dạng hex
        """
        return self.compute(data, key).hex()

    def verify(self, data: bytes, key: bytes, expected_hmac: bytes) -> bool:
        """
        Xác minh HMAC-SHA256 của dữ liệu.
        Dùng hmac.compare_digest() để tránh timing attack.

        Args:
            data: Dữ liệu cần kiểm tra
            key: HMAC secret key
            expected_hmac: HMAC mong đợi (bytes)

        Returns:
            bool: True nếu HMAC hợp lệ
        """
        computed = self.compute(data, key)
        # compare_digest: constant-time comparison, chống timing attack
        return hmac.compare_digest(computed, expected_hmac)

    def verify_hex(self, data: bytes, key: bytes, expected_hmac_hex: str) -> bool:
        """
        Xác minh HMAC-SHA256 với expected_hmac ở dạng hex.
        Args:
            data: Dữ liệu cần kiểm tra
            key: HMAC secret key
            expected_hmac_hex: HMAC mong đợi (hex string)
        Returns:
            bool: True nếu HMAC hợp lệ
        """
        try:
            expected_bytes = bytes.fromhex(expected_hmac_hex)
            return self.verify(data, key, expected_bytes)
        except (ValueError, TypeError):
            return False

    def compute_chunk_hmac(self, chunk_metadata: dict, ciphertext: bytes,
                           nonce: bytes, tag: bytes, key: bytes) -> str:
        """
        Tính HMAC cho một chunk dựa trên toàn bộ nội dung.
        Bảo vệ: file_id, chunk_id, sequence_number, ciphertext, nonce, tag.

        Args:
            chunk_metadata: Dict chứa file_id, chunk_id, seq_num, total_chunks
            ciphertext: Nội dung mã hóa của chunk
            nonce: Nonce AES-GCM
            tag: Authentication tag AES-GCM
            key: HMAC key (session key hoặc derived key)

        Returns:
            str: HMAC hex string
        """
        import json
        # Kết hợp tất cả dữ liệu quan trọng để xác thực
        data_parts = [
            chunk_metadata.get('file_id', '').encode(),
            chunk_metadata.get('chunk_id', '').encode(),
            str(chunk_metadata.get('sequence_number', 0)).encode(),
            str(chunk_metadata.get('total_chunks', 0)).encode(),
            nonce,
            tag,
            ciphertext
        ]
        combined = b'||'.join(data_parts)
        return self.compute_hex(combined, key)
