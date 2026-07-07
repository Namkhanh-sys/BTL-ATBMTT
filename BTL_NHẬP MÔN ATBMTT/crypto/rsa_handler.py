"""
RSA Handler - NÂNG CẤP
Thay đổi so với hệ thống cũ:
  - RSA 1024-bit → RSA 2048-bit (NIST khuyến nghị tối thiểu 2048-bit)
  - PKCS#1 v1.5 encrypt → OAEP với SHA-256 (chống Bleichenbacher attack)
  - PKCS#1 v1.5 sign → PSS với SHA-256 (Probabilistic Signature Scheme, an toàn hơn)
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
import base64
import os


class RSAHandler:
    """
    RSA-2048 Handler với OAEP (mã hóa) và PSS (ký số).
    NÂNG CẤP từ RSA-1024 PKCS#1 v1.5 của hệ thống cũ.
    """

    KEY_SIZE = 2048  # NÂNG CẤP: 1024 → 2048 bit

    # ─── Giữ lại DES/legacy mode để minh họa thuật toán cũ ───
    LEGACY_KEY_SIZE = 1024  # Chỉ dùng cho demo/so sánh

    def generate_key_pair(self, key_size: int = None) -> tuple:
        """
        Tạo cặp khóa RSA.
        NÂNG CẤP: Mặc định 2048-bit thay vì 1024-bit.

        Args:
            key_size: Kích thước key (mặc định 2048)

        Returns:
            tuple: (private_key_pem: str, public_key_pem: str)
        """
        size = key_size or self.KEY_SIZE
        key = RSA.generate(size)
        private_key = key.export_key().decode()
        public_key = key.publickey().export_key().decode()
        return private_key, public_key

    def generate_legacy_key_pair(self) -> tuple:
        """
        Tạo cặp khóa RSA-1024 (LEGACY - chỉ dùng để minh họa thuật toán cũ).
        KHÔNG dùng cho production. Theo phép của đề: DES/RSA-1024 chỉ dùng
        trong 'chế độ minh họa thuật toán cũ hoặc chế độ so sánh legacy'.

        Returns:
            tuple: (private_key_pem: str, public_key_pem: str)
        """
        return self.generate_key_pair(key_size=self.LEGACY_KEY_SIZE)

    def import_key(self, key_data):
        """
        Import khóa từ PEM string hoặc bytes.
        Args:
            key_data: PEM string hoặc bytes
        Returns:
            RSA key object
        """
        if isinstance(key_data, str):
            key_data = key_data.encode()
        return RSA.import_key(key_data)

    # ─── MÃ HÓA / GIẢI MÃ (OAEP) ───────────────────────────────────────────

    def encrypt_session_key(self, session_key: bytes, public_key_pem: str) -> bytes:
        """
        Mã hóa session key bằng RSA-OAEP-SHA256.
        NÂNG CẤP: PKCS#1 v1.5 → OAEP (chống Bleichenbacher attack).

        Args:
            session_key: AES-256 key cần mã hóa (32 bytes)
            public_key_pem: Khóa công khai RSA dạng PEM

        Returns:
            bytes: Session key đã mã hóa
        """
        public_key = self.import_key(public_key_pem)
        # OAEP với SHA-256 thay vì PKCS#1 v1.5
        cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        return cipher_rsa.encrypt(session_key)

    def decrypt_session_key(self, encrypted_session_key: bytes,
                            private_key_pem: str) -> bytes:
        """
        Giải mã session key bằng RSA-OAEP-SHA256.
        NÂNG CẤP: PKCS#1 v1.5 → OAEP.

        Args:
            encrypted_session_key: Session key đã mã hóa
            private_key_pem: Khóa riêng RSA dạng PEM

        Returns:
            bytes: Session key gốc hoặc None nếu thất bại
        """
        try:
            private_key = self.import_key(private_key_pem)
            cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
            session_key = cipher_rsa.decrypt(encrypted_session_key)

            # Kiểm tra độ dài session key cho AES-256 (32 bytes)
            if session_key and len(session_key) == 32:
                return session_key

            # Tương thích ngược: AES-128 (16 bytes)
            if session_key and len(session_key) == 16:
                return session_key

            return None
        except Exception as e:
            print(f"RSA-OAEP decryption failed: {e}")
            return None

    # ─── KÝ SỐ / XÁC MINH (PSS) ───────────────────────────────────────────

    def sign_data(self, data: bytes, private_key_pem: str) -> bytes:
        """
        Ký số dữ liệu bằng RSA-PSS-SHA256.
        NÂNG CẤP: PKCS#1 v1.5 signing → PSS (Probabilistic Signature Scheme).

        Ưu điểm PSS:
        - Có salt ngẫu nhiên → mỗi lần ký khác nhau (probabilistic)
        - Chứng minh bảo mật chặt chẽ hơn PKCS#1 v1.5

        Args:
            data: Dữ liệu cần ký
            private_key_pem: Khóa riêng RSA dạng PEM

        Returns:
            bytes: Chữ ký số RSA-PSS
        """
        private_key = self.import_key(private_key_pem)
        hash_obj = SHA256.new(data)
        signature = pss.new(private_key).sign(hash_obj)
        return signature

    def verify_signature(self, data: bytes, signature: bytes,
                         public_key_pem: str) -> bool:
        """
        Xác minh chữ ký số RSA-PSS-SHA256.
        NÂNG CẤP: PKCS#1 v1.5 → PSS.

        Args:
            data: Dữ liệu gốc
            signature: Chữ ký số
            public_key_pem: Khóa công khai RSA dạng PEM

        Returns:
            bool: True nếu chữ ký hợp lệ
        """
        try:
            public_key = self.import_key(public_key_pem)
            hash_obj = SHA256.new(data)
            pss.new(public_key).verify(hash_obj, signature)
            return True
        except Exception as e:
            print(f"RSA-PSS signature verification failed: {e}")
            return False

    # ─── QUẢN LÝ KHÓA HỆ THỐNG ────────────────────────────────────────────

    def load_system_keys(self, keys_folder: str) -> tuple:
        """
        Load khóa hệ thống từ thư mục.
        Returns:
            tuple: (private_key_pem: str, public_key_pem: str)
        """
        private_key_path = os.path.join(keys_folder, 'system_private.pem')
        public_key_path = os.path.join(keys_folder, 'system_public.pem')

        with open(private_key_path, 'rb') as f:
            private_key = f.read().decode()
        with open(public_key_path, 'rb') as f:
            public_key = f.read().decode()

        return private_key, public_key

    def save_system_keys(self, keys_folder: str):
        """
        Tạo và lưu khóa hệ thống RSA-2048.
        NÂNG CẤP: Tạo RSA-2048 thay vì 1024-bit.
        """
        private_key_path = os.path.join(keys_folder, 'system_private.pem')
        public_key_path = os.path.join(keys_folder, 'system_public.pem')

        if not os.path.exists(private_key_path):
            private_key_pem, public_key_pem = self.generate_key_pair()  # 2048-bit

            with open(private_key_path, 'w') as f:
                f.write(private_key_pem)
            with open(public_key_path, 'w') as f:
                f.write(public_key_pem)

            print(f"System RSA-2048 keys generated and saved to {keys_folder}")
        else:
            # Kiểm tra xem key cũ có phải RSA-1024 không để cảnh báo
            with open(private_key_path, 'r') as f:
                existing_key_pem = f.read()
            try:
                existing_key = RSA.import_key(existing_key_pem)
                if existing_key.n.bit_length() < 2048:
                    print(f"WARNING: System key is only {existing_key.n.bit_length()}-bit. "
                          f"Delete {private_key_path} and restart to regenerate RSA-2048 key.")
            except Exception:
                pass