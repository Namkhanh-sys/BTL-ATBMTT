"""
DES Handler - Xử lý mã hóa và giải mã DES
Thuật toán: DES với CBC mode và PKCS#7 padding
"""

from Crypto.Cipher import DES
import secrets

class DESHandler:
    def __init__(self):
        self.key_size = 8  # DES key size: 8 bytes (64-bit, 56-bit effective)
        self.block_size = 8  # DES block size: 8 bytes
        self.mode = DES.MODE_CBC  # CBC mode theo đề
    
    def generate_session_key(self):
        """
        Tạo SessionKey ngẫu nhiên cho DES (8 bytes)
        Returns:
            bytes - SessionKey 8 bytes
        """
        return secrets.token_bytes(self.key_size)
    
    def generate_iv(self):
        """
        Tạo IV ngẫu nhiên cho DES (8 bytes)
        Returns:
            bytes - IV 8 bytes
        """
        return secrets.token_bytes(self.block_size)
    
    def add_pkcs7_padding(self, data):
        """
        Thêm PKCS#7 padding cho DES (block size = 8 bytes)
        Args:
            data: bytes - Dữ liệu cần padding
        Returns:
            bytes - Dữ liệu đã padding
        """
        pad_length = self.block_size - (len(data) % self.block_size)
        padding = bytes([pad_length] * pad_length)
        return data + padding
    
    def remove_pkcs7_padding(self, padded_data):
        """
        Loại bỏ PKCS#7 padding
        Args:
            padded_data: bytes - Dữ liệu đã padding
        Returns:
            bytes - Dữ liệu gốc
        """
        if len(padded_data) == 0:
            return padded_data
        
        pad_length = padded_data[-1]
        
        # Kiểm tra tính hợp lệ của padding
        if pad_length > self.block_size or pad_length == 0:
            return padded_data
        
        # Kiểm tra tất cả bytes padding có giống nhau không
        for i in range(pad_length):
            if padded_data[-(i+1)] != pad_length:
                return padded_data
        
        return padded_data[:-pad_length]
    
    def encrypt(self, plaintext, session_key, iv=None):
        """
        Mã hóa dữ liệu bằng DES/CBC
        Args:
            plaintext: bytes - Dữ liệu cần mã hóa
            session_key: bytes - SessionKey DES (8 bytes)
            iv: bytes - IV (8 bytes), tự động tạo nếu None
        Returns:
            tuple - (iv, ciphertext)
        """
        if iv is None:
            iv = self.generate_iv()
        
        # Thêm padding
        padded_plaintext = self.add_pkcs7_padding(plaintext)
        
        # Mã hóa bằng DES/CBC
        cipher = DES.new(session_key, self.mode, iv)
        ciphertext = cipher.encrypt(padded_plaintext)
        
        return iv, ciphertext
    
    def decrypt(self, ciphertext, session_key, iv):
        """
        Giải mã dữ liệu bằng DES/CBC
        Args:
            ciphertext: bytes - Dữ liệu đã mã hóa
            session_key: bytes - SessionKey DES (8 bytes)
            iv: bytes - IV (8 bytes)
        Returns:
            bytes - Dữ liệu gốc hoặc None nếu thất bại
        """
        try:
            # Giải mã bằng DES/CBC
            cipher = DES.new(session_key, self.mode, iv)
            padded_plaintext = cipher.decrypt(ciphertext)
            
            # Loại bỏ padding
            plaintext = self.remove_pkcs7_padding(padded_plaintext)
            
            return plaintext
        except Exception as e:
            print(f"DES decryption failed: {e}")
            return None
    
    def encrypt_file_part(self, file_part, session_key):
        """
        Mã hóa một phần file
        Args:
            file_part: bytes - Phần file cần mã hóa
            session_key: bytes - SessionKey DES
        Returns:
            tuple - (iv, ciphertext)
        """
        return self.encrypt(file_part, session_key)
    
    def decrypt_file_part(self, ciphertext, session_key, iv):
        """
        Giải mã một phần file
        Args:
            ciphertext: bytes - Phần file đã mã hóa
            session_key: bytes - SessionKey DES
            iv: bytes - IV
        Returns:
            bytes - Phần file gốc
        """
        return self.decrypt(ciphertext, session_key, iv)