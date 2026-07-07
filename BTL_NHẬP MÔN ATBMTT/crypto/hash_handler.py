"""
Hash Handler - Xử lý băm SHA-512
Thuật toán: SHA-512 cho kiểm tra tính toàn vẹn
"""

from Crypto.Hash import SHA512

class HashHandler:
    def __init__(self):
        self.algorithm = "SHA-512"
    
    def calculate_hash(self, data):
        """
        Tính hash SHA-512 của dữ liệu
        Args:
            data: bytes - Dữ liệu cần băm
        Returns:
            str - Hash dạng hex
        """
        hash_obj = SHA512.new(data)
        return hash_obj.hexdigest()
    
    def calculate_hash_bytes(self, data):
        """
        Tính hash SHA-512 của dữ liệu (trả về bytes)
        Args:
            data: bytes - Dữ liệu cần băm
        Returns:
            bytes - Hash dạng bytes
        """
        hash_obj = SHA512.new(data)
        return hash_obj.digest()
    
    def verify_hash(self, data, expected_hash):
        """
        Xác minh hash của dữ liệu
        Args:
            data: bytes - Dữ liệu gốc
            expected_hash: str - Hash mong đợi (hex)
        Returns:
            bool - True nếu hash khớp
        """
        calculated_hash = self.calculate_hash(data)
        return calculated_hash == expected_hash
    
    def calculate_part_hash(self, iv, ciphertext):
        """
        Tính hash cho một phần file theo đề: SHA-512(IV || ciphertext)
        Args:
            iv: bytes - IV của phần
            ciphertext: bytes - Ciphertext của phần
        Returns:
            str - Hash dạng hex
        """
        hash_data = iv + ciphertext
        return self.calculate_hash(hash_data)
    
    def verify_part_hash(self, iv, ciphertext, expected_hash):
        """
        Xác minh hash của một phần file
        Args:
            iv: bytes - IV của phần
            ciphertext: bytes - Ciphertext của phần
            expected_hash: str - Hash mong đợi (hex)
        Returns:
            bool - True nếu hash khớp
        """
        calculated_hash = self.calculate_part_hash(iv, ciphertext)
        return calculated_hash == expected_hash
    
    def create_hash_object(self, data):
        """
        Tạo hash object SHA-512 (dùng cho ký số)
        Args:
            data: bytes - Dữ liệu cần băm
        Returns:
            SHA512 object
        """
        return SHA512.new(data)