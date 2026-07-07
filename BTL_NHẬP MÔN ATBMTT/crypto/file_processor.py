"""
File Processor - NÂNG CẤP cho Đề tài 6: Secure Assignment Chunk Transfer
Thay đổi so với hệ thống cũ:
  1. Chunk có đầy đủ: file_id, chunk_id, sequence_number, total_chunks, nonce, tag
  2. Manifest mô tả toàn bộ file (chunk list, hash, ký số)
  3. Phát hiện: thiếu chunk, trùng chunk, đảo thứ tự, chunk bị sửa
  4. Cơ chế resume: gửi lại chunk bị thiếu
  5. AES-256-GCM thay DES, RSA-2048/PSS thay RSA-1024/PKCS#1v1.5
"""

import os
import json
import base64
import secrets
import uuid
import hashlib
from datetime import datetime, timezone
from .aes_gcm_handler import AESGCMHandler
from .rsa_handler import RSAHandler
from .hmac_handler import HMACHandler
from .hash_handler import HashHandler


class FileProcessor:
    """
    Xử lý chia file, tạo manifest, mã hóa/giải mã chunk.
    NÂNG CẤP: Toàn bộ cấu trúc chunk và manifest theo yêu cầu Đề tài 6.
    """

    def __init__(self):
        self.aes_handler = AESGCMHandler()
        self.rsa_handler = RSAHandler()
        self.hmac_handler = HMACHandler()
        self.hash_handler = HashHandler()
        self.default_chunks = 3  # Mặc định chia 3 phần

    # ─── CHIA FILE ──────────────────────────────────────────────────────────

    def split_file(self, file_content: bytes, num_chunks: int = None) -> list:
        """
        Chia file thành nhiều chunk.
        Args:
            file_content: Nội dung file gốc (bytes)
            num_chunks: Số chunk (mặc định 3)
        Returns:
            list[bytes]: Danh sách các chunk
        """
        n = num_chunks or self.default_chunks
        chunk_size = len(file_content) // n
        chunks = []
        for i in range(n):
            if i == n - 1:
                chunks.append(file_content[i * chunk_size:])
            else:
                chunks.append(file_content[i * chunk_size:(i + 1) * chunk_size])
        return chunks

    def reconstruct_file(self, decrypted_chunks: list) -> bytes:
        """
        Ghép các chunk đã giải mã thành file hoàn chỉnh.
        Args:
            decrypted_chunks: Danh sách chunk đã giải mã (theo thứ tự)
        Returns:
            bytes: File hoàn chỉnh
        """
        return b''.join(decrypted_chunks)

    # ─── MANIFEST ───────────────────────────────────────────────────────────

    def create_manifest(self, filename: str, file_content: bytes,
                        sender: str, num_chunks: int = None) -> dict:
        """
        Tạo manifest mô tả toàn bộ file.
        NÂNG CẤP: Hệ thống cũ chỉ có metadata đơn giản, nay có manifest đầy đủ.

        Manifest chứa:
        - file_id: UUID duy nhất cho file
        - original_filename: Tên file gốc
        - total_chunks: Số chunk
        - total_size: Kích thước file gốc
        - file_hash: SHA-256 của file gốc (để verify sau ghép)
        - sender: Người gửi
        - nonce: Nonce chống replay cho manifest
        - timestamp: Thời gian tạo (ISO 8601 UTC)
        - session_id: ID phiên truyền file
        - chunks[]: Mảng thông tin từng chunk

        Args:
            filename: Tên file gốc
            file_content: Nội dung file gốc
            sender: Tên người gửi
            num_chunks: Số chunk

        Returns:
            dict: Manifest
        """
        n = num_chunks or self.default_chunks
        file_id = str(uuid.uuid4())
        session_id = secrets.token_hex(16)
        file_hash = hashlib.sha256(file_content).hexdigest()

        # Chia file để tính hash từng chunk
        chunks = self.split_file(file_content, n)
        chunks_info = []
        for i, chunk in enumerate(chunks):
            chunk_id = str(uuid.uuid4())
            chunk_hash = hashlib.sha256(chunk).hexdigest()
            chunks_info.append({
                'chunk_id': chunk_id,
                'sequence_number': i + 1,
                'size': len(chunk),
                'chunk_hash': chunk_hash
            })

        manifest = {
            'file_id': file_id,
            'original_filename': filename,
            'total_chunks': n,
            'total_size': len(file_content),
            'file_hash': file_hash,
            'sender': sender,
            'nonce': secrets.token_hex(16),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'session_id': session_id,
            'chunks': chunks_info
        }

        return manifest

    def sign_manifest(self, manifest: dict, private_key_pem: str) -> bytes:
        """
        Ký manifest bằng RSA-PSS-SHA256.
        NÂNG CẤP: PSS thay PKCS#1 v1.5.

        Args:
            manifest: Manifest dict
            private_key_pem: Khóa riêng RSA

        Returns:
            bytes: Chữ ký manifest
        """
        manifest_str = json.dumps(manifest, sort_keys=True)
        manifest_bytes = manifest_str.encode('utf-8')
        return self.rsa_handler.sign_data(manifest_bytes, private_key_pem)

    def verify_manifest_signature(self, manifest: dict, signature: bytes,
                                   public_key_pem: str) -> bool:
        """
        Xác minh chữ ký manifest bằng RSA-PSS-SHA256.
        Args:
            manifest: Manifest dict
            signature: Chữ ký bytes
            public_key_pem: Khóa công khai RSA
        Returns:
            bool: True nếu hợp lệ
        """
        manifest_str = json.dumps(manifest, sort_keys=True)
        manifest_bytes = manifest_str.encode('utf-8')
        return self.rsa_handler.verify_signature(manifest_bytes, signature, public_key_pem)

    # Giữ tương thích với code cũ
    def verify_metadata_signature(self, metadata, signature, public_key_pem):
        """Tương thích ngược: alias cho verify_manifest_signature."""
        return self.verify_manifest_signature(metadata, signature, public_key_pem)

    # ─── MÃ HÓA CHUNK ─────────────────────────────────────────────────────

    def encrypt_chunks(self, file_content: bytes, manifest: dict,
                       session_key: bytes, private_key_pem: str) -> list:
        """
        Mã hóa và ký số các chunk theo cấu trúc Đề tài 6.

        NÂNG CẤP: Mỗi chunk có đầy đủ:
          file_id, chunk_id, sequence_number, total_chunks,
          nonce, timestamp, cipher, tag, hmac, sig

        Args:
            file_content: Nội dung file gốc
            manifest: Manifest đã tạo
            session_key: AES-256 session key (32 bytes)
            private_key_pem: Khóa riêng RSA để ký

        Returns:
            list[dict]: Danh sách chunk đã mã hóa
        """
        chunks = self.split_file(file_content, manifest['total_chunks'])
        encrypted_chunks = []

        for i, chunk_data in enumerate(chunks):
            chunk_info = manifest['chunks'][i]

            # Associated Authenticated Data (AAD) cho AES-GCM
            aad = json.dumps({
                'file_id': manifest['file_id'],
                'chunk_id': chunk_info['chunk_id'],
                'sequence_number': chunk_info['sequence_number'],
                'total_chunks': manifest['total_chunks']
            }, sort_keys=True).encode('utf-8')

            # Mã hóa chunk bằng AES-256-GCM
            enc_result = self.aes_handler.encrypt_chunk(chunk_data, session_key,
                                                         associated_data=aad)

            nonce_b64 = base64.b64encode(enc_result['nonce']).decode()
            cipher_b64 = base64.b64encode(enc_result['ciphertext']).decode()
            tag_b64 = base64.b64encode(enc_result['tag']).decode()

            # Tính HMAC-SHA256 cho toàn bộ chunk
            chunk_meta = {
                'file_id': manifest['file_id'],
                'chunk_id': chunk_info['chunk_id'],
                'sequence_number': chunk_info['sequence_number'],
                'total_chunks': manifest['total_chunks']
            }
            hmac_hex = self.hmac_handler.compute_chunk_hmac(
                chunk_meta, enc_result['ciphertext'],
                enc_result['nonce'], enc_result['tag'], session_key
            )

            # Ký toàn bộ chunk bằng RSA-PSS
            data_to_sign = (enc_result['nonce'] + enc_result['ciphertext'] +
                            enc_result['tag'] + bytes.fromhex(hmac_hex))
            signature = self.rsa_handler.sign_data(data_to_sign, private_key_pem)
            sig_b64 = base64.b64encode(signature).decode()

            # Tạo gói chunk đầy đủ theo yêu cầu Đề tài 6
            encrypted_chunk = {
                'file_id': manifest['file_id'],
                'chunk_id': chunk_info['chunk_id'],
                'sequence_number': chunk_info['sequence_number'],
                'total_chunks': manifest['total_chunks'],
                'nonce': nonce_b64,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'cipher': cipher_b64,
                'tag': tag_b64,
                'hmac': hmac_hex,
                'sig': sig_b64
            }

            encrypted_chunks.append(encrypted_chunk)
            print(f"  Chunk {i+1}/{manifest['total_chunks']} encrypted: "
                  f"size={len(chunk_data)}B, cipher={len(enc_result['ciphertext'])}B")

        return encrypted_chunks

    # ─── GIẢI MÃ CHUNK ────────────────────────────────────────────────────

    def verify_and_decrypt_chunk(self, chunk: dict, session_key: bytes,
                                  public_key_pem: str) -> dict:
        """
        Xác minh và giải mã một chunk.

        Quy trình verify:
        1. Kiểm tra HMAC-SHA256 (xác thực nguồn + toàn vẹn)
        2. Kiểm tra RSA-PSS signature (xác thực người ký)
        3. Giải mã AES-GCM (tag tự động verify toàn vẹn)

        Args:
            chunk: Dict chunk đã mã hóa
            session_key: AES-256 session key
            public_key_pem: Khóa công khai RSA để verify

        Returns:
            dict: {'success': bool, 'data': bytes or None, 'error': str or None}
        """
        try:
            nonce = base64.b64decode(chunk['nonce'])
            ciphertext = base64.b64decode(chunk['cipher'])
            tag = base64.b64decode(chunk['tag'])
            hmac_hex = chunk['hmac']
            signature = base64.b64decode(chunk['sig'])

            # 1. Verify HMAC
            chunk_meta = {
                'file_id': chunk['file_id'],
                'chunk_id': chunk['chunk_id'],
                'sequence_number': chunk['sequence_number'],
                'total_chunks': chunk['total_chunks']
            }
            expected_hmac = self.hmac_handler.compute_chunk_hmac(
                chunk_meta, ciphertext, nonce, tag, session_key
            )
            if expected_hmac != hmac_hex:
                return {'success': False, 'data': None,
                        'error': f'HMAC verification failed (chunk seq={chunk["sequence_number"]})'}

            # 2. Verify RSA-PSS signature
            data_to_verify = nonce + ciphertext + tag + bytes.fromhex(hmac_hex)
            if not self.rsa_handler.verify_signature(data_to_verify, signature, public_key_pem):
                return {'success': False, 'data': None,
                        'error': f'RSA-PSS signature failed (chunk seq={chunk["sequence_number"]})'}

            # 3. Decrypt AES-GCM (tag verify tích hợp)
            aad = json.dumps({
                'file_id': chunk['file_id'],
                'chunk_id': chunk['chunk_id'],
                'sequence_number': chunk['sequence_number'],
                'total_chunks': chunk['total_chunks']
            }, sort_keys=True).encode('utf-8')

            plaintext = self.aes_handler.decrypt_chunk(ciphertext, session_key, nonce, tag,
                                                        associated_data=aad)

            return {'success': True, 'data': plaintext, 'error': None}

        except ValueError as e:
            return {'success': False, 'data': None, 'error': str(e)}
        except Exception as e:
            return {'success': False, 'data': None, 'error': f'Unexpected error: {str(e)}'}

    # ─── XỬ LÝ NHẬN CHUNKS (phát hiện thiếu/trùng/đảo thứ tự) ──────────

    def validate_received_chunks(self, manifest: dict, received_chunks: list) -> dict:
        """
        Validate tập hợp chunk nhận được dựa trên manifest.

        NÂNG CẤP: Hệ thống cũ không có phát hiện lỗi chunk.
        Phát hiện:
        - Thiếu chunk
        - Trùng chunk
        - Đảo thứ tự → tự sắp xếp

        Args:
            manifest: Manifest gốc
            received_chunks: Danh sách chunk đã nhận

        Returns:
            dict: {
                'valid': bool,
                'missing': list[int],     # sequence_numbers thiếu
                'duplicates': list[int],  # sequence_numbers bị trùng
                'out_of_order': bool,     # có đảo thứ tự không
                'sorted_chunks': list,    # chunks đã sắp xếp đúng thứ tự
                'errors': list[str]
            }
        """
        total = manifest['total_chunks']
        expected_seq = set(range(1, total + 1))
        received_seq = [c['sequence_number'] for c in received_chunks]

        # Tìm trùng
        seen = set()
        duplicates = []
        for seq in received_seq:
            if seq in seen:
                duplicates.append(seq)
            seen.add(seq)

        # Tìm thiếu
        missing = sorted(expected_seq - seen)

        # Kiểm tra thứ tự
        unique_seq = []
        for seq in received_seq:
            if seq not in [s for s in unique_seq]:
                unique_seq.append(seq)
        out_of_order = unique_seq != sorted(unique_seq)

        # Lọc bỏ duplicate và sắp xếp
        unique_chunks = {}
        for chunk in received_chunks:
            seq = chunk['sequence_number']
            if seq not in unique_chunks:
                unique_chunks[seq] = chunk
        sorted_chunks = [unique_chunks[s] for s in sorted(unique_chunks.keys())]

        errors = []
        if missing:
            errors.append(f"Thiếu chunk: {missing}")
        if duplicates:
            errors.append(f"Trùng chunk: {duplicates}")
        if out_of_order:
            errors.append("Chunk bị đảo thứ tự (đã tự sắp xếp lại)")

        valid = len(missing) == 0

        return {
            'valid': valid,
            'missing': missing,
            'duplicates': duplicates,
            'out_of_order': out_of_order,
            'sorted_chunks': sorted_chunks,
            'errors': errors
        }

    def get_missing_chunks(self, manifest: dict, received_chunks: list) -> list:
        """
        Lấy danh sách chunk bị thiếu (cho cơ chế resume).

        Args:
            manifest: Manifest gốc
            received_chunks: Danh sách chunk đã nhận

        Returns:
            list[dict]: Danh sách thông tin chunk cần gửi lại
        """
        result = self.validate_received_chunks(manifest, received_chunks)
        missing_info = []
        for seq in result['missing']:
            chunk_info = manifest['chunks'][seq - 1]
            missing_info.append({
                'sequence_number': seq,
                'chunk_id': chunk_info['chunk_id'],
                'size': chunk_info['size']
            })
        return missing_info

    # ─── QUY TRÌNH ĐẦY ĐỦ ─────────────────────────────────────────────────

    def process_file_for_sending(self, file_path: str, username: str,
                                  system_public_key_pem: str,
                                  user_private_key_pem: str) -> dict:
        """
        Xử lý file để gửi (toàn bộ quy trình nâng cấp).

        Quy trình:
        1. Đọc file → tạo manifest
        2. Ký manifest bằng RSA-PSS
        3. Tạo AES-256 session key → mã hóa bằng RSA-OAEP
        4. Chia file → mã hóa chunk bằng AES-GCM + HMAC + RSA-PSS
        5. Trả về manifest + chunks

        Args:
            file_path: Đường dẫn file gốc
            username: Tên người gửi
            system_public_key_pem: Khóa công khai hệ thống (để mã hóa session key)
            user_private_key_pem: Khóa riêng người gửi (để ký)

        Returns:
            dict: Kết quả xử lý
        """
        try:
            # Đọc file
            with open(file_path, 'rb') as f:
                file_content = f.read()

            filename = os.path.basename(file_path)
            print(f"Processing file: {filename} ({len(file_content)} bytes)")

            # 1. Tạo manifest
            manifest = self.create_manifest(filename, file_content, username)
            print(f"  Manifest created: file_id={manifest['file_id']}, "
                  f"chunks={manifest['total_chunks']}")

            # 2. Ký manifest
            manifest_signature = self.sign_manifest(manifest, user_private_key_pem)
            print(f"  Manifest signed (RSA-PSS-SHA256)")

            # 3. Tạo AES-256 session key
            session_key = self.aes_handler.generate_key()  # 32 bytes

            # 4. Mã hóa session key bằng RSA-OAEP
            encrypted_session_key = self.rsa_handler.encrypt_session_key(
                session_key, system_public_key_pem
            )
            print(f"  Session key encrypted (RSA-2048-OAEP)")

            # 5. Mã hóa chunks
            encrypted_chunks = self.encrypt_chunks(
                file_content, manifest, session_key, user_private_key_pem
            )

            return {
                'success': True,
                'manifest': manifest,
                'manifest_signature': manifest_signature,
                'encrypted_session_key': encrypted_session_key,
                'encrypted_parts': encrypted_chunks,  # tương thích tên cũ
                'metadata': manifest,                 # tương thích tên cũ
                'metadata_signature': manifest_signature,
                'username': username
            }

        except Exception as e:
            print(f"File processing failed: {e}")
            return {'success': False, 'error': str(e)}

    def process_received_file(self, manifest: dict, manifest_signature: bytes,
                               encrypted_session_key: bytes, encrypted_chunks: list,
                               username: str, system_private_key_pem: str,
                               user_public_key_pem: str) -> dict:
        """
        Xử lý file nhận được (toàn bộ quy trình).

        Quy trình:
        1. Verify manifest signature (RSA-PSS)
        2. Decrypt session key (RSA-OAEP)
        3. Validate chunks (thiếu/trùng/đảo)
        4. Verify + decrypt từng chunk (HMAC + AES-GCM)
        5. Ghép file + verify hash

        Args:
            manifest: Manifest
            manifest_signature: Chữ ký manifest
            encrypted_session_key: Session key đã mã hóa
            encrypted_chunks: Các chunk đã mã hóa
            username: Tên người gửi
            system_private_key_pem: Khóa riêng hệ thống
            user_public_key_pem: Khóa công khai người gửi

        Returns:
            dict: {'success': bool, 'file_content': bytes, ...}
        """
        try:
            # 1. Verify manifest
            if not self.verify_manifest_signature(manifest, manifest_signature,
                                                   user_public_key_pem):
                return {'success': False, 'error': 'Invalid manifest signature'}

            # 2. Decrypt session key
            session_key = self.rsa_handler.decrypt_session_key(
                encrypted_session_key, system_private_key_pem
            )
            if not session_key:
                return {'success': False, 'error': 'Cannot decrypt session key'}

            # 3. Validate chunks
            validation = self.validate_received_chunks(manifest, encrypted_chunks)
            if not validation['valid']:
                return {
                    'success': False,
                    'error': f'Chunk validation failed: {validation["errors"]}',
                    'missing': validation['missing']
                }

            # 4. Decrypt sorted chunks
            sorted_chunks = validation['sorted_chunks']
            decrypted_parts = []
            for chunk in sorted_chunks:
                result = self.verify_and_decrypt_chunk(chunk, session_key,
                                                       user_public_key_pem)
                if not result['success']:
                    return {'success': False, 'error': result['error']}
                decrypted_parts.append(result['data'])

            # 5. Reconstruct + verify hash
            complete_file = self.reconstruct_file(decrypted_parts)
            file_hash = hashlib.sha256(complete_file).hexdigest()
            if file_hash != manifest['file_hash']:
                return {'success': False,
                        'error': f'File hash mismatch after reconstruction! '
                                 f'Expected: {manifest["file_hash"]}, Got: {file_hash}'}

            return {
                'success': True,
                'file_content': complete_file,
                'manifest': manifest,
                'username': username,
                'file_hash': file_hash
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}