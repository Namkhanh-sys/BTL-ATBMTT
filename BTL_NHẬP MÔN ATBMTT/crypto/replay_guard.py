"""
Replay Guard - Chống tấn công gửi lại (Replay Attack)
NÂNG CẤP: Hoàn toàn mới - hệ thống cũ không có cơ chế chống replay

Hệ thống cũ: Attacker chụp gói tin hợp lệ → gửi lại → server chấp nhận ❌
Hệ thống mới:
  1. Nonce: mỗi chunk có nonce ngẫu nhiên, lưu danh sách đã dùng
  2. Timestamp: từ chối gói tin cũ hơn MAX_AGE_SECONDS
  3. (chunk_id, sequence_number): tracking chunk đã nhận
"""

import threading
import time
from datetime import datetime, timezone
from typing import Set, Dict, Tuple


class ReplayGuard:
    """
    Bảo vệ chống Replay Attack.

    Cơ chế hoạt động:
    - Lưu tất cả nonce đã nhận trong NONCE_TTL giây
    - Kiểm tra timestamp của gói tin không được quá cũ
    - Tự động dọn dẹp nonce hết hạn (cleanup thread)
    """

    MAX_AGE_SECONDS = 300    # Gói tin tối đa 5 phút tuổi
    NONCE_TTL = 600          # Lưu nonce 10 phút (> MAX_AGE để đảm bảo không miss)
    CLEANUP_INTERVAL = 60    # Dọn dẹp mỗi 60 giây

    def __init__(self):
        # Dict: nonce_hex -> expiry_timestamp
        self._seen_nonces: Dict[str, float] = {}
        # Set: (file_id, chunk_id) đã nhận
        self._received_chunks: Set[Tuple[str, str]] = set()
        self._lock = threading.Lock()

        # Khởi động cleanup thread
        self._start_cleanup_thread()

    def _start_cleanup_thread(self):
        """Khởi động thread tự động dọn dẹp nonce hết hạn."""
        def cleanup_loop():
            while True:
                time.sleep(self.CLEANUP_INTERVAL)
                self._cleanup_expired_nonces()

        t = threading.Thread(target=cleanup_loop, daemon=True)
        t.start()

    def _cleanup_expired_nonces(self):
        """Xóa các nonce đã hết TTL."""
        now = time.time()
        with self._lock:
            expired = [n for n, exp in self._seen_nonces.items() if exp < now]
            for n in expired:
                del self._seen_nonces[n]

    def check_nonce(self, nonce_hex: str) -> bool:
        """
        Kiểm tra nonce có bị dùng lại không.

        Args:
            nonce_hex: Nonce dạng hex string

        Returns:
            bool: True nếu nonce HỢP LỆ (chưa dùng), False nếu đã dùng (replay)
        """
        with self._lock:
            if nonce_hex in self._seen_nonces:
                return False  # Nonce đã dùng → replay attack

            # Đăng ký nonce với thời gian hết hạn
            self._seen_nonces[nonce_hex] = time.time() + self.NONCE_TTL
            return True

    def check_timestamp(self, timestamp_iso: str) -> bool:
        """
        Kiểm tra timestamp của gói tin.
        Từ chối gói tin cũ hơn MAX_AGE_SECONDS.

        Args:
            timestamp_iso: Timestamp dạng ISO 8601 (UTC hoặc local)

        Returns:
            bool: True nếu timestamp HỢP LỆ (trong phạm vi cho phép)
        """
        try:
            # Parse timestamp
            if timestamp_iso.endswith('Z'):
                ts = datetime.fromisoformat(timestamp_iso.replace('Z', '+00:00'))
            else:
                ts = datetime.fromisoformat(timestamp_iso)

            # Chuẩn hóa về UTC-aware
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            age_seconds = abs((now - ts).total_seconds())

            return age_seconds <= self.MAX_AGE_SECONDS

        except (ValueError, TypeError):
            return False  # Timestamp không hợp lệ → từ chối

    def check_chunk_duplicate(self, file_id: str, chunk_id: str) -> bool:
        """
        Kiểm tra chunk có bị gửi trùng không.

        Args:
            file_id: ID của file
            chunk_id: ID của chunk

        Returns:
            bool: True nếu chunk là MỚI (chưa nhận), False nếu trùng
        """
        key = (file_id, chunk_id)
        with self._lock:
            if key in self._received_chunks:
                return False  # Chunk đã nhận → duplicate
            self._received_chunks.add(key)
            return True

    def validate_chunk(self, chunk_data: dict) -> dict:
        """
        Validate toàn bộ một chunk packet.
        Kiểm tra: nonce, timestamp, duplicate.

        Args:
            chunk_data: Dict chứa 'nonce', 'timestamp', 'file_id', 'chunk_id'

        Returns:
            dict: {'valid': bool, 'reason': str}
        """
        nonce = chunk_data.get('nonce', '')
        timestamp = chunk_data.get('timestamp', '')
        file_id = chunk_data.get('file_id', '')
        chunk_id = chunk_data.get('chunk_id', '')

        # Kiểm tra nonce
        if not nonce:
            return {'valid': False, 'reason': 'Thiếu nonce'}

        if not self.check_nonce(nonce):
            return {'valid': False, 'reason': f'REPLAY ATTACK: nonce đã được dùng trước đó'}

        # Kiểm tra timestamp
        if not timestamp:
            return {'valid': False, 'reason': 'Thiếu timestamp'}

        if not self.check_timestamp(timestamp):
            return {'valid': False, 'reason': f'Gói tin quá cũ (> {self.MAX_AGE_SECONDS}s) hoặc timestamp không hợp lệ'}

        # Kiểm tra duplicate chunk
        if file_id and chunk_id:
            if not self.check_chunk_duplicate(file_id, chunk_id):
                return {'valid': False, 'reason': f'DUPLICATE: chunk {chunk_id} đã nhận trước đó'}

        return {'valid': True, 'reason': 'OK'}

    def validate_metadata(self, metadata: dict) -> dict:
        """
        Validate metadata packet (handshake).
        Args:
            metadata: Dict chứa 'nonce', 'timestamp', 'session_id'
        Returns:
            dict: {'valid': bool, 'reason': str}
        """
        nonce = metadata.get('nonce', '')
        timestamp = metadata.get('timestamp', '')

        if not nonce or not self.check_nonce(nonce):
            return {'valid': False, 'reason': 'REPLAY: metadata nonce đã dùng hoặc thiếu'}

        if not timestamp or not self.check_timestamp(timestamp):
            return {'valid': False, 'reason': f'Metadata timestamp quá cũ hoặc không hợp lệ'}

        return {'valid': True, 'reason': 'OK'}

    def reset_file_chunks(self, file_id: str):
        """
        Xóa trạng thái các chunk của file (dùng khi resume).
        Args:
            file_id: ID của file cần reset
        """
        with self._lock:
            to_remove = {k for k in self._received_chunks if k[0] == file_id}
            self._received_chunks -= to_remove
