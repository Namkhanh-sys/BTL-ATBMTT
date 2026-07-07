"""
Security Logger - Ghi log sự kiện bảo mật
NÂNG CẤP: Hoàn toàn mới - hệ thống cũ chỉ print() ra console

Yêu cầu đề bài (mục 4.5):
  - Ghi log: đăng nhập, tạo phiên, gửi/nhận, mã hóa/giải mã,
    xác minh chữ ký, lỗi toàn vẹn, lỗi quyền, hết hạn, replay
  - Log KHÔNG chứa: mật khẩu thô, khóa bí mật, dữ liệu nhạy cảm
"""

import logging
import os
from datetime import datetime


class SecurityLogger:
    """
    Logger chuyên dụng cho sự kiện bảo mật.
    Output: logs/security.log + console
    """

    # Event types
    LOGIN = "LOGIN"
    REGISTER = "REGISTER"
    LOGOUT = "LOGOUT"
    SESSION = "SESSION"
    UPLOAD_START = "UPLOAD_START"
    UPLOAD_COMPLETE = "UPLOAD_COMPLETE"
    CHUNK_SEND = "CHUNK_SEND"
    CHUNK_RECV = "CHUNK_RECV"
    CHUNK_VERIFY = "CHUNK_VERIFY"
    ENCRYPT = "ENCRYPT"
    DECRYPT = "DECRYPT"
    SIGN = "SIGN"
    VERIFY_SIG = "VERIFY_SIG"
    INTEGRITY_ERROR = "INTEGRITY_ERROR"
    ACCESS_DENIED = "ACCESS_DENIED"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    DUPLICATE_CHUNK = "DUPLICATE_CHUNK"
    MISSING_CHUNK = "MISSING_CHUNK"
    RESUME = "RESUME"
    KEY_GENERATE = "KEY_GENERATE"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    MANIFEST_CREATE = "MANIFEST_CREATE"
    MANIFEST_VERIFY = "MANIFEST_VERIFY"
    FILE_RECONSTRUCT = "FILE_RECONSTRUCT"
    HASH_MISMATCH = "HASH_MISMATCH"
    EXPIRED = "EXPIRED"
    HANDSHAKE = "HANDSHAKE"
    ERROR = "ERROR"

    def __init__(self, log_dir: str = "logs"):
        """
        Khởi tạo Security Logger.
        Args:
            log_dir: Thư mục chứa file log
        """
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "security.log")

        # Tạo logger riêng
        self.logger = logging.getLogger("SecurityLogger")
        self.logger.setLevel(logging.DEBUG)

        # Xóa handler cũ nếu có (tránh duplicate khi reload)
        self.logger.handlers.clear()

        # File handler
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # Format: [TIMESTAMP] [LEVEL] [EVENT_TYPE] detail
        formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)-7s] [%(event_type)-18s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def _log(self, level: int, event_type: str, message: str, **kwargs):
        """
        Ghi log internal.
        QUAN TRỌNG: Tự động lọc bỏ thông tin nhạy cảm.
        """
        # Lọc thông tin nhạy cảm
        safe_message = self._sanitize(message)
        extra = {'event_type': event_type}
        self.logger.log(level, safe_message, extra=extra)

    def _sanitize(self, message: str) -> str:
        """
        Lọc bỏ thông tin nhạy cảm khỏi log message.
        KHÔNG log: password, private key, secret key, token.
        """
        sensitive_keywords = [
            'password', 'private_key', 'secret_key', 'token',
            'session_key', 'private key', 'secret key'
        ]
        sanitized = message
        for keyword in sensitive_keywords:
            if keyword.lower() in sanitized.lower():
                # Tìm và che giấu giá trị
                import re
                # Che giấu giá trị sau dấu = hoặc :
                pattern = rf'({keyword}\s*[=:]\s*)\S+'
                sanitized = re.sub(pattern, rf'\1[REDACTED]', sanitized,
                                    flags=re.IGNORECASE)
        return sanitized

    # ─── Convenience methods ────────────────────────────────────────────────

    def info(self, event_type: str, message: str):
        """Log sự kiện ở mức INFO."""
        self._log(logging.INFO, event_type, message)

    def warning(self, event_type: str, message: str):
        """Log sự kiện ở mức WARNING."""
        self._log(logging.WARNING, event_type, message)

    def error(self, event_type: str, message: str):
        """Log sự kiện ở mức ERROR."""
        self._log(logging.ERROR, event_type, message)

    def critical(self, event_type: str, message: str):
        """Log sự kiện ở mức CRITICAL."""
        self._log(logging.CRITICAL, event_type, message)

    # ─── Sự kiện cụ thể ────────────────────────────────────────────────────

    def log_login(self, username: str, ip: str, success: bool):
        """Ghi log đăng nhập."""
        status = "SUCCESS" if success else "FAILED"
        self.info(self.LOGIN, f"user={username}, ip={ip} -> {status}")

    def log_register(self, username: str, email: str):
        """Ghi log đăng ký. Không log password."""
        self.info(self.REGISTER, f"user={username}, email={email}")

    def log_logout(self, username: str):
        """Ghi log đăng xuất."""
        self.info(self.LOGOUT, f"user={username}")

    def log_upload_start(self, username: str, filename: str, file_id: str,
                         chunks: int):
        """Ghi log bắt đầu upload."""
        self.info(self.UPLOAD_START,
                  f"user={username}, file={filename}, file_id={file_id}, chunks={chunks}")

    def log_upload_complete(self, username: str, file_id: str, success: bool,
                             error: str = None):
        """Ghi log hoàn thành upload."""
        if success:
            self.info(self.UPLOAD_COMPLETE,
                      f"file_id={file_id}, user={username} -> SUCCESS")
        else:
            self.error(self.UPLOAD_COMPLETE,
                       f"file_id={file_id}, user={username} -> FAILED: {error}")

    def log_chunk_received(self, file_id: str, seq: int, total: int,
                            verified: bool):
        """Ghi log nhận chunk."""
        status = "VERIFIED" if verified else "VERIFICATION_FAILED"
        self.info(self.CHUNK_RECV,
                  f"file_id={file_id}, chunk={seq}/{total} -> {status}")

    def log_replay_detected(self, nonce: str, source: str = "unknown"):
        """Ghi log phát hiện replay attack."""
        # Chỉ log 8 ký tự đầu của nonce
        nonce_short = nonce[:8] + "..." if len(nonce) > 8 else nonce
        self.warning(self.REPLAY_DETECTED,
                     f"nonce={nonce_short}, source={source}")

    def log_duplicate_chunk(self, file_id: str, chunk_id: str, seq: int):
        """Ghi log phát hiện chunk trùng."""
        self.warning(self.DUPLICATE_CHUNK,
                     f"file_id={file_id}, chunk_id={chunk_id}, seq={seq}")

    def log_missing_chunks(self, file_id: str, missing_seqs: list):
        """Ghi log chunk bị thiếu."""
        self.warning(self.MISSING_CHUNK,
                     f"file_id={file_id}, missing={missing_seqs}")

    def log_integrity_error(self, detail: str):
        """Ghi log lỗi toàn vẹn dữ liệu."""
        self.error(self.INTEGRITY_ERROR, detail)

    def log_access_denied(self, username: str, resource: str):
        """Ghi log lỗi quyền truy cập."""
        self.warning(self.ACCESS_DENIED,
                     f"user={username}, resource={resource}")

    def log_key_generate(self, username: str, key_type: str, key_size: int):
        """Ghi log tạo khóa. KHÔNG log giá trị khóa."""
        self.info(self.KEY_GENERATE,
                  f"user={username}, type={key_type}, size={key_size}bit")

    def log_handshake(self, address: str, success: bool):
        """Ghi log handshake."""
        status = "SUCCESS" if success else "FAILED"
        self.info(self.HANDSHAKE, f"addr={address} -> {status}")

    def log_manifest_verify(self, file_id: str, success: bool):
        """Ghi log xác minh manifest."""
        status = "VALID" if success else "INVALID"
        level = logging.INFO if success else logging.ERROR
        self._log(level, self.MANIFEST_VERIFY,
                  f"file_id={file_id} -> {status}")

    def log_hash_mismatch(self, file_id: str, expected: str, got: str):
        """Ghi log hash không khớp sau ghép file."""
        # Chỉ log 16 ký tự đầu
        self.error(self.HASH_MISMATCH,
                   f"file_id={file_id}, expected={expected[:16]}..., "
                   f"got={got[:16]}...")

    def log_file_reconstruct(self, file_id: str, filename: str, success: bool):
        """Ghi log ghép file."""
        status = "SUCCESS" if success else "FAILED"
        self.info(self.FILE_RECONSTRUCT,
                  f"file_id={file_id}, file={filename} -> {status}")
