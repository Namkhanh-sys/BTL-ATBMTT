"""
Crypto Package - NÂNG CẤP
Export tất cả các handler mới và cũ.
"""

from .rsa_handler import RSAHandler
from .des_handler import DESHandler          # Legacy - giữ lại để so sánh
from .aes_gcm_handler import AESGCMHandler   # NÂNG CẤP: thay thế DES
from .hash_handler import HashHandler
from .hmac_handler import HMACHandler        # NÂNG CẤP: mới
from .replay_guard import ReplayGuard        # NÂNG CẤP: mới
from .file_processor import FileProcessor

__all__ = [
    'RSAHandler',
    'DESHandler',         # Legacy
    'AESGCMHandler',      # Mới
    'HashHandler',
    'HMACHandler',        # Mới
    'ReplayGuard',        # Mới
    'FileProcessor',
]