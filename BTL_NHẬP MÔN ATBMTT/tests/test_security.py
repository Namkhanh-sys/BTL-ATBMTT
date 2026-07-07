import pytest
import os
import json
import base64
import time
import secrets
from datetime import datetime, timezone, timedelta
from crypto.aes_gcm_handler import AESGCMHandler
from crypto.rsa_handler import RSAHandler
from crypto.hmac_handler import HMACHandler
from crypto.replay_guard import ReplayGuard
from crypto.file_processor import FileProcessor

# 1. Test AES-GCM encryption/decryption
def test_aes_gcm_encrypt_decrypt():
    handler = AESGCMHandler()
    key = handler.generate_key()
    plaintext = b"Hello, this is a secret assignment chunk!"
    aad = b"associated metadata details"
    
    # Encrypt
    result = handler.encrypt(plaintext, key, aad=aad)
    assert 'nonce' in result
    assert 'ciphertext' in result
    assert 'tag' in result
    assert len(result['nonce']) == 12
    assert len(result['tag']) == 16
    
    # Decrypt
    decrypted = handler.decrypt(result['ciphertext'], key, result['nonce'], result['tag'], aad=aad)
    assert decrypted == plaintext

# 2. Test AES-GCM data modification fails
def test_aes_gcm_modified_data_fails():
    handler = AESGCMHandler()
    key = handler.generate_key()
    plaintext = b"Original plaintext data"
    aad = b"some AAD"
    
    result = handler.encrypt(plaintext, key, aad=aad)
    
    # Modify ciphertext
    modified_ciphertext = bytearray(result['ciphertext'])
    modified_ciphertext[0] ^= 0xFF
    
    with pytest.raises(ValueError, match="AES-GCM authentication failed"):
        handler.decrypt(bytes(modified_ciphertext), key, result['nonce'], result['tag'], aad=aad)
        
    # Modify AAD
    with pytest.raises(ValueError, match="AES-GCM authentication failed"):
        handler.decrypt(result['ciphertext'], key, result['nonce'], result['tag'], aad=b"different AAD")

# 3. Test AES-GCM invalid key size
def test_aes_gcm_invalid_key():
    handler = AESGCMHandler()
    invalid_key = b"short_key_16_bytes"
    plaintext = b"plaintext"
    
    with pytest.raises(ValueError, match="Key phải là 32 bytes"):
        handler.encrypt(plaintext, invalid_key)

# 4. Test RSA-2048 Key Pair Generation
def test_rsa_key_generation():
    handler = RSAHandler()
    private_key, public_key = handler.generate_key_pair()
    assert "BEGIN RSA PRIVATE KEY" in private_key
    assert "BEGIN PUBLIC KEY" in public_key
    
    # Verify key size
    rsa_key = handler.import_key(private_key)
    assert rsa_key.n.bit_length() >= 2048

# 5. Test RSA-OAEP encrypt/decrypt of session key
def test_rsa_oaep_encrypt_decrypt():
    handler = RSAHandler()
    private_key, public_key = handler.generate_key_pair()
    session_key = os.urandom(32)
    
    encrypted = handler.encrypt_session_key(session_key, public_key)
    decrypted = handler.decrypt_session_key(encrypted, private_key)
    assert decrypted == session_key

# 6. Test RSA-PSS signing and verification
def test_rsa_pss_sign_verify():
    handler = RSAHandler()
    private_key, public_key = handler.generate_key_pair()
    data = b"Verify this signature with RSA-PSS"
    
    sig = handler.sign_data(data, private_key)
    assert len(sig) == 256 # For 2048-bit key, signature is 256 bytes
    
    valid = handler.verify_signature(data, sig, public_key)
    assert valid is True

# 7. Test RSA-PSS incorrect / modified signatures
def test_rsa_pss_invalid_signature():
    handler = RSAHandler()
    private_key, public_key = handler.generate_key_pair()
    data = b"Original data"
    
    sig = handler.sign_data(data, private_key)
    
    # Modified data
    assert handler.verify_signature(b"Modified data", sig, public_key) is False
    
    # Modified signature
    modified_sig = bytearray(sig)
    modified_sig[0] ^= 0xFF
    assert handler.verify_signature(data, bytes(modified_sig), public_key) is False

# 8. Test HMAC-SHA256
def test_hmac_sha256_compute_verify():
    handler = HMACHandler()
    key = handler.generate_hmac_key()
    data = b"Chunk payload data to authenticate"
    
    mac = handler.compute(data, key)
    assert len(mac) == 32
    
    assert handler.verify(data, key, mac) is True
    assert handler.verify(data + b"extra", key, mac) is False
    
    wrong_key = handler.generate_hmac_key()
    assert handler.verify(data, wrong_key, mac) is False

# 9. Test ReplayGuard Nonce reuse detection
def test_replay_guard_nonce():
    guard = ReplayGuard()
    nonce1 = secrets.token_hex(16)
    
    assert guard.check_nonce(nonce1) is True
    assert guard.check_nonce(nonce1) is False # Reused nonce must be rejected

# 10. Test ReplayGuard Timestamp age
def test_replay_guard_timestamp():
    guard = ReplayGuard()
    
    # Valid recent timestamp
    recent_ts = datetime.now(timezone.utc).isoformat()
    assert guard.check_timestamp(recent_ts) is True
    
    # Old timestamp (> 5 minutes ago)
    old_ts = (datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat()
    assert guard.check_timestamp(old_ts) is False
    
    # Future timestamp (should also be protected or evaluated, within limits)
    future_ts = (datetime.now(timezone.utc) + timedelta(minutes=6)).isoformat()
    assert guard.check_timestamp(future_ts) is False

# 11. Test ReplayGuard duplicate chunks
def test_replay_guard_duplicate_chunk():
    guard = ReplayGuard()
    file_id = "test-file-uuid"
    chunk_id = "chunk-1"
    
    assert guard.check_chunk_duplicate(file_id, chunk_id) is True
    assert guard.check_chunk_duplicate(file_id, chunk_id) is False # Duplicate rejected

# 12. Test FileProcessor complete pipeline (split, encrypt, sign, verify, reconstruct)
def test_file_processor_pipeline():
    fp = FileProcessor()
    private_key, public_key = fp.rsa_handler.generate_key_pair()
    session_key = fp.aes_handler.generate_key()
    
    original_content = b"This is a relatively large file content that will be split into multiple chunks and then processed."
    filename = "test_assignment.zip"
    sender = "student_user"
    
    # Create manifest
    manifest = fp.create_manifest(filename, original_content, sender, num_chunks=3)
    assert manifest['total_chunks'] == 3
    assert manifest['original_filename'] == filename
    
    # Sign manifest
    sig = fp.sign_manifest(manifest, private_key)
    assert fp.verify_manifest_signature(manifest, sig, public_key) is True
    
    # Encrypt chunks
    enc_chunks = fp.encrypt_chunks(original_content, manifest, session_key, private_key)
    assert len(enc_chunks) == 3
    
    # Verify and decrypt chunks
    decrypted_chunks = []
    for chunk in enc_chunks:
        chunk_result = fp.verify_and_decrypt_chunk(chunk, session_key, public_key)
        assert chunk_result['success'] is True
        decrypted_chunks.append(chunk_result['data'])
        
    reconstructed = fp.reconstruct_file(decrypted_chunks)
    assert reconstructed == original_content


# 13. Test integration pipeline with missing chunk
def test_pipeline_missing_chunk():
    fp = FileProcessor()
    private_key, public_key = fp.rsa_handler.generate_key_pair()
    session_key = fp.aes_handler.generate_key()
    original_content = b"This content will be split into three chunks but one will be lost."
    manifest = fp.create_manifest("assignment.txt", original_content, "student_user", num_chunks=3)
    enc_chunks = fp.encrypt_chunks(original_content, manifest, session_key, private_key)
    
    # Remove one chunk (e.g. index 1)
    incomplete_chunks = [enc_chunks[0], enc_chunks[2]]
    
    # Validate chunks
    validation = fp.validate_received_chunks(manifest, incomplete_chunks)
    assert validation['valid'] is False
    assert 2 in validation['missing']
    assert len(validation['missing']) == 1
    assert "Thiếu chunk: [2]" in validation['errors'][0]


# 14. Test integration pipeline with out-of-order chunks
def test_pipeline_out_of_order_chunks():
    fp = FileProcessor()
    private_key, public_key = fp.rsa_handler.generate_key_pair()
    session_key = fp.aes_handler.generate_key()
    original_content = b"Chunks of this file will be received out of order but sorted correctly."
    manifest = fp.create_manifest("assignment.txt", original_content, "student_user", num_chunks=3)
    enc_chunks = fp.encrypt_chunks(original_content, manifest, session_key, private_key)
    
    # Shuffle chunks: [chunk 3, chunk 1, chunk 2]
    shuffled_chunks = [enc_chunks[2], enc_chunks[0], enc_chunks[1]]
    
    # Validate chunks
    validation = fp.validate_received_chunks(manifest, shuffled_chunks)
    assert validation['out_of_order'] is True
    assert validation['valid'] is True # True because all chunks are present, just out of order
    
    # Verify we can decrypt sorted chunks and reconstruct original content
    decrypted_chunks = []
    for chunk in validation['sorted_chunks']:
        chunk_result = fp.verify_and_decrypt_chunk(chunk, session_key, public_key)
        assert chunk_result['success'] is True
        decrypted_chunks.append(chunk_result['data'])
        
    reconstructed = fp.reconstruct_file(decrypted_chunks)
    assert reconstructed == original_content


# 15. Test integration pipeline with duplicate chunks
def test_pipeline_duplicate_chunks():
    fp = FileProcessor()
    private_key, public_key = fp.rsa_handler.generate_key_pair()
    session_key = fp.aes_handler.generate_key()
    original_content = b"This content will have duplicate chunks sent to the receiver."
    manifest = fp.create_manifest("assignment.txt", original_content, "student_user", num_chunks=3)
    enc_chunks = fp.encrypt_chunks(original_content, manifest, session_key, private_key)
    
    # Duplicate chunk 2: [chunk 1, chunk 2, chunk 2, chunk 3]
    duplicated_list = [enc_chunks[0], enc_chunks[1], enc_chunks[1], enc_chunks[2]]
    
    # Validate chunks
    validation = fp.validate_received_chunks(manifest, duplicated_list)
    assert 2 in validation['duplicates']
    assert validation['valid'] is True # Since all chunks are still present (1, 2, 3), it's valid for reconstruction
    
    # Verify we can decrypt sorted chunks (with duplicates filtered out)
    decrypted_chunks = []
    for chunk in validation['sorted_chunks']:
        chunk_result = fp.verify_and_decrypt_chunk(chunk, session_key, public_key)
        assert chunk_result['success'] is True
        decrypted_chunks.append(chunk_result['data'])
        
    reconstructed = fp.reconstruct_file(decrypted_chunks)
    assert reconstructed == original_content


# 16. Test integration pipeline with reconstructed file hash mismatch
def test_pipeline_hash_mismatch():
    fp = FileProcessor()
    user_private, user_public = fp.rsa_handler.generate_key_pair()
    system_private, system_public = fp.rsa_handler.generate_key_pair()
    
    original_content = b"Original content that will have hash checked."
    
    # Process file for sending
    temp_file = "temp_test_hash.txt"
    with open(temp_file, "wb") as f:
        f.write(original_content)
        
    try:
        send_data = fp.process_file_for_sending(temp_file, "student_user", system_public, user_private)
        assert send_data['success'] is True
        
        # Modify the manifest's file_hash to cause a mismatch
        malicious_manifest = send_data['manifest'].copy()
        malicious_manifest['file_hash'] = "0" * 64
        
        # We need a new signature for the modified manifest, otherwise signature verification will fail first
        malicious_sig = fp.sign_manifest(malicious_manifest, user_private)
        
        # Attempt to process received file with modified manifest hash
        recv_result = fp.process_received_file(
            malicious_manifest,
            malicious_sig,
            send_data['encrypted_session_key'],
            send_data['encrypted_parts'],
            "student_user",
            system_private,
            user_public
        )
        
        assert recv_result['success'] is False
        assert "File hash mismatch" in recv_result['error']
        
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)

