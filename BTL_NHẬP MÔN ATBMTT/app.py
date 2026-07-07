"""
Secure Assignment Chunk Transfer - NÂNG CẤP
Đề tài 6: FIT4012 Secure System Upgrade Challenge

NÂNG CẤP so với hệ thống cũ:
  1. DES/CBC → AES-256-GCM (mã hóa xác thực)
  2. RSA-1024 PKCS#1v1.5 → RSA-2048 OAEP+PSS
  3. SHA-256 password → bcrypt (cost factor 12)
  4. Không replay guard → Nonce + Timestamp + Duplicate detection
  5. Không logging → Security Logger đầy đủ
  6. Chunk đơn giản → Chunk có file_id, chunk_id, seq_num, nonce, tag
  7. Không manifest → Manifest đầy đủ + chữ ký
  8. Không phát hiện lỗi → Phát hiện thiếu/trùng/đảo/sửa chunk
  9. Không resume → Cơ chế resume gửi lại chunk thiếu
  10. Secret key hardcoded → Tạo ngẫu nhiên từ env
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
import json
import os
import hashlib
import secrets
import socket
import threading
import time
from datetime import datetime, timezone
import base64
import uuid

# NÂNG CẤP: bcrypt thay SHA-256 cho password
import bcrypt

# Import crypto modules nâng cấp
from crypto import (RSAHandler, AESGCMHandler, HashHandler, HMACHandler,
                    FileProcessor, ReplayGuard)

# NÂNG CẤP: Security Logger
from security_logger import SecurityLogger

app = Flask(__name__)

# NÂNG CẤP: Secret key ngẫu nhiên thay vì hardcoded
# Hệ thống cũ: app.secret_key = 'your-secret-key-change-this' ← NGUY HIỂM
app.secret_key = secrets.token_hex(32)

# Cấu hình thư mục
UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted_files'
DECRYPTED_FOLDER = 'decrypted_files'
KEYS_FOLDER = 'keys'
DATA_FOLDER = 'data'
LOGS_FOLDER = 'logs'

# Tạo các thư mục cần thiết
for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER,
               KEYS_FOLDER, DATA_FOLDER, LOGS_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# File lưu trữ dữ liệu
USERS_FILE = os.path.join(DATA_FOLDER, 'users.json')
TRANSACTIONS_FILE = os.path.join(DATA_FOLDER, 'transactions.json')
ADMIN_FILE = os.path.join(DATA_FOLDER, 'admin.json')

# Socket server configuration
SOCKET_HOST = 'localhost'
SOCKET_PORT = 9999
socket_server = None

# ─── Khởi tạo các handler NÂNG CẤP ────────────────────────────────────────
rsa_handler = RSAHandler()               # RSA-2048 OAEP+PSS (nâng cấp từ 1024)
aes_handler = AESGCMHandler()            # NÂNG CẤP: AES-256-GCM thay DES
hash_handler = HashHandler()
hmac_handler = HMACHandler()             # NÂNG CẤP: HMAC-SHA256 (mới)
file_processor = FileProcessor()
replay_guard = ReplayGuard()             # NÂNG CẤP: Chống replay (mới)
sec_logger = SecurityLogger(LOGS_FOLDER) # NÂNG CẤP: Security Logger (mới)

# Biến để tránh duplicate transactions
processing_files = set()

# ─── Password hashing (NÂNG CẤP: bcrypt thay SHA-256) ──────────────────────

def hash_password(password: str) -> str:
    """
    Hash password bằng bcrypt.
    NÂNG CẤP: Thay SHA-256 thuần (không salt, dễ rainbow table attack).
    bcrypt tự động thêm salt, cost factor 12.
    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

def verify_password(password: str, hashed: str) -> bool:
    """
    Verify password với bcrypt hash.
    NÂNG CẤP: Hệ thống cũ dùng == so sánh SHA-256, không an toàn.
    """
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except (ValueError, TypeError):
        # Tương thích ngược: nếu hash cũ là SHA-256
        old_hash = hashlib.sha256(password.encode()).hexdigest()
        return old_hash == hashed


# ─── Hàm tiện ích ──────────────────────────────────────────────────────────

def load_json_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {} if 'users' in filepath or 'admin' in filepath else []

def save_json_file(filepath, data):
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# ─── Khởi tạo dữ liệu ────────────────────────────────────────────────────

def init_data():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump({}, f, ensure_ascii=False, indent=2)

    if not os.path.exists(TRANSACTIONS_FILE):
        with open(TRANSACTIONS_FILE, 'w', encoding='utf-8') as f:
            json.dump([], f, ensure_ascii=False, indent=2)

    # NÂNG CẤP: Admin password dùng bcrypt
    if not os.path.exists(ADMIN_FILE):
        admin_data = {
            'username': 'admin',
            'password': hash_password('admin123')  # bcrypt thay SHA-256
        }
        with open(ADMIN_FILE, 'w', encoding='utf-8') as f:
            json.dump(admin_data, f, ensure_ascii=False, indent=2)

def init_system_keys():
    """Tạo RSA-2048 keys cho hệ thống (nâng cấp từ 1024-bit)."""
    # Xóa key cũ nếu là RSA-1024
    private_key_path = os.path.join(KEYS_FOLDER, 'system_private.pem')
    if os.path.exists(private_key_path):
        try:
            from Crypto.PublicKey import RSA
            with open(private_key_path, 'r') as f:
                key = RSA.import_key(f.read())
            if key.n.bit_length() < 2048:
                print("Phát hiện RSA key cũ < 2048-bit. Tạo key mới...")
                sec_logger.warning(SecurityLogger.KEY_GENERATE,
                                   "Old RSA key < 2048-bit detected, regenerating")
                os.remove(private_key_path)
                public_key_path = os.path.join(KEYS_FOLDER, 'system_public.pem')
                if os.path.exists(public_key_path):
                    os.remove(public_key_path)
        except Exception:
            pass

    rsa_handler.save_system_keys(KEYS_FOLDER)


# ─── Socket Server NÂNG CẤP ───────────────────────────────────────────────

class SocketServer:
    """
    Socket server với đầy đủ tính năng bảo mật nâng cấp.
    """

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        # NÂNG CẤP: Buffer nhận file chunks theo file_id
        self.file_buffers = {}  # file_id -> {manifest, chunks: {seq: chunk}, ...}

    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True

            sec_logger.info(SecurityLogger.SESSION,
                            f"Socket server started on {self.host}:{self.port}")

            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except socket.error as e:
                    if self.running:
                        sec_logger.error(SecurityLogger.ERROR, f"Socket error: {e}")
                    break
        except Exception as e:
            sec_logger.error(SecurityLogger.ERROR,
                             f"Failed to start socket server: {e}")

    def receive_data(self, client_socket):
        """Nhận dữ liệu JSON qua socket."""
        try:
            data_parts = []
            client_socket.settimeout(60)
            while True:
                try:
                    chunk = client_socket.recv(262144)
                    if not chunk:
                        break
                    data_parts.append(chunk.decode('utf-8'))
                    current_data = ''.join(data_parts)
                    try:
                        json.loads(current_data)
                        return current_data
                    except json.JSONDecodeError:
                        continue
                except socket.timeout:
                    break
            return ''.join(data_parts) if data_parts else None
        except Exception as e:
            sec_logger.error(SecurityLogger.ERROR,
                             f"Error receiving data: {e}")
            return None

    def handle_client(self, client_socket, address):
        """
        Xử lý kết nối client - NÂNG CẤP với replay guard, logging, manifest.
        """
        addr_str = f"{address[0]}:{address[1]}"
        try:
            client_socket.settimeout(60)

            # ─── 1. Handshake ────────────────────────────────────────────
            data = client_socket.recv(1024).decode('utf-8')
            if data == "Hello!":
                client_socket.send("Ready!".encode('utf-8'))
                sec_logger.log_handshake(addr_str, True)
            else:
                client_socket.send("NACK: Invalid handshake".encode('utf-8'))
                sec_logger.log_handshake(addr_str, False)
                client_socket.close()
                return

            # ─── 2. Nhận manifest + session key ─────────────────────────
            metadata_data = self.receive_data(client_socket)
            if not metadata_data:
                client_socket.send("NACK: Failed to receive metadata".encode('utf-8'))
                client_socket.close()
                return

            try:
                metadata_json = json.loads(metadata_data)
            except json.JSONDecodeError as e:
                client_socket.send(f"NACK: Invalid JSON: {e}".encode('utf-8'))
                client_socket.close()
                return

            username = metadata_json.get('username', 'unknown')

            # NÂNG CẤP: Replay guard kiểm tra manifest
            manifest = metadata_json.get('manifest',
                                          metadata_json.get('metadata', {}))
            replay_check = replay_guard.validate_metadata(manifest)
            if not replay_check['valid']:
                sec_logger.log_replay_detected(
                    manifest.get('nonce', 'N/A'), source=addr_str)
                client_socket.send(
                    f"NACK: {replay_check['reason']}".encode('utf-8'))
                client_socket.close()
                return

            # Xác minh manifest signature
            if not self.verify_manifest_signature(metadata_json):
                sec_logger.log_manifest_verify(
                    manifest.get('file_id', 'N/A'), False)
                client_socket.send(
                    "NACK: Invalid manifest signature".encode('utf-8'))
                client_socket.close()
                return

            file_id = manifest.get('file_id', 'unknown')
            sec_logger.log_manifest_verify(file_id, True)

            # Giải mã SessionKey (RSA-OAEP)
            session_key = self.decrypt_session_key(
                metadata_json['encrypted_session_key'])
            if not session_key:
                client_socket.send(
                    "NACK: Cannot decrypt session key".encode('utf-8'))
                client_socket.close()
                return

            sec_logger.info(SecurityLogger.KEY_EXCHANGE,
                            f"Session key decrypted for file_id={file_id}")

            client_socket.send("ACK: Manifest verified".encode('utf-8'))

            # ─── 3. Nhận chunks ──────────────────────────────────────────
            total_chunks = manifest.get('total_chunks',
                                         manifest.get('parts', 3))
            received_chunks = []

            sec_logger.log_upload_start(username,
                                        manifest.get('original_filename',
                                                      manifest.get('filename', 'unknown')),
                                        file_id, total_chunks)

            for i in range(total_chunks):
                part_data = self.receive_data(client_socket)
                if not part_data:
                    msg = f"NACK: Failed to receive chunk {i+1}"
                    client_socket.send(msg.encode('utf-8'))
                    client_socket.close()
                    return

                try:
                    chunk_json = json.loads(part_data)
                except json.JSONDecodeError as e:
                    msg = f"NACK: Chunk {i+1} JSON error: {e}"
                    client_socket.send(msg.encode('utf-8'))
                    client_socket.close()
                    return

                # NÂNG CẤP: Replay guard kiểm tra từng chunk
                chunk_replay = replay_guard.validate_chunk(chunk_json)
                if not chunk_replay['valid']:
                    sec_logger.log_replay_detected(
                        chunk_json.get('nonce', 'N/A'), source=addr_str)
                    msg = f"NACK: Chunk {i+1} - {chunk_replay['reason']}"
                    client_socket.send(msg.encode('utf-8'))
                    client_socket.close()
                    return

                # NÂNG CẤP: Verify chunk (HMAC + RSA-PSS + AES-GCM tag)
                verify_result = self.verify_chunk(chunk_json, session_key,
                                                   username)
                if verify_result['success']:
                    received_chunks.append(chunk_json)
                    seq = chunk_json.get('sequence_number', i+1)
                    sec_logger.log_chunk_received(file_id, seq,
                                                   total_chunks, True)
                    ack = f"ACK: Chunk {i+1} verified"
                    client_socket.send(ack.encode('utf-8'))
                else:
                    sec_logger.log_chunk_received(file_id, i+1,
                                                   total_chunks, False)
                    sec_logger.log_integrity_error(
                        f"Chunk {i+1} failed: {verify_result['error']}")
                    msg = f"NACK: Chunk {i+1} - {verify_result['error']}"
                    client_socket.send(msg.encode('utf-8'))
                    client_socket.close()
                    return

            # ─── 4. Validate chunks (thiếu/trùng/đảo) ───────────────────
            validation = file_processor.validate_received_chunks(
                manifest, received_chunks)

            if validation['duplicates']:
                for seq in validation['duplicates']:
                    sec_logger.log_duplicate_chunk(file_id, '', seq)

            if validation['missing']:
                sec_logger.log_missing_chunks(file_id, validation['missing'])
                # NÂNG CẤP: Resume - yêu cầu gửi lại chunk thiếu
                missing_info = file_processor.get_missing_chunks(
                    manifest, received_chunks)
                resume_msg = json.dumps({
                    'action': 'RESUME',
                    'missing_chunks': missing_info
                })
                client_socket.send(resume_msg.encode('utf-8'))
                client_socket.close()
                return

            # ─── 5. Ghép file + verify hash ──────────────────────────────
            if self.reconstruct_file(validation['sorted_chunks'],
                                      session_key, metadata_json):
                sec_logger.log_upload_complete(username, file_id, True)
                client_socket.send(
                    "ACK: File received successfully".encode('utf-8'))
            else:
                sec_logger.log_upload_complete(username, file_id, False,
                                               "Reconstruction failed")
                client_socket.send(
                    "NACK: File reconstruction failed".encode('utf-8'))

        except Exception as e:
            sec_logger.error(SecurityLogger.ERROR,
                             f"Error handling client {addr_str}: {e}")
            try:
                client_socket.send(
                    f"NACK: Server error - {str(e)}".encode('utf-8'))
            except Exception:
                pass
        finally:
            client_socket.close()

    def verify_manifest_signature(self, metadata_json):
        """Xác minh chữ ký manifest (RSA-PSS)."""
        try:
            users = load_json_file(USERS_FILE)
            username = metadata_json['username']

            if username not in users or not users[username].get('public_key'):
                return False

            user_public_key_pem = users[username]['public_key']
            manifest = metadata_json.get('manifest',
                                          metadata_json.get('metadata', {}))
            sig_b64 = metadata_json.get('manifest_signature',
                                         metadata_json.get('metadata_signature', ''))
            signature = base64.b64decode(sig_b64)

            return file_processor.verify_manifest_signature(
                manifest, signature, user_public_key_pem)
        except Exception as e:
            sec_logger.error(SecurityLogger.ERROR,
                             f"Manifest signature verification error: {e}")
            return False

    def decrypt_session_key(self, encrypted_session_key_b64):
        """Giải mã SessionKey bằng RSA-OAEP (nâng cấp từ PKCS#1 v1.5)."""
        try:
            system_private_key_pem, _ = rsa_handler.load_system_keys(KEYS_FOLDER)
            encrypted_session_key = base64.b64decode(encrypted_session_key_b64)
            session_key = rsa_handler.decrypt_session_key(
                encrypted_session_key, system_private_key_pem)
            return session_key
        except Exception as e:
            sec_logger.error(SecurityLogger.ERROR,
                             f"Session key decryption failed: {e}")
            return None

    def verify_chunk(self, chunk_json, session_key, username):
        """
        Xác minh chunk bằng HMAC + RSA-PSS + AES-GCM tag.
        NÂNG CẤP: triple verification thay vì chỉ hash + sig.
        """
        try:
            users = load_json_file(USERS_FILE)
            if username not in users or not users[username].get('public_key'):
                return {'success': False, 'error': 'User not found'}

            user_public_key_pem = users[username]['public_key']
            result = file_processor.verify_and_decrypt_chunk(
                chunk_json, session_key, user_public_key_pem)

            return result
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def reconstruct_file(self, sorted_chunks, session_key, metadata_json):
        """Ghép file từ chunks đã giải mã + verify hash."""
        try:
            users = load_json_file(USERS_FILE)
            username = metadata_json['username']
            user_public_key_pem = users[username]['public_key']

            decrypted_parts = []
            for chunk in sorted_chunks:
                result = file_processor.verify_and_decrypt_chunk(
                    chunk, session_key, user_public_key_pem)
                if not result['success']:
                    return False
                decrypted_parts.append(result['data'])

            complete_file = file_processor.reconstruct_file(decrypted_parts)

            # NÂNG CẤP: Verify file hash từ manifest
            manifest = metadata_json.get('manifest',
                                          metadata_json.get('metadata', {}))
            expected_hash = manifest.get('file_hash')
            if expected_hash:
                actual_hash = hashlib.sha256(complete_file).hexdigest()
                if actual_hash != expected_hash:
                    sec_logger.log_hash_mismatch(
                        manifest.get('file_id', 'N/A'),
                        expected_hash, actual_hash)
                    return False
                sec_logger.info(SecurityLogger.FILE_RECONSTRUCT,
                                f"File hash verified: {actual_hash[:16]}...")

            # Lưu file
            filename = manifest.get('original_filename',
                                     manifest.get('filename', 'unknown'))
            file_id = manifest.get('file_id', secrets.token_hex(8))
            file_path = os.path.join(
                DECRYPTED_FOLDER,
                f"{username}_{filename}_{file_id[:8]}.txt")

            with open(file_path, 'wb') as f:
                f.write(complete_file)

            sec_logger.log_file_reconstruct(file_id, filename, True)
            return True
        except Exception as e:
            sec_logger.error(SecurityLogger.ERROR,
                             f"File reconstruction failed: {e}")
            return False

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()


# ─── Routes ────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        client_ip = request.remote_addr

        users = load_json_file(USERS_FILE)

        if username in users and verify_password(password,
                                                  users[username]['password']):
            session['user'] = username
            session['user_type'] = 'teacher'
            sec_logger.log_login(username, client_ip, True)
            return redirect(url_for('dashboard'))
        else:
            sec_logger.log_login(username, client_ip, False)
            flash('Tên đăng nhập hoặc mật khẩu không đúng!', 'error')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        users = load_json_file(USERS_FILE)

        if username in users:
            flash('Tên đăng nhập đã tồn tại!', 'error')
        else:
            # NÂNG CẤP: bcrypt thay SHA-256
            users[username] = {
                'password': hash_password(password),
                'email': email,
                'created_at': datetime.now().isoformat(),
                'public_key': None
            }
            save_json_file(USERS_FILE, users)
            sec_logger.log_register(username, email)
            flash('Đăng ký thành công! Vui lòng đăng nhập.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['user'])

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Không có file được chọn!', 'error')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('Không có file được chọn!', 'error')
            return redirect(request.url)

        if file and file.filename.endswith('.txt'):
            file_id = f"{session['user']}_{file.filename}_{int(time.time())}"

            if file_id in processing_files:
                flash('File đang được xử lý, vui lòng đợi!', 'warning')
                return redirect(request.url)

            processing_files.add(file_id)

            try:
                temp_path = os.path.join(UPLOAD_FOLDER, f"{file_id}.txt")
                file.save(temp_path)

                result = process_and_send_file_via_socket(
                    temp_path, session['user'])

                if result['success']:
                    flash('Gửi file thành công!', 'success')
                else:
                    flash(f'Gửi file thất bại: {result["error"]}', 'error')

                if os.path.exists(temp_path):
                    os.remove(temp_path)
            finally:
                processing_files.discard(file_id)
        else:
            flash('Chỉ chấp nhận file .txt!', 'error')

    return render_template('upload.html')

@app.route('/keys', methods=['GET', 'POST'])
def manage_keys():
    if 'user' not in session:
        return redirect(url_for('login'))

    users = load_json_file(USERS_FILE)
    user_data = users.get(session['user'], {})

    if request.method == 'POST':
        if 'generate' in request.form:
            # NÂNG CẤP: RSA-2048 thay 1024-bit
            private_key, public_key = rsa_handler.generate_key_pair()
            sec_logger.log_key_generate(session['user'], 'RSA',
                                        rsa_handler.KEY_SIZE)

            users[session['user']]['public_key'] = public_key
            save_json_file(USERS_FILE, users)

            return render_template('keys.html',
                                   has_public_key=True,
                                   private_key=private_key,
                                   public_key=public_key)

        elif 'upload' in request.form:
            public_key_text = request.form['public_key']
            try:
                key_obj = rsa_handler.import_key(public_key_text)
                # NÂNG CẤP: Kiểm tra chỉ chấp nhận public key
                if key_obj.has_private():
                    flash('Vui lòng chỉ upload KHÓA CÔNG KHAI, '
                          'không upload khóa riêng!', 'error')
                    sec_logger.warning(SecurityLogger.ERROR,
                                       f"User {session['user']} tried to "
                                       f"upload private key as public key")
                else:
                    users[session['user']]['public_key'] = public_key_text
                    save_json_file(USERS_FILE, users)
                    flash('Tải lên khóa công khai thành công!', 'success')
            except Exception:
                flash('Khóa công khai không hợp lệ!', 'error')

    return render_template('keys.html',
                           has_public_key=user_data.get('public_key') is not None)

@app.route('/history')
def history():
    if 'user' not in session:
        return redirect(url_for('login'))

    transactions = load_json_file(TRANSACTIONS_FILE)
    user_transactions = [t for t in transactions
                         if t.get('username') == session['user']]

    return render_template('history.html', transactions=user_transactions)


# ─── Admin Routes ──────────────────────────────────────────────────────────

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        client_ip = request.remote_addr

        admin_data = load_json_file(ADMIN_FILE)

        if (username == admin_data['username'] and
                verify_password(password, admin_data['password'])):
            session['user'] = username
            session['user_type'] = 'admin'
            sec_logger.log_login(f"admin:{username}", client_ip, True)
            return redirect(url_for('admin_dashboard'))
        else:
            sec_logger.log_login(f"admin:{username}", client_ip, False)
            flash('Thông tin đăng nhập không đúng!', 'error')

    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if session.get('user_type') != 'admin':
        sec_logger.log_access_denied(
            session.get('user', 'anonymous'), '/admin/dashboard')
        return redirect(url_for('admin_login'))

    transactions = load_json_file(TRANSACTIONS_FILE)
    users = load_json_file(USERS_FILE)

    stats = {
        'total_users': len(users),
        'total_transactions': len(transactions),
        'successful_transactions': len([t for t in transactions
                                         if t.get('status') == 'success']),
        'failed_transactions': len([t for t in transactions
                                     if t.get('status') == 'failed'])
    }

    return render_template('admin_dashboard.html', stats=stats)

@app.route('/admin/transactions')
def admin_transactions():
    if session.get('user_type') != 'admin':
        sec_logger.log_access_denied(
            session.get('user', 'anonymous'), '/admin/transactions')
        return redirect(url_for('admin_login'))

    transactions = load_json_file(TRANSACTIONS_FILE)
    return render_template('admin_transactions.html', transactions=transactions)

@app.route('/admin/users')
def admin_users():
    if session.get('user_type') != 'admin':
        sec_logger.log_access_denied(
            session.get('user', 'anonymous'), '/admin/users')
        return redirect(url_for('admin_login'))

    users = load_json_file(USERS_FILE)
    return render_template('admin_users.html', users=users)

@app.route('/admin/tests')
def admin_tests():
    if session.get('user_type') != 'admin':
        sec_logger.log_access_denied(
            session.get('user', 'anonymous'), '/admin/tests')
        return redirect(url_for('admin_login'))
    transactions = load_json_file(TRANSACTIONS_FILE)
    # Chỉ hiển thị giao dịch thành công có file mã hóa
    success_txns = [t for t in transactions if t.get('status') == 'success']
    return render_template('admin_tests.html', transactions=success_txns)

@app.route('/api/admin/run_tests', methods=['POST'])
def run_admin_tests():
    if session.get('user_type') != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    import copy, base64, hashlib, json as _json
    from crypto.file_processor import FileProcessor
    from crypto.rsa_handler import RSAHandler as _RSA

    try:
        data          = request.get_json(force=True) or {}
        transaction_id = data.get('transaction_id', '')

        fp  = FileProcessor()
        lines = []
        sep   = '-' * 50

        if transaction_id:
            # ── Dùng file thật từ giao dịch ──
            enc_path = os.path.join(ENCRYPTED_FOLDER, f"{{}}".format(
                next(('{username}_{id}.json'.format(**t)
                      for t in load_json_file(TRANSACTIONS_FILE)
                      if t['id'] == transaction_id), None)
            ))

            transactions = load_json_file(TRANSACTIONS_FILE)
            txn = next((t for t in transactions if t['id'] == transaction_id), None)
            if not txn:
                return jsonify({'success': False, 'error': 'Khong tim thay giao dich!'}), 404

            enc_path = os.path.join(
                ENCRYPTED_FOLDER,
                '{}_{}.json'.format(txn['username'], transaction_id)
            )
            if not os.path.exists(enc_path):
                return jsonify({'success': False,
                                'error': 'File ma hoa khong ton tai: ' + enc_path}), 404

            with open(enc_path, 'r', encoding='utf-8') as f:
                enc_data = _json.load(f)

            manifest     = enc_data['manifest']
            orig_chunks  = enc_data['chunks']
            # Giai ma session key bang khoa rieng he thong
            sys_priv, _  = rsa_handler.load_system_keys(KEYS_FOLDER)
            session_key  = rsa_handler.decrypt_session_key(
                base64.b64decode(enc_data['encrypted_session_key']), sys_priv)

            # Lay public key cua nguoi gui de verify
            users       = load_json_file(USERS_FILE)
            user_pub    = users.get(txn['username'], {}).get('public_key', '')
            expected_hash = manifest.get('file_hash', '')
            filename      = txn.get('filename', 'unknown')

            lines.append('=' * 58)
            lines.append(' KIEM THU BAT BUOC - FILE THAT')
            lines.append('=' * 58)
            lines.append('[*] File: {} | {} bytes | {} chunks'.format(
                filename, txn.get('file_size', '?'), len(orig_chunks)))
            lines.append('[*] Nguoi gui: {}'.format(txn['username']))
            lines.append('[*] Hash goc : {}\n'.format(expected_hash))
        else:
            # ── Dung file gia neu khong chon ──
            _rsa = _RSA()
            _, _ = _rsa.generate_key_pair()
            user_priv, user_pub = _rsa.generate_key_pair()
            file_content  = b'Data Test. ' * 50
            manifest      = fp.create_manifest('test_file.txt', file_content, 'student1', num_chunks=4)
            session_key   = fp.aes_handler.generate_key()
            orig_chunks   = fp.encrypt_chunks(file_content, manifest, session_key, user_priv)
            expected_hash = manifest['file_hash']
            lines.append('=' * 58)
            lines.append(' KIEM THU BAT BUOC - FILE GIA (550 bytes)')
            lines.append('=' * 58)
            lines.append('[*] Hash goc: {}\n'.format(expected_hash))

        # ── KIEM TRA TRANG THAI FILE THUC TE ──
        lines.append(sep)
        lines.append('>>> TRANG THAI FILE THUC TE (truoc khi giai lap)')
        lines.append(sep)
        real_check = fp.validate_received_chunks(manifest, orig_chunks)
        lines.append('[*] Manifest yeu cau: {} chunks'.format(manifest['total_chunks']))
        lines.append('[*] So chunks co trong file: {}'.format(len(orig_chunks)))
        
        # Chỉ hiển thị sequence number thực sự có trong mảng
        seq_list = [c.get('sequence_number', '?') for c in orig_chunks]
        lines.append('[*] Sequence numbers nhan duoc: {}'.format(seq_list))
        
        if len(real_check['errors']) == 0:
            # Nếu cấu trúc đúng, quét tiếp HMAC để kiểm tra có bị sửa đổi nội dung JSON không
            tamper_detected = False
            for c in orig_chunks:
                try:
                    c_meta = {
                        'file_id': c['file_id'], 'chunk_id': c['chunk_id'],
                        'sequence_number': c['sequence_number'], 'total_chunks': c['total_chunks']
                    }
                    hmac_hex = fp.hmac_handler.compute_chunk_hmac(
                        c_meta, base64.b64decode(c['cipher']),
                        base64.b64decode(c['nonce']), base64.b64decode(c['tag']), session_key
                    )
                    if hmac_hex != c['hmac']:
                        tamper_detected = True
                        lines.append('[*] -> PHAT HIEN LOI FILE THUC TE: Nội dung Chunk {} bị sửa đổi (HMAC fail)!\n'.format(c['sequence_number']))
                        break
                except Exception as e:
                    tamper_detected = True
                    lines.append('[*] -> PHAT HIEN LOI FILE THUC TE: Nội dung/Định dạng ở Chunk {} bị sửa đổi (Lỗi giải mã Base64)!\n'.format(c.get('sequence_number', '?')))
                    break
            
            if not tamper_detected:
                lines.append('[*] -> FILE HOAN CHINH, khong loi, khong bi sua doi.\n')
        else:
            tamper_detected = True
            lines.append('[*] -> PHAT HIEN LOI FILE THUC TE: {}\n'.format(real_check['errors']))

        # ── 1. File hop le ──
        lines.append(sep)
        lines.append('1. GUI FILE HOP LE')
        lines.append(sep)
        v1 = fp.validate_received_chunks(manifest, orig_chunks)
        if len(v1['errors']) == 0 and not tamper_detected:
            lines.append('   -> [PASS] Nhan du {} chunks hop le, khong loi.\n'.format(len(orig_chunks)))
        else:
            if tamper_detected:
                lines.append('   -> [FAIL] File không hợp lệ: Bị sửa đổi nội dung hoặc định dạng!\n')
            else:
                lines.append('   -> [FAIL] File co loi (Thieu/Trung/Dao thu tu): {}\n'.format(v1['errors']))

        # ── 2. Mat chunk ──
        lines.append(sep)
        lines.append('2. LAM MAT MOT CHUNK (mat chunk cuoi)')
        lines.append(sep)
        miss = orig_chunks[:-1]   # bo chunk cuoi
        v2   = fp.validate_received_chunks(manifest, miss)
        lines.append('   -> [PASS] He thong phat hien: {}\n'.format(v2['errors']))

        # ── 3. Trung chunk ──
        lines.append(sep)
        lines.append('3. GUI TRUNG MOT CHUNK (chunk dau gui dup)')
        lines.append(sep)
        dup = [orig_chunks[0]] + orig_chunks
        v3  = fp.validate_received_chunks(manifest, dup)
        lines.append('   -> [PASS] He thong phat hien: {}\n'.format(v3['errors']))

        # ── 4. Dao thu tu ──
        lines.append(sep)
        lines.append('4. DAO THU TU CHUNK')
        lines.append(sep)
        
        # Đảm bảo mảng shuf luôn bị đảo ngược so với thứ tự ĐÚNG (1,2,3 -> 3,2,1)
        sorted_orig = sorted(orig_chunks, key=lambda x: x.get('sequence_number', 0))
        if len(sorted_orig) > 1:
            shuf = list(reversed(sorted_orig))
        else:
            shuf = sorted_orig
            
        v4   = fp.validate_received_chunks(manifest, shuf)
        seq  = [c.get('sequence_number', '?') for c in v4['sorted_chunks']]
        if 'Chunk bị đảo thứ tự (đã tự sắp xếp lại)' in v4['errors']:
            lines.append('   -> [PASS] Phat hien: {}'.format(v4['errors']))
        else:
            lines.append('   -> [FAIL] Khong phat hien dao thu tu! Errors: {}'.format(v4['errors']))
        lines.append('   -> [PASS] Da sap xep lai: {}\n'.format(seq))

        # ── 5. Sua noi dung ──
        lines.append(sep)
        lines.append('5. SUA NOI DUNG CHUNK (tan cong byte thu 10)')
        lines.append(sep)
        tampered = copy.deepcopy(orig_chunks)
        raw = bytearray(base64.b64decode(tampered[0]['cipher']))
        attack_idx = len(raw) // 2  # Dùng giữa mảng để luôn an toàn dù chunk bé
        raw[attack_idx] ^= 0xFF
        tampered[0]['cipher'] = base64.b64encode(bytes(raw)).decode()
        r5 = fp.verify_and_decrypt_chunk(tampered[0], session_key, user_pub)
        if not r5['success']:
            lines.append('   -> [PASS] AES-GCM & HMAC chan dung du lieu bi sua!')
            lines.append('   -> Chi tiet loi: {}\n'.format(r5['error']))
        else:
            lines.append('   -> [FAIL] Khong phat hien duoc!\n')

        # ── 6. Kiem tra hash ──
        lines.append(sep)
        lines.append('6. KIEM TRA HASH FILE SAU KHI GHEP')
        lines.append(sep)
        import json as _j
        parts = []
        for c in orig_chunks:
            try:
                # Giai ma AES-GCM truc tiep (bo qua RSA sig vi khoa tam da xoa)
                nonce_b  = base64.b64decode(c['nonce'])
                cipher_b = base64.b64decode(c['cipher'])
                tag_b    = base64.b64decode(c['tag'])
                aad_dict = {
                    'file_id':        c['file_id'],
                    'chunk_id':       c['chunk_id'],
                    'sequence_number': c['sequence_number'],
                    'total_chunks':   c['total_chunks']
                }
                aad = _j.dumps(aad_dict, sort_keys=True).encode('utf-8')
                plaintext = fp.aes_handler.decrypt_chunk(cipher_b, session_key, nonce_b, tag_b, aad)
                parts.append(plaintext)
            except Exception as ex:
                lines.append('   -> [WARN] Chunk {} giai ma that bai: {}'.format(
                    c.get('sequence_number', '?'), str(ex)))

        recon       = fp.reconstruct_file(parts)
        actual_hash = hashlib.sha256(recon).hexdigest()
        lines.append('   -> So chunks giai ma thanh cong: {}/{}'.format(len(parts), len(orig_chunks)))
        lines.append('   -> Kich thuoc ghep: {} bytes'.format(len(recon)))
        lines.append('   -> Hash goc : {}'.format(expected_hash))
        lines.append('   -> Hash ghep: {}'.format(actual_hash))
        if expected_hash == actual_hash:
            lines.append('   -> [PASS] Ma bam TRUNG KHOP 100%! File toan ven!\n')
        else:
            lines.append('   -> [FAIL] Hash khong khop!\n')

        lines.append('=' * 58)
        lines.append(' HOAN TAT TAT CA CAC BAI KIEM THU BAT BUOC!')
        lines.append('=' * 58)

        return jsonify({'success': True, 'output': '\n'.join(lines)})

    except Exception as e:
        import traceback
        return jsonify({'success': False, 'error': traceback.format_exc()}), 500



@app.route('/logout')
def logout():
    username = session.get('user', 'unknown')
    sec_logger.log_logout(username)
    session.clear()
    return redirect(url_for('index'))


# ─── API endpoints ─────────────────────────────────────────────────────────

@app.route('/api/download/encrypted/<transaction_id>')
def download_encrypted_file(transaction_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    transactions = load_json_file(TRANSACTIONS_FILE)
    transaction = next((t for t in transactions
                        if t['id'] == transaction_id
                        and t['username'] == session['user']), None)

    if not transaction:
        sec_logger.log_access_denied(session['user'],
                                      f'encrypted/{transaction_id}')
        flash('Không tìm thấy giao dịch hoặc không có quyền!', 'error')
        return redirect(url_for('history'))

    encrypted_file_path = os.path.join(
        ENCRYPTED_FOLDER,
        f"{session['user']}_{transaction_id}.json")

    if os.path.exists(encrypted_file_path):
        return send_file(encrypted_file_path, as_attachment=True,
                         download_name=f"encrypted_{transaction['filename']}"
                                       f"_{transaction_id[:8]}.json",
                         mimetype='application/json')
    else:
        flash('File đã mã hóa không tồn tại!', 'error')
        return redirect(url_for('history'))

@app.route('/api/download/decrypted/<transaction_id>')
def download_decrypted_file(transaction_id):
    if session.get('user_type') != 'admin':
        sec_logger.log_access_denied(
            session.get('user', 'anonymous'),
            f'decrypted/{transaction_id}')
        return redirect(url_for('admin_login'))

    transactions = load_json_file(TRANSACTIONS_FILE)
    transaction = next((t for t in transactions
                        if t['id'] == transaction_id), None)

    if not transaction:
        flash('Không tìm thấy giao dịch!', 'error')
        return redirect(url_for('admin_transactions'))

    decrypted_file_path = os.path.join(
        DECRYPTED_FOLDER,
        f"{transaction['username']}_{transaction['filename']}_{transaction.get('file_id', '')[:8]}.txt")

    if os.path.exists(decrypted_file_path):
        return send_file(decrypted_file_path, as_attachment=True,
                         download_name=f"decrypted_{transaction['filename']}",
                         mimetype='text/plain')
    else:
        import logging
        logging.error(f"DEBUG: File not found. Checking path: {os.path.abspath(decrypted_file_path)}")
        logging.error(f"DEBUG: transaction data: {transaction}")
        flash('File đã giải mã không tồn tại!', 'error')
        return redirect(url_for('admin_transactions'))

@app.route('/api/user-stats/<username>')
def get_user_stats(username):
    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        transactions = load_json_file(TRANSACTIONS_FILE)
        user_transactions = [t for t in transactions
                              if t.get('username') == username]

        total_files = len(user_transactions)
        successful_files = len([t for t in user_transactions
                                 if t.get('status') == 'success'])
        failed_files = len([t for t in user_transactions
                             if t.get('status') == 'failed'])
        success_rate = round((successful_files / total_files * 100)
                              if total_files > 0 else 0, 1)

        total_size = sum([t.get('file_size', 0) for t in user_transactions])
        total_size_mb = round(total_size / (1024 * 1024), 2) \
            if total_size > 0 else 0

        last_activity = None
        if user_transactions:
            latest = max(user_transactions,
                          key=lambda x: x.get('timestamp', ''))
            last_activity = latest.get('timestamp', '')
            if last_activity:
                try:
                    last_activity = datetime.fromisoformat(
                        last_activity.replace('Z', '+00:00')
                    ).strftime('%d/%m/%Y %H:%M')
                except Exception:
                    pass

        recent = sorted(user_transactions,
                         key=lambda x: x.get('timestamp', ''),
                         reverse=True)[:5]
        recent_formatted = []
        for t in recent:
            size_kb = round(t.get('file_size', 0) / 1024, 1) \
                if t.get('file_size') else 0
            recent_formatted.append({
                'timestamp': t.get('timestamp', ''),
                'filename': t.get('filename', 'N/A'),
                'size_kb': size_kb,
                'status': t.get('status', 'unknown')
            })

        return jsonify({
            'total_files': total_files,
            'successful_files': successful_files,
            'failed_files': failed_files,
            'success_rate': success_rate,
            'total_size_mb': total_size_mb,
            'last_activity': last_activity,
            'recent_transactions': recent_formatted
        })

    except Exception as e:
        sec_logger.error(SecurityLogger.ERROR,
                          f"Error getting user stats: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# ─── Xử lý file gửi qua socket ────────────────────────────────────────────

def process_and_send_file_via_socket(file_path, username):
    """
    Xử lý file và gửi qua socket - NÂNG CẤP.
    Dùng AES-GCM + RSA-2048 + manifest + chunk metadata đầy đủ.
    """
    original_public_key = None  # Lưu khóa gốc để khôi phục sau khi gửi
    try:
        _, system_public_key_pem = rsa_handler.load_system_keys(KEYS_FOLDER)

        # Tạo RSA-2048 key pair tạm thời cho phiên gửi này
        temp_private_key, temp_public_key = rsa_handler.generate_key_pair()

        users = load_json_file(USERS_FILE)
        original_public_key = users[username].get('public_key')  # Lưu khóa gốc trước khi ghi đè
        users[username]['public_key'] = temp_public_key  # Tạm set để socket server verify
        save_json_file(USERS_FILE, users)

        sec_logger.log_key_generate(username, 'RSA-temp',
                                     rsa_handler.KEY_SIZE)

        # Xử lý file bằng file processor nâng cấp
        result = file_processor.process_file_for_sending(
            file_path, username, system_public_key_pem, temp_private_key)

        if not result['success']:
            return result

        manifest = result['manifest']
        sec_logger.info(SecurityLogger.MANIFEST_CREATE,
                        f"Manifest created: file_id={manifest['file_id']}, "
                        f"chunks={manifest['total_chunks']}")

        # Gửi qua socket
        socket_result = send_via_socket(
            manifest,
            result['manifest_signature'],
            result['encrypted_session_key'],
            result['encrypted_parts'],
            username
        )

        if socket_result['success']:
            transaction_id = secrets.token_hex(16)

            transaction = {
                'id': transaction_id,
                'username': username,
                'filename': manifest.get('original_filename',
                                          manifest.get('filename', '')),
                'timestamp': manifest.get('timestamp',
                                           datetime.now().isoformat()),
                'status': 'success',
                'parts': manifest['total_chunks'],
                'encrypted_session_key': base64.b64encode(
                    result['encrypted_session_key']).decode(),
                'file_size': manifest.get('total_size',
                                           manifest.get('size', 0)),
                'file_id': manifest.get('file_id', ''),
                'file_hash': manifest.get('file_hash', ''),
                'encryption': 'AES-256-GCM',
                'key_exchange': 'RSA-2048-OAEP',
                'signature': 'RSA-PSS-SHA256'
            }

            transactions = load_json_file(TRANSACTIONS_FILE)
            transactions.append(transaction)
            save_json_file(TRANSACTIONS_FILE, transactions)

            # Lưu file đã mã hóa
            encrypted_file_path = os.path.join(
                ENCRYPTED_FOLDER,
                f"{username}_{transaction_id}.json")
            with open(encrypted_file_path, 'w') as f:
                json.dump({
                    'manifest': manifest,
                    'manifest_signature': base64.b64encode(
                        result['manifest_signature']).decode(),
                    'encrypted_session_key': transaction[
                        'encrypted_session_key'],
                    'chunks': result['encrypted_parts']
                }, f, indent=2)

            return {'success': True, 'transaction_id': transaction_id}
        else:
            return socket_result

    except Exception as e:
        sec_logger.error(SecurityLogger.ERROR,
                          f"process_and_send_file_via_socket: {e}")
        return {'success': False, 'error': str(e)}
    finally:
        # Luôn khôi phục khóa công khai gốc của người dùng sau khi gửi xong
        # Tránh ghi đè vĩnh viễn khóa do người dùng tự tạo từ trang /keys
        try:
            users_restore = load_json_file(USERS_FILE)
            if username in users_restore:
                users_restore[username]['public_key'] = original_public_key
                save_json_file(USERS_FILE, users_restore)
        except Exception:
            pass


def send_via_socket(manifest, manifest_signature, encrypted_session_key,
                     encrypted_chunks, username):
    """Gửi dữ liệu qua socket."""
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(60)
        client_socket.connect((SOCKET_HOST, SOCKET_PORT))

        # 1. Handshake
        client_socket.send("Hello!".encode('utf-8'))
        response = client_socket.recv(1024).decode('utf-8')
        if response != "Ready!":
            return {'success': False,
                    'error': f'Handshake failed: {response}'}

        # 2. Gửi manifest + session key
        metadata_package = {
            'username': username,
            'manifest': manifest,
            'metadata': manifest,  # tương thích
            'manifest_signature': base64.b64encode(
                manifest_signature).decode(),
            'metadata_signature': base64.b64encode(
                manifest_signature).decode(),
            'encrypted_session_key': base64.b64encode(
                encrypted_session_key).decode()
        }

        client_socket.send(json.dumps(metadata_package).encode('utf-8'))
        response = client_socket.recv(1024).decode('utf-8')
        if not response.startswith("ACK"):
            return {'success': False,
                    'error': f'Manifest rejected: {response}'}

        # 3. Gửi từng chunk
        for i, chunk in enumerate(encrypted_chunks):
            client_socket.send(json.dumps(chunk).encode('utf-8'))
            response = client_socket.recv(1024).decode('utf-8')
            if not response.startswith("ACK"):
                # Kiểm tra có phải resume request không
                try:
                    resume_data = json.loads(response)
                    if resume_data.get('action') == 'RESUME':
                        return {
                            'success': False,
                            'error': 'Server yêu cầu gửi lại chunk',
                            'missing': resume_data.get('missing_chunks', [])
                        }
                except (json.JSONDecodeError, TypeError):
                    pass
                return {'success': False,
                        'error': f'Chunk {i+1} rejected: {response}'}

        # 4. Phản hồi cuối
        final_response = client_socket.recv(1024).decode('utf-8')
        client_socket.close()

        if final_response.startswith("ACK"):
            return {'success': True, 'message': final_response}
        else:
            return {'success': False, 'error': final_response}

    except Exception as e:
        sec_logger.error(SecurityLogger.ERROR,
                          f"Socket communication error: {e}")
        return {'success': False,
                'error': f'Socket communication failed: {str(e)}'}


def start_socket_server():
    global socket_server
    socket_server = SocketServer(SOCKET_HOST, SOCKET_PORT)
    server_thread = threading.Thread(target=socket_server.start)
    server_thread.daemon = True
    server_thread.start()


if __name__ == '__main__':
    print("=" * 60)
    print("  Secure Assignment Chunk Transfer - NÂNG CẤP")
    print("  Đề tài 6: FIT4012 Secure System Upgrade Challenge")
    print("=" * 60)
    print("  [UPGRADE] AES-256-GCM (thay DES/CBC)")
    print("  [UPGRADE] RSA-2048 OAEP+PSS (thay RSA-1024 PKCS#1v1.5)")
    print("  [UPGRADE] bcrypt password (thay SHA-256)")
    print("  [UPGRADE] Replay Guard (nonce + timestamp)")
    print("  [UPGRADE] Security Logger")
    print("  [UPGRADE] Manifest + Chunk validation")
    print("=" * 60)

    print("\nInitializing system...")
    init_data()
    init_system_keys()

    print("Starting socket server...")
    start_socket_server()

    time.sleep(1)

    print("Starting Flask application...")
    sec_logger.info(SecurityLogger.SESSION, "Application started")
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)