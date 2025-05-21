from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import io

app = Flask(__name__)
# Đặt SECRET_KEY cho Flask session. RẤT QUAN TRỌNG cho bảo mật session.
# Sử dụng os.urandom(24) để tạo khóa ngẫu nhiên, thay thế bằng khóa tĩnh trong môi trường production.
app.secret_key = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload size

# Hàm chuyển đổi mật khẩu thành khóa AES 256-bit
def derive_key(password: str) -> bytes:
    """Derives a 256-bit (32-byte) key from a password using SHA256."""
    h = SHA256.new()
    h.update(password.encode('utf-8'))
    return h.digest() # Returns 32 bytes

# --- Routes để hiển thị trang ---

@app.route('/')
def home():
    # Xóa các dữ liệu session cũ khi về trang chủ
    session.pop('encrypted_data', None)
    session.pop('encrypted_filename', None)
    session.pop('decrypted_data', None)
    session.pop('decrypted_filename', None)
    return render_template('home.html')

@app.route('/encrypt_page')
def show_encrypt_page():
    # Xóa dữ liệu mã hóa cũ khi vào trang mã hóa
    session.pop('encrypted_data', None)
    session.pop('encrypted_filename', None)
    return render_template('encrypt.html')

@app.route('/decrypt_page')
def show_decrypt_page():
    # Xóa dữ liệu giải mã cũ khi vào trang giải mã
    session.pop('decrypted_data', None)
    session.pop('decrypted_filename', None)
    return render_template('decrypt.html')

# --- Routes để xử lý mã hóa và giải mã ---

@app.route('/perform_encrypt', methods=['POST'])
def perform_encrypt():
    if 'file' not in request.files:
        flash('No file selected.', 'error')
        return redirect(url_for('show_encrypt_page'))
    file = request.files['file']
    if file.filename == '':
        flash('No selected file.', 'error')
        return redirect(url_for('show_encrypt_page'))

    password = request.form['password']
    if not password:
        flash('Password cannot be empty.', 'error')
        return redirect(url_for('show_encrypt_page'))

    try:
        file_content = file.read()
        key = derive_key(password)
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(file_content, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        encrypted_data_bytes = iv + ciphertext

        encrypted_filename = file.filename + '.aes'

        # Lưu dữ liệu đã mã hóa và tên file vào session
        session['encrypted_data'] = encrypted_data_bytes
        session['encrypted_filename'] = encrypted_filename

        flash('File encrypted successfully! You can now download it.', 'success')
        return render_template('encrypt.html', show_download=True, filename=encrypted_filename)

    except Exception as e:
        flash(f'Encryption failed: {e}', 'error')
        return redirect(url_for('show_encrypt_page'))

@app.route('/perform_decrypt', methods=['POST'])
def perform_decrypt():
    if 'file' not in request.files:
        flash('No file selected.', 'error')
        return redirect(url_for('show_decrypt_page'))
    file = request.files['file']
    if file.filename == '':
        flash('No selected file.', 'error')
        return redirect(url_for('show_decrypt_page'))

    password = request.form['password']
    if not password:
        flash('Password cannot be empty.', 'error')
        return redirect(url_for('show_decrypt_page'))

    try:
        encrypted_data_bytes = file.read()

        if len(encrypted_data_bytes) < AES.block_size:
            flash('Invalid encrypted file format (too short for IV).', 'error')
            return redirect(url_for('show_decrypt_page'))

        iv = encrypted_data_bytes[:AES.block_size]
        ciphertext = encrypted_data_bytes[AES.block_size:]

        key = derive_key(password)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        decrypted_padded_data = cipher.decrypt(ciphertext)
        original_data_bytes = unpad(decrypted_padded_data, AES.block_size)

        original_filename = file.filename
        if original_filename.endswith('.aes'):
            original_filename = original_filename[:-4] # Remove .aes extension
        else:
            # Fallback for files without .aes extension, append _decrypted
            name, ext = os.path.splitext(file.filename)
            original_filename = f"{name}_decrypted{ext}"


        # Lưu dữ liệu đã giải mã và tên file vào session
        session['decrypted_data'] = original_data_bytes
        session['decrypted_filename'] = original_filename

        flash('File decrypted successfully! You can now download it.', 'success')
        return render_template('decrypt.html', show_download=True, filename=original_filename)

    except ValueError as e:
        # Lỗi giải mã do sai mật khẩu hoặc file bị hỏng
        flash(f'Decryption failed: Incorrect password or corrupted file. Please try again.', 'error')
        # Khi giải mã sai, người dùng vẫn ở trang giải mã và file đã upload vẫn được giữ
        # trong form (nếu browser hỗ trợ) hoặc có thể upload lại dễ dàng.
        # Dữ liệu `file.read()` đã được xử lý, không cần lưu lại file trên server.
        # Người dùng sẽ cần chọn lại file nếu trình duyệt không tự nhớ.
        # Để giữ lại file đã upload, bạn sẽ cần một cơ chế lưu file tạm thời trên server.
        # Ở đây, chúng ta chỉ giữ lại thông báo lỗi và không mất trạng thái tải xuống.
        return render_template('decrypt.html', last_uploaded_filename=file.filename)
    except Exception as e:
        flash(f'Decryption failed: An unexpected error occurred. ({e})', 'error')
        return redirect(url_for('show_decrypt_page'))

# --- Routes để tải xuống ---

@app.route('/download_encrypted')
def download_encrypted():
    encrypted_data = session.get('encrypted_data')
    encrypted_filename = session.get('encrypted_filename', 'encrypted_file.aes')

    if encrypted_data:
        # Xóa dữ liệu khỏi session sau khi tải xuống để giải phóng bộ nhớ
        session.pop('encrypted_data', None)
        session.pop('encrypted_filename', None)
        return send_file(io.BytesIO(encrypted_data),
                         mimetype='application/octet-stream',
                         as_attachment=True,
                         download_name=encrypted_filename)
    else:
        flash('No encrypted file available for download. Please encrypt a file first.', 'error')
        return redirect(url_for('show_encrypt_page'))

@app.route('/download_decrypted')
def download_decrypted():
    decrypted_data = session.get('decrypted_data')
    decrypted_filename = session.get('decrypted_filename', 'decrypted_file')

    if decrypted_data:
        # Xóa dữ liệu khỏi session sau khi tải xuống để giải phóng bộ nhớ
        session.pop('decrypted_data', None)
        session.pop('decrypted_filename', None)
        return send_file(io.BytesIO(decrypted_data),
                         mimetype='application/octet-stream',
                         as_attachment=True,
                         download_name=decrypted_filename)
    else:
        flash('No decrypted file available for download. Please decrypt a file first.', 'error')
        return redirect(url_for('show_decrypt_page'))

if __name__ == '__main__':
    # Đặt debug=False trong môi trường production để bảo mật
    app.run(debug=True)