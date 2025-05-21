from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import io

app = Flask(__name__)
app.secret_key = os.urandom(24) # RẤT QUAN TRỌNG cho bảo mật session.
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # Tăng giới hạn upload lên 50 MB cho ảnh lớn

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

        # Giữ phần mở rộng gốc của file ảnh để có thể gợi ý khi giải mã
        original_extension = os.path.splitext(file.filename)[1]
        encrypted_filename = file.filename + '.aes'
        
        # Lưu dữ liệu đã mã hóa và tên file vào session
        session['encrypted_data'] = encrypted_data_bytes
        session['encrypted_filename'] = encrypted_filename
        # Lưu phần mở rộng gốc để dùng khi giải mã
        session['original_extension'] = original_extension

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

        # Khôi phục tên file gốc và phần mở rộng
        original_filename = file.filename
        if original_filename.endswith('.aes'):
            # Cố gắng lấy phần mở rộng gốc từ session (nếu có từ quá trình mã hóa)
            # Hoặc loại bỏ '.aes' và để lại phần mở rộng nếu có
            name_without_aes = original_filename[:-4]
            # Kiểm tra session trước để ưu tiên phần mở rộng đã lưu
            if 'original_extension' in session and session['original_extension']:
                original_filename = name_without_aes + session['original_extension']
                session.pop('original_extension', None) # Xóa sau khi dùng
            else:
                # Nếu không có trong session, cố gắng lấy phần mở rộng từ tên file trước khi mã hóa
                # (ví dụ: my_image.jpg.aes -> my_image.jpg)
                base_name, _ = os.path.splitext(name_without_aes)
                original_filename = name_without_aes if not _ else f"{base_name}{_}"

        else:
            # Nếu file không có '.aes' (người dùng upload file không phải .aes),
            # thêm đuôi _decrypted để tránh trùng tên nếu là file gốc.
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
        return render_template('decrypt.html')
    except Exception as e:
        flash(f'Decryption failed: An unexpected error occurred. ({e})', 'error')
        return redirect(url_for('show_decrypt_page'))

# --- Routes để tải xuống ---

@app.route('/download_encrypted')
def download_encrypted():
    encrypted_data = session.get('encrypted_data')
    encrypted_filename = session.get('encrypted_filename', 'encrypted_file.aes')

    if encrypted_data:
        session.pop('encrypted_data', None)
        session.pop('encrypted_filename', None)
        session.pop('original_extension', None) # Đảm bảo dọn dẹp session
        return send_file(io.BytesIO(encrypted_data),
                         mimetype='application/octet-stream', # Mime type chung cho binary data
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
        session.pop('decrypted_data', None)
        session.pop('decrypted_filename', None)
        return send_file(io.BytesIO(decrypted_data),
                         mimetype='application/octet-stream', # Flask thường tự động nhận diện mimetype nếu tên file đúng
                         as_attachment=True,
                         download_name=decrypted_filename)
    else:
        flash('No decrypted file available for download. Please decrypt a file first.', 'error')
        return redirect(url_for('show_decrypt_page'))

#if __name__ == '__main__':
    app.run(debug=True)
if __name__ == '__main__':
    app.run(debug=True, port=5001) # Chạy trên cổng 5001