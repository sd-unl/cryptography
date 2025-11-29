import os
import secrets
import base64
from flask import Flask, request, jsonify, render_template_string
from sqlalchemy import create_engine, text
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__)

# Database Connection
DB_URL = os.environ.get("DATABASE_URL")
engine = create_engine(DB_URL)

def init_db():
    """Create table to store Special Keys and Passwords"""
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS code_vault (
                special_key TEXT PRIMARY KEY,
                stored_password TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );
        """))
        conn.commit()

init_db()

# --- HELPER: Turn Password into Encryption Key ---
def derive_key(password: str, salt: bytes = b'static_salt_for_demo') -> bytes:
    """Derives a safe URL-safe base64 key from a text password"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# --- 1. ADMIN PANEL (Encryptor) ---
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    result_html = ""
    
    if request.method == 'POST':
        python_code = request.form.get('code')
        password = request.form.get('password')

        if python_code and password:
            # 1. Generate the Encryption Key from Password
            fernet_key = derive_key(password)
            f = Fernet(fernet_key)
            
            # 2. Encrypt the Python Code
            encrypted_bytes = f.encrypt(python_code.encode())
            encrypted_str = encrypted_bytes.decode('utf-8')
            
            # 3. Generate a Special Key (The Token)
            special_key = secrets.token_hex(16)
            
            # 4. Save Special Key + Password to DB
            with engine.connect() as conn:
                conn.execute(
                    text("INSERT INTO code_vault (special_key, stored_password) VALUES (:sk, :pwd)"),
                    {"sk": special_key, "pwd": password}
                )
                conn.commit()
            
            result_html = f"""
            <div style="background: #e8f5e9; padding: 15px; border-radius: 5px; margin-top: 20px;">
                <h3>✅ Encryption Successful</h3>
                <p><strong>1. Special Key (For Colab):</strong><br>
                <code style="background:#fff; padding:5px;">{special_key}</code></p>
                
                <p><strong>2. Encrypted Code (For Colab):</strong><br>
                <textarea style="width:100%; height:100px;">{encrypted_str}</textarea></p>
            </div>
            """

    html = f"""
    <html>
    <body style="font-family: sans-serif; padding: 40px; max-width: 800px; margin: auto;">
        <h1>🔒 Code Encryptor</h1>
        <form method="POST">
            <label><strong>Python Code to Run:</strong></label><br>
            <textarea name="code" style="width:100%; height:150px;" placeholder="print('Hello Secret World')"></textarea><br><br>
            
            <label><strong>Encryption Password:</strong></label><br>
            <input type="text" name="password" style="width:100%; padding: 8px;" placeholder="secret123"><br><br>
            
            <button type="submit" style="padding: 10px 20px; background: black; color: white; cursor:pointer;">Encrypt & Save</button>
        </form>
        {result_html}
    </body>
    </html>
    """
    return render_template_string(html)

# --- 2. USER ENDPOINT (Colab Handshake) ---
@app.route('/api/get_decryption_pass', methods=['POST'])
def get_password():
    data = request.json
    special_key = data.get('special_key')
    
    if not special_key:
        return jsonify({"error": "No key provided"}), 400

    with engine.connect() as conn:
        # Check if the Special Key exists in DB
        result = conn.execute(
            text("SELECT stored_password FROM code_vault WHERE special_key = :sk"),
            {"sk": special_key}
        ).fetchone()
        
        if result:
            # Return the password so Colab can decrypt the blob
            return jsonify({"success": True, "password": result[0]})
        else:
            return jsonify({"success": False, "error": "Invalid or Expired Key"}), 403

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
