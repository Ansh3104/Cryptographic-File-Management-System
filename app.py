from flask import Flask, render_template, request, jsonify, send_file
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import json
import os
import io

app = Flask(__name__)

# CONFIG

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Dummy users
users = {
    "ansh": "123",
    "admin": "admin"
}

# AES Key (16 bytes)
K = b'0000000000000024'

# RSA Keys
keyA = RSA.generate(2048)
private_A = keyA
public_A = keyA.publickey()

# Database file
DB_FILE = "database.json"

if not os.path.exists(DB_FILE):
    with open(DB_FILE, "w") as f:
        json.dump({}, f)

# DATABASE FUNCTIONS

def load_db():
    with open(DB_FILE) as f:
        return json.load(f)

def save_db(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f)


# ROUTES

@app.route("/")
def login_page():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data["username"]
    password = data["password"]

    if username in users and users[username] == password:
        return jsonify({"success": True})
    else:
        return jsonify({"success": False})


@app.route("/sender")
def sender():
    return render_template("sender.html")

# FILE UPLOAD + ENCRYPT + SIGN

@app.route("/upload", methods=["POST"])
def upload():

    file = request.files["file"]
    filename = file.filename

    # Get key inputs
    a1 = request.form["a1"]
    a2 = request.form["a2"]
    a3 = request.form["a3"]
    a4 = request.form["a4"]

    content = file.read()

    # AES Encryption
    cipher = AES.new(K, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(content)

    encrypted_data = cipher.nonce + tag + ciphertext

    # Save encrypted file
    enc_filename = filename + ".enc"
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], enc_filename)

    with open(filepath, "wb") as f:
        f.write(encrypted_data)

    # Create digital signature (m1)
    message = a1 + a2 + a3 + a4 + "24"
    hash_obj = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_A).sign(hash_obj)

    m1 = base64.b64encode(signature).decode()

    # Store signature per file
    db = load_db()
    db[enc_filename] = m1
    save_db(db)

    return jsonify({"status": "File uploaded, encrypted, and secured"})

# SECURE DOWNLOAD + VERIFY

@app.route("/secure_download", methods=["POST"])
def secure_download():

    data = request.json

    filename = data["filename"]
    a1 = data["a1"]
    a2 = data["a2"]
    a3 = data["a3"]
    a4 = data["a4"]

    message = a1 + a2 + a3 + a4 + "24"

    db = load_db()

    # Check if file exists in DB
    if filename not in db:
        return jsonify({"valid": False})

    signature = base64.b64decode(db[filename])
    hash_obj = SHA256.new(message.encode())

    # Verify signature
    try:
        pkcs1_15.new(public_A).verify(hash_obj, signature)
    except:
        return jsonify({"valid": False})

    # If verified → decrypt file
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

    if not os.path.exists(path):
        return jsonify({"valid": False})

    with open(path, "rb") as f:
        file_data = f.read()

    nonce = file_data[:16]
    tag = file_data[16:32]
    ciphertext = file_data[32:]

    cipher = AES.new(K, AES.MODE_EAX, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)

    original_name = filename.replace(".enc", "")

    return send_file(
        io.BytesIO(decrypted),
        as_attachment=True,
        download_name=original_name
    )


# RUN APP

if __name__ == "__main__":
    app.run(debug=True)