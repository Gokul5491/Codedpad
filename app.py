import os
import base64
import hashlib
import sqlite3
from functools import wraps

from flask import (
    Flask, request, render_template, redirect, url_for,
    send_from_directory, flash, session
)

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.path.join(BASE_DIR, "codedpad.db")
KDF_ITERATIONS = 390_000  # PBKDF2 iteration count for deriving the encryption key
MIN_KEY_LENGTH = 6        # the key now doubles as the lookup identifier, so require a bit more than before

app = Flask(__name__)
app.secret_key = "change-this-secret-key"  # used for flash messages AND the admin session cookie
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB upload limit

# Password for /admin. In a real deployment this should come from an
# environment variable, e.g. os.environ.get("CODEDPAD_ADMIN_PASSWORD").
ADMIN_PASSWORD = "gokul"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS entries (
            key_hash TEXT PRIMARY KEY,     -- SHA-256 of the user's encryption key (never the key itself)
            entry_type TEXT NOT NULL,      -- 'text' or 'file'
            content TEXT,                  -- encrypted text (Fernet token, text entries only)
            original_filename TEXT,        -- original name of uploaded file
            stored_filename TEXT,          -- encrypted file's name on disk
            salt TEXT NOT NULL,            -- base64 salt used to derive the Fernet key from the passphrase
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            edit_count INTEGER DEFAULT 0
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT NOT NULL,        -- identifies WHICH entry, never the key itself
            action TEXT NOT NULL,          -- save / retrieve_success / retrieve_fail / download
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.close()


def log_activity(key_hash, action):
    """Record who did what and when. Only the hash identifies the entry --
    the raw key and the decrypted content are never logged or stored."""
    conn = get_db()
    conn.execute(
        "INSERT INTO activity_log (key_hash, action, ip_address, user_agent) VALUES (?, ?, ?, ?)",
        (key_hash[:16], action, request.remote_addr, request.headers.get("User-Agent", "")[:255]),
    )
    conn.commit()
    conn.close()


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def key_hash_exists(key_hash):
    conn = get_db()
    existing = conn.execute(
        "SELECT 1 FROM entries WHERE key_hash = ?", (key_hash,)
    ).fetchone()
    conn.close()
    return existing is not None


def is_valid_key(key):
    return bool(key) and len(key) >= MIN_KEY_LENGTH


# ---------------------------------------------------------------------------
# Encryption helpers
#
# The key the user types is never stored anywhere -- only:
#   1) a SHA-256 hash of it, used purely to look the entry up, and
#   2) a random salt, used to derive the actual encryption key.
#
# PBKDF2-HMAC-SHA256 turns (key + salt) into a Fernet key. To decrypt, the
# same key string must be supplied again -- reproducing the same hash (to
# find the row) AND the same derived key (to open it). The host only ever
# sees the hash and the salt, never the key itself, so they can't reverse
# either one back into the original passphrase.
# ---------------------------------------------------------------------------

def derive_fernet_key(key: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(key.encode("utf-8")))


def encrypt_bytes(data: bytes, key: str):
    salt = os.urandom(16)
    fernet_key = derive_fernet_key(key, salt)
    token = Fernet(fernet_key).encrypt(data)
    return token, salt


def decrypt_bytes(token: bytes, key: str, salt: bytes) -> bytes:
    fernet_key = derive_fernet_key(key, salt)
    return Fernet(fernet_key).decrypt(token)  # raises InvalidToken on wrong key


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


@app.route("/save-text", methods=["POST"])
def save_text():
    text = request.form.get("content", "").strip()
    key = request.form.get("encryption_key", "")

    if not text:
        flash("Please enter some text before saving.")
        return redirect(url_for("home"))

    if not is_valid_key(key):
        flash(f"Please set an encryption key of at least {MIN_KEY_LENGTH} characters. You'll need it again to retrieve this.")
        return redirect(url_for("home"))

    key_hash = hash_key(key)
    if key_hash_exists(key_hash):
        flash("That key is already in use. Please choose a different one.")
        return redirect(url_for("home"))

    token, salt = encrypt_bytes(text.encode("utf-8"), key)

    conn = get_db()
    conn.execute(
        "INSERT INTO entries (key_hash, entry_type, content, salt) VALUES (?, 'text', ?, ?)",
        (key_hash, token.decode("ascii"), base64.b64encode(salt).decode("ascii")),
    )
    conn.commit()
    conn.close()
    log_activity(key_hash, "save")
    return render_template("saved.html", key=key)


@app.route("/save-file", methods=["POST"])
def save_file():
    file = request.files.get("file")
    key = request.form.get("encryption_key", "")

    if not file or file.filename == "":
        flash("Please choose a file to upload.")
        return redirect(url_for("home"))

    if not is_valid_key(key):
        flash(f"Please set an encryption key of at least {MIN_KEY_LENGTH} characters. You'll need it again to retrieve this.")
        return redirect(url_for("home"))

    key_hash = hash_key(key)
    if key_hash_exists(key_hash):
        flash("That key is already in use. Please choose a different one.")
        return redirect(url_for("home"))

    original_name = file.filename
    ext = os.path.splitext(original_name)[1]
    stored_name = f"{key_hash}{ext}.enc"

    token, salt = encrypt_bytes(file.read(), key)
    with open(os.path.join(app.config["UPLOAD_FOLDER"], stored_name), "wb") as f:
        f.write(token)

    conn = get_db()
    conn.execute(
        """INSERT INTO entries (key_hash, entry_type, original_filename, stored_filename, salt)
           VALUES (?, 'file', ?, ?, ?)""",
        (key_hash, original_name, stored_name, base64.b64encode(salt).decode("ascii")),
    )
    conn.commit()
    conn.close()
    log_activity(key_hash, "save")
    return render_template("saved.html", key=key)


@app.route("/retrieve", methods=["GET", "POST"])
def retrieve():
    if request.method == "GET":
        return render_template("retrieve.html", entry=None)

    key = request.form.get("encryption_key", "").strip()
    if not key:
        flash("Please enter your encryption key.")
        return render_template("retrieve.html", entry=None)

    key_hash = hash_key(key)

    conn = get_db()
    entry = conn.execute(
        "SELECT * FROM entries WHERE key_hash = ?", (key_hash,)
    ).fetchone()
    conn.close()

    if entry is None:
        flash("No data found for that key.")
        log_activity(key_hash, "retrieve_fail")
        return render_template("retrieve.html", entry=None)

    salt = base64.b64decode(entry["salt"])

    if entry["entry_type"] == "text":
        try:
            plaintext = decrypt_bytes(entry["content"].encode("ascii"), key, salt).decode("utf-8")
        except (InvalidToken, ValueError):
            flash("No data found for that key.")
            log_activity(key_hash, "retrieve_fail")
            return render_template("retrieve.html", entry=None)

        log_activity(key_hash, "retrieve_success")
        return render_template(
            "retrieve.html",
            entry={"entry_type": "text", "content": plaintext},
        )

    # File entry: confirm it decrypts, then hand the browser a small form
    # (holding the key) that posts to /download to fetch it.
    try:
        with open(os.path.join(app.config["UPLOAD_FOLDER"], entry["stored_filename"]), "rb") as f:
            decrypt_bytes(f.read(), key, salt)  # validate only; discard the result
    except (InvalidToken, ValueError, FileNotFoundError):
        flash("No data found for that key.")
        log_activity(key_hash, "retrieve_fail")
        return render_template("retrieve.html", entry=None)

    log_activity(key_hash, "retrieve_success")
    return render_template(
        "retrieve.html",
        entry={
            "entry_type": "file",
            "key": key,
            "original_filename": entry["original_filename"],
        },
    )


@app.route("/download", methods=["POST"])
def download():
    key = request.form.get("encryption_key", "").strip()
    key_hash = hash_key(key)

    conn = get_db()
    entry = conn.execute(
        "SELECT * FROM entries WHERE key_hash = ? AND entry_type = 'file'", (key_hash,)
    ).fetchone()
    conn.close()

    if entry is None:
        flash("No data found for that key.")
        return redirect(url_for("retrieve"))

    salt = base64.b64decode(entry["salt"])
    try:
        with open(os.path.join(app.config["UPLOAD_FOLDER"], entry["stored_filename"]), "rb") as f:
            plaintext = decrypt_bytes(f.read(), key, salt)
    except (InvalidToken, ValueError, FileNotFoundError):
        flash("No data found for that key.")
        log_activity(key_hash, "retrieve_fail")
        return redirect(url_for("retrieve"))

    # Stream the decrypted bytes from a short-lived temp file, then delete it
    # as soon as the response finishes -- the plaintext never stays on disk.
    tmp_name = f"_tmp_{entry['stored_filename']}"
    tmp_path = os.path.join(app.config["UPLOAD_FOLDER"], tmp_name)
    with open(tmp_path, "wb") as f:
        f.write(plaintext)

    log_activity(key_hash, "download")

    response = send_from_directory(
        app.config["UPLOAD_FOLDER"],
        tmp_name,
        as_attachment=True,
        download_name=entry["original_filename"],
    )
    response.call_on_close(lambda: os.path.exists(tmp_path) and os.remove(tmp_path))
    return response


# ---------------------------------------------------------------------------
# Admin (host) dashboard -- audit-only.
#
# The host can see every save/retrieve/download event (which entry, by a
# short hash prefix, from which IP, at what time) so they know the app is
# being used and by whom. The host can NEVER see the decrypted content or
# the encryption key itself -- neither is ever stored anywhere.
# ---------------------------------------------------------------------------

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if request.form.get("password", "") == ADMIN_PASSWORD:
            session["is_admin"] = True
            return redirect(url_for("admin_dashboard"))
        flash("Incorrect admin password.")
    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("admin_login"))


@app.route("/admin", methods=["GET"])
@admin_required
def admin_dashboard():
    conn = get_db()
    entries = conn.execute(
        """SELECT key_hash, entry_type, original_filename, created_at, updated_at, edit_count
           FROM entries ORDER BY created_at DESC"""
    ).fetchall()
    activity = conn.execute(
        """SELECT key_hash, action, ip_address, user_agent, created_at
           FROM activity_log ORDER BY id DESC LIMIT 200"""
    ).fetchall()
    conn.close()
    return render_template("admin.html", entries=entries, activity=activity)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
