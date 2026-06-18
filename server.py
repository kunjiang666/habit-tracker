
import json, os, sqlite3, hashlib, secrets
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from functools import wraps

app = Flask(__name__, static_folder=os.path.dirname(os.path.abspath(__file__)))
CORS(app, supports_credentials=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "data.db")

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, date TEXT NOT NULL, weight REAL, poop INTEGER DEFAULT 0, FOREIGN KEY (user_id) REFERENCES users(id), UNIQUE(user_id, date))")
    conn.execute("CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, token TEXT UNIQUE NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id))")
    conn.commit()
    return conn

def hash_password(password):
    return hashlib.sha256((password + "habit_tracker_salt_2026").encode()).hexdigest()

def generate_token():
    return secrets.token_hex(32)

def get_user_by_token(token):
    if not token:
        return None
    conn = get_db()
    row = conn.execute("SELECT user_id FROM sessions WHERE token = ?", (token,)).fetchone()
    conn.close()
    if row:
        return row["user_id"]
    return None

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "") or request.args.get("token", "")
        user_id = get_user_by_token(token)
        if not user_id:
            return jsonify({"error": "unauthorized"}), 401
        request.user_id = user_id
        return f(*args, **kwargs)
    return decorated

# ---- Serve frontend ----
@app.route("/")
def serve_index():
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/<path:path>")
def serve_static(path):
    return send_from_directory(BASE_DIR, path)

# ---- Auth ----
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if not username or not password:
        return jsonify({"error": "用户名或密码不能为空"}), 400
    if len(username) < 2 or len(username) > 20:
        return jsonify({"error": "用户名需要2-20个字符"}), 400
    if len(password) < 4:
        return jsonify({"error": "密码至少4位"}), 400
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                     (username, hash_password(password)))
        conn.commit()
        user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        token = generate_token()
        conn.execute("INSERT INTO sessions (user_id, token) VALUES (?, ?)", (user["id"], token))
        conn.commit()
        conn.close()
        return jsonify({"ok": True, "token": token, "username": username})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "用户名已存在"}), 400

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if not username or not password:
        return jsonify({"error": "用户名或密码不能为空"}), 400
    conn = get_db()
    user = conn.execute("SELECT id, username FROM users WHERE username = ? AND password_hash = ?",
                        (username, hash_password(password))).fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "用户名或密码错误"}), 403
    token = generate_token()
    conn.execute("INSERT INTO sessions (user_id, token) VALUES (?, ?)", (user["id"], token))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "token": token, "username": user["username"]})

@app.route("/api/logout", methods=["POST"])
@require_auth
def logout():
    token = request.headers.get("Authorization", "").replace("Bearer ", "") or request.args.get("token", "")
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.route("/api/me", methods=["GET"])
@require_auth
def me():
    conn = get_db()
    user = conn.execute("SELECT id, username, created_at FROM users WHERE id = ?", (request.user_id,)).fetchone()
    conn.close()
    if not user:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": user["id"], "username": user["username"], "created_at": user["created_at"]})

# ---- Records API ----
@app.route("/api/records", methods=["GET"])
@require_auth
def get_records():
    year = request.args.get("year")
    month = request.args.get("month")
    conn = get_db()
    if year and month:
        prefix = f"{year}-{int(month):02d}"
        rows = conn.execute("SELECT date, weight, poop FROM records WHERE user_id = ? AND date LIKE ?",
                            (request.user_id, prefix + "%")).fetchall()
    else:
        rows = conn.execute("SELECT date, weight, poop FROM records WHERE user_id = ?",
                            (request.user_id,)).fetchall()
    conn.close()
    result = {}
    for r in rows:
        entry = {}
        if r["weight"] is not None:
            entry["weight"] = r["weight"]
        if r["poop"]:
            entry["poop"] = True
        result[r["date"]] = entry
    return jsonify(result)

@app.route("/api/records/<date>", methods=["PUT"])
@require_auth
def put_record(date):
    record = request.get_json(silent=True) or {}
    conn = get_db()
    weight = record.get("weight")
    poop = 1 if record.get("poop") else 0
    if weight is not None:
        conn.execute("INSERT OR REPLACE INTO records (user_id, date, weight, poop) VALUES (?, ?, ?, ?)",
                     (request.user_id, date, weight, poop))
    else:
        conn.execute("INSERT OR REPLACE INTO records (user_id, date, weight, poop) VALUES (?, ?, ?, ?)",
                     (request.user_id, date, None, poop))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.route("/api/records/<date>", methods=["DELETE"])
@require_auth
def delete_record(date):
    conn = get_db()
    conn.execute("DELETE FROM records WHERE user_id = ? AND date = ?", (request.user_id, date))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    import socket
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print("=== 服务已启动！===")
    print(f"   本机访问: http://localhost:{port}")
    print(f"   局域网访问: http://{local_ip}:{port}")
    print(f"   按 Ctrl+C 停止服务")
    app.run(host="0.0.0.0", port=port, debug=False)
