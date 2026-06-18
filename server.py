
import json, os, sqlite3, hashlib, secrets
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from functools import wraps

app = Flask(__name__, static_folder=os.path.dirname(os.path.abspath(__file__)))
CORS(app, supports_credentials=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "data.db")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
USE_PG = bool(DATABASE_URL)

if USE_PG:
    import psycopg2
    from psycopg2.extras import RealDictCursor

def get_db_sqlite():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, date TEXT NOT NULL, weight REAL, poop INTEGER DEFAULT 0, FOREIGN KEY (user_id) REFERENCES users(id), UNIQUE(user_id, date))")
    conn.execute("CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, token TEXT UNIQUE NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id))")
    conn.commit()
    return conn

def get_db_pg():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    with conn.cursor() as cur:
        cur.execute("CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(100) UNIQUE NOT NULL, password_hash VARCHAR(200) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
        cur.execute("CREATE TABLE IF NOT EXISTS records (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), date VARCHAR(20) NOT NULL, weight REAL, poop INTEGER DEFAULT 0, UNIQUE(user_id, date))")
        cur.execute("CREATE TABLE IF NOT EXISTS sessions (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), token VARCHAR(200) UNIQUE NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.commit()
    return conn

def get_db():
    return get_db_pg() if USE_PG else get_db_sqlite()

def hash_password(password):
    return hashlib.sha256((password + "habit_tracker_salt_2026").encode()).hexdigest()

def generate_token():
    return secrets.token_hex(32)

def get_user_by_token(token):
    if not token:
        return None
    conn = get_db()
    try:
        if USE_PG:
            with conn.cursor() as cur:
                cur.execute("SELECT user_id FROM sessions WHERE token = %s", (token,))
                row = cur.fetchone()
                return row["user_id"] if row else None
        else:
            row = conn.execute("SELECT user_id FROM sessions WHERE token = ?", (token,)).fetchone()
            return row["user_id"] if row else None
    finally:
        conn.close()

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
        ph = hash_password(password)
        if USE_PG:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, ph))
                cur.execute("SELECT id FROM users WHERE username = %s", (username,))
                user_id = cur.fetchone()["id"]
                token = generate_token()
                cur.execute("INSERT INTO sessions (user_id, token) VALUES (%s, %s)", (user_id, token))
            conn.commit()
            conn.close()
        else:
            conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, ph))
            conn.commit()
            user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            token = generate_token()
            conn.execute("INSERT INTO sessions (user_id, token) VALUES (?, ?)", (user["id"], token))
            conn.commit()
            conn.close()
        return jsonify({"ok": True, "token": token, "username": username})
    except Exception as e:
        conn.close()
        if "UNIQUE" in str(e) or "duplicate" in str(e).lower():
            return jsonify({"error": "用户名已存在"}), 400
        return jsonify({"error": str(e)[:100]}), 400

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if not username or not password:
        return jsonify({"error": "用户名或密码不能为空"}), 400
    conn = get_db()
    try:
        ph = hash_password(password)
        if USE_PG:
            with conn.cursor() as cur:
                cur.execute("SELECT id, username FROM users WHERE username = %s AND password_hash = %s", (username, ph))
                user = cur.fetchone()
                if not user:
                    return jsonify({"error": "用户名或密码错误"}), 403
                token = generate_token()
                cur.execute("INSERT INTO sessions (user_id, token) VALUES (%s, %s)", (user["id"], token))
                conn.commit()
                return jsonify({"ok": True, "token": token, "username": user["username"]})
        else:
            user = conn.execute("SELECT id, username FROM users WHERE username = ? AND password_hash = ?", (username, ph)).fetchone()
            if not user:
                return jsonify({"error": "用户名或密码错误"}), 403
            token = generate_token()
            conn.execute("INSERT INTO sessions (user_id, token) VALUES (?, ?)", (user["id"], token))
            conn.commit()
            return jsonify({"ok": True, "token": token, "username": user["username"]})
    finally:
        conn.close()

@app.route("/api/logout", methods=["POST"])
@require_auth
def logout():
    token = request.headers.get("Authorization", "").replace("Bearer ", "") or request.args.get("token", "")
    conn = get_db()
    try:
        if USE_PG:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM sessions WHERE token = %s", (token,))
        else:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True})

@app.route("/api/me", methods=["GET"])
@require_auth
def me():
    conn = get_db()
    try:
        if USE_PG:
            with conn.cursor() as cur:
                cur.execute("SELECT id, username, created_at FROM users WHERE id = %s", (request.user_id,))
                user = cur.fetchone()
        else:
            user = conn.execute("SELECT id, username, created_at FROM users WHERE id = ?", (request.user_id,)).fetchone()
        if not user:
            return jsonify({"error": "not found"}), 404
        return jsonify({"id": user["id"], "username": user["username"], "created_at": str(user["created_at"])})
    finally:
        conn.close()

# ---- Records API ----
@app.route("/api/records", methods=["GET"])
@require_auth
def get_records():
    year = request.args.get("year")
    month = request.args.get("month")
    conn = get_db()
    try:
        if USE_PG:
            with conn.cursor() as cur:
                prefix = f"{year}-{int(month):02d}" if year and month else ""
                if prefix:
                    cur.execute("SELECT date, weight, poop FROM records WHERE user_id = %s AND date LIKE %s", (request.user_id, prefix + "%"))
                else:
                    cur.execute("SELECT date, weight, poop FROM records WHERE user_id = %s", (request.user_id,))
                rows = cur.fetchall()
        else:
            if year and month:
                prefix = f"{year}-{int(month):02d}"
                rows = conn.execute("SELECT date, weight, poop FROM records WHERE user_id = ? AND date LIKE ?", (request.user_id, prefix + "%")).fetchall()
            else:
                rows = conn.execute("SELECT date, weight, poop FROM records WHERE user_id = ?", (request.user_id,)).fetchall()
        result = {}
        for r in rows:
            entry = {}
            if r["weight"] is not None:
                entry["weight"] = r["weight"]
            if r["poop"]:
                entry["poop"] = True
            result[r["date"]] = entry
        return jsonify(result)
    finally:
        conn.close()

@app.route("/api/records/<date>", methods=["PUT"])
@require_auth
def put_record(date):
    record = request.get_json(silent=True) or {}
    conn = get_db()
    try:
        weight = record.get("weight")
        poop = 1 if record.get("poop") else 0
        if USE_PG:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO records (user_id, date, weight, poop) VALUES (%s, %s, %s, %s) ON CONFLICT (user_id, date) DO UPDATE SET weight = %s, poop = %s",
                           (request.user_id, date, weight, poop, weight, poop))
        else:
            if weight is not None:
                conn.execute("INSERT OR REPLACE INTO records (user_id, date, weight, poop) VALUES (?, ?, ?, ?)",
                            (request.user_id, date, weight, poop))
            else:
                conn.execute("INSERT OR REPLACE INTO records (user_id, date, weight, poop) VALUES (?, ?, ?, ?)",
                            (request.user_id, date, None, poop))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True})

@app.route("/api/records/<date>", methods=["DELETE"])
@require_auth
def delete_record(date):
    conn = get_db()
    try:
        if USE_PG:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM records WHERE user_id = %s AND date = %s", (request.user_id, date))
        else:
            conn.execute("DELETE FROM records WHERE user_id = ? AND date = ?", (request.user_id, date))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    import socket
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    db_type = "PostgreSQL" if USE_PG else "SQLite"
    print(f"=== \u670d\u52a1\u5df2\u542f\u52a8\uff01===")
    print(f"   \u6570\u636e\u5e93: {db_type}")
    print(f"   \u672c\u673a\u8bbf\u95ee: http://localhost:{port}")
    print(f"   \u5c40\u57df\u7f51\u8bbf\u95ee: http://{local_ip}:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
