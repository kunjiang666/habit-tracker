import json, os, sqlite3
from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
from functools import wraps
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=BASE_DIR)
CORS(app, supports_credentials=True)

DB_FILE = os.path.join(BASE_DIR, 'data.db')
PASSWORD = os.environ.get('APP_PASSWORD', '')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute('CREATE TABLE IF NOT EXISTS records (date TEXT PRIMARY KEY, weight REAL, poop INTEGER DEFAULT 0)')
    conn.commit()
    return conn

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if PASSWORD and not session.get('authenticated'):
            return jsonify({'error': 'unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

# --- Serve frontend ---
@app.route('/')
def serve_index():
    return send_from_directory(BASE_DIR, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(BASE_DIR, path)

# --- Auth ---
@app.route('/api/check-auth')
def check_auth():
    if not PASSWORD:
        return jsonify({'auth': True, 'required': False})
    return jsonify({'auth': session.get('authenticated', False), 'required': True})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    if data.get('password') == PASSWORD:
        session['authenticated'] = True
        return jsonify({'ok': True})
    return jsonify({'error': 'wrong password'}), 403

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('authenticated', None)
    return jsonify({'ok': True})

# --- API ---
@app.route('/api/records', methods=['GET'])
@require_auth
def get_records():
    year = request.args.get('year')
    month = request.args.get('month')
    conn = get_db()
    if year and month:
        prefix = f'{year}-{int(month):02d}'
        rows = conn.execute('SELECT * FROM records WHERE date LIKE ?', (prefix + '%',)).fetchall()
    else:
        rows = conn.execute('SELECT * FROM records').fetchall()
    conn.close()
    result = {}
    for r in rows:
        entry = {}
        if r['weight'] is not None:
            entry['weight'] = r['weight']
        if r['poop']:
            entry['poop'] = True
        result[r['date']] = entry
    return jsonify(result)

@app.route('/api/records/<date>', methods=['PUT'])
@require_auth
def put_record(date):
    record = request.get_json(silent=True) or {}
    conn = get_db()
    weight = record.get('weight')
    poop = 1 if record.get('poop') else 0
    if weight is not None:
        conn.execute('INSERT OR REPLACE INTO records (date, weight, poop) VALUES (?, ?, ?)',
                     (date, weight, poop))
    else:
        conn.execute('INSERT OR REPLACE INTO records (date, weight, poop) VALUES (?, ?, ?)',
                     (date, None, poop))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/api/records/<date>', methods=['DELETE'])
@require_auth
def delete_record(date):
    conn = get_db()
    conn.execute('DELETE FROM records WHERE date = ?', (date,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    import socket
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    auth_status = '已启用' if PASSWORD else '未启用'
    print('=== 服务已启动！===')
    print(f'   本机访问: http://localhost:{port}')
    print(f'   局域网访问: http://{local_ip}:{port}')
    print(f'   密码认证: {auth_status}')
    if PASSWORD:
        print(f'   密码: {PASSWORD}')
    print(f'   按 Ctrl+C 停止服务')
    app.run(host='0.0.0.0', port=port, debug=False)
