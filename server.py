import hashlib, secrets, os
from flask import Flask, request, jsonify, send_from_directory, session

app = Flask(__name__, static_folder='.')
app.secret_key = secrets.token_hex(32)

# Passwords stored as SHA-256 hashes — plain text never lives in code
USERS = {
    'eli':   '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',  # test
    'ethan': '1b376fecd7314b27d8e8878b4c064e0d81455cd7b88c9bc6f18dcc11aeff697a',  # ethansux
}

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

# ── API ──────────────────────────────────────────────────────────────

@app.post('/api/login')
def login():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    expected = USERS.get(username)
    if expected and secrets.compare_digest(hash_pw(password), expected):
        session['user'] = username
        return jsonify({'ok': True})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.post('/api/logout')
def logout():
    session.clear()
    return jsonify({'ok': True})

@app.get('/api/check')
def check():
    if session.get('user'):
        return jsonify({'user': session['user']})
    return jsonify({'error': 'Unauthorized'}), 401

# ── STATIC FILES ────────────────────────────────────────────────────

@app.get('/')
def index():
    return send_from_directory('.', 'index.html')

@app.get('/<path:filename>')
def static_files(filename):
    return send_from_directory('.', filename)

# ── MAIN ────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f'\n  deadend creative — running at http://localhost:{port}\n')
    app.run(debug=False, port=port)
