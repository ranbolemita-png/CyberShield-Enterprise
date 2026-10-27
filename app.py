from flask import Flask, render_template, jsonify, request, Response, session, redirect, url_for
import sqlite3
import datetime
import requests
import urllib3
import csv
import io
from apscheduler.schedulers.background import BackgroundScheduler
from collections import defaultdict
import time
import socket
from concurrent.futures import ThreadPoolExecutor
import psutil
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = 'cybershield_secret_key_for_insa'

login_attempts = defaultdict(lambda: {'count': 0, 'lockout_until': 0})

def init_db():
    conn = sqlite3.connect('cybershield.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_ip TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            status TEXT NOT NULL,
            risk_score TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE NOT NULL,
            added_by TEXT NOT NULL
        )
    ''')
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        cursor.execute('INSERT INTO users (username, role) VALUES (?, ?)', ('admin_rambo', 'Admin'))
        cursor.execute('INSERT INTO users (username, role) VALUES (?, ?)', ('auditor_insa', 'Auditor'))
    
    conn.commit()
    conn.close()

init_db()

def send_telegram_alert(target, risk):
    TOKEN = "8943827924:AAEibTknm-iIlgZqwGaI2wE_d8xEZpRRsf0"
    CHAT_ID = "6496119890"
    
    message = f"🚨 *CyberShield Automated Security Alert!*\n\n🌐 Target: `{target}`\n⚠️ Status: *{risk}*\n⏰ Time: `{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
    
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    
    try:
        requests.post(url, json=payload, timeout=5)
    except Exception as e:
        print(f"Telegram alert failed: {e}")

def scheduled_audit_job():
    with app.app_context():
        conn = sqlite3.connect('cybershield.db')
        cursor = conn.cursor()
        cursor.execute('SELECT url FROM targets')
        rows = cursor.fetchall()
        conn.close()
        
        targets = [row[0] for row in rows] if rows else ["https://mtu.edu.et", "https://www.gov.et"]
        
        for target in targets:
            risk_score = "Low Risk"
            status = "Completed"
            try:
                response = requests.get(target, timeout=5, verify=False)
                headers = response.headers
                
                owasp_security_headers = [
                    'Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options',
                    'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy',
                    'Cross-Origin-Opener-Policy', 'Cross-Origin-Resource-Policy',
                    'Cross-Origin-Embedder-Policy', 'Cache-Control',
                    'X-Permitted-Cross-Domain-Policies', 'Clear-Site-Data'
                ]
                
                missing_headers = sum(1 for h in owasp_security_headers if h not in headers)

                if missing_headers >= 8:
                    risk_score = f"High Risk ({missing_headers}/12 Headers Missing)"
                    send_telegram_alert(target, risk_score)
                elif missing_headers >= 4:
                    risk_score = f"Medium Risk ({missing_headers}/12 Headers Missing)"
                elif missing_headers > 0:
                    risk_score = f"Low-Medium Risk ({missing_headers}/12 Headers Missing)"
                else:
                    risk_score = "Low Risk (Secure - All OWASP Headers Present)"

            except Exception as e:
                risk_score = "Unreachable / Error"
                status = "Failed"

            current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            conn = sqlite3.connect('cybershield.db')
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO scan_logs (target_ip, scan_date, status, risk_score) VALUES (?, ?, ?, ?)',
                (target + " [Automated]", current_time, status, risk_score)
            )
            conn.commit()
            conn.close()

scheduler = BackgroundScheduler()
scheduler.add_job(func=scheduled_audit_job, trigger="interval", hours=12)
scheduler.start()

# --- Public Routes ---
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/services')
def services():
    return render_template('services.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

# --- Auth & Dashboard ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    client_ip = request.remote_addr
    record = login_attempts[client_ip]
    
    if record['lockout_until'] > time.time():
        remaining = int(record['lockout_until'] - time.time())
        error = f"Too many failed login attempts! Locked out for {remaining} seconds."
        return render_template('login.html', error=error)

    if request.method == 'POST':
        username = request.form.get('username')
        conn = sqlite3.connect('cybershield.db')
        cursor = conn.cursor()
        cursor.execute('SELECT username, role FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            login_attempts[client_ip] = {'count': 0, 'lockout_until': 0}
            session['username'] = user[0]
            session['role'] = user[1]
            return redirect(url_for('dashboard'))
        else:
            record['count'] += 1
            if record['count'] >= 3:
                record['lockout_until'] = time.time() + 30
                error = "Too many failed attempts. Locked out for 30 seconds!"
                record['count'] = 0
            else:
                error = f"Invalid username! Attempts left: {3 - record['count']}"
            
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', username=session['username'], role=session['role'])

# --- APIs ---
@app.route('/api/scans', methods=['GET'])
def get_scan_history():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
        
    conn = sqlite3.connect('cybershield.db')
    cursor = conn.cursor()
    cursor.execute('SELECT target_ip, scan_date, status, risk_score FROM scan_logs ORDER BY id DESC')
    rows = cursor.fetchall()
    
    cursor.execute('SELECT risk_score, COUNT(*) FROM scan_logs GROUP BY risk_score')
    risk_stats = {row[0]: row[1] for row in cursor.fetchall()}
    conn.close()
    
    logs = [{"target": row[0], "date": row[1], "status": row[2], "risk": row[3]} for row in rows]
    return jsonify({"logs": logs, "stats": risk_stats})

@app.route('/api/export-csv', methods=['GET'])
def export_csv():
    if 'username' not in session:
        return redirect(url_for('login'))
        
    conn = sqlite3.connect('cybershield.db')
    cursor = conn.cursor()
    cursor.execute('SELECT target_ip, scan_date, status, risk_score FROM scan_logs ORDER BY id DESC')
    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Target IP / Domain', 'Date & Time', 'Status', 'Risk Score'])
    for row in rows:
        writer.writerow(row)

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=cybershield_enterprise_report.csv"}
    )

@app.route('/api/start-audit', methods=['POST'])
def start_audit():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
        
    data = request.json
    target = data.get('target', '127.0.0.1')
    target_url = target if target.startswith('http://') or target.startswith('https://') else 'https://' + target

    risk_score = "Low Risk"
    status = "Completed"

    try:
        response = requests.get(target_url, timeout=5, verify=False)
        headers = response.headers
        
        owasp_security_headers = [
            'Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options',
            'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy',
            'Cross-Origin-Opener-Policy', 'Cross-Origin-Resource-Policy',
            'Cross-Origin-Embedder-Policy', 'Cache-Control',
            'X-Permitted-Cross-Domain-Policies', 'Clear-Site-Data'
        ]
        
        missing_headers = sum(1 for h in owasp_security_headers if h not in headers)

        if missing_headers >= 8:
            risk_score = f"High Risk ({missing_headers}/12 Headers Missing)"
            send_telegram_alert(target, risk_score)
        elif missing_headers >= 4:
            risk_score = f"Medium Risk ({missing_headers}/12 Headers Missing)"
        elif missing_headers > 0:
            risk_score = f"Low-Medium Risk ({missing_headers}/12 Headers Missing)"
        else:
            risk_score = "Low Risk (Secure - All OWASP Headers Present)"

    except Exception as e:
        risk_score = "Unreachable / Error"
        status = "Failed"

    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect('cybershield.db')
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO scan_logs (target_ip, scan_date, status, risk_score) VALUES (?, ?, ?, ?)',
        (target, current_time, status, risk_score)
    )
    conn.commit()
    conn.close()
    
    return jsonify({"message": f"Audit completed for: {target}", "risk": risk_score})

@app.route('/api/targets', methods=['GET', 'POST'])
def manage_targets():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
        
    conn = sqlite3.connect('cybershield.db')
    cursor = conn.cursor()
    
    if request.method == 'POST':
        data = request.json
        target_url = data.get('url')
        if target_url:
            try:
                cursor.execute('INSERT INTO targets (url, added_by) VALUES (?, ?)', (target_url, session['username']))
                conn.commit()
            except sqlite3.IntegrityError:
                pass
        
    cursor.execute('SELECT id, url, added_by FROM targets ORDER BY id DESC')
    targets = [{"id": row[0], "url": row[1], "added_by": row[2]} for row in cursor.fetchall()]
    conn.close()
    
    return jsonify({"targets": targets})

@app.route('/api/targets/<int:target_id>', methods=['DELETE'])
def delete_target(target_id):
    if 'username' not in session or session.get('role') != 'Admin':
        return jsonify({"error": "Unauthorized / Admin only"}), 403
        
    conn = sqlite3.connect('cybershield.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM targets WHERE id = ?', (target_id,))
    conn.commit()
    conn.close()
    
    return jsonify({"message": "Target deleted successfully"})

def scan_single_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return port
    except Exception:
        return None
    return None

@app.route('/api/scan-ports', methods=['POST'])
def scan_ports_api():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    target_host = data.get('target', '127.0.0.1')
    target_host = target_host.replace('https://', '').replace('http://', '').split('/')[0]

    try:
        target_ip = socket.gethostbyname(target_host)
    except Exception:
        return jsonify({"error": f"Could not resolve host: {target_host}"}), 400

    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]
    open_ports = []

    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(lambda p: scan_single_port(target_ip, p), common_ports)
        for port in results:
            if port:
                open_ports.append(port)

    risk = "Low Risk (Standard Ports)"
    if 21 in open_ports or 23 in open_ports or 3389 in open_ports:
        risk = "High Risk (Unsecured Management/FTP Port Open!)"
        send_telegram_alert(target_host, f"Open Critical Ports Detected: {open_ports}")

    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect('cybershield.db')
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO scan_logs (target_ip, scan_date, status, risk_score) VALUES (?, ?, ?, ?)',
        (f"{target_host} [Port Scan: {open_ports}]", current_time, "Completed", risk)
    )
    conn.commit()
    conn.close()

    return jsonify({"target": target_host, "ip": target_ip, "open_ports": open_ports, "risk": risk})

@app.route('/api/scan-vulnerabilities', methods=['POST'])
def scan_vulnerabilities():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    target = data.get('target', '127.0.0.1')
    target_url = target if target.startswith('http://') or target.startswith('https://') else 'https://' + target

    vulnerabilities = []
    risk_level = "Secure"
    sqli_payloads = ["' OR '1'='1", "' UNION SELECT NULL--"]
    xss_payloads = ["<script>alert('XSS')</script>", "\"><script>alert(1)</script>"]

    try:
        for payload in sqli_payloads:
            test_url = f"{target_url}/?q={payload}"
            res = requests.get(test_url, timeout=4, verify=False)
            if "sql" in res.text.lower() or "syntax" in res.text.lower() or "database" in res.text.lower():
                vulnerabilities.append("Potential SQL Injection (SQLi) Vulnerability Detected")
                break

        for payload in xss_payloads:
            test_url = f"{target_url}/?search={payload}"
            res = requests.get(test_url, timeout=4, verify=False)
            if payload in res.text:
                vulnerabilities.append("Reflected Cross-Site Scripting (XSS) Vulnerability Detected")
                break

        if vulnerabilities:
            risk_level = "High Risk (Vulnerabilities Found)"
            send_telegram_alert(target, f"Security Warning: {vulnerabilities}")
        else:
            risk_level = "Low Risk (No basic SQLi/XSS reflected)"

    except Exception as e:
        risk_level = "Scan Failed / Target Unreachable"
        vulnerabilities.append(str(e))

    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect('cybershield.db')
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO scan_logs (target_ip, scan_date, status, risk_score) VALUES (?, ?, ?, ?)',
        (target + " [Vuln Scan]", current_time, "Completed", risk_level)
    )
    conn.commit()
    conn.close()

    return jsonify({"target": target, "vulnerabilities": vulnerabilities if vulnerabilities else ["None detected"], "risk": risk_level})

@app.route('/api/export-pdf', methods=['GET'])
def export_pdf():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('cybershield.db')
    cursor = conn.cursor()
    cursor.execute('SELECT target_ip, scan_date, status, risk_score FROM scan_logs ORDER BY id DESC')
    rows = cursor.fetchall()
    conn.close()

    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    p.setFillColorRGB(0.02, 0.1, 0.2)
    p.rect(0, height - 80, width, 80, fill=1, stroke=0)
    
    p.setFillColorRGB(1, 1, 1)
    p.setFont("Helvetica-Bold", 20)
    p.drawString(50, height - 45, "CyberShield Enterprise Security Report")
    
    p.setFont("Helvetica", 10)
    p.drawString(50, height - 62, f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | INSA & Banking Standard")

    y = height - 120
    p.setFillColorRGB(0.1, 0.1, 0.1)
    p.setFont("Helvetica-Bold", 11)
    p.drawString(50, y, "Target IP / Domain")
    p.drawString(220, y, "Date & Time")
    p.drawString(380, y, "Status")
    p.drawString(450, y, "Risk Score")

    p.setStrokeColorRGB(0.7, 0.7, 0.7)
    p.line(50, y - 5, width - 50, y - 5)

    y -= 25
    p.setFont("Helvetica", 9)

    for row in rows:
        if y < 50:
            p.showPage()
            y = height - 50

        p.drawString(50, y, str(row[0])[:30])
        p.drawString(220, y, str(row[1]))
        p.drawString(380, y, str(row[2]))
        p.drawString(450, y, str(row[3])[:20])
        y -= 20

    p.save()
    buffer.seek(0)

    return Response(
        buffer.getvalue(),
        mimetype='application/pdf',
        headers={"Content-Disposition": "attachment;filename=CyberShield_Security_Report.pdf"}
    )

@app.route('/api/system-stats', methods=['GET'])
def system_stats():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    cpu_usage = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    return jsonify({"cpu": cpu_usage, "ram": memory.percent, "disk": disk.percent})

if __name__ == '__main__':
    app.run(debug=True)