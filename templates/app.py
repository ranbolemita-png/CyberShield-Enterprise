from flask import Flask, render_template, jsonify, request, Response, session, redirect, url_for
import sqlite3
import datetime
import requests
import urllib3
import csv
import io
from apscheduler.schedulers.background import BackgroundScheduler

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = 'cybershield_secret_key_for_insa'

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

# አውቶማቲክ ቅኝት የሚያካሂደው ፈንክሽን
def scheduled_audit_job():
    with app.app_context():
        # በራስ ሰር የሚቃኙ ቁልፍ ታርጌቶች (ለምሳሌ የባንክ ወይም የಸರ್ል ስልጠና ዌብሳይቶች)
        targets = ["https://mtu.edu.et", "https://www.gov.et"]
        
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
        print("[INFO] Scheduled automated security scan completed successfully.")

# በጀርባ በሰዓት አንዴ (ወይም በደቂቃ) እንዲሰራ ማቀናበር (ለሙከራ በየ 2 ደቂቃው እንዲሰራ አድርገነዋል)
scheduler = BackgroundScheduler()
scheduler.add_job(func=scheduled_audit_job, trigger="interval", minutes=2)
scheduler.start()

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        conn = sqlite3.connect('cybershield.db')
        cursor = conn.cursor()
        cursor.execute('SELECT username, role FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['username'] = user[0]
            session['role'] = user[1]
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid username! Try 'admin_rambo' or 'auditor_insa'."
            
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', username=session['username'], role=session['role'])

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
    
    logs = [
        {"target": row[0], "date": row[1], "status": row[2], "risk": row[3]}
        for row in rows
    ]
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
    
    if not target.startswith('http://') and not target.startswith('https://'):
        target_url = 'https://' + target
    else:
        target_url = target

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

if __name__ == 'main':
    app.run(debug=True)