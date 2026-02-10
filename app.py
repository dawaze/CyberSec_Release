from flask import Flask, render_template, request, redirect, url_for, session, g, flash, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import subprocess
import shlex
import sys
import codecs
import time
import sqlite3
from datetime import datetime
import threading
import os
from cryptography.fernet import Fernet, InvalidToken
import hashlib 
import base64
from groq import Groq
import json

sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())
sys.stderr = codecs.getwriter("utf-8")(sys.stderr.detach())
GROQ_API_KEY = "PUT_GROQ_API_KEY_RIGHT_HERE"
groq_client = Groq(api_key=GROQ_API_KEY)

app = Flask(__name__)
app.config.from_pyfile('config.py')
from forms import RegForm, LoginForm, CryptoForm

from groq import Groqr

client = Groq(api_key=GROQ_API_KEY)
def ask_groq(question):
    try:
        chat_completion = groq_client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": question,
                }
            ],
            model="openai/gpt-oss-120b",
            temperature=0.7,                 
            max_tokens=1024,                  
            top_p=0.9,
        )
        
        return chat_completion.choices[0].message.content.strip()
    
    except Exception as e:
        return f"Groq Error: {str(e)}"
@app.route('/ai-assistant', methods=['GET', 'POST'])
@login_required
def ai_assistant():
    response = ""
    
    if request.method == 'POST':
        user_question = request.form.get('question', '').strip()
        if user_question:
            response = ask_groq(user_question)
    
    return render_template('ai_assistant.html', response=response)


ALLOWED_TARGETS = [
    "scanme.nmap.org",       
    "localhost",
    "127.0.0.1",
]

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin):
    def __init__(self, id, login, first_name, last_name, email, password, role="user"):
        self.id = id
        self.login = login
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.password = password
        self.role = role
    @property
    def is_admin(self):
        return self.role == 'admin'
    

def connect_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def add_user(conn, login, first_name, last_name, email, hpsw):
    c = conn.cursor()
    try:
        conn.execute(
            "INSERT INTO users (login, first_name, last_name, email, password) "
            "VALUES (?, ?, ?, ?, ?)",
            (login, first_name, last_name, email, hpsw)
        )
        conn.commit()
        return True

    except sqlite3.IntegrityError:
        return False

    except sqlite3.Error as e:
        print(e)
        return False
    
def add_scan(conn, user_id, target, result):
    c = conn.cursor()
    try:
        conn.execute(
            "INSERT INTO scans (user_id, target, result) "
            "VALUES (?, ?, ?)",
            (user_id, target, result)
        )
        conn.commit()
        return True

    except sqlite3.IntegrityError:
        return False

    except sqlite3.Error as e:
        print(e)
        return False
    
def add_crypto_log(conn, user_id, cipher_type, operation, input_text, result):
    c = conn.cursor()
    c.execute(
        "INSERT INTO crypto_logs (user_id, cipher_type, operation, input_text, result, date) "
        "VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
        (user_id, cipher_type, operation, input_text, result)
    )
    conn.commit() 


def get_db():
    if not hasattr(g, 'link_db'):
        g.link_db = connect_db()
    return g.link_db


@login_manager.user_loader
def load_user(user_id):
    db = connect_db()
    conn = db.cursor()
    conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user_data = conn.fetchone()   
    if user_data: 
        return User(user_data['id'], user_data['login'], user_data['first_name'], user_data['last_name'], user_data['email'], user_data['password'], user_data['role']) 

@app.route("/", methods=['POST', 'GET'])
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET","POST"])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        db = get_db()
        c = db.cursor()
        c.execute("SELECT * FROM users WHERE login = ?", (form.login.data,))
        user_data = c.fetchone()
        
        if user_data and check_password_hash(user_data['password'], form.psw.data):
            user_obj = User(user_data['id'], user_data['login'], user_data['first_name'], user_data['last_name'], user_data['email'], user_data['password']) 
            login_user(user_obj)
            return redirect(url_for("index"))
        else:
            flash("Wrong password or login")
            
    return render_template("login.html", form=form)


@app.route("/reg", methods=["GET", "POST"])
def reg():
    form = RegForm()

    if form.validate_on_submit(): 
        db = get_db()
        password_hash = generate_password_hash(form.psw.data)

        if add_user(
            db,
            form.login.data,
            form.first_name.data,
            form.last_name.data,
            form.email.data,
            password_hash
        ):
            return redirect(url_for("login"))
        else:
            flash("Login or email already taken", category="error_taken")

    return render_template("reg.html", form=form)
    
@app.route('/success')
def success():
    return render_template('success.html')    
@app.route('/crypto', methods=['GET', 'POST'])
@login_required
def crypto():
    form = CryptoForm()
    result = None

    if form.validate_on_submit():
        cipher_type = form.cipher_type.data
        operation = form.operation.data
        text = form.text.data.strip()
        key = form.key.data.strip() if form.key.data else 'default_key'

        try:
            if cipher_type == 'sha256':
                result = hashlib.sha256(text.encode()).hexdigest()
                operation = 'hash'
            
            elif cipher_type == 'sha512':
                result = hashlib.sha512(text.encode()).hexdigest()
                operation = 'hash'
            
            elif cipher_type == 'md5':
                result = hashlib.md5(text.encode()).hexdigest()
                operation = 'hash'

            elif cipher_type == 'caesar':
                try:
                    shift = int(key)
                except ValueError:
                    shift = 3
                
                if operation == 'encrypt':
                    result = ''.join(
                        chr((ord(c) - 65 + shift) % 26 + 65) if c.isupper() else 
                        chr((ord(c) - 97 + shift) % 26 + 97) if c.islower() else c 
                        for c in text
                    )
                else:
                    result = ''.join(
                        chr((ord(c) - 65 - shift) % 26 + 65) if c.isupper() else 
                        chr((ord(c) - 97 - shift) % 26 + 97) if c.islower() else c 
                        for c in text
                    )

            elif cipher_type == 'vigenere':
                if not key:
                    key = 'KEY'
                key = key.upper()
                result = ''
                k_index = 0
                for c in text:
                    if c.isalpha():
                        base = 65 if c.isupper() else 97
                        shift = ord(key[k_index % len(key)]) - 65
                        result += chr((ord(c) - base + (shift if operation == 'encrypt' else -shift)) % 26 + base)
                        k_index += 1
                    else:
                        result += c

            elif cipher_type == 'aes':
                key_bytes = hashlib.sha256(key.encode()).digest()
                fernet = Fernet(base64.urlsafe_b64encode(key_bytes[:32]))
                
                if operation == 'encrypt':
                    result = fernet.encrypt(text.encode()).decode()
                else:
                    try:
                        result = fernet.decrypt(text.encode()).decode()
                    except InvalidToken:
                        result = "Invalid key or corrupted data"

            elif cipher_type == 'base64':
                if operation == 'encrypt':
                    result = base64.b64encode(text.encode()).decode()
                else:
                    try:
                        result = base64.b64decode(text.encode()).decode()
                    except Exception:
                        result = "Invalid Base64 string"

            if result:
                db = get_db()
                c = db.cursor()
                c.execute(
                    "INSERT INTO crypto_logs (user_id, cipher_type, operation, input_text, result, date) "
                    "VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
                    (current_user.id, cipher_type, operation, text, result)
                )
                db.commit()
                db.close()

        except Exception as e:
            result = None

    return render_template('crypto.html', form=form, result=result)

scan_results = {}

@app.route('/social-engineering', methods=['GET', 'POST'])
@login_required
def social_engineering():
    if request.method == 'POST':
        db = get_db()
        c = db.cursor()

        correct = {
            'q1': "Call the bank using official number",
            'q2': "Hang up and call IT yourself",
            'q3': "Ignore it",
            'q4': "Ask in person or via official channel",
            'q5': "Throw it away",
            'q6': "Ignore and check official tracking",
            'q7': "Hang up immediately",
            'q8': "Ignore and report",
            'q9': "Contact them another way",
            'q10': "Never provide early"
        }

        score = 0
        answers = {}

        for q in correct:
            answer = request.form.get(q)
            if answer:
                answers[q] = answer
                if answer == correct[q]:
                    score += 1

        import json
        answers_json = json.dumps(answers)
        
        c.execute(
            "INSERT INTO social_logs (user_id, scenario, input_text, result, score, date) "
            "VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
            (current_user.id, "Awareness Test (10 questions)", answers_json, f"Score: {score}/10", score)
        )
        db.commit()
        db.close()

        return redirect(url_for('account_social'))

    return render_template('social_engineering.html')

@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    if request.method == 'POST':
        data = request.get_json()
        target = data.get('target', '').strip()
        scan_type = data.get('scan_type', 'quick')
        
        if not target:
            return jsonify({'error': 'No target specified'}), 400
        
        if target not in ALLOWED_TARGETS:
            return jsonify({'error': 'Scan only allowed for whitelisted targets (e.g., scanme.nmap.org)'}), 403
        
        # Определяем флаги в зависимости от типа сканирования
        scan_flags = {
            'quick': ['-T4', '-F'],
            'standard': ['-sV'],
            'intensive': ['-A', '-T4'],
            'stealth': ['-sS', '-T2']
        }
        
        flags = scan_flags.get(scan_type, ['-sV'])
        
        try:
            cmd = ['nmap'] + flags + [target]
            result = subprocess.check_output(cmd, text=True, timeout=180, stderr=subprocess.STDOUT)
            
            db = connect_db()
            add_scan(db, current_user.id, target, result)
            
            return jsonify({'output': result})
        
        except subprocess.TimeoutExpired:
            return jsonify({'error': 'Scan timed out (180 seconds)'}), 504
        
        except subprocess.CalledProcessError as e:
            return jsonify({'error': f'Nmap error: {e.output}'}), 500
        
        except Exception as e:
            return jsonify({'error': f'Unknown error: {str(e)}'}), 500
    
    time = datetime.now().strftime("%Y-%m-%d %H:%M")
    return render_template('scan.html', time=time)


@app.route('/dirsearch', methods=['GET', 'POST'])
@login_required
def dirsearch():
    result = ""
    found_count = 0
    target = ""

    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        if not target:
            flash("Enter target URL", "error")
            return render_template('dirsearch.html', result=result, target=target, found_count=found_count)

        allowed = ["scanme.nmap.org", "testphp.vulnweb.com", "localhost", "127.0.0.1", "zero.webappsecurity.com"]
        if target not in allowed and not target.startswith("http://localhost") and not target.startswith("http://127.0.0.1"):
            flash("Scanning allowed only on test targets (scanme.nmap.org, localhost, etc.)", "error")
            return render_template('dirsearch.html', result=result, target=target, found_count=found_count)

        try:
            cmd = [
                "dirsearch",
                "-u", target,
  
                "-t", "20",           
                "--no-color"
            ]
            output = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, timeout=300)

            lines = output.splitlines()
            found = [line for line in lines if "200" in line or "301" in line or "302" in line or "403" in line]
            found_count = len(found)

            db = get_db()
            c = db.cursor()
            c.execute(
                "INSERT INTO dirsearch_logs (user_id, target, result, found_count, date) "
                "VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
                (current_user.id, target, output, found_count)
            )
            db.commit()
            db.close()

            result = output

        except subprocess.TimeoutExpired:
            result = "Timeout after 300 seconds"
        except subprocess.CalledProcessError as e:
            result = f"Dirsearch error: {e.output}"
        except FileNotFoundError:
            result = "Dirsearch not found on server. Install it first."
        except Exception as e:
            result = f"Unexpected error: {str(e)}"

    return render_template('dirsearch.html', result=result, target=target, found_count=found_count)
    
@app.route('/account')
@login_required
def account():
    return render_template('account.html')

@app.route('/account/scan', methods=['GET', 'POST'])
@login_required
def account_scan():
    db = get_db()
    c = db.cursor()

    if request.method == 'POST':
        data = request.get_json()
        scan_id = data.get('scan_id')

        if not scan_id:
            return jsonify({'success': False, 'error': 'Scan ID not provided'})
        c.execute("DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, current_user.id))
        db.commit()

        if c.rowcount > 0:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Scan not found or access denied'})

    c.execute("SELECT id, target, result, date FROM scans WHERE user_id = ? ORDER BY date DESC", (current_user.id,))
    scan_history = [dict(row) for row in c.fetchall()]

    return render_template('account_scan.html', scan_history=scan_history)


@app.route('/account/crypto', methods=['GET', 'POST'])
@login_required
def account_crypto():
    db = get_db()
    c = db.cursor()

    if request.method == 'POST':
        data = request.get_json()
        log_id = data.get('log_id')

        if not log_id:
            return jsonify({'success': False, 'error': 'Log ID not provided'})

        c.execute("DELETE FROM crypto_logs WHERE id = ? AND user_id = ?", (log_id, current_user.id))
        db.commit()

        if c.rowcount > 0:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Log not found or access denied'})

    c.execute("SELECT COUNT(*) FROM crypto_logs WHERE user_id = ?", (current_user.id,))
    total = c.fetchone()[0]

    if total > 15:
        c.execute("""
            DELETE FROM crypto_logs 
            WHERE user_id = ? 
            AND id NOT IN (
                SELECT id FROM crypto_logs 
                WHERE user_id = ? 
                ORDER BY date DESC 
                LIMIT 15
            )
        """, (current_user.id, current_user.id))
        db.commit()

    c.execute("""
        SELECT id, cipher_type, operation, input_text, result, date 
        FROM crypto_logs 
        WHERE user_id = ? 
        ORDER BY date DESC 
        LIMIT 15
    """, (current_user.id,))
    crypto_history = [dict(row) for row in c.fetchall()]

    db.close() 

    return render_template('account_crypto.html', crypto_history=crypto_history)

@app.route('/account/social', methods=['GET', 'POST'])
@login_required
def account_social():
    db = get_db()
    c = db.cursor()

    if request.method == 'POST':
        delete_id = request.form.get('delete_id')
        
        if delete_id:
            c.execute("DELETE FROM social_logs WHERE id = ? AND user_id = ?", (delete_id, current_user.id))
            db.commit()
            return redirect(url_for('account_social'))

    correct_answers = {
        'q1': "Call the bank using official number",
        'q2': "Hang up and call IT yourself",
        'q3': "Ignore it",
        'q4': "Ask in person or via official channel",
        'q5': "Throw it away",
        'q6': "Ignore and check official tracking",
        'q7': "Hang up immediately",
        'q8': "Ignore and report",
        'q9': "Contact them another way",
        'q10': "Never provide early"
    }

    c.execute("SELECT id, scenario, input_text, result, score, date FROM social_logs WHERE user_id = ? ORDER BY date DESC LIMIT 15", (current_user.id,))
    rows = c.fetchall()
    
    social_history = []
    for row in rows:
        test_dict = dict(row)
        
        try:
            input_text = row['input_text']
            
            if input_text.startswith('{'):
                test_dict['answers_dict'] = json.loads(input_text)
            else:
                cleaned = input_text.replace("'", '"')
                test_dict['answers_dict'] = json.loads(cleaned)
        except Exception as e:
            print(f"Error parsing answers: {e}, input_text: {row['input_text']}")
            test_dict['answers_dict'] = {}
        
        test_dict['correct_answers'] = type('obj', (object,), correct_answers)
        
        social_history.append(test_dict)

    return render_template('account_social.html', social_history=social_history)
    
@app.route('/account/dirsearch', methods=['GET', 'POST'])
@login_required
def account_dirsearch():
    db = get_db()
    c = db.cursor()

    if request.method == 'POST':
        data = request.get_json()
        log_id = data.get('log_id')

        if not log_id:
            return jsonify({'success': False, 'error': 'Log ID not provided'})

        c.execute("DELETE FROM dirsearch_logs WHERE id = ? AND user_id = ?", (log_id, current_user.id))
        db.commit()

        if c.rowcount > 0:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Log not found or access denied'})

    c.execute("""
        SELECT id, target, result, found_count, date 
        FROM dirsearch_logs 
        WHERE user_id = ? 
        ORDER BY date DESC 
        LIMIT 15
    """, (current_user.id,))
    dirsearch_history = [dict(row) for row in c.fetchall()]

    db.close()

    return render_template('account_dirsearch.html', dirsearch_history=dirsearch_history)    
    
@app.route('/admin')
@login_required
def admin():
    if not current_user.role == 'admin':
        flash("Access denied. Admins only.", "error")
        return redirect(url_for('index'))

    db = get_db()
    c = db.cursor()

    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM scans")
    total_scans = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM crypto_logs")
    total_crypto = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM social_logs")
    total_social = c.fetchone()[0]
    
    c.execute("SELECt COUNT(*) FROM dirsearch_logs")
    total_dirsearch = c.fetchone()[0]
    
    c.execute("""
        SELECT 
            id, login, first_name, last_name, email, role,
            (SELECT COUNT(*) FROM scans WHERE user_id = users.id) AS scan_count,
            (SELECT COUNT(*) FROM crypto_logs WHERE user_id = users.id) AS crypto_count,
            (SELECT COUNT(*) FROM social_logs WHERE user_id = users.id) AS social_count,
            (SELECT COUNT(*) FROM social_logs WHERE user_id = users.id) AS dirsearch_count
        FROM users
        ORDER BY id
    """)
    users = [dict(row) for row in c.fetchall()]

    db.close()

    return render_template('admin.html',
                          total_users=total_users,
                          total_scans=total_scans,
                          total_crypto=total_crypto,
                          total_social=total_social,
                          total_dirsearch=total_dirsearch,
                          users=users)   
    
@app.route('/admin/delete/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        abort(403)

    if user_id == current_user.id:
        return redirect(url_for('admin'))

    db = get_db()
    c = db.cursor()
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    db.close()
    
    return redirect(url_for('admin'))   
    
    
@app.route("/logout", methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'link_db'):
        g.link_db.close()

if __name__ == "__main__":
    app.run(debug=True, port=4000)
