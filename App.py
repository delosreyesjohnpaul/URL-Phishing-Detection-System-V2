from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_dance.contrib.google import make_google_blueprint, google
import sqlite3
import bcrypt
import hashlib
import os
import numpy as np
import pickle
import warnings
import google.generativeai as genai
from feature import FeatureExtraction

# Suppress warnings
warnings.filterwarnings('ignore')

# Flask app setup
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your_flask_secret_key')

# --- Configure Google Gemini (GenAI) ---
genai.configure(api_key=os.environ.get('GEMINI_API_KEY', 'AIzaSyDx4syfU509v0gD8cofsIvUbRpRM-_XqXA'))
model = genai.GenerativeModel(model_name="models/gemini-1.5-flash-latest")

# --- OAuth setup ---
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
google_bp = make_google_blueprint(
    client_id=os.environ.get('GOOGLE_OAUTH_CLIENT_ID', ''),
    client_secret=os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET', ''),
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email"
    ],
    redirect_url="/google_login"
)
app.register_blueprint(google_bp, url_prefix="/login")

# --- Constants ---
DB_FILE = 'users.db'
SECRET_PEPPER = os.environ.get('SECRET_PEPPER', 'my secret pepper')

# --- Load ML models ---
with open("pickle/modele.pkl", "rb") as f_model, \
     open("pickle/vectorizer.pkl", "rb") as f_vect:
    email_clf = pickle.load(f_model)
    email_vect = pickle.load(f_vect)

with open("pickle/model.pkl", "rb") as f_url_model:
    url_clf = pickle.load(f_url_model)

# --- Database Initialization ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
      CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        hashed_password BLOB NOT NULL,
        salt_for_secret BLOB NOT NULL,
        hashed_secret2 BLOB NOT NULL
      )
    ''')
    cursor.execute('''
      CREATE TABLE IF NOT EXISTS url_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        url TEXT NOT NULL,
        confidence REAL NOT NULL,
        is_safe INTEGER NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(username) REFERENCES users(username)
        ON DELETE CASCADE
      )
    ''')
    conn.commit()
    conn.close()

init_db()

# --- Helper Functions for Auth ---
def generate_random_salt():
    return os.urandom(16)

def hash_secret_with_salt(secret, salt):
    return hashlib.sha256(secret.encode('utf-8') + salt).hexdigest()

def get_user_by_email(email):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def create_user(email, password):
    salt_for_secret = generate_random_salt()
    hashed_secret = hash_secret_with_salt(SECRET_PEPPER, salt_for_secret)
    hashed_secret2 = bcrypt.hashpw(hashed_secret.encode('utf-8'), bcrypt.gensalt())
    combined_password = password + hashed_secret2.decode('utf-8')
    final_hashed_password = bcrypt.hashpw(combined_password.encode('utf-8'), bcrypt.gensalt())

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO users (username, hashed_password, salt_for_secret, hashed_secret2) VALUES (?, ?, ?, ?)',
            (email, final_hashed_password, salt_for_secret, hashed_secret2)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def validate_login(email, password):
    user = get_user_by_email(email)
    if not user:
        return False
    stored_hashed_password, salt, hashed_secret2 = user[1], user[2], user[3]
    combined_input = password + hashed_secret2.decode('utf-8')
    return bcrypt.checkpw(combined_input.encode('utf-8'), stored_hashed_password)

# --- Routes ---

@app.route('/', methods=['GET', 'POST'])
def home():
    if 'user' not in session:
        return redirect(url_for('auth'))

    xx = -1
    url = None
    ai_report = None

    if request.method == 'POST':
        url = request.form.get('url').strip()
        if url:
            # ML classifier
            obj = FeatureExtraction(url)
            features = obj.getFeaturesList()
            X = np.array(features).reshape(1, -1)
            y_pred = url_clf.predict(X)[0]
            pro_safe = url_clf.predict_proba(X)[0, 1]
            xx = round(pro_safe, 2)

            # Save to history
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO url_history (username, url, confidence, is_safe) VALUES (?, ?, ?, ?)',
                (session['user'], url, float(pro_safe), int(y_pred))
            )
            conn.commit()
            conn.close()

            # AI analysis via Gemini
            prompt = (
                f"Analyze the URL: {url}. Tell me what kind of site it is (social media, business, scam, phishing) "
                "and whether it is safe or not. Provide a simple sentence conclusion and a concise explanation."
            )
            try:
                response = model.generate_content(prompt)
                ai_report = response.text.strip()
            except Exception as e:
                ai_report = f"Error fetching AI analysis: {e}"

    return render_template('index.html', user=session.get('user'),
                           xx=xx, url=url, ai_report=ai_report)


@app.route('/phishmail')
def phishmail():
    if 'user' not in session:
        return redirect(url_for('auth'))
    return render_template('phishmail.html', user=session['user'])


@app.route('/predict', methods=['POST'])
def predict_email():
    data = request.get_json(force=True, silent=True) or {}
    if not data.get('email'):
        data['email'] = request.form.get('email', '')
    email_text = data['email'].strip()
    if not email_text:
        return jsonify({'error': 'No email content provided.'}), 400

    # existing email ML
    X = email_vect.transform([email_text])
    proba = email_clf.predict_proba(X)[0]
    y_pred = email_clf.predict(X)[0]
    confidence = float(proba.max())
    is_phish = (int(y_pred) == 1) if not isinstance(y_pred, str) else y_pred.lower().startswith('phish')
    prediction = 'Phishing Email' if is_phish else 'Safe Email'

    # new: Gemini‐powered email analysis
    try:
        gen_prompt = (
            f"Below is the full email content. "
            f"First, state in one sentence whether this is a phishing email or a safe email (use exactly those phrases), "
            f"then give a concise explanation that matches your classification:\n\n"
            f"\"\"\"\n{email_text}\n\"\"\""
        )
        ai_resp = model.generate_content(gen_prompt)
        ai_analysis = ai_resp.text.strip()
    except Exception:
        ai_analysis = "Detailed AI analysis unavailable at this time."

    return jsonify({
        'prediction': prediction,
        'confidence': confidence,
        'ai_analysis': ai_analysis
    })


@app.route('/history')
def history():
    if 'user' not in session:
        return redirect(url_for('auth'))
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT url, confidence, is_safe, timestamp FROM url_history '
        'WHERE username = ? ORDER BY timestamp DESC',
        (session['user'],)
    )
    rows = cursor.fetchall()
    conn.close()
    return render_template('history.html', user=session['user'], history=rows)


@app.route('/auth', methods=['GET', 'POST'])
def auth():
    if 'user' in session:
        return redirect(url_for('home'))
    if request.method == 'POST':
        mode = request.form['form_mode']
        email = request.form['email'].strip().lower()
        password = request.form['password']
        if mode == 'signup':
            confirm = request.form.get('confirmPassword')
            if password != confirm:
                flash("Passwords do not match.", "danger")
            elif create_user(email, password):
                flash("Account created! Please log in.", "success")
            else:
                flash("Email already exists.", "warning")
        else:
            if validate_login(email, password):
                session['user'] = email
                flash(f"Welcome back, {email}!", "success")
                return redirect(url_for('home'))
            else:
                flash("Invalid email or password.", "danger")
    return render_template('login.html')


@app.route('/google_login')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))
    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", "danger")
        return redirect(url_for('auth'))
    user_info = resp.json()
    email = user_info.get("email").lower()
    if not get_user_by_email(email):
        dummy_pass = bcrypt.gensalt().decode('utf-8')
        create_user(email, dummy_pass)
    session['user'] = email
    flash(f"Logged in as {email} via Google.", "success")
    return redirect(url_for('home'))


@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logged out successfully.", "info")
    return redirect(url_for('auth'))


if __name__ == '__main__':
    app.run(debug=True)
