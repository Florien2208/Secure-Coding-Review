import os
from flask import Flask, request, jsonify, session
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import re
from datetime import timedelta
from flask_talisman import Talisman

app = Flask(__name__)

# Secure configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(app, key_func=get_remote_address)
Talisman(app, force_https=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)

def is_valid_username(username):
    return re.match(r'^[a-zA-Z0-9_]{3,20}$', username) is not None

def is_strong_password(password):
    return (len(password) >= 12 and
            re.search(r"\d", password) and
            re.search(r"[A-Z]", password) and
            re.search(r"[a-z]", password) and
            re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
@csrf.exempt  # Exempt for API usage, implement token-based auth for better security
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    if not username or not password:
        return jsonify({"status": "error", "message": "Invalid input"}), 400
    
    user = User.query.filter_by(username=username).first()
    
    if user and user.locked_until and user.locked_until > datetime.utcnow():
        return jsonify({"status": "error", "message": "Account temporarily locked"}), 403
    
    if user and check_password_hash(user.password, password):
        session.clear()
        session['user_id'] = user.id
        user.failed_attempts = 0
        db.session.commit()
        return jsonify({"status": "success", "message": "Login successful"})
    else:
        if user:
            user.failed_attempts += 1
            if user.failed_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=15)
            db.session.commit()
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

@app.route('/register', methods=['POST'])
@limiter.limit("5 per hour")
@csrf.exempt  # Exempt for API usage, implement token-based auth for better security
def register():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    if not username or not password:
        return jsonify({"status": "error", "message": "Invalid input"}), 400
    
    if not is_valid_username(username):
        return jsonify({"status": "error", "message": "Invalid username format"}), 400
    
    if not is_strong_password(password):
        return jsonify({"status": "error", "message": "Password does not meet complexity requirements"}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({"status": "error", "message": "Username already exists"}), 409
    
    new_user = User(username=username, password=generate_password_hash(password))
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"status": "success", "message": "User registered successfully"})

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"status": "success", "message": "Logged out successfully"})

if __name__ == '__main__':
    db.create_all()
    app.run(ssl_context='adhoc')  