from flask import Flask, request, render_template, redirect, url_for, session, flash
import psycopg2
import hashlib
import os
import redis
from flask_session import Session
import time

app = Flask(__name__)
app.secret_key = os.urandom(24)

# connection  Redis
redis_client = redis.StrictRedis(host='redis', port=6379, db=0)

# config session
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis_client
Session(app)

# connection postgres
conn = psycopg2.connect(
    dbname='postgres',
    user='postgres',
    password=os.getenv('POSTGRES_PASSWORD'),
    host='db'
)

def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()

def is_banned(ip: str, username: str) -> bool:
    ip_key = f"ban:ip:{ip}"
    username_key = f"ban:username:{username}"
    return redis_client.exists(ip_key) or redis_client.exists(username_key)

def increment_login_attempts(ip: str, username: str) -> int:
    key = f"login_attempts:{ip}:{username}"
    pipe = redis_client.pipeline()
    pipe.incr(key)
    pipe.expire(key, 180)  # 3 minutes
    result = pipe.execute()
    return result[0]

def ban_user(ip: str, username: str):
    ip_key = f"ban:ip:{ip}"
    username_key = f"ban:username:{username}"
    pipe = redis_client.pipeline()
    pipe.setex(ip_key, 180, 1)  # 3 minutes
    pipe.setex(username_key, 180, 1)  # 3 minutes
    pipe.execute()

@app.route('/')
def index():
    return render_template('index.html', title='Home')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        salt = os.urandom(16)
        password_hash = hash_password(password, salt)
        
        with conn.cursor() as cur:
            cur.execute("INSERT INTO users (username, password_hash, salt) VALUES (%s, %s, %s)", (username, password_hash, salt.hex()))
            conn.commit()
        
        flash('User registered successfully')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    session.pop('_flashes', None)
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip = request.remote_addr
        
        if is_banned(ip, username):
            flash('Too many failed attempts. Please try again later.')
            return render_template('login.html', title='Login')
        
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash, salt FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
        
        if user:
            stored_password_hash, salt = user
            salt = bytes.fromhex(salt)
            if hash_password(password, salt) == stored_password_hash:
                session['username'] = username
                flash('Login successful')
                return redirect(url_for('index'))
        
        attempts = increment_login_attempts(ip, username)
        if attempts >= 3:
            ban_user(ip, username)
            flash('Too many failed attempts. You are banned for 3 minutes.')
        else:
            flash('Invalid credentials')
    return render_template('login.html', title='Login')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0')