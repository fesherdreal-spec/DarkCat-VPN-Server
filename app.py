import os
import sys
import time
import hashlib
import secrets
import logging
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, request, jsonify, g, session, render_template
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy.engine import URL
import redis
from redis.exceptions import ConnectionError, TimeoutError, AuthenticationError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Импортируем Blueprint для фронтенда
from front import frontend_bp

# --- Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
)
load_dotenv()
app = Flask(__name__)

# --- CRITICAL: Secret Management ---
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    logging.critical("FATAL: SECRET_KEY environment variable is not set or is too short (must be at least 32 bytes).")
    sys.exit(1)
app.config['SECRET_KEY'] = SECRET_KEY

# --- Session Configuration ---
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_USE_SIGNER"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = 86400

# --- Redis Configuration ---
REDIS_HOST = os.getenv("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
REDIS_USE_TLS = os.getenv("REDIS_USE_TLS", "False").lower() in ('true', '1', 't')
REDIS_CONNECT_TIMEOUT = 3

try:
    redis_connection_params = {
        'host': REDIS_HOST,
        'port': REDIS_PORT,
        'db': REDIS_DB,
        'socket_connect_timeout': REDIS_CONNECT_TIMEOUT,
        'decode_responses': False,
        'password': REDIS_PASSWORD if REDIS_PASSWORD else None
    }
    if REDIS_USE_TLS:
        logging.info(f"Connecting to Redis at {REDIS_HOST}:{REDIS_PORT} with TLS enabled.")
        redis_connection_params['ssl'] = True
        redis_connection_params['ssl_cert_reqs'] = 'required'
    
    if not REDIS_PASSWORD and REDIS_HOST not in ('127.0.0.1', 'localhost'):
        logging.warning(f"!!! SECURITY WARNING: Connecting to remote Redis at {REDIS_HOST}:{REDIS_PORT} without a password. This is NOT recommended.")

    redis_client = redis.Redis(**redis_connection_params)
    redis_client.ping()
    
    app.config["SESSION_TYPE"] = "redis"
    app.config["SESSION_REDIS"] = redis_client
    logging.info(f"Session backend configured to use Redis at {REDIS_HOST}:{REDIS_PORT}")
except AuthenticationError:
    logging.critical(f"FATAL: Redis authentication failed. Check REDIS_PASSWORD.")
    sys.exit(1)
except (ConnectionError, TimeoutError) as e:
    logging.critical(f"FATAL: Could not connect to Redis at {REDIS_HOST}:{REDIS_PORT}. Error: {e}")
    sys.exit(1)

Session(app)

# --- Database Configuration (SQLAlchemy) ---
DB_TYPE = os.getenv("DB_TYPE", "sqlite").lower()
db_url = None
if DB_TYPE == "sqlite":
    DB_NAME = os.getenv("DB_NAME", "vpn_server.db")
    db_url = URL.create(drivername="sqlite", database=DB_NAME)
    logging.info(f"Using SQLite database: {DB_NAME}")
elif DB_TYPE == "postgres":
    db_url = URL.create(
        drivername="postgresql",
        username=os.getenv("POSTGRES_USER"),
        password=os.getenv("POSTGRES_PASSWORD"),
        host=os.getenv("POSTGRES_HOST"),
        port=os.getenv("POSTGRES_PORT"),
        database=os.getenv("POSTGRES_DB")
    )
    logging.info(f"Using PostgreSQL database: {db_url.host}:{db_url.port}/{db_url.database}")
elif DB_TYPE == "mysql":
    db_url = URL.create(
        drivername="mysql+mysqlconnector",
        username=os.getenv("MYSQL_USER"),
        password=os.getenv("MYSQL_PASSWORD"),
        host=os.getenv("MYSQL_HOST"),
        port=os.getenv("MYSQL_PORT"),
        database=os.getenv("MYSQL_DB")
    )
    logging.info(f"Using MySQL database: {db_url.host}:{db_url.port}/{db_url.database}")
else:
    logging.critical(f"FATAL: Unsupported DB_TYPE '{DB_TYPE}'. Use 'sqlite', 'postgres', or 'mysql'.")
    sys.exit(1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 3600,
}
db = SQLAlchemy(app)

# --- Rate Limiting ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour", "50 per minute"],
    storage_uri=f"redis{'s' if REDIS_USE_TLS else ''}://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}",
    storage_options={"password": REDIS_PASSWORD} if REDIS_PASSWORD else {}
)

# --- WSGI Middleware ---
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# --- Constants ---
DEFAULT_CONFIG = os.getenv("DEFAULT_CONFIG", "vless://placeholder")
ALLOWED_ADMIN_IPS = {ip.strip() for ip in os.getenv("ADMIN_IPS", "127.0.0.1,::1").split(",") if ip.strip()}
PBKDF2_ITERATIONS = 600000
ROOT_ADMIN_USER = os.getenv("ROOT_ADMIN_USER")
if not ROOT_ADMIN_USER:
    logging.critical("FATAL: ROOT_ADMIN_USER environment variable is not set. This is required.")
    sys.exit(1)

# --- Database Model (SQLAlchemy ORM) ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    hashed_password = db.Column(db.String(256), nullable=False)
    config_link = db.Column(db.Text, nullable=True)
    config_name = db.Column(db.String(120), nullable=False, default='Server Default')
    role = db.Column(db.String(10), nullable=False, default='user', index=True)
    last_seen = db.Column(db.Float, default=0)
    expire_date = db.Column(db.Float, default=0)

# --- CLI Command for DB Initialization ---
@app.cli.command('init-db')
def init_db_command():
    db.create_all()
    if User.query.filter_by(username=ROOT_ADMIN_USER).count() == 0:
        temp_password = secrets.token_hex(16)
        hashed_password = hash_password(temp_password)
        admin_user = User(username=ROOT_ADMIN_USER, hashed_password=hashed_password, role='admin')
        db.session.add(admin_user)
        db.session.commit()
        print(f"!!! CRITICAL: Created initial root admin '{ROOT_ADMIN_USER}' with temporary password: {temp_password}", file=sys.stderr)
        print(f"!!! This password will only be shown once. Change it immediately after login.", file=sys.stderr)
    print("Database initialized.")

# --- Security & Helpers ---
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
    return f"{salt.hex()}:{pwd_hash.hex()}"

def verify_password(stored_password: str, provided_password: str) -> bool:
    if not stored_password or ':' not in stored_password:
        return False
    try:
        salt_hex, pwd_hash_stored_hex = stored_password.split(':')
        salt = bytes.fromhex(salt_hex)
    except (ValueError, AttributeError):
        return False
    pwd_hash_provided = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
    return secrets.compare_digest(pwd_hash_stored_hex.encode(), pwd_hash_provided.hex().encode())

def is_request_from_admin_ip(request) -> bool:
    return request.remote_addr in ALLOWED_ADMIN_IPS

# --- Blueprint Registration ---
app.register_blueprint(frontend_bp)

# --- Global Error Handlers ---
@app.errorhandler(400)
def bad_request_error(error):
    if request.path.startswith('/admin/') or request.path.startswith('/login'):
        return jsonify({"status": "error", "message": "Bad Request"}), 400
    return render_template('400.html'), 400

@app.errorhandler(403)
def forbidden_error(error):
    if request.path.startswith('/admin/') or request.path.startswith('/login'):
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    return render_template('403.html'), 403

@app.errorhandler(404)
def not_found_error(error):
    if request.path.startswith('/admin/') or request.path.startswith('/login'):
        return jsonify({"status": "error", "message": "Not Found"}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    if request.path.startswith('/admin/') or request.path.startswith('/login'):
        return jsonify({"status": "error", "message": "Internal Server Error"}), 500
    return render_template('500.html'), 500

# --- Security Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id: return jsonify({"status": "error", "message": "Unauthorized"}), 401
        g.current_user = User.query.get(user_id)
        if g.current_user is None:
            session.clear()
            return jsonify({"status": "error", "message": "Unauthorized: User not found"}), 401
        return f(*args, **kwargs)
    return decorated_function

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if g.current_user.role != required_role:
                logging.warning(f"Permission denied for user '{g.current_user.username}'. Required: {required_role}, has: {g.current_user.role}")
                return jsonify({"status": "error", "message": "Forbidden"}), 403
            if required_role == 'admin' and not is_request_from_admin_ip(request):
                logging.warning(f"Admin action by '{g.current_user.username}' DENIED from untrusted IP: {request.remote_addr}")
                return jsonify({"status": "error", "message": "Forbidden: Admin access from this IP is not allowed"}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- API: Public Routes ---
@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    if not data: return jsonify({"status": "error", "message": "Invalid JSON"}), 400
    username = data.get('username')
    password = data.get('password')
    if not (username and password): return jsonify({"status": "error", "message": "Missing credentials"}), 400
    user = User.query.filter_by(username=username).first()
    if not user or not verify_password(user.hashed_password, password):
        logging.warning(f"Failed login attempt for user '{username}' from {request.remote_addr}")
        time.sleep(secrets.randbelow(1000) / 1000.0 + 0.5)
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401
    session.clear()
    session['user_id'] = user.id
    session['username'] = user.username
    session['role'] = user.role
    logging.info(f"Successful login for user '{username}' from {request.remote_addr}")
    current_config, config_name, expired_alert = user.config_link, user.config_name, False
    if user.expire_date > 0 and time.time() > user.expire_date:
        user.config_link, user.config_name, user.expire_date = "", "Expired", 0
        db.session.commit()
        current_config, config_name, expired_alert = "", "Expired", True
    return jsonify({"status": "success", "message": "Login successful", "role": user.role, "config": current_config, "config_name": config_name, "expired_alert": expired_alert})

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    return jsonify({"status": "success", "message": "Logged out successfully"})

@app.route('/register', methods=['POST'])
@limiter.limit("5 per hour")
def register():
    if not os.getenv("ALLOW_REGISTRATION", "False").lower() in ('true', '1', 't'):
        return jsonify({"status": "error", "message": "Registration is disabled"}), 403
    data = request.get_json()
    if not data: return jsonify({"status": "error", "message": "Invalid JSON"}), 400
    username = data.get('username')
    password = data.get('password')
    if not (username and password and len(password) >= 12):
        return jsonify({"status": "error", "message": "Username and a password of at least 12 characters are required"}), 400
    try:
        new_user = User(username=username, hashed_password=hash_password(password), config_link=DEFAULT_CONFIG, config_name='Starter Pack')
        db.session.add(new_user)
        db.session.commit()
        logging.info(f"New user registered: '{username}'")
        return jsonify({"status": "success", "message": "User registered successfully"}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({"status": "error", "message": "Username already exists"}), 409
    except Exception as e:
        db.session.rollback()
        logging.error(f"Registration failed for '{username}': {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

# --- API: Authenticated Routes ---
@app.route('/heartbeat', methods=['POST'])
@login_required
def heartbeat():
    g.current_user.last_seen = time.time()
    db.session.commit()
    return jsonify({"status": "ok"})

# --- API: ADMIN ROUTES ---
@app.route('/admin/users', methods=['GET'])
@role_required('admin')
def get_all_users():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    paginated_users = User.query.paginate(page=page, per_page=per_page, error_out=False)
    user_list = []
    current_time = time.time()
    for u in paginated_users.items:
        days_left_str = "∞"
        if u.expire_date > 0:
            days_left_str = f"{int((u.expire_date - current_time) / 86400)}d" if u.expire_date > current_time else "Expired"
        user_list.append({"id": u.id, "username": u.username, "role": u.role, "status": "ONLINE" if (current_time - u.last_seen) < 60 else "OFFLINE", "has_config": bool(u.config_link), "config_name": u.config_name or "N/A", "days_left": days_left_str})
    return jsonify({"users": user_list, "total": paginated_users.total, "pages": paginated_users.pages, "current_page": paginated_users.page})

@app.route('/admin/update_config', methods=['POST'])
@role_required('admin')
def update_user_config():
    data = request.get_json()
    if not data: return jsonify({"status": "error", "message": "Invalid JSON"}), 400
    target_username = data.get('target_user')
    if not target_username: return jsonify({"status": "error", "message": "target_user is required"}), 400
    target_user = User.query.filter_by(username=target_username).first()
    if not target_user: return jsonify({"status": "error", "message": "User not found"}), 404
    days = data.get('days')
    if days is not None:
        try:
            target_user.expire_date = (time.time() + (int(days) * 86400)) if int(days) > 0 else 0
        except (ValueError, TypeError):
            return jsonify({"status": "error", "message": "'days' must be an integer"}), 400
    if 'config' in data: target_user.config_link = data['config']
    if 'config_name' in data: target_user.config_name = data['config_name']
    db.session.commit()
    logging.info(f"Config updated for user '{target_username}' by admin '{g.current_user.username}'")
    return jsonify({"status": "success"})

@app.route('/admin/delete_user', methods=['POST'])
@role_required('admin')
def delete_user():
    data = request.get_json()
    if not data: return jsonify({"status": "error", "message": "Invalid JSON"}), 400
    target_username = data.get('target_user')
    if not target_username: return jsonify({"status": "error", "message": "target_user is required"}), 400
    if target_username == g.current_user.username: return jsonify({"status": "error", "message": "Cannot delete your own account"}), 403
    if target_username == ROOT_ADMIN_USER: return jsonify({"status": "error", "message": "Cannot delete the root admin account"}), 403
    target_user = User.query.filter_by(username=target_username).first()
    if not target_user: return jsonify({"status": "error", "message": "User not found"}), 404
    if target_user.role == 'admin' and g.current_user.username != ROOT_ADMIN_USER:
        return jsonify({"status": "error", "message": "Forbidden: Only the root admin can delete other admin accounts"}), 403
    db.session.delete(target_user)
    db.session.commit()
    logging.info(f"User '{target_username}' deleted by admin '{g.current_user.username}'")
    return jsonify({"status": "success"})

@app.route('/admin/reset_password', methods=['POST'])
@role_required('admin')
def reset_password():
    data = request.get_json()
    if not data: return jsonify({"status": "error", "message": "Invalid JSON"}), 400
    target_username = data.get('target_user')
    new_password = data.get('new_password')
    if not (target_username and new_password): return jsonify({"status": "error", "message": "target_user and new_password are required"}), 400
    if len(new_password) < 12: return jsonify({"status": "error", "message": "New password must be at least 12 characters long"}), 400
    if target_username == ROOT_ADMIN_USER: return jsonify({"status": "error", "message": "Cannot reset password for the root admin account via API"}), 403
    target_user = User.query.filter_by(username=target_username).first()
    if not target_user: return jsonify({"status": "error", "message": "User not found"}), 404
    if target_user.role == 'admin' and g.current_user.username != ROOT_ADMIN_USER:
         return jsonify({"status": "error", "message": "Forbidden: Only the root admin can reset passwords for other admins"}), 403
    target_user.hashed_password = hash_password(new_password)
    db.session.commit()
    logging.info(f"Password for user '{target_username}' has been reset by admin '{g.current_user.username}'")
    return jsonify({"status": "success"})

if __name__ == '__main__':
    # For development only. In production, use a proper WSGI server like Gunicorn.
    # Example: gunicorn --bind 0.0.0.0:5000 --workers 4 app:app
    DEBUG_MODE = os.getenv("FLASK_DEBUG", "False").lower() in ('true', '1', 't')
    if DEBUG_MODE:
        logging.warning("!!! SECURITY WARNING: Flask is running in DEBUG MODE. DO NOT use this in production.")
    app.run(host='0.0.0.0', port=5000, debug=DEBUG_MODE)