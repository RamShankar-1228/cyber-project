from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import timedelta, datetime
import re
import secrets
from collections import defaultdict
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.permanent_session_lifetime = timedelta(minutes=30)

# Security configurations
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Hardcoded credentials
VALID_USERNAME = "admin"
VALID_PASSWORD = "cyber123"
FLAG = "flag{y0u_dID_It_Man}"

# IP-based rate limiting storage (in production, use Redis or database)
failed_attempts = defaultdict(lambda: {'count': 0, 'lockout_until': None})
MAX_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)  # 15 minute lockout

# CAPTCHA token storage - tracks which tokens have been used
captcha_tokens = {}  # {token: {'used': bool, 'created_at': datetime, 'ip': str}}
CAPTCHA_TOKEN_EXPIRY = timedelta(minutes=5)

# SQL Injection patterns
SQL_INJECTION_PATTERNS = [
    r"(\bOR\b|\bAND\b).*=.*",
    r"--",
    r"/\*.*\*/",
    r";\s*(DROP|DELETE|INSERT|UPDATE|ALTER|EXEC|EXECUTE|UNION|SELECT)",
    r"\bUNION\b.*\bSELECT\b",
    r"'\s*OR\s*'1'\s*=\s*'1",
    r"'\s*OR\s*1\s*=\s*1",
    r"\bDROP\b.*\bTABLE\b",
    r"\bEXEC\b|\bEXECUTE\b",
    r"xp_cmdshell",
    r"\bWAITFOR\b|\bDELAY\b|\bSLEEP\b",
]

# XSS patterns
XSS_PATTERNS = [
    r"<script.*?>.*?</script>",
    r"javascript:",
    r"on\w+\s*=",
    r"<iframe.*?>",
    r"<embed.*?>",
    r"<object.*?>",
]

def get_client_ip():
    """Get real client IP address, considering proxies"""
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr
    return ip

def generate_captcha_token(ip):
    """Generate a unique CAPTCHA token and track it server-side"""
    token = secrets.token_urlsafe(32)
    captcha_tokens[token] = {
        'used': False,
        'created_at': datetime.now(),
        'ip': ip
    }
    # Clean up old tokens
    cleanup_expired_tokens()
    return token

def cleanup_expired_tokens():
    """Remove expired CAPTCHA tokens"""
    current_time = datetime.now()
    expired_tokens = [
        token for token, data in captcha_tokens.items()
        if current_time - data['created_at'] > CAPTCHA_TOKEN_EXPIRY
    ]
    for token in expired_tokens:
        del captcha_tokens[token]

def validate_captcha_token(token, ip):
    """Validate CAPTCHA token - must exist, not be used, not expired, and match IP"""
    if not token or token not in captcha_tokens:
        return False, "Invalid CAPTCHA token"
    
    token_data = captcha_tokens[token]
    
    # Check if already used
    if token_data['used']:
        return False, "CAPTCHA token already used"
    
    # Check if expired
    if datetime.now() - token_data['created_at'] > CAPTCHA_TOKEN_EXPIRY:
        del captcha_tokens[token]
        return False, "CAPTCHA token expired"
    
    # Check if IP matches
    if token_data['ip'] != ip:
        return False, "CAPTCHA token IP mismatch"
    
    return True, "Valid"

def mark_token_used(token):
    """Mark a CAPTCHA token as used so it can't be reused"""
    if token in captcha_tokens:
        captcha_tokens[token]['used'] = True

def is_ip_locked_out(ip):
    """Check if IP is currently locked out"""
    if ip in failed_attempts:
        lockout_until = failed_attempts[ip]['lockout_until']
        if lockout_until and datetime.now() < lockout_until:
            return True, lockout_until
        elif lockout_until and datetime.now() >= lockout_until:
            # Lockout expired, reset counter
            failed_attempts[ip] = {'count': 0, 'lockout_until': None}
    return False, None

def record_failed_attempt(ip):
    """Record a failed login attempt for an IP"""
    failed_attempts[ip]['count'] += 1
    
    if failed_attempts[ip]['count'] >= MAX_ATTEMPTS:
        failed_attempts[ip]['lockout_until'] = datetime.now() + LOCKOUT_DURATION
        return True  # IP is now locked out
    return False

def reset_failed_attempts(ip):
    """Reset failed attempts on successful login"""
    if ip in failed_attempts:
        failed_attempts[ip] = {'count': 0, 'lockout_until': None}

def rate_limit_check(f):
    """Decorator to check IP-based rate limiting"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = get_client_ip()
        is_locked, lockout_until = is_ip_locked_out(ip)
        
        if is_locked:
            time_remaining = int((lockout_until - datetime.now()).total_seconds() / 60)
            flash(f'Too many failed attempts. Your IP is locked for {time_remaining} more minutes.', 'error')
            return render_template('login.html', locked_out=True, captcha_token='')
        
        return f(*args, **kwargs)
    return decorated_function

def regenerate_session():
    """Regenerate session to prevent session fixation attacks"""
    logged_in = session.get('logged_in')
    username = session.get('username')
    
    session.clear()
    session.modified = True
    
    if logged_in:
        session['logged_in'] = logged_in
        session['username'] = username

def check_sql_injection(user_input):
    """Check if input contains SQL injection patterns"""
    if not user_input:
        return False
    
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True
    return False

def check_xss(user_input):
    """Check if input contains XSS patterns"""
    if not user_input:
        return False
    
    for pattern in XSS_PATTERNS:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True
    return False

def sanitize_input(user_input):
    """Sanitize input - remove dangerous characters"""
    if not user_input:
        return ""
    
    user_input = re.sub(r'<[^>]*>', '', user_input)
    user_input = re.sub(r'--.*$', '', user_input)
    user_input = re.sub(r'/\*.*?\*/', '', user_input)
    user_input = user_input.replace('\x00', '')
    
    return user_input.strip()

def validate_input(user_input, field_name):
    """Validate input for SQL injection and XSS"""
    if not user_input:
        return f"{field_name} is required", None
    
    if check_sql_injection(user_input):
        return f"{field_name} contains potential SQL injection patterns", None
    
    if check_xss(user_input):
        return f"{field_name} contains potential XSS patterns", None
    
    sanitized = sanitize_input(user_input)
    
    if len(sanitized) < 3:
        return f"{field_name} must be at least 3 characters", None
    
    if len(sanitized) > 50:
        return f"{field_name} must not exceed 50 characters", None
    
    return None, sanitized

@app.after_request
def set_security_headers(response):
    """Set security headers on all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com;"
    return response

@app.route('/')
def home():
    """Home route"""
    if session.get('logged_in'):
        return redirect(url_for('success'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@rate_limit_check
def login():
    """Login route with IP-based rate limiting"""
    ip = get_client_ip()
    
    # Generate new CAPTCHA token for each page load (GET request)
    if request.method == 'GET':
        captcha_token = generate_captcha_token(ip)
        return render_template('login.html', locked_out=False, captcha_token=captcha_token)
    
    # Check if IP is locked out
    is_locked, lockout_until = is_ip_locked_out(ip)
    if is_locked:
        time_remaining = int((lockout_until - datetime.now()).total_seconds() / 60)
        flash(f'Too many failed attempts. Your IP is locked for {time_remaining} more minutes.', 'error')
        return render_template('login.html', locked_out=True, captcha_token='')
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        captcha_verified = request.form.get('captcha', '0')
        captcha_token = request.form.get('captcha_token', '')
        remember = request.form.get('remember')
        
        # Validate CAPTCHA token first
        is_valid, error_msg = validate_captcha_token(captcha_token, ip)
        
        if not is_valid or captcha_verified != '1':
            record_failed_attempt(ip)
            flash(f'CAPTCHA verification failed: {error_msg}', 'error')
            
            # Mark token as used to prevent reuse
            mark_token_used(captcha_token)
            
            attempts_left = MAX_ATTEMPTS - failed_attempts[ip]['count']
            if attempts_left > 0:
                flash(f'{attempts_left} attempts remaining before lockout.', 'warning')
                new_token = generate_captcha_token(ip)
                return render_template('login.html', locked_out=False, captcha_token=new_token)
            else:
                flash(f'Too many failed attempts. Your IP is locked for {int(LOCKOUT_DURATION.total_seconds() / 60)} minutes.', 'error')
                return render_template('login.html', locked_out=True, captcha_token='')
        
        # Mark token as used immediately after validation
        mark_token_used(captcha_token)
        
        # Validate username
        username_error, sanitized_username = validate_input(username, "Username")
        if username_error:
            record_failed_attempt(ip)
            flash(username_error, 'error')
            
            attempts_left = MAX_ATTEMPTS - failed_attempts[ip]['count']
            if attempts_left > 0:
                flash(f'{attempts_left} attempts remaining before lockout.', 'warning')
                new_token = generate_captcha_token(ip)
                return render_template('login.html', locked_out=False, captcha_token=new_token)
            else:
                flash(f'Too many failed attempts. Your IP is locked for {int(LOCKOUT_DURATION.total_seconds() / 60)} minutes.', 'error')
                return render_template('login.html', locked_out=True, captcha_token='')
        
        # Validate password
        password_error, sanitized_password = validate_input(password, "Password")
        if password_error:
            record_failed_attempt(ip)
            flash(password_error, 'error')
            
            attempts_left = MAX_ATTEMPTS - failed_attempts[ip]['count']
            if attempts_left > 0:
                flash(f'{attempts_left} attempts remaining before lockout.', 'warning')
                new_token = generate_captcha_token(ip)
                return render_template('login.html', locked_out=False, captcha_token=new_token)
            else:
                flash(f'Too many failed attempts. Your IP is locked for {int(LOCKOUT_DURATION.total_seconds() / 60)} minutes.', 'error')
                return render_template('login.html', locked_out=True, captcha_token='')
        
        # Check credentials using constant-time comparison
        username_match = secrets.compare_digest(sanitized_username, VALID_USERNAME)
        password_match = secrets.compare_digest(sanitized_password, VALID_PASSWORD)
        
        if username_match and password_match:
            # Successful login - reset failed attempts for this IP
            reset_failed_attempts(ip)
            regenerate_session()
            
            session.permanent = True if remember else False
            session['logged_in'] = True
            session['username'] = sanitized_username
            
            return redirect(url_for('success'))
        else:
            # Failed login
            is_locked_out = record_failed_attempt(ip)
            flash('Invalid username or password. Please try again.', 'error')
            
            if is_locked_out:
                flash(f'Too many failed attempts. Your IP is locked for {int(LOCKOUT_DURATION.total_seconds() / 60)} minutes.', 'error')
                return render_template('login.html', locked_out=True, captcha_token='')
            
            attempts_left = MAX_ATTEMPTS - failed_attempts[ip]['count']
            flash(f'{attempts_left} attempts remaining before lockout.', 'warning')
            new_token = generate_captcha_token(ip)
            return render_template('login.html', locked_out=False, captcha_token=new_token)

@app.route('/success')
def success():
    """Success page with flag"""
    if not session.get('logged_in'):
        flash('Please login to access this page', 'error')
        return redirect(url_for('login'))
    
    username = session.get('username', 'User')
    return render_template('success.html', username=username, flag=FLAG)

@app.route('/logout')
def logout():
    """Logout route"""
    session.clear()
    flash('You have been logged out successfully!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
