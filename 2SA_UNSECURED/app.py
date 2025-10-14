from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import timedelta

app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-this-in-production'  # Change this!
app.permanent_session_lifetime = timedelta(minutes=30)

# Hardcoded credentials for demo
VALID_USERNAME = "admin"
VALID_PASSWORD = "cyber123"
FLAG = "flag{y0u_dID_It_Man}"

@app.route('/')
def home():
    """Home route - redirects to login"""
    if 'logged_in' in session and session['logged_in']:
        return redirect(url_for('success'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login route - handles both GET and POST"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember')
        
        # Validate credentials
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('login.html')
        
        if username == VALID_USERNAME and password == VALID_PASSWORD:
            # Set session
            session.permanent = True if remember else False
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('success'))
        else:
            flash('Invalid username or password. Please try again.', 'error')
            return render_template('login.html')
    
    # GET request - show login form
    return render_template('login.html')

@app.route('/success')
def success():
    """Success page with flag - requires login"""
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login'))
    
    username = session.get('username', 'User')
    return render_template('success.html', username=username, flag=FLAG)

@app.route('/logout')
def logout():
    """Logout route - clears session"""
    session.clear()
    flash('You have been logged out successfully!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
