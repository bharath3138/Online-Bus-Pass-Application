from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong secret key

# Database configuration for registration data
DB_REGISTER_NAME = 'register.db'

# Initialize the registration database table
def init_register_db():
    conn = sqlite3.connect(DB_REGISTER_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS registered_users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_register_db()

@app.route('/')
def index():
    return render_template('login.html')

# Route to render the apply.html template
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        # You can render a dashboard template here for authenticated users.
        return render_template('dashboard.html')
    else:
        return redirect(url_for('index'))

# Route to render the registration form
@app.route('/register', methods=['GET'])
def register_form():
    return render_template('register.html')

# Route to handle the registration form submission
@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('register-email')
    password = request.form.get('register-password')
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')  # Updated method

    conn = sqlite3.connect(DB_REGISTER_NAME)
    cursor = conn.cursor()

    # Check if the username is already taken
    cursor.execute("SELECT id FROM registered_users WHERE username = ?", (username,))
    existing_user = cursor.fetchone()

    if existing_user:
        conn.close()
        return "Username already exists. Choose another username."
    else:
        cursor.execute("INSERT INTO registered_users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        conn.close()
        return "Registration successful. You can now log in."

# Add the login route, similar to your existing implementation
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('login-email')
    password = request.form.get('login-password')

    conn = sqlite3.connect(DB_REGISTER_NAME)
    cursor = conn.cursor()

    # Check if the user exists
    cursor.execute("SELECT id, password FROM registered_users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if user and check_password_hash(user[1], password):
        session['user_id'] = user[0]
        conn.close()
        return redirect(url_for('dashboard'))  # Redirect to dashboard on successful login
    else:
        conn.close()
        return "Invalid login credentials"

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
