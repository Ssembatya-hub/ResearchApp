from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure random key
app.config['COMPANY_NAME'] = "SSEMBATYA RESEARCH SOLUTIONS"
app.config['SERVICES_OUTLINE'] = "Data Analysis, Proposal Writing, Training, Consultation, Questionnaire Development, Questionnaire Upload on Kobocollect, GIS Study Area Maps, Business Apps Development"

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, is_admin):
        self.id = id
        self.username = username
        self.is_admin = is_admin

# Database setup
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT,
            service TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT,
            date TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            amount REAL,
            purpose TEXT,
            mobile_number TEXT,
            date TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Initialize the database
init_db()

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return User(id=user[0], username=user[1], is_admin=user[2])
    return None

# Utility function to check admin status
def is_admin():
    return current_user.is_admin == 1

# Home page
@app.route('/')
@login_required
def index():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT name, service FROM orders WHERE user_id = ?", (current_user.id,))
    orders = cursor.fetchall()
    cursor.execute("SELECT name, date FROM schedules WHERE user_id = ?", (current_user.id,))
    schedules = cursor.fetchall()
    cursor.execute("SELECT amount, purpose, mobile_number, date FROM payments WHERE user_id = ?", (current_user.id,))
    payments = cursor.fetchall()
    conn.close()
    return render_template('index.html', company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'], orders=orders, schedules=schedules, payments=payments)

# Admin route to view all orders
@app.route('/admin/orders')
@login_required
def admin_orders():
    if not is_admin():
        flash("You do not have permission to view this page.", "danger")
        return redirect(url_for('index'))
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT name, service FROM orders")
    orders = cursor.fetchall()
    conn.close()
    return render_template('admin_orders.html', company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'], orders=orders)

# Registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'danger')
        conn.close()
    return render_template('register.html', company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'])

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, password, is_admin FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        if user and check_password_hash(user[1], password):
            login_user(User(id=user[0], username=username, is_admin=user[2]))
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'])

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

# Order page
@app.route('/order', methods=['GET', 'POST'])
@login_required
def order():
    if request.method == 'POST':
        name = request.form['name']
        service = request.form['service']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO orders (user_id, name, service) VALUES (?, ?, ?)", (current_user.id, name, service))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    services = app.config['SERVICES_OUTLINE'].split(", ")
    return render_template('order.html', company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'], services=services)

# Schedule page
@app.route('/schedule', methods=['GET', 'POST'])
@login_required
def schedule():
    if request.method == 'POST':
        name = request.form['name']
        date = request.form['date']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO schedules (user_id, name, date) VALUES (?, ?, ?)", (current_user.id, name, date))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    return render_template('schedule.html', company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'])

# Payment page
@app.route('/payment', methods=['GET', 'POST'])
@login_required
def payment():
    if request.method == 'POST':
        amount = request.form.get('amount')
        purpose = request.form.get('purpose')
        mobile_number = request.form.get('mobile_number')

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO payments (user_id, amount, purpose, mobile_number, date) VALUES (?, ?, ?, ?, date('now'))",
            (current_user.id, amount, purpose, mobile_number)
        )
        conn.commit()
        conn.close()

        flash(f"Payment of UGX {amount} for '{purpose}' with mobile number {mobile_number} has been recorded.", "success")
        return redirect(url_for('index'))

    services = app.config['SERVICES_OUTLINE'].split(", ")
    return render_template('payment.html', company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'], services=services)

# Run the app
if __name__ == '__main__':
    app.run(debug=True)









