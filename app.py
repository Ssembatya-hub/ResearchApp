from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key'
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

# Configure upload folder and allowed extensions
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'xlsx', 'jpg', 'png'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Ensure the upload folder exists

# Database setup
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            phone_number TEXT,
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
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT,
            upload_date TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
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

# Utility function to check allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password, is_admin FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            login_user(User(id=user[0], username=user[1], is_admin=user[3]))
            flash("Logged in successfully!", "success")
            return redirect(url_for('index'))
        else:
            flash("Invalid username or password.", "danger")

    return render_template('login.html', company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'])

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        password = request.form.get('password')

        if not email or not phone_number or not password:
            flash("All fields are required!", "danger")
            return redirect(url_for('profile'))

        hashed_password = generate_password_hash(password)

        try:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET email = ?, phone_number = ?, password = ? WHERE id = ?",
                (email, phone_number, hashed_password, current_user.id)
            )
            conn.commit()
            conn.close()
            flash("Profile updated successfully!", "success")
        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            return redirect(url_for('profile'))

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT email, phone_number FROM users WHERE id = ?", (current_user.id,))
    profile_data = cursor.fetchone()
    conn.close()

    return render_template('profile.html', profile_data=profile_data)

@app.route('/order', methods=['GET', 'POST'])
@login_required
def place_order():
    services = app.config['SERVICES_OUTLINE'].split(", ")
    if request.method == 'POST':
        name = request.form['name']
        service = request.form['service']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO orders (user_id, name, service) VALUES (?, ?, ?)", (current_user.id, name, service))
        conn.commit()
        conn.close()
        flash('Order placed successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('order.html', company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'], services=services)

@app.route('/schedule', methods=['GET', 'POST'])
@login_required
def schedule_training():
    if request.method == 'POST':
        name = request.form['name']
        date = request.form['date']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO schedules (user_id, name, date) VALUES (?, ?, ?)", (current_user.id, name, date))
        conn.commit()
        conn.close()
        flash('Training scheduled successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('schedule.html', company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'])

@app.route('/payment', methods=['GET', 'POST'])
@login_required
def payment():
    services = app.config['SERVICES_OUTLINE'].split(", ")
    if request.method == 'POST':
        amount = request.form['amount']
        purpose = request.form['purpose']
        mobile_number = request.form['mobile_number']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO payments (user_id, amount, purpose, mobile_number, date) VALUES (?, ?, ?, ?, date('now'))", 
                       (current_user.id, amount, purpose, mobile_number))
        conn.commit()
        conn.close()
        flash(f"Payment of UGX {amount} for '{purpose}' has been recorded.", 'success')
        return redirect(url_for('index'))
    return render_template('payment.html', company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'], services=services)

@app.route('/admin/orders', methods=['GET', 'POST'])
@login_required
def admin_orders():
    if not is_admin():
        flash("You do not have permission to view this page.", "danger")
        return redirect(url_for('index'))
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("""
        SELECT orders.id, users.username, orders.name, orders.service
        FROM orders
        INNER JOIN users ON orders.user_id = users.id
    """)
    orders = cursor.fetchall()
    conn.close()
    return render_template('admin_orders.html', orders=orders, company_name=app.config['COMPANY_NAME'])

@app.route('/order/edit/<int:order_id>', methods=['GET', 'POST'])
@login_required
def edit_order(order_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    if request.method == 'POST':
        name = request.form['name']
        service = request.form['service']
        cursor.execute("UPDATE orders SET name = ?, service = ? WHERE id = ?", (name, service, order_id))
        conn.commit()
        conn.close()
        flash("Order updated successfully!", "success")
        return redirect(url_for('admin_orders'))
    cursor.execute("SELECT name, service FROM orders WHERE id = ?", (order_id,))
    order = cursor.fetchone()
    conn.close()
    return render_template('edit_order.html', order=order, company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'])

@app.route('/order/delete/<int:order_id>', methods=['POST'])
@login_required
def delete_order(order_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    conn.commit()
    conn.close()
    flash("Order deleted successfully!", "success")
    return redirect(url_for('admin_orders'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO files (user_id, filename, upload_date) VALUES (?, ?, date('now'))",
                (current_user.id, filename)
            )
            conn.commit()
            conn.close()

            flash('File uploaded successfully!', 'success')
            return redirect(url_for('index'))

    return render_template('upload.html', company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'])

@app.route('/files')
@login_required
def view_files():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT filename, upload_date FROM files WHERE user_id = ?", (current_user.id,))
    files = cursor.fetchall()
    conn.close()
    return render_template('files.html', files=files, company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'])

if __name__ == '__main__':
    app.run(debug=True)


























