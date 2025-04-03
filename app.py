from flask import Flask, render_template, request, redirect, url_for, flash, current_app
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime

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
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER,
        recipient_id INTEGER,
        content TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_read INTEGER DEFAULT 0,
        FOREIGN KEY(sender_id) REFERENCES users(id),
        FOREIGN KEY(recipient_id) REFERENCES users(id)
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

    cursor.execute("SELECT id, name, service, status FROM orders WHERE user_id = ?", (current_user.id,))
    orders = cursor.fetchall()

    cursor.execute("SELECT id, name, date FROM schedules WHERE user_id = ?", (current_user.id,))
    schedules = cursor.fetchall()

    cursor.execute("SELECT amount, purpose, mobile_number, status, id FROM payments WHERE user_id = ?", (current_user.id,))

    payments = cursor.fetchall()

    conn.close()

    return render_template(
        'index.html',
        company_name=app.config['COMPANY_NAME'],
        services_outline=app.config['SERVICES_OUTLINE'],
        orders=orders,
        schedules=schedules,
        payments=payments
    )

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
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    if request.method == 'POST':
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not email or not phone_number:
            flash("Email and phone number are required!", "danger")
            return redirect(url_for('profile'))

        update_query = "UPDATE users SET email = ?, phone_number = ?"
        params = [email, phone_number]

        if new_password:
            if new_password != confirm_password:
                flash("Passwords do not match!", "danger")
                conn.close()
                return redirect(url_for('profile'))
            hashed_password = generate_password_hash(new_password)
            update_query += ", password = ?"
            params.append(hashed_password)

        update_query += " WHERE id = ?"
        params.append(current_user.id)

        try:
            cursor.execute(update_query, tuple(params))
            conn.commit()
            flash("Profile updated successfully!", "success")
        except Exception as e:
            flash(f"An error occurred: {e}", "danger")

        conn.close()
        return redirect(url_for('profile'))

    # GET: load existing profile data
    cursor.execute("SELECT email, phone_number FROM users WHERE id = ?", (current_user.id,))
    profile_data = cursor.fetchone()
    conn.close()

    return render_template('profile.html', profile_data=profile_data, company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'])

@app.route('/order', methods=['GET', 'POST'])
@login_required
def place_order():
    services = app.config['SERVICES_OUTLINE'].split(", ")

    if request.method == 'POST':
        name = request.form.get('name')
        phone_number = request.form.get('phone_number')
        service = request.form.get('service')
        schedule_date = request.form.get('schedule_date')

        try:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()

            # Save all order details permanently
            cursor.execute("""
                INSERT INTO orders (user_id, name, service, schedule_date, phone_number, status)
                VALUES (?, ?, ?, ?, ?, 'submitted')
            """, (current_user.id, name, service, schedule_date, phone_number))

            conn.commit()
            conn.close()

            flash("Order placed successfully and saved permanently!", "success")
            return redirect(url_for('index'))
        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            return redirect(url_for('place_order'))

    return render_template(
        'order.html',
        company_name=app.config['COMPANY_NAME'],
        services_outline=app.config['SERVICES_OUTLINE'],
        services=services
    )

@app.route('/submit_order/<int:order_id>', methods=['POST'])
@login_required
def submit_order(order_id):
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        # Update the status of the order to 'submitted'
        cursor.execute("""
            UPDATE orders 
            SET status = 'submitted' 
            WHERE id = ? AND user_id = ?
        """, (order_id, current_user.id))
        conn.commit()

        # Check if the update was successful
        if cursor.rowcount > 0:
            flash("Order successfully submitted to the admin.", "success")
        else:
            flash("Failed to submit order. Please try again.", "danger")
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
    finally:
        conn.close()

    return redirect(url_for('user_orders'))
@app.route('/accept_order/<int:order_id>', methods=['POST'])
@login_required
def accept_order(order_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE orders SET status = 'Accepted' WHERE id = ?", (order_id,))
        conn.commit()
        conn.close()
        flash("Order has been accepted!", "success")
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")

    return redirect(url_for('admin_orders'))
@app.route('/verify_order/<int:order_id>', methods=['POST'])
@login_required
def verify_order(order_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE orders SET status = 'Verified' WHERE id = ?", (order_id,))
        conn.commit()
        conn.close()
        flash("Order has been verified!", "success")
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")

    return redirect(url_for('admin_orders'))
@app.route('/confirm_order/<int:order_id>', methods=['POST'])
@login_required
def confirm_order(order_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        # Update the order status to 'Verified'
        cursor.execute("UPDATE orders SET status = 'Verified' WHERE id = ?", (order_id,))
        conn.commit()
        conn.close()

        flash("Order has been verified!", "success")
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")

    return redirect(url_for('admin_orders'))

@app.route('/payment', methods=['GET', 'POST'])
@login_required
def payment():
    services = app.config['SERVICES_OUTLINE'].split(", ")
    if request.method == 'POST':
        amount = request.form['amount']
        purpose = request.form['purpose']
        mobile_number = request.form['mobile_number']

        try:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO payments (user_id, amount, purpose, mobile_number, date, status)
                VALUES (?, ?, ?, ?, date('now'), 'Pending Verification')
            """, (current_user.id, amount, purpose, mobile_number))
            conn.commit()
            conn.close()

            flash("Payment recorded and saved permanently!", "success")
            return redirect(url_for('index'))
        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            return redirect(url_for('payment'))

    return render_template('payment.html', company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'], services=services)

@app.route('/admin/orders')
@login_required
def admin_orders():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            orders.id,               -- 0: Order ID
            users.username,          -- 1: Username
            orders.phone_number,     -- ✅ Now fetching from correct place
            orders.name,             -- 3: Name (client)
            orders.service,          -- 4: Service
            orders.schedule_date,    -- 5: Schedule Date
            orders.status            -- 6: Status
        FROM orders
        JOIN users ON orders.user_id = users.id
        ORDER BY orders.id DESC
    """)
    orders = cursor.fetchall()
    conn.close()

    return render_template('admin_orders.html', orders=orders)

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
from flask import send_from_directory

@app.route('/uploads/<filename>')
@login_required
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validate input
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        try:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
                (username, hashed_password)
            )
            conn.commit()
            conn.close()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username already exists. Please choose another.", "danger")

    return render_template('register.html', company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'])

@app.route('/files')
@login_required
def view_files():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT filename, upload_date FROM files WHERE user_id = ?", (current_user.id,))
    files = cursor.fetchall()
    conn.close()
    return render_template('files.html', files=files, company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'])

@app.route('/payment/edit/<int:payment_id>', methods=['GET', 'POST'])
@login_required
def edit_payment(payment_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Fetch payment details
    cursor.execute("SELECT id, amount, purpose, mobile_number FROM payments WHERE id = ? AND user_id = ?", 
                   (payment_id, current_user.id))
    payment = cursor.fetchone()

    if not payment:
        flash("Payment not found or you do not have permission to edit it.", "danger")
        conn.close()
        return redirect(url_for('index'))

    if request.method == 'POST':
        amount = request.form['amount']
        purpose = request.form.get('purpose', '')  # Default to empty string if missing
        mobile_number = request.form.get('mobile_number', '')  # Default to empty string

        cursor.execute("""
            UPDATE payments 
            SET amount = ?, purpose = ?, mobile_number = ? 
            WHERE id = ? AND user_id = ?
        """, (amount, purpose, mobile_number, payment_id, current_user.id))

        conn.commit()

        if cursor.rowcount > 0:
            flash("Payment updated successfully!", "success")
        else:
            flash("Payment update failed. Please try again.", "danger")

        conn.close()
        return redirect(url_for('index'))

    conn.close()
    return render_template('edit_payment.html', payment=payment)


# Delete a payment
@app.route('/payment/delete/<int:payment_id>', methods=['POST'])
@login_required
def delete_payment(payment_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Check if the payment exists before deleting
    cursor.execute("SELECT id FROM payments WHERE id = ? AND user_id = ?", (payment_id, current_user.id))
    payment = cursor.fetchone()

    if not payment:
        flash("Payment not found or you do not have permission to delete it.", "danger")
        conn.close()
        return redirect(url_for('index'))

    # Delete the payment
    cursor.execute("DELETE FROM payments WHERE id = ? AND user_id = ?", (payment_id, current_user.id))
    conn.commit()

    if cursor.rowcount > 0:
        flash("Payment deleted successfully!", "success")
    else:
        flash("Failed to delete payment. Please try again.", "danger")

    conn.close()
    return redirect(url_for('index'))

@app.route('/admin/payments')
@login_required
def admin_payments():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Join with users to get username
    cursor.execute("""
        SELECT 
            payments.id,            -- 0: Payment ID
            users.username,         -- 1: Username
            payments.amount,        -- 2: Amount
            payments.purpose,       -- 3: Purpose
            payments.mobile_number, -- 4: Mobile Number
            payments.date,          -- 5: Date
            payments.status         -- 6: Status
        FROM payments
        JOIN users ON payments.user_id = users.id
        ORDER BY payments.id DESC
    """)
    payments = cursor.fetchall()
    conn.close()

    return render_template('admin_orders.html', payments=payments)

@app.route('/confirm_payment/<int:payment_id>', methods=['POST'])
@login_required
def confirm_payment(payment_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE payments SET status = 'Confirmed' WHERE id = ?", (payment_id,))
        conn.commit()
        conn.close()
        flash("Payment has been confirmed!", "success")
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")

    return redirect(url_for('admin_payments'))
from flask import send_file
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from io import BytesIO
import os

@app.route('/receipt/<int:payment_id>')
@login_required
def generate_receipt(payment_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("""
        SELECT payments.amount, payments.purpose, payments.mobile_number, payments.date, payments.status, users.username
        FROM payments
        JOIN users ON payments.user_id = users.id
        WHERE payments.id = ? AND payments.user_id = ?
    """, (payment_id, current_user.id))
    payment = cursor.fetchone()
    conn.close()

    if not payment:
        flash("Payment not found or access denied.", "danger")
        return redirect(url_for('index'))

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    # Paths
    logo_path = os.path.join(current_app.root_path, 'static', 'images', 'logo.png')
    stamp_path = os.path.join(current_app.root_path, 'static', 'images', 'stamp.png')


    # --- Top Logo + Company Name ---
    if os.path.exists(logo_path):
        logo = ImageReader(logo_path)
        pdf.drawImage(logo, 40, height - 90, width=50, height=50, mask='auto')
        pdf.setFont("Helvetica-Bold", 16)
        pdf.drawString(100, height - 70, "SSEMBATYA RESEARCH SOLUTIONS")
    else:
        pdf.setFont("Helvetica-Bold", 18)
        pdf.drawString(100, height - 70, "SSEMBATYA RESEARCH SOLUTIONS")

    # --- Title ---
    pdf.setFont("Helvetica", 12)
    pdf.drawString(100, height - 100, "Payment Receipt")
    pdf.line(100, height - 102, 500, height - 102)

    # --- Payment Info ---
    pdf.drawString(100, height - 130, f"Username: {payment[5]}")
    pdf.drawString(100, height - 150, f"Amount: UGX {payment[0]:,.0f}")
    pdf.drawString(100, height - 170, f"Purpose: {payment[1]}")
    pdf.drawString(100, height - 190, f"Mobile Number: {payment[2]}")
    pdf.drawString(100, height - 210, f"Date: {payment[3]}")
    pdf.drawString(100, height - 230, f"Status: {payment[4]}")

    # --- Thank You + Stamp ---
    pdf.drawString(100, height - 270, "Thank you for your payment!")

    if os.path.exists(stamp_path):
        stamp = ImageReader(stamp_path)
        pdf.drawImage(stamp, 330, height - 310, width=120, height=60, mask='auto')

    pdf.showPage()
    pdf.save()
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name=f"receipt_{payment_id}.pdf", mimetype='application/pdf')

@app.route('/admin/files')
@login_required
def admin_files():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("""
        SELECT users.username, files.filename, files.upload_date
        FROM files
        JOIN users ON files.user_id = users.id
    """)
    uploads = cursor.fetchall()
    conn.close()
    return render_template('admin_files.html', uploads=uploads)
@app.route('/admin/upload', methods=['GET', 'POST'])
@login_required
def admin_upload_file():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users")
    users = cursor.fetchall()

    if request.method == 'POST':
        user_id = request.form['user_id']
        file = request.files['file']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            cursor.execute(
                "INSERT INTO files (user_id, filename, upload_date) VALUES (?, ?, date('now'))",
                (user_id, filename)
            )
            conn.commit()
            flash('File uploaded successfully for user!', 'success')
        else:
            flash('Invalid file or no file selected.', 'danger')

    conn.close()
    return render_template('admin_upload.html', users=users)
@app.route('/admin/message', methods=['GET', 'POST'])
@login_required
def admin_message():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    if request.method == 'POST':
        recipient_id = request.form['recipient_id']
        message = request.form['message']

        cursor.execute("INSERT INTO messages (sender_id, recipient_id, message) VALUES (?, ?, ?)",
                       (current_user.id, recipient_id, message))
        conn.commit()
        conn.close()
        flash("Message sent successfully!", "success")
        return redirect(url_for('admin_message'))

    cursor.execute("SELECT id, username FROM users WHERE is_admin = 0")
    users = cursor.fetchall()
    conn.close()
    return render_template('admin_send_message.html', users=users)
@app.route('/admin/messages')
@login_required
def admin_messages():
    if not current_user.is_admin:
        flash("Access denied", "danger")
        return redirect(url_for('index'))

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("""
        SELECT messages.id, messages.sender_id, messages.recipient_id, messages.message, messages.timestamp, 
               users.username 
        FROM messages 
        JOIN users ON messages.sender_id = users.id OR messages.recipient_id = users.id
        WHERE sender_id = ? OR recipient_id = ?
        ORDER BY messages.timestamp ASC
    """, (current_user.id, current_user.id))
    messages = cursor.fetchall()
    conn.close()

    return render_template('admin_chat.html', messages=messages)

@app.route('/messages', methods=['GET', 'POST'])
@login_required
def messages():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Send a message to admin
    if request.method == 'POST':
        message = request.form['message']
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute(
            "INSERT INTO messages (sender_id, recipient_id, message, timestamp) VALUES (?, ?, ?, ?)",
            (current_user.id, 1, message, timestamp)
        )
        conn.commit()

    # Fetch all messages between user and admin (ID = 1)
    cursor.execute("""
        SELECT messages.sender_id, messages.message, messages.timestamp, users.username
        FROM messages
        JOIN users ON messages.sender_id = users.id
        WHERE (sender_id = ? AND recipient_id = 1) OR (sender_id = 1 AND recipient_id = ?)
        ORDER BY messages.timestamp ASC
    """, (current_user.id, current_user.id))
    messages = cursor.fetchall()
    conn.close()

    return render_template('messages.html', messages=messages)

@app.context_processor
def inject_unread_message_count():
    if current_user.is_authenticated and not current_user.is_admin:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM messages
            WHERE recipient_id = ? AND status = 'unread'
        """, (current_user.id,))
        count = cursor.fetchone()[0]
        conn.close()
        return dict(unread_count=count)
    return dict(unread_count=0)
@app.route('/reply/<int:message_id>', methods=['POST'])
@login_required
def reply_message(message_id):
    content = request.form.get('message')

    if not content:
        flash("Message cannot be empty.", "danger")
        return redirect(url_for('messages'))

    # Assume admin has ID = 1
    admin_id = 1

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO messages (sender_id, recipient_id, subject, message, timestamp, status)
        VALUES (?, ?, ?, ?, datetime('now'), 'unread')
    """, (current_user.id, admin_id, f"Reply to message {message_id}", content))
    conn.commit()
    conn.close()

    flash("Reply sent to admin!", "success")
    return redirect(url_for('messages'))

@app.route('/admin/inbox')
@login_required
def admin_inbox():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("""
        SELECT messages.id, users.username, messages.message, messages.timestamp
        FROM messages
        JOIN users ON messages.sender_id = users.id
        WHERE messages.recipient_id = ?
        ORDER BY messages.timestamp DESC
    """, (current_user.id,))
    inbox = cursor.fetchall()
    conn.close()

    return render_template('admin_inbox.html', inbox=inbox)

@app.route('/send-message', methods=['GET', 'POST'])
@login_required
def send_message():
    if request.method == 'POST':
        subject = request.form.get('subject')
        content = request.form.get('message')

        if not subject or not content:
            flash("Subject and message are required.", "danger")
            return redirect(url_for('send_message'))

        admin_id = 1  # assuming admin has ID 1

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO messages (sender_id, recipient_id, subject, message, timestamp, status)
            VALUES (?, ?, ?, ?, datetime('now'), 'unread')
        """, (current_user.id, admin_id, subject, content))
        conn.commit()
        conn.close()

        flash("Message sent to admin!", "success")
        return redirect(url_for('messages'))

    return render_template('send_message.html')
@app.route('/send_message_to_admin', methods=['POST'])
@login_required
def send_message_to_admin():
    message = request.form.get('message')
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Find admin ID (assuming there's only one admin)
    cursor.execute("SELECT id FROM users WHERE is_admin = 1 LIMIT 1")
    admin = cursor.fetchone()
    if admin:
        admin_id = admin[0]
        cursor.execute("""
            INSERT INTO messages (sender_id, recipient_id, message, timestamp, status)
            VALUES (?, ?, ?, ?, 'unread')
        """, (current_user.id, admin_id, message, timestamp))
        conn.commit()
    conn.close()

    flash("Message sent!", "success")
    return redirect(url_for('messages'))

@app.route('/send_user_message', methods=['POST'])
@login_required
def send_user_message():
    message = request.form.get('message')

    if message:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        # Send to admin (assumed to have id = 1)
        cursor.execute("""
            INSERT INTO messages (sender_id, recipient_id, message, timestamp)
            VALUES (?, ?, ?, datetime('now'))
        """, (current_user.id, 1, message))
        conn.commit()
        conn.close()
        flash("Message sent to admin.", "success")
    else:
        flash("Message cannot be empty.", "danger")

    return redirect(url_for('messages'))
@app.route('/test-image')
def test_image():
    return '''
        <h3>Logo test</h3>
        <img src="/static/images/logo.png" width="200">
        <h3>Stamp test</h3>
        <img src="/static/images/stamp.png" width="200">
    '''
@app.route('/fix-passwords')
def fix_passwords():
    if not current_user.is_authenticated or not current_user.is_admin:
        return "Access Denied", 403

    import sqlite3
    from werkzeug.security import generate_password_hash

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, password FROM users")
    users = cursor.fetchall()

    fixed = 0
    for uid, pwd in users:
        if not pwd.startswith("pbkdf2:sha256"):
            hashed = generate_password_hash(pwd)
            cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, uid))
            fixed += 1

    conn.commit()
    conn.close()
    return f"{fixed} user password(s) updated."

@app.route('/mtn/callback', methods=['POST'])
def mtn_callback():
    data = request.json
    # Process the callback data here
    print("Callback data received:", data)
    return "Received", 200
if __name__ == '__main__':
    app.run(debug=True)


























