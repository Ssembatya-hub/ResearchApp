import os
from dotenv import load_dotenv

# Load env
load_dotenv()

print("Loaded DATABASE_URL:", os.environ.get("DATABASE_URL"))

print("Loaded DATABASE_URL:", os.environ.get("DATABASE_URL"))
from flask import Flask, render_template, request, redirect, url_for, flash, current_app, send_file, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload size
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['COMPANY_NAME'] = "SSEMBATYA RESEARCH SOLUTIONS"
app.config['SERVICES_OUTLINE'] = "Data Analysis, Proposal Writing, Training, Consultation, Questionnaire Development, Questionnaire Upload on Kobocollect, GIS Study Area Maps, Business Apps Development"
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Define models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(200))
    email = db.Column(db.String(120))
    phone_number = db.Column(db.String(15))
    is_admin = db.Column(db.Boolean, default=False)
    messages_sent = db.relationship('Message', backref='sender', foreign_keys='Message.sender_id')
    messages_received = db.relationship('Message', backref='recipient', foreign_keys='Message.recipient_id')

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.String(100))
    service = db.Column(db.String(100))
    schedule_date = db.Column(db.String(50))
    phone_number = db.Column(db.String(20))
    status = db.Column(db.String(50), default='submitted')

class Schedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.String(100))
    date = db.Column(db.String(50))

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    amount = db.Column(db.Float)
    purpose = db.Column(db.String(200))
    mobile_number = db.Column(db.String(20))
    date = db.Column(db.String(50))
    status = db.Column(db.String(50), default='Pending Verification')

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    filename = db.Column(db.String(200))
    upload_date = db.Column(db.String(50))

class Message(db.Model):
    __tablename__ = 'message'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text)
    audio = db.Column(db.Text)  # ✅ ensure this is included
    timestamp = db.Column(db.DateTime)
    subject = db.Column(db.String(200))
    status = db.Column(db.String(20), default='unread')


# Login manager user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Utility: allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'pdf', 'docx', 'xlsx', 'jpg', 'png'}

# Admin check
def is_admin():
    return current_user.is_authenticated and current_user.is_admin

# Home page
@app.route('/')
@login_required
def index():
    orders = Order.query.filter_by(user_id=current_user.id).all()
    schedules = Schedule.query.filter_by(user_id=current_user.id).all()
    payments = Payment.query.filter_by(user_id=current_user.id).all()

    return render_template(
        'index.html',
        company_name=app.config['COMPANY_NAME'],
        services_outline=app.config['SERVICES_OUTLINE'],
        orders=orders,
        schedules=schedules,
        payments=payments
    )

# Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful!", "success")
        return redirect(url_for('login'))

    return render_template('register.html', company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'])

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for('index'))
        flash("Invalid username or password.", "danger")

    return render_template('login.html', company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'])

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for('login'))
# Profile page
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(current_user.id)

    if request.method == 'POST':
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not email or not phone_number:
            flash("Email and phone number are required!", "danger")
            return redirect(url_for('profile'))

        user.email = email
        user.phone_number = phone_number

        if new_password:
            if new_password != confirm_password:
                flash("Passwords do not match!", "danger")
                return redirect(url_for('profile'))
            user.password = generate_password_hash(new_password)

        try:
            db.session.commit()
            flash("Profile updated successfully!", "success")
        except Exception as e:
            flash(f"An error occurred: {str(e)}", "danger")

        return redirect(url_for('profile'))

    return render_template('profile.html', profile_data=user, company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'])

# Place order
@app.route('/order', methods=['GET', 'POST'])
@login_required
def place_order():
    services = app.config['SERVICES_OUTLINE'].split(", ")

    if request.method == 'POST':
        name = request.form.get('name')
        service = request.form.get('service')
        schedule_date = request.form.get('schedule_date')
        phone_number = request.form.get('phone_number')

        try:
            new_order = Order(
                user_id=current_user.id,
                name=name,
                service=service,
                schedule_date=schedule_date,
                phone_number=phone_number,
                status='submitted'
            )
            db.session.add(new_order)
            db.session.commit()
            flash("Order placed successfully!", "success")
            return redirect(url_for('index'))
        except Exception as e:
            flash(f"An error occurred: {str(e)}", "danger")
            return redirect(url_for('place_order'))

    return render_template('order.html', company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'], services=services)
# Submit order
@app.route('/submit_order/<int:order_id>', methods=['POST'])
@login_required
def submit_order(order_id):
    order = Order.query.filter_by(id=order_id, user_id=current_user.id).first()
    if order:
        order.status = 'submitted'
        db.session.commit()
        flash("Order successfully submitted to the admin.", "success")
    else:
        flash("Failed to submit order. Please try again.", "danger")
    return redirect(url_for('index'))

# Accept order (Admin)
@app.route('/accept_order/<int:order_id>', methods=['POST'])
@login_required
def accept_order(order_id):
    if not is_admin():
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    order = Order.query.get(order_id)
    if order:
        order.status = 'Accepted'
        db.session.commit()
        flash("Order has been accepted!", "success")
    else:
        flash("Order not found.", "danger")
    return redirect(url_for('admin_orders'))

# Verify order (Admin)
@app.route('/verify_order/<int:order_id>', methods=['POST'])
@login_required
def verify_order(order_id):
    if not is_admin():
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    order = Order.query.get(order_id)
    if order:
        order.status = 'Verified'
        db.session.commit()
        flash("Order has been verified!", "success")
    else:
        flash("Order not found.", "danger")
    return redirect(url_for('admin_orders'))

# Confirm order (Admin)
@app.route('/confirm_order/<int:order_id>', methods=['POST'])
@login_required
def confirm_order(order_id):
    if not is_admin():
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    order = Order.query.get(order_id)
    if order:
        order.status = 'Verified'
        db.session.commit()
        flash("Order has been verified!", "success")
    else:
        flash("Order not found.", "danger")
    return redirect(url_for('admin_orders'))
# Payment
@app.route('/payment', methods=['GET', 'POST'])
@login_required
def payment():
    services = app.config['SERVICES_OUTLINE'].split(", ")
    if request.method == 'POST':
        amount = request.form['amount']
        purpose = request.form['purpose']
        mobile_number = request.form['mobile_number']

        new_payment = Payment(
            user_id=current_user.id,
            amount=amount,
            purpose=purpose,
            mobile_number=mobile_number,
            date=datetime.now().strftime('%Y-%m-%d'),
            status="Pending Verification"
        )
        db.session.add(new_payment)
        db.session.commit()
        flash("Payment recorded and saved permanently!", "success")
        return redirect(url_for('index'))

    return render_template(
        'payment.html',
        company_name=app.config['COMPANY_NAME'],
        services_outline=app.config['SERVICES_OUTLINE'],
        services=services
    )

# Admin view of orders
@app.route('/admin/orders')
@login_required
def admin_orders():
    if not is_admin():
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    orders = db.session.query(
        Order.id,
        User.username,
        Order.phone_number,
        Order.name,
        Order.service,
        Order.schedule_date,
        Order.status
    ).join(User).order_by(Order.id.desc()).all()

    return render_template('admin_orders.html', orders=orders)
@app.route('/order/edit/<int:order_id>', methods=['GET', 'POST'])
@login_required
def edit_order(order_id):
    order = Order.query.get_or_404(order_id)

    if request.method == 'POST':
        order.name = request.form['name']
        order.service = request.form['service']
        db.session.commit()
        flash("Order updated successfully!", "success")
        return redirect(url_for('admin_orders'))

    return render_template(
        'edit_order.html',
        order=order,
        company_name=app.config['COMPANY_NAME'],
        services_outline=app.config['SERVICES_OUTLINE']
    )

@app.route('/order/delete/<int:order_id>', methods=['POST'])
@login_required
def delete_order(order_id):
    order = Order.query.get_or_404(order_id)
    db.session.delete(order)
    db.session.commit()
    flash("Order deleted successfully!", "success")
    return redirect(url_for('admin_orders'))

@app.route('/files')
@login_required
def view_files():
    files = File.query.filter_by(user_id=current_user.id).all()
    return render_template(
        'files.html',
        files=files,
        company_name=app.config['COMPANY_NAME'],
        services_outline=app.config['SERVICES_OUTLINE']
    )

@app.route('/payment/edit/<int:payment_id>', methods=['GET', 'POST'])
@login_required
def edit_payment(payment_id):
    payment = Payment.query.filter_by(id=payment_id, user_id=current_user.id).first()
    if not payment:
        flash("Payment not found or you do not have permission to edit it.", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        payment.amount = request.form.get('amount', 0.0)
        payment.purpose = request.form.get('purpose', '')
        payment.mobile_number = request.form.get('mobile_number', '')
        db.session.commit()
        flash("Payment updated successfully!", "success")
        return redirect(url_for('index'))

    return render_template('edit_payment.html', payment=payment)

@app.route('/payment/delete/<int:payment_id>', methods=['POST'])
@login_required
def delete_payment(payment_id):
    payment = Payment.query.filter_by(id=payment_id, user_id=current_user.id).first()
    if not payment:
        flash("Payment not found or you do not have permission to delete it.", "danger")
        return redirect(url_for('index'))

    db.session.delete(payment)
    db.session.commit()
    flash("Payment deleted successfully!", "success")
    return redirect(url_for('index'))
@app.route('/admin/payments')
@login_required
def admin_payments():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    payments = Payment.query.join(User).add_columns(
        Payment.id,
        User.username,
        Payment.amount,
        Payment.purpose,
        Payment.mobile_number,
        Payment.date,
        Payment.status
    ).order_by(Payment.id.desc()).all()

    return render_template('admin_orders.html', payments=payments)

@app.route('/confirm_payment/<int:payment_id>', methods=['POST'])
@login_required
def confirm_payment(payment_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    payment = Payment.query.get(payment_id)
    if payment:
        payment.status = 'Confirmed'
        db.session.commit()
        flash("Payment has been confirmed!", "success")
    else:
        flash("Payment not found.", "danger")

    return redirect(url_for('admin_payments'))

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
    users = User.query.all()
    updated = 0
    for user in users:
        if not user.password.startswith('pbkdf2:sha256'):
            user.password = generate_password_hash(user.password)
            updated += 1
    db.session.commit()
    return f"{updated} user password(s) updated."

@app.route('/mtn/callback', methods=['POST'])
def mtn_callback():
    data = request.json
    print("Callback data received:", data)
    return "Received", 200

@app.context_processor
def inject_unread_message_count():
    if current_user.is_authenticated and not current_user.is_admin:
        count = Message.query.filter_by(recipient_id=current_user.id, status='unread').count()
        return dict(unread_count=count)
    return dict(unread_count=0)

@app.route('/send_message_to_admin', methods=['POST'])
@login_required
def send_message_to_admin():
    message = request.form.get('message')
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    admin = User.query.filter_by(is_admin=True).first()
    if admin:
        new_msg = Message(
            sender_id=current_user.id,
            recipient_id=admin.id,
            message=message,
            timestamp=timestamp,
            status='unread'
        )
        db.session.add(new_msg)
        db.session.commit()
        flash("Message sent!", "success")
    else:
        flash("Admin not found.", "danger")

    return redirect(url_for('messages'))

@app.route('/generate_receipt/<int:payment_id>')
@login_required
def generate_receipt(payment_id):
    payment = Payment.query.get_or_404(payment_id)
    user = User.query.get(payment.user_id)

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    # Logo and Company Name on the same line
    logo_path = os.path.join('static', 'images', 'logo.png')
    if os.path.exists(logo_path):
        p.drawImage(logo_path, 40, height - 100, width=60, height=60, mask='auto')

    p.setFont("Helvetica-Bold", 16)
    p.drawString(110, height - 60, "SSEMBATYA RESEARCH SOLUTIONS")

    # Line under header
    p.line(40, height - 110, width - 40, height - 110)

    # Payment Details
    p.setFont("Helvetica", 12)
    y = height - 140
    line_spacing = 20
    details = [
        f"Username: {user.username}",
        f"Amount: UGX {int(payment.amount):,}",
        f"Purpose: {payment.purpose}",
        f"Mobile Number: {payment.mobile_number}",
        f"Date: {payment.date}",
        f"Status: {payment.status}"
    ]
    for detail in details:
        p.drawString(60, y, detail)
        y -= line_spacing

    # Thank you note
    y -= 10
    p.drawString(60, y, "Thank you for your payment!")

    # Stamp
    stamp_path = os.path.join('static', 'images', 'stamp.png')
    if os.path.exists(stamp_path):
        p.drawImage(stamp_path, width - 170, height - 240, width=100, height=100, mask='auto')

    p.showPage()
    p.save()

    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"receipt_{payment_id}.pdf", mimetype='application/pdf')

@app.route('/messages', methods=['GET', 'POST'])
@login_required
def messages():
    admin = User.query.filter_by(is_admin=True).first()

    if not admin:
        flash("Admin account not found.", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        content = request.form.get('message')
        if content:
            new_msg = Message(
                sender_id=current_user.id,
                recipient_id=admin.id,
                content=content,
                timestamp=datetime.now(),
                status='unread'
            )
            db.session.add(new_msg)
            db.session.commit()
            flash("Message sent to admin.", "success")
            return redirect(url_for('messages'))

    msgs = Message.query.filter(
        (Message.sender_id == current_user.id) | 
        (Message.recipient_id == current_user.id)
    ).order_by(Message.timestamp.asc()).all()

    return render_template('messages.html', messages=msgs)
@app.route('/admin/messages', methods=['GET', 'POST'])
@login_required
def admin_messages():
    if not current_user.is_admin:
        flash("Access denied", "danger")
        return redirect(url_for('index'))

    # Get list of users who have messaged the admin or received messages from admin
    user_ids = db.session.query(Message.sender_id).filter(Message.recipient_id == current_user.id).distinct().all()
    user_ids += db.session.query(Message.recipient_id).filter(Message.sender_id == current_user.id).distinct().all()
    user_ids = set([uid[0] for uid in user_ids if uid[0] != current_user.id])

    users = User.query.filter(User.id.in_(user_ids)).all()

    # Unread counts
    unread_counts = {
        user.id: Message.query.filter_by(recipient_id=current_user.id, sender_id=user.id, status='unread').count()
        for user in users
    }

    return render_template('admin_messages_list.html', users=users, unread_counts=unread_counts)

    # Get conversation
    messages = Message.query.filter(
        ((Message.sender_id == user_id) & (Message.recipient_id == current_user.id)) |
        ((Message.sender_id == current_user.id) & (Message.recipient_id == user_id))
    ).order_by(Message.timestamp).all()

    return render_template('admin_chat.html', user=user, messages=messages)
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            new_file = File(
                user_id=current_user.id,
                filename=filename,
                upload_date=datetime.now().strftime('%Y-%m-%d %H:%M')
            )
            db.session.add(new_file)
            db.session.commit()
            flash("File uploaded successfully!", "success")
            return redirect(url_for('view_files'))

        flash("Invalid file type.", "danger")

    return render_template('upload.html', company_name=app.config['COMPANY_NAME'], services_outline=app.config['SERVICES_OUTLINE'])

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    file_record = File.query.filter_by(user_id=current_user.id, filename=filename).first()
    if not file_record:
        abort(403)  # Forbidden access

    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
@app.route('/admin/files')
@login_required
def admin_files():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    all_files = db.session.query(File, User.username).join(User).order_by(File.upload_date.desc()).all()

    return render_template(
        'admin_files.html',
        all_files=all_files,
        company_name=app.config['COMPANY_NAME'],
        services_outline=app.config['SERVICES_OUTLINE']
    )
@app.route('/admin/upload', methods=['GET', 'POST'])
@login_required
def admin_upload():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    users = User.query.filter_by(is_admin=False).all()

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        file = request.files.get('file')

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            new_file = File(
                user_id=user_id,
                filename=filename,
                upload_date=datetime.now().strftime('%Y-%m-%d')
            )
            db.session.add(new_file)
            db.session.commit()

            flash("File uploaded for user successfully!", "success")
            return redirect(url_for('admin_upload'))
        else:
            flash("Invalid file type or no file selected.", "danger")

    return render_template('admin_upload.html', users=users)

@app.route('/send_user_message', methods=['POST'])
@login_required
def send_user_message():
    content = request.form.get('message', '')
    audio = request.form.get('voice_note', '')  # ✅ must match input name in messages.html
    print("🟢 User is sending message. Content:", content)
    print("🟢 User voice note (first 100 chars):", audio[:100] if audio else "No audio")

    admin = User.query.filter_by(is_admin=True).first()
    if not admin:
        flash("Admin not found.", "danger")
        return redirect(url_for('messages'))

    new_msg = Message(
        sender_id=current_user.id,
        recipient_id=admin.id,
        content=content,
        audio=audio,
        timestamp=datetime.now(),
        status='unread'
    )
    db.session.add(new_msg)
    db.session.commit()
    flash("Message sent to admin.", "success")
    return redirect(url_for('messages'))

@app.route('/admin/messages/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_view_conversation(user_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        content = request.form.get('message', '')
        audio = request.form.get('voice_note', '')  # ✅ must match name in admin_conversation.html
        print("🟢 Admin is sending message. Content:", content)
        print("🟢 Admin voice note (first 100 chars):", audio[:100] if audio else "No audio")

        new_msg = Message(
            sender_id=current_user.id,
            recipient_id=user_id,
            content=content,
            audio=audio,
            timestamp=datetime.now(),
            status='unread'
        )
        db.session.add(new_msg)
        db.session.commit()
        flash("Message sent to user.", "success")
        return redirect(url_for('admin_view_conversation', user_id=user_id))

    messages = Message.query.filter(
        ((Message.sender_id == user_id) & (Message.recipient_id == current_user.id)) |
        ((Message.sender_id == current_user.id) & (Message.recipient_id == user_id))
    ).order_by(Message.timestamp).all()

    return render_template('admin_conversation.html', user=user, messages=messages)
@app.route('/reset-admin-password')
def reset_admin_password():
    from werkzeug.security import generate_password_hash
    from yourapp import db  # Make sure `db = SQLAlchemy(app)` is imported
    from yourapp.models import User  # Adjust if models are in different place

    try:
        admin = db.session.execute(db.select(User).filter_by(username="Ssembatya")).scalar_one_or_none()
        if admin:
            admin.password = generate_password_hash("Breakthrough123456")
            db.session.commit()
            return "Admin password reset successfully!"
        return "Admin not found!"
    except Exception as e:
        return f"Error: {e}"

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)



























