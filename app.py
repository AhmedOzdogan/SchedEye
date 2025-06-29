from datetime import UTC, date, datetime, timedelta, timezone, time
import time as time_module
from flask_mail import Mail, Message
from functools import wraps
import time
import uuid
import os
from dotenv import load_dotenv
from flask import Flask, abort, render_template, request, redirect, session, url_for, flash
from numpy import extract
import requests
from sqlalchemy import Date, cast, distinct, func, desc, and_, extract, asc, text, literal_column
from sqlalchemy.orm import aliased
from sqlalchemy.sql import column, expression
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer





app = Flask(__name__)
app.secret_key = 'your_secret_key'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # type: ignore

load_dotenv()

app.secret_key = os.getenv('SECRET_KEY', 'fallback-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

serializer = URLSafeTimedSerializer(app.secret_key)  # type: ignore

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'mail.privateemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_NOREPLY_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_NOREPLY_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('EMAIL_NOREPLY_USERNAME')


mail = Mail(app)


currency_codes = [
    " USD",  # Global standard
    " VND",  # Vietnam
    " THB",  # Thailand
    " KHR",  # Cambodia
    " LAK",  # Laos
    " CNY",  # China
    " MYR",  # Malaysia
    " SGD",  # Singapore
    " IDR",  # Indonesia
    " PHP",  # Philippines
    " TWD",  # Taiwan
    " KRW",  # South Korea
    " JPY",  # Japan
    " INR",  # India
    " HKD",  # Hong Kong

    # European Currencies
    " EUR", " GBP", " CHF", " SEK", " NOK", " DKK",
    " PLN", " CZK", " HUF", " RON", " BGN"
    ]


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    user_type = db.Column(db.String(20), default='regular')  # 'regular' or 'admin'
    currency = db.Column(db.String(10), default=' USD') # instead of another func just add a space before it.
    disabled = db.Column(db.Boolean, default=False)  # to disable user accounts
    confirmed = db.Column(db.Boolean, default=False)  # to confirm user accounts
    blocked = db.Column(db.Boolean, default=False)  # to block user accounts
    registration_date = db.Column(db.Date, default=date.today) 
    login_attempts = db.Column(db.Integer, default=0)  # Track login attempts

    # Use string here
    sessions = db.relationship('UserSession', backref='user', lazy=True)
    schedules = db.relationship('TeachingSchedule', back_populates='teacher')


class UserSession(db.Model):
    __tablename__ = 'user_sessions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    login_time = db.Column(db.DateTime, nullable=False, server_default=func.current_timestamp())
    logout_time = db.Column(db.DateTime)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    session_token = db.Column(db.String(64))
    status = db.Column(db.String(32), default='success') 
    

class AdminActionLog(db.Model):
    __tablename__ = 'admin_action_logs'

    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    target_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # e.g., 'disable_user'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    note = db.Column(db.Text)
    
class TeachingSchedule(db.Model):
    __tablename__ = 'teaching_schedule'

    id = db.Column(db.Integer, primary_key=True)
    class_name = db.Column("class", db.String(50), nullable=False)
    date = db.Column(db.Date, nullable=False)
    starttime = db.Column(db.Time, nullable=False)
    endtime = db.Column(db.Time, nullable=False)
    school = db.Column(db.String(50), nullable=False)
    rate = db.Column(db.Numeric(10, 2), nullable=False, default=0.00)
    paid = db.Column(db.String(3), nullable=False, default='no')

    teacher_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    teacher = db.relationship('User', back_populates='schedules')
      
def get_user(field, value):
    if field not in {'id', 'username', 'email'}:
        raise ValueError("Invalid field for user lookup.")

    # Get the column dynamically from the model
    column = getattr(User, field)

    # Query the user
    return db.session.query(User).filter(column == value).first()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.user_type != 'admin':
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

def get_user_by_email(email):
    return User.query.filter_by(email=email).first()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) 

def send_email(to, subject, html_body):
    msg = Message(
        subject=subject,
        sender=os.getenv('EMAIL_NOREPLY_USERNAME'),
        recipients=[to]
    )
    msg.html = html_body

    try:
        mail.send(msg)
        print(f"✅ Email sent to {to}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")


def format_timedelta_to_time_str(value):
    """Convert a timedelta to a formatted time string."""
    return f"{value.hour:02d}:{value.minute:02d}"
        
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        
        email = request.form['email']
        password = request.form['password']
        session_token = str(uuid.uuid4())
        user_agent = request.user_agent.string
        user = get_user_by_email(email)
        now = datetime.now(UTC)
        ip = request.remote_addr
                
        recaptcha_token = request.form.get('recaptcha_token')
        secret = os.getenv('RECAPTCHA_SECRET_KEY')
        print(secret)

        recaptcha_response = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={
                'secret': secret,
                'response': recaptcha_token
            }
        )
        result = recaptcha_response.json()
        print("reCAPTCHA result:", result)
        
        
        # if not result.get('success') or result.get('score', 0) < 0.5:
        #     print("reCAPTCHA failed:", result)  # Optional logging
        #     flash("reCAPTCHA verification failed. Are you a robot?")
        #     session_entry = UserSession(
        #         user_id=None, # type: ignore
        #         ip_address=ip, # type: ignore
        #         user_agent=user_agent, # type: ignore
        #         session_token=None, # type: ignore
        #         login_time=now, # type: ignore
        #         status='invalid_captcha' # type: ignore
        #     )
        #     db.session.add(session_entry)
        #     db.session.commit()
        #     return redirect(url_for('login'))
    
        

        # 1. If user is None (invalid email)
        if not user:
            session_entry = UserSession(
                user_id=None, # type: ignore
                ip_address=ip, # type: ignore
                user_agent=user_agent, # type: ignore
                session_token=None, # type: ignore
                login_time=now, # type: ignore
                status='invalid_email' # type: ignore
            )
            db.session.add(session_entry)
            db.session.commit()
            flash("Invalid email or password.", "danger")
            return redirect(url_for('login'))

        # 2. If user is blocked
        if user.blocked:
            session_entry = UserSession(
                user_id=user.id, # type: ignore
                ip_address=ip, # type: ignore
                user_agent=user_agent, # type: ignore
                session_token=session_token, # type: ignore
                login_time=now, # type: ignore
                status='blocked' # type: ignore
            )
            db.session.add(session_entry)
            db.session.commit()
            flash("Your account has been permanently blocked. Please contact the Admin for assistance (admin@schedeye.com).", "danger")
            return redirect(url_for('login'))

        # 3. If user is not confirmed
        if not user.confirmed:
            # send confirmation email again
            email_token = serializer.dumps(email, salt='email-confirm')
            confirm_url = url_for('confirm_email', token=email_token, _external=True)
            html = render_template('emails/register_email.html', confirm_url=confirm_url)
            send_email(email, 'Confirm Your Email - SchedEye', html)

            session_entry = UserSession(
                user_id=user.id, # type: ignore
                ip_address=ip, # type: ignore
                user_agent=user_agent, # type: ignore
                session_token=None, # type: ignore
                login_time=now, # type: ignore
                status='unconfirmed' # type: ignore
            )
            db.session.add(session_entry)
            db.session.commit()
            flash("Please confirm your email.", "danger")
            return redirect(url_for('login'))

        # 4. If password is wrong
        if not check_password_hash(user.password_hash, password):
            session_entry = UserSession(
                user_id=user.id, # type: ignore
                ip_address=ip, # type: ignore
                user_agent=user_agent, # type: ignore
                session_token=None, # type: ignore
                login_time=now, # type: ignore
                status='wrong_password' # type: ignore
            )
            db.session.add(session_entry)

            user.login_attempts += 1
            if user.login_attempts >= 5:
                user.disabled = True
                 # Email to the admin
                body = f"""A user account has been automatically disabled due to too many failed login attempts.

                Username:
                {user.username}

                Email:
                {user.email}

                User ID:
                {user.id}

                Time (UTC):
                {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}

                IP Address:
                {request.remote_addr}
                """

                msg = Message(
                    subject='User Account Disabled - SchedEye',
                    sender=os.getenv('EMAIL_NOREPLY_USERNAME'),
                    recipients=os.getenv('EMAIL_ADMIN_USERNAME'), # type: ignore
                    body=body  # plain text body
                )

                mail.send(msg)
                flash("Account disabled after too many failed login attempts.", "danger")
                
                #email to the user
                html = render_template('emails/disabled.html')
                send_email(user.email, "Your Account has been disabled - SchedEye", html)
            elif user.login_attempts == 4:
                flash("Your account will be disabled after one more failed login attempt.", "warning")
            else:
                flash("Invalid email or password.", "danger")

            db.session.commit()
            return redirect(url_for('login'))

        # 5. If disabled (after checking password)
        if user.disabled:
            session_entry = UserSession(
                user_id=user.id, # type: ignore
                ip_address=ip, # type: ignore
                user_agent=user_agent, # type: ignore
                session_token=session_token, # type: ignore
                login_time=now, # type: ignore
                status='disabled' # type: ignore
            )
            db.session.add(session_entry)
            db.session.commit()
            flash("Your account is disabled. Please reset your password.", "danger")
            return redirect(url_for('login'))

        # 6. SUCCESS
        login_user(user)
        user.login_attempts = 0

        new_session = UserSession(
            user_id=user.id, # type: ignore
            ip_address=ip, # type: ignore
            user_agent=user_agent, # type: ignore
            session_token=session_token, # type: ignore
            login_time=now, # type: ignore
            status='success' # type: ignore 
        )

        db.session.add(new_session)
        db.session.commit()

        session['session_token'] = session_token
        session['search_date'] = date.today().isoformat()
        session['show_tutorial'] = True
        print(session['search_date'])
        
        return redirect(url_for('dashboard'))


    return render_template('login.html', recaptcha_site_key=os.getenv('RECAPTCHA_SITE_KEY'))


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if current_user.is_authenticated:
        contact_email = current_user.email  # type: ignore
    else:
        contact_email = ''

    if request.method == 'POST':
        contact_email = request.form.get('email', '').strip()
        message = request.form.get('message', '').strip()
        topic = request.form.get('topic', '').strip()
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

        # Optionally validate content here

        # Flash success message
        flash(f'Thank you for your message, {contact_email}! We will get back to you shortly.', 'success')

        # Simulated delay (not recommended in production)
        time.sleep(2) # type: ignore
        
        body_contact = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6;">
            <h2>New Contact Form Submission</h2>
            <p><strong>Email:</strong> {contact_email}</p>
            <p><strong>Time (UTC):</strong> {timestamp}</p>
            <p><strong>Topic:</strong><br>{topic}</p>
            <p><strong>Message:</strong><br>{message}</p>
        </body>
        </html>"""
        
        
        # Send email or log
        send_email(
            "admin@schedeye.com",
            "New Contact Form Submission",
            body_contact
        )
        
        if get_user_by_email(contact_email):
            user = get_user_by_email(contact_email)
            html_body = render_template('emails/contact_email.html')
            send_email(
                user.email, # type: ignore
                "New Contact Form Submission",
                html_body
            )

        # Redirect to prevent form resubmission
        return redirect(url_for('contact'))

    return render_template('contact.html', email=contact_email)

@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
        user = get_user_by_email(email)

        if user:
            if user.confirmed:
                flash('Your email is already confirmed. Please log in.', 'info')
            else:
                user.confirmed = True
                db.session.commit()
                flash('Email confirmed successfully! You can now log in.', 'success')
        else:
            flash('User not found.', 'danger')

    except Exception as e:
        print(e)
        flash('Invalid or expired confirmation link.', 'danger')

    return redirect(url_for('login'))
       
@app.route('/register', methods=['GET', 'POST'])
def register():
    global currency_codes
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        password_again = request.form['password_again']

        # Handle currency fallback
        currency_input = request.form['currency'].strip()
        currency = f' {currency_input}' if currency_input else ' USD'

        # Validation checks
        if get_user_by_email(email):
            flash('Email already exists.', 'danger')
            return redirect(url_for('register'))

        elif len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('register'))

        elif password != password_again:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        elif not any(char.isdigit() for char in password):
            flash('Password must contain at least one digit.', 'danger')
            return redirect(url_for('register'))

        # Create new user
        password_hash = generate_password_hash(password)
        new_user = User(
            username=username, # type: ignore
            email=email, # type: ignore
            password_hash=password_hash, # type: ignore
            user_type='regular',    # type: ignore
            currency=currency,  # type: ignore
            confirmed=False, # type: ignore
            registration_date=date.today()  # type: ignore
        )

        # Generate confirmation email
        token = serializer.dumps(email, salt='email-confirm')
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('emails/register_email.html', confirm_url=confirm_url)
        send_email(email, 'Confirm Your Email - SchedEye', html)

        # Save to DB
        db.session.add(new_user)
        db.session.commit()
        
        # Create example classes for the new user
        example_classes = [
            TeachingSchedule(
                class_name='Demo Class 1', # type: ignore
                date=date.today(), # type: ignore
                starttime=time(9, 0), # type: ignore
                endtime=time(10, 0), # type: ignore
                school='', # type: ignore
                rate=0.00, # type: ignore
                paid='no', # type: ignore
                teacher_id=new_user.id # type: ignore
            ),
            TeachingSchedule(
                class_name='Demo Class 2', # type: ignore
                date=date.today(), # type: ignore
                starttime=time(10, 30), # type: ignore
                endtime=time(11, 30), # type: ignore
                school='', # type: ignore
                rate=0.00, # type: ignore
                paid='no', # type: ignore
                teacher_id=new_user.id # type: ignore
            ),
            TeachingSchedule(
                class_name='Demo Class 3', # type: ignore 
                date=date.today(), # type: ignore
                starttime=time(13, 0), # type: ignore
                endtime=time(14, 0), # type: ignore
                school='', # type: ignore
                rate=0.00, # type: ignore
                paid='no', # type: ignore
                teacher_id=new_user.id # type: ignore
            )
        ]

        db.session.add_all(example_classes) 
        db.session.commit()

        flash('Registration successful! Please check your email to confirm your account.', 'info')
        time.sleep(2)
        return redirect(url_for('login'))

    return render_template('register.html', currency_codes=currency_codes)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = get_user_by_email(email)
        ip = request.remote_addr

        if user.blocked: # type: ignore
            flash('Your account has been blocked. Please contact <admin@schedeye.com> for assistance.', 'danger')
            return redirect(url_for('login'))
        
        elif user:
            token = serializer.dumps(email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            html = render_template('emails/reset_password_email.html', reset_url=reset_url)
            send_email(email, 'Reset Your Password - SchedEye', html)

        login_time = datetime.now(UTC)

        new_session = UserSession(
            user_id=user.id if user else None, # type: ignore
            ip_address=ip, # type: ignore
            user_agent=None, # type: ignore
            session_token=None, # type: ignore
            login_time=login_time, # type: ignore
            logout_time=login_time, # type: ignore

            status='forgot_password' # type: ignore
        )

        db.session.add(new_session)
        db.session.commit()

        flash('If your email exists, a reset link has been sent.', 'info')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)
    except:
        flash('Reset link is invalid or expired.', 'danger')
        return redirect(url_for('forgot_password'))
    
    user = get_user_by_email(email)
    
    
    if user and user.blocked:
        session_entry = UserSession(
        user_id=user.id, # type: ignore
        ip_address=request.remote_addr, # type: ignore
        user_agent=request.user_agent.string, # type: ignore
        session_token=None, # type: ignore
        login_time=datetime.now(UTC), # type: ignore
        logout_time=datetime.now(UTC), # type: ignore
        status='reset_password_blocked' # type: ignore
    )
        db.session.add(session_entry)
        db.session.commit()
        flash("Your account is blocked and cannot reset the password. Please contact admin.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(request.url)

        if len(new_password) < 8 or not any(char.isdigit() for char in new_password):
            flash('Password must be at least 8 characters and contain a number and character.', 'danger')
            return redirect(request.url)

        user.password_hash = generate_password_hash(new_password) # type: ignore
        user.disabled = False # type: ignore
        user.login_attempts = 0 # type: ignore
        db.session.commit()
        
        ip = request.remote_addr
        
        user_id = user.id if user else None
         
        new_session = UserSession(
            user_id=user_id, # type: ignore
            ip_address=ip, # type: ignore
            user_agent=None, # type: ignore
            session_token=None, # type: ignore
            login_time=datetime.now(UTC), # type: ignore
            logout_time=datetime.now(UTC), # type: ignore
            status='reset password' # type: ignore
        )
        db.session.add(new_session)
        db.session.commit()
        flash('Password successfully reset! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


@app.route('/dashboard')
@login_required
def dashboard():
    if request.args.get('reset_search_date') == '1':
        session['search_date'] = date.today().isoformat()  # Reset to today
    if request.args.get('date_search_triggered') == '1':
        selected_date = request.args.get('selected_date')
        session['search_date'] = selected_date  # Store in session
    else:
        selected_date = session.get('search_date')
    

    print("Selected date from session:", selected_date)
    print("search date is ",session.get('search_date'))
    
    if selected_date:
        selected_date_dt = datetime.strptime(selected_date, "%Y-%m-%d")
    
    start_date = selected_date_dt - timedelta(days=selected_date_dt.weekday())  # Monday
    end_date = start_date + timedelta(days=6)  # Sunday

    # SQLAlchemy query
    teaching_schedule_data = (
        TeachingSchedule.query
        .filter(
            and_(
                TeachingSchedule.teacher_id == current_user.id,
                TeachingSchedule.date.between(start_date.date(), end_date.date()) # type: ignore
            )
        )
        .order_by(TeachingSchedule.date.asc(), TeachingSchedule.starttime.asc())
        .all()
    )

    # Generate week dates
    week_dates = []
    for i in range(7):
        current_day = start_date + timedelta(days=i)
        week_dates.append({
            'day_name': current_day.strftime('%A'), # type: ignore
            'day_date': current_day.strftime('%d.%m.%Y') # type: ignore
        })

    login_count = db.session.query(UserSession).filter_by(user_id=current_user.id).count()
    show_tutorial = login_count < 3 and session.get('show_tutorial', False)
    
    
    feature_list = [
    {
        "title": "Update User Details",
        "text": "You can easily update your username, password, and currency preferences. Just click your username at the top right and choose <strong>Settings</strong>.",
        "gif": "update_user.gif",
        "alt": "Update User Details GIF",
        "keywords": "username password login details user account"
    },
    {
        "title": "Adding a New Class",
        "text": "To add a new class, click the <strong>Add Lesson</strong> button at the top, fill in the class name, date, time, and school information, then click <strong>Save</strong>.",
        "gif": "add_lesson.gif",
        "alt": "Add Class GIF",
        "keywords": "add class schedule new lesson"
    },
    {
        "title": "Edit Lesson",
        "text": "You can edit your lessons without deleting them. Simply right-click on a lesson, select <strong>Edit</strong>, and update the details as needed.",
        "gif": "edit_lesson.gif",
        "alt": "Edit Lessons GIF",
        "keywords": "edit class schedule modify lesson"
    },
    {
        "title": "Update Payments",
        "text": "Easily update the payment status for one or multiple lessons. Right-click on a lesson and choose <strong>Paid</strong> or <strong>Unpaid</strong>. You can also select multiple lessons at once to update them together.",
        "gif": "paid_unpaid.gif",
        "alt": "Update Payments GIF",
        "keywords": "pay paid unpaid payments money"
    },
    {
        "title": "Deleting Lessons",
        "text": "Easily remove lessons from your schedule. Select the lessons you want to delete, then right-click and choose <strong>Delete</strong>. You can delete one or multiple lessons at once.",
        "gif": "delete_lessons.gif",
        "alt": "Delete Lessons GIF",
        "keywords": "delete remove lessons schedule"
    },
    {
        "title": "Duplicating Lessons",
        "text": "Easily create copies of existing lessons. To duplicate a class, select it, right-click, and choose <strong>Duplicate</strong>. Then, pick the new date and time — your lesson will be copied instantly.",
        "gif": "duplicate_single.gif",
        "alt": "Duplicate Lessons GIF",
        "keywords": "copy duplicate lessons"
    },
    {
        "title": "Duplicating Weeks",
        "text": "Easily copy an entire week of lessons. Select all the classes from the week, then choose the week you want to copy them to from the menu. All selected lessons will be duplicated to the new week without hassle.",
        "gif": "duplicate_bundle.gif",
        "alt": "Duplicate Weeks GIF",
        "keywords": "copy duplicate week whole week lessons"
    },
    {
        "title": "Lesson Details",
        "text": "View detailed information for each lesson from the <strong>View</strong> menu. From there, you can also edit, duplicate, or delete lessons as needed.",
        "gif": "details_lesson.gif",
        "alt": "Lesson Details GIF",
        "keywords": "view details lesson information"
    },
    {
        "title": "Calculate Total Hours",
        "text": "Quickly calculate the total hours for your lessons. Click <strong>Calculate</strong> at the top right to view your teaching hours by school, month, year, or overall.",
        "gif": "calculate_hours.gif",
        "alt": "Calculate Total Hours GIF",
        "keywords": "Total hours calculate time"
    },
    {
        "title": "Calculate Total Payments",
        "text": "Quickly calculate your total payments. Click <strong>Calculate</strong> at the top right, then select <strong>Payments</strong>. You can view your salary, received payments, and pending amounts by school, class, month, or year.<br><br>You can also mark all lessons as <strong>Paid</strong> or <strong>Unpaid</strong> from this section without selecting them one by one.",
        "gif": "Payments.gif",
        "alt": "Calculate Total Payments GIF",
        "keywords": "Total hours payment money salary calculate time"
    }
]


    return render_template('dashboard.html',
                           teaching_schedule_data=teaching_schedule_data,
                           week_dates=week_dates,
                           start_date=start_date,
                           end_date=end_date,
                           show_tutorial=show_tutorial,
                           selected_date=selected_date,
                           feature_list=feature_list,)

@app.route('/mark_tutorial_seen', methods=['POST'])
@login_required
def mark_tutorial_seen():
    session['show_tutorial'] = False
    return '', 204

@app.before_request
def session_timeout():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=5)
    session.modified = True
    if current_user.is_authenticated:
        now = datetime.utcnow()
        last_activity = session.get('last_activity')
        if last_activity:
            last_activity_dt = datetime.strptime(last_activity, "%Y-%m-%d %H:%M:%S")
            if (now - last_activity_dt) > timedelta(minutes=5):
                logout_user()
                session.clear()
                flash('You have been logged out due to inactivity.', 'info')
                return redirect(url_for('login'))
        session['last_activity'] = now.strftime("%Y-%m-%d %H:%M:%S")

@app.route('/logout')
@login_required
def logout():
    session_token = session.get('session_token')

    if session_token:
        try:
            user_session = UserSession.query.filter_by(session_token=session_token).first()
            if user_session and user_session.logout_time is None:

                user_session.logout_time = datetime.now(UTC)
                db.session.commit()
        except Exception as e:
            print(f"Failed to update logout time: {e}")
                
    logout_user()
    session.pop('_flashes', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

    
@app.route('/toggle_paid', methods=['POST'])
@login_required
def toggle_paid():
    data = request.get_json()
    lesson_ids = data.get('lesson_ids', [])

    if not lesson_ids:
        return "No lesson IDs provided", 400

    # Update using SQLAlchemy
    updated = (
        TeachingSchedule.query
        .filter(
            TeachingSchedule.id.in_(lesson_ids),
            TeachingSchedule.teacher_id == current_user.id
        )
        .update({'paid': 'yes'}, synchronize_session=False)
    )

    db.session.commit()

    return f"Updated {updated} lesson(s) as paid", 200


@app.route('/toggle_unpaid', methods=['POST'])
@login_required
def toggle_unpaid():
    data = request.get_json()
    lesson_ids = data.get('lesson_ids', [])
    print(lesson_ids)

    if not lesson_ids:
        return "No lesson IDs provided", 400

    # Update using SQLAlchemy
    updated = (
        TeachingSchedule.query
        .filter(
            TeachingSchedule.id.in_(lesson_ids),
            TeachingSchedule.teacher_id == current_user.id
        )
        .update({'paid': 'no'}, synchronize_session=False)
    )

    db.session.commit()

    return f"Updated {updated} lesson(s) as unpaid", 200

from datetime import datetime, timedelta




@app.route('/edit/<int:lesson_id>', methods=['POST', 'GET'])
@login_required
def edit_lesson(lesson_id):
    # Fetch the lesson and ensure ownership
    lesson = db.session.query(TeachingSchedule).filter(
        TeachingSchedule.id == lesson_id,
        TeachingSchedule.teacher_id == current_user.id
    ).first()

    if not lesson:
        return redirect(url_for('dashboard'))

    if request.method == 'GET':
        starttime= format_timedelta_to_time_str(lesson.starttime)
        endtime = format_timedelta_to_time_str(lesson.endtime)
        
    elif request.method == 'POST':
        # Get form values
        class_name = request.form['class_name']
        date_str = request.form['selected_date']
        start_time_str = request.form['start_time']
        end_time_str = request.form['end_time']
        school = request.form['school']
        rate = request.form['rate']
        paid = request.form['paid']

        # Convert values
        class_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        start_hours, start_minutes = map(int, start_time_str.split(':'))
        end_hours, end_minutes = map(int, end_time_str.split(':'))

        # Update the lesson object
        lesson.class_name = class_name
        lesson.date = class_date
        lesson.starttime = timedelta(hours=start_hours, minutes=start_minutes)
        lesson.endtime = timedelta(hours=end_hours, minutes=end_minutes)
        lesson.school = school
        lesson.rate = rate
        lesson.paid = paid
        
        session['search_date'] = lesson.date.isoformat()  # Store the date in session for consistency

        db.session.commit()
        flash("Lesson updated successfully.", "success")
        return redirect(url_for('dashboard'))

    return render_template(
        'base_info.html',
        lesson_id=lesson_id,
        page_title='Edit Lesson',
        lesson=lesson,
        starttime=starttime,
        endtime=endtime,
        form_action=url_for('edit_lesson', lesson_id=lesson_id)
    )

    
@app.route('/add_lesson', methods=['POST', 'GET'])
@login_required
def add_lesson():
    if request.method == 'GET':
        lesson = None

        
    if request.method == 'POST':
        class_name = request.form['class_name']
        date_str = request.form['selected_date']
        start_time_str = request.form['start_time']
        end_time_str = request.form['end_time']
        school = request.form['school']
        rate = request.form['rate']
        paid = request.form['paid']

        # Convert to correct types
        class_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        start_time = list(map(int, start_time_str.split(':')))
        end_time = list(map(int, end_time_str.split(':')))

        start_time = timedelta(hours=start_time[0], minutes=start_time[1])
        end_time = timedelta(hours=end_time[0], minutes=end_time[1])
        
        # Update the lesson object
        
        lesson = TeachingSchedule()  # Create a new instance
        # Set the attributes
        lesson.class_name = class_name
        lesson.date = class_date
        lesson.starttime = start_time
        lesson.endtime = end_time
        lesson.school = school
        lesson.rate = rate
        lesson.paid = paid
        lesson.teacher_id = current_user.id  # Set the teacher_id
        # Save to the database
        db.session.add(lesson)
        db.session.commit()
        
        session['search_date'] = lesson.date.isoformat()  # Store the date in session for consistency
        
        return redirect(url_for('dashboard'))

    return render_template('base_info.html',
                           lesson_id=None,
                           page_title='Add Lesson',
                           lesson = lesson,
                           form_action = url_for('add_lesson')
    )
    
@app.route('/toggle_delete', methods=['POST'])
@login_required
def toggle_delete_bulk():
    data = request.get_json()
    lesson_ids = data.get('lesson_ids', [])

    if not lesson_ids:
        return "No lesson IDs provided", 400

    for cls_id in lesson_ids:
        db.session.query(TeachingSchedule).filter(
            TeachingSchedule.id == cls_id,
            TeachingSchedule.teacher_id == current_user.id
        ).delete(synchronize_session=False)

    db.session.commit()

    return "Deleted", 200



    # return '', 204
    
@app.route('/duplicate/<int:lesson_id>', methods=['GET','POST'])
@login_required
def duplicate_lesson(lesson_id):

    if request.method == 'GET':
        # Fetch the lesson to duplicate      
        lesson = db.session.query(TeachingSchedule).filter(
            TeachingSchedule.id == lesson_id,
            TeachingSchedule.teacher_id == current_user.id
        ).first()
        
        starttime = format_timedelta_to_time_str(lesson.starttime) # type: ignore
        endtime = format_timedelta_to_time_str(lesson.endtime) # type: ignore
        
        
        if not lesson:
            return redirect(url_for('dashboard'))
        
    elif request.method == 'POST':
        class_name = request.form['class_name']
        date_str = request.form['selected_date']
        start_time_str = request.form['start_time']
        end_time_str = request.form['end_time']
        school = request.form['school']
        rate = request.form['rate']
        paid = request.form['paid']

        # Convert to correct types
        class_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        start_time = list(map(int, start_time_str.split(':')))
        end_time = list(map(int, end_time_str.split(':')))

        start_time = timedelta(hours=start_time[0], minutes=start_time[1])
        end_time = timedelta(hours=end_time[0], minutes=end_time[1])
        
        lesson = TeachingSchedule()  # Create a new instance
        # Set the attributes
        lesson.class_name = class_name
        lesson.date = class_date
        lesson.starttime = start_time
        lesson.endtime = end_time
        lesson.school = school
        lesson.rate = rate
        lesson.paid = paid
        lesson.teacher_id = current_user.id  # Set the teacher_id

        db.session.add(lesson)
        db.session.commit()
        
        session['search_date'] = lesson.date.isoformat()  # Store the date in session for consistency

        return redirect(url_for('dashboard'))

    return render_template('base_info.html',
                           lesson=lesson,
                           starttime=starttime,
                           endtime=endtime,
                           lesson_id=lesson_id,
                           page_title='Duplicate the Lesson',
                           form_action = url_for('duplicate_lesson', lesson_id=lesson_id)
    )


@app.route('/duplicate_bulk', methods=['POST'])
@login_required
def duplicate_bulk():
    data = request.get_json()
    lesson_ids = data.get('lesson_ids', [])
    copy_date = data.get('copy_date')  # e.g. '2025-06-01'

    copy_date_dt = datetime.strptime(copy_date, "%Y-%m-%d")
    start_date = copy_date_dt - timedelta(days=copy_date_dt.weekday())  # Monday of that week
    end_date = start_date + timedelta(days=6)

    class_list = []

    # Fetch all selected lessons
    lessons = db.session.query(TeachingSchedule).filter(
        TeachingSchedule.id.in_(lesson_ids),
        TeachingSchedule.teacher_id == current_user.id
    ).all()
    
    session['search_date'] = copy_date  # Store the date in session for consistency

    for lesson in lessons:
        original_weekday = lesson.date.weekday()
        new_date = start_date + timedelta(days=original_weekday)

        # Create new lesson with updated date
        new_lesson = TeachingSchedule(
            class_name=lesson.class_name, # type: ignore
            date=new_date, # type: ignore
            starttime=lesson.starttime, # type: ignore
            endtime=lesson.endtime, # type: ignore
            school=lesson.school, # type: ignore
            rate=lesson.rate, # type: ignore
            paid="no",  # always set to unpaid # type: ignore
            teacher_id=current_user.id   # type: ignore
        )
        db.session.add(new_lesson)

    db.session.commit()
    return "Duplicate", 200


def calculate_totals(data): 
    total_hours = 0
    total_salary = 0
    hourly_rate = 0
    currency = current_user.currency.strip()

    if not data:
        return total_hours, f"0 {currency}", hourly_rate, 
    else:
        for row in data:
            rate_perhour = row[0]
            total_hour = row[1]
            total_hours += total_hour
            total_salary += rate_perhour * total_hour
            hourly_rate = rate_perhour

        # Format total salary with thousand separators and append currency
        total_salary_2 = f"{int(total_salary):,}".replace(",", ".") + f" {currency}"
        return total_hours, total_salary_2, hourly_rate, 


@app.route('/admin')
@admin_required
def admin_home():
    return render_template('admin_home.html')
    
    
@app.route('/admin/users')
@admin_required
def admin_users():
    
    username = request.args.get('username', '').strip()
    email = request.args.get('email', '').strip()
    user_id = request.args.get('user_id', '').strip()
    user_type = request.args.get('user_type', '').strip()
    disabled = request.args.get('disabled', '')
    confirmed = request.args.get('confirmed', '')
    registration_date = request.args.get('registration_date', '')
    last_login_filter = request.args.get('last_login_filter', '')

    query = db.session.query(
        User,
        func.count(UserSession.id).label('login_count')
    ).outerjoin(UserSession)

    if username:
        query = query.filter(User.username.ilike(f"%{username}%"))
    if email:
        query = query.filter(User.email.ilike(f"%{email}%"))
    if user_id:
        query = query.filter(User.id.cast(db.String).ilike(f"%{user_id}%"))
    if user_type:
        query = query.filter(User.user_type == user_type)
    if disabled in ('0', '1'):
        query = query.filter(User.disabled == (disabled == '1'))
    if confirmed in ('0', '1'):
        query = query.filter(User.confirmed == (confirmed == '1'))
    if registration_date:
        reg_date = datetime.strptime(registration_date, '%Y-%m-%d').date()
        query = query.filter(User.registration_date == reg_date)
    # inside your existing query-building block
    if last_login_filter in ['today', 'last_week', 'last_month']:
        now = datetime.utcnow()
        if last_login_filter == 'today':
            cutoff = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif last_login_filter == 'last_week':
            cutoff = now - timedelta(days=7)
        elif last_login_filter == 'last_month':
            cutoff = now - timedelta(days=30)
            
        # Subquery: get latest login per user
        recent_logins = db.session.query(
            UserSession.user_id,
            func.max(UserSession.login_time).label('last_login')
        ).filter(UserSession.status == 'success'
        ).group_by(UserSession.user_id).subquery()

        # Join that subquery and filter by time
        query = query.join(recent_logins, User.id == recent_logins.c.user_id
        ).filter(recent_logins.c.last_login >= cutoff)

    user_data = query.group_by(User.id).all()
    
    user_count = len(user_data)
    
    # Build a dictionary of last logins per user ID
    last_login_map = dict(
    db.session.query(
        UserSession.user_id,
        func.max(UserSession.login_time)
    ).filter(UserSession.status == 'success')
     .group_by(UserSession.user_id)
     .all()
)

    print(f"Last login: {last_login_map}")

    return render_template('admin_users.html', user_data=user_data, filters={
        'username': username,
        'email': email,
        'user_id': user_id,
        'user_type': user_type,
        'disabled': disabled
    }, user_count=user_count, last_login_map=last_login_map)

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        user.user_type = request.form['user_type']
        user.currency = ' ' + request.form['currency'].strip()

        # 🧠 Parse new disabled value as boolean
        new_disabled = request.form.get('disabled') == '1'
        new_blocked = request.form.get('blocked') == '1'

        note_text = request.form.get('note', '').strip()
        print(f"Note text: {note_text}")

        if user.blocked != new_blocked:
            user.blocked = new_blocked
            
            log = AdminActionLog(
                admin_id=current_user.id,  # type: ignore
                target_user_id=user.id,  # type: ignore
                action='block_user' if new_blocked else 'unblock_user',  # type: ignore
                note=note_text or 'Changed from user edit page.'  # type: ignore
            )
            db.session.add(log)
            
            html = render_template('emails/blocked.html')
            send_email(
                user.email, "Your Account has blocked - SchedEye", html)

        elif user.disabled != new_disabled:
            user.disabled = new_disabled

            log = AdminActionLog(
                admin_id=current_user.id,  # type: ignore
                target_user_id=user.id, # type: ignore
                action='disable_user' if new_disabled else 'enable_user',  # type: ignore
                note=note_text or 'Changed from user edit page.' # type: ignore
            )
            db.session.add(log)
            
            html = render_template('emails/disabled.html')
            send_email("admin@schedeye.com", "Your Account has been disabled - SchedEye", html)

        db.session.commit()
        flash('User updated successfully.', 'success')
        return redirect(url_for('admin_users'))
    
     # Login stats
    login_counts = (
        db.session.query(UserSession.status, func.count())
        .filter(UserSession.user_id == user.id)
        .group_by(UserSession.status)
        .all()
    )
    stats = {status: count for status, count in login_counts}

    # Last successful login
    last_login = (
        UserSession.query
        .filter_by(user_id=user.id, status='success')
        .order_by(UserSession.login_time.desc())
        .first()
    )

    # IP summary: distinct IPs used
    distinct_ips = (
        db.session.query(UserSession.ip_address)
        .filter_by(user_id=user.id)
        .distinct()
        .all()
    )
    ip_list = [ip[0] for ip in distinct_ips]

    # Recent 10 login attempts
    recent_attempts = (
        UserSession.query
        .filter_by(user_id=user.id)
        .order_by(UserSession.login_time.desc())
        .limit(10)
        .all()
    )
    # Fetch action logs related to this user
    admin_logs = (
        AdminActionLog.query
        .filter_by(target_user_id=user.id)
        .order_by(AdminActionLog.timestamp.desc())
        .all()
    )
    
    disable_count = AdminActionLog.query.filter_by(
        target_user_id=user.id,
        action='disable_user'
    ).count()

    enable_count = AdminActionLog.query.filter_by(
        target_user_id=user.id,
        action='enable_user'
    ).count()
    return render_template(
        'edit_user.html',
        user=user,
        currency_codes=currency_codes,
        stats=stats,
        last_login=last_login,
        ip_list=ip_list,
        recent_attempts=recent_attempts,
        admin_logs=admin_logs,
        disable_count=disable_count,
        enable_count=enable_count
    )

@app.route('/admin/sessions')
@admin_required
def admin_sessions():
    filters = {
        'user_id': request.args.get('user_id', '').strip(),
        'username': request.args.get('username', '').strip(),
        'login_date': request.args.get('login_date', '').strip(),
        'ip_address': request.args.get('ip_address', '').strip(),
        'status': request.args.get('status', '').strip(),
    }

    query = UserSession.query.join(User).order_by(UserSession.login_time.desc())

    if filters['user_id']:
        query = query.filter(User.id.cast(db.String).ilike(f"%{filters['user_id']}%"))
    if filters['username']:
        query = query.filter(User.username.ilike(f"%{filters['username']}%"))
    if filters['login_date']:
        query = query.filter(cast(UserSession.login_time, Date) == filters['login_date'])
    if filters['ip_address']:
        query = query.filter(UserSession.ip_address.ilike(f"%{filters['ip_address']}%"))
    if filters['status']:
        query = query.filter(UserSession.status == filters['status'])

    sessions = query.limit(100).all()
    
    sessions_count = len(sessions)

    # ✅ Set duration description for each session
    for s in sessions:
        if s.logout_time:
            s.duration = s.logout_time - s.login_time
        elif s.status == 'wrong_password':
            s.duration = "Session failed due to wrong password."
        elif s.status == 'disabled':
            s.duration = "Session failed due to account being disabled."
        elif s.status == 'blocked':
            s.duration = "Session failed due to account being blocked."
        elif s.status == 'invalid_captcha':
            s.duration = "Session failed due to invalid CAPTCHA."
        else:
            s.duration = "Session is active or expired."

    return render_template('admin_sessions.html', sessions=sessions, filters=filters, sessions_count=sessions_count)

@app.route('/settings', methods=['GET'])
@login_required
def settings():
    global currency_codes

    return render_template('settings.html', user=current_user, currency_codes=currency_codes)

@app.route('/update_account_info', methods=['POST'])
@login_required
def update_account_info():
    username = request.form.get('username')
    email = request.form.get('email')
    currency = request.form.get('currency')

    changed = False

    if username and username != current_user.username:
        current_user.username = username
        changed = True
        print(current_user.username)

    if email and email != current_user.email:
        current_user.email = email
        changed = True
        print(current_user.email)

    if currency and currency != current_user.currency:
        current_user.currency = currency
        changed = True
        print(current_user.currency)

    if changed:
        try:
            db.session.commit()
            flash('Account information updated successfully!', 'success')
            print(current_user)
            print(type(current_user))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating account info: {str(e)}', 'danger')
    else:
        flash('No changes detected.', 'info')

    return redirect(url_for('settings'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('currentPassword')
    new_password = request.form.get('newPassword')
    confirm_password = request.form.get('confirmPassword')

    if not current_password or not new_password or not confirm_password:
        flash('All fields are required.', 'danger')
        return redirect(url_for('settings'))

    if new_password != confirm_password:
        flash('New password and confirmation do not match.', 'danger')
        return redirect(url_for('settings'))

    if not check_password_hash(current_user.password_hash, current_password):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('settings'))

    current_user.password_hash = generate_password_hash(new_password)
    db.session.commit()

    flash('Password changed successfully!', 'success')
    return redirect(url_for('settings'))


    

def get_unique_values_orm(session, model, field_expr, filters, alias="value"):
    """
    SQLAlchemy ORM version of get_unique_values.

    Args:
        session: SQLAlchemy session (e.g. db.session)
        model: SQLAlchemy model (e.g. TeachingSchedule)
        field_expr: SQLAlchemy column expression (e.g. extract('year', model.date))
        filters: dict of {column: value}, where column is either a string or model attribute
        alias: alias for the selected field

    Returns:
        List of unique values ordered by the alias.
    """

    # Apply label (alias) to the field expression
    labeled_field = field_expr.label(alias)

    # Build base query
    query = session.query(distinct(labeled_field))

    # Apply filters
    for key, value in filters.items():
        col = getattr(model, key) if isinstance(key, str) else key
        query = query.filter(col == value)

    # Order by alias
    query = query.order_by(asc(labeled_field))

    return [row[0] for row in query.all()]

def get_totals_orm(session, year, teacher_id, paid="yes", month=None, school=None):
    # Use TIME_TO_SEC(endtime - starttime)/3600
    duration_expr = (
        func.time_to_sec(
            func.timediff(TeachingSchedule.endtime, TeachingSchedule.starttime)
        ) / 3600
    ).label("total_hour")

    query = session.query(
        TeachingSchedule.rate.label("rate_perhour"),
        duration_expr
    ).filter(
        extract('year', TeachingSchedule.date) == year,
        TeachingSchedule.teacher_id == teacher_id,
        TeachingSchedule.paid == paid
    )

    if month:
        query = query.filter(extract('month', TeachingSchedule.date) == month)
    if school:
        query = query.filter(TeachingSchedule.school == school)

    query = query.order_by(extract('month', TeachingSchedule.date))

    results = query.all()
    return calculate_totals(results)

def get_month_names(month_nums, month_names_dict):
    return [month_names_dict.get(num, "Unknown") for num in month_nums]

@app.route('/payments', methods=['GET', 'POST'])
@login_required
def payments():

    years2 = (
        db.session.query(distinct(extract('year', TeachingSchedule.date)).label('year'))
        .filter(TeachingSchedule.teacher_id == current_user.id)
        .order_by(desc(extract('year', TeachingSchedule.date)))
        .all()
        )

    # Flatten the result
    years2 = [year.year for year in years2]

    years2_unpaid = (db.session.query(distinct(extract('year', TeachingSchedule.date)).label('year'))
        .filter(TeachingSchedule.teacher_id == current_user.id, TeachingSchedule.paid == 'no')
        .order_by(desc(extract('year', TeachingSchedule.date)))
        .all()
    )

    # Flatten the list of tuples
    years2_unpaid = [year.year for year in years2_unpaid]

    # Static and init vars
    month_names = {
        1: 'January', 2: 'February', 3: 'March', 4: 'April',
        5: 'May', 6: 'June', 7: 'July', 8: 'August',
        9: 'September', 10: 'October', 11: 'November', 12: 'December'
    }
    months2, months2_unpaid, companies, companies_unpaid, schools, schools_unpaid = [], [], [], [], [], []
    selected_year = selected_month = selected_company = selected_school = None
    yearly_total_salary = yearly_total_salary_unpaid = monthly_total_salary = monthly_total_salary_unpaid = company_total_salary = company_total_salary_unpaid = school_total_salary = school_total_salary_unpaid = 0

    if request.method == 'POST':
        selected_year = request.form.get('year')
        selected_month = request.form.get('month')
        selected_company = request.form.get('company')
        selected_school = request.form.get('school')

        if selected_year:
            # Get unique months for the selected year
            months = get_unique_values_orm(
                session=db.session,  # Fixed typo
                model=TeachingSchedule,
                field_expr=extract('month', TeachingSchedule.date),
                filters={
                    extract('year', TeachingSchedule.date): selected_year,
                    TeachingSchedule.teacher_id: current_user.id
                },
                alias="month"
            )
            show_all_option = months and len(months) > 1
            months2 = get_month_names(months, month_names) + (["ALL"] if show_all_option else [])

            # Get unpaid months
            months_unpaid = get_unique_values_orm(
                session=db.session,
                model=TeachingSchedule,
                field_expr=extract('month', TeachingSchedule.date),
                filters={
                    extract('year', TeachingSchedule.date): selected_year,
                    TeachingSchedule.teacher_id: current_user.id,
                    TeachingSchedule.paid: 'no'
                },
                alias="month"
            )
            show_all_option = months_unpaid and len(months_unpaid) > 1
            months2_unpaid = get_month_names(months_unpaid, month_names) + (["ALL"] if show_all_option else [])


            yearly_total_hours, yearly_total_salary, _ = get_totals_orm(
                session=db.session,
                year=selected_year,
                teacher_id=current_user.id
            )
            yearly_total_hours_unpaid, yearly_total_salary_unpaid, _ = get_totals_orm(
                session=db.session,
                year=selected_year,
                teacher_id=current_user.id,
                paid="no"
            )

        if selected_month:
            month_number = next((k for k, v in month_names.items() if v == selected_month), None)
            # Start with year and teacher
            filters_month = {
                extract('year', TeachingSchedule.date): selected_year,
                TeachingSchedule.teacher_id: current_user.id
            }

            # Add month filter only if not "ALL"
            if selected_month != "ALL":
                filters_month[extract('month', TeachingSchedule.date)] = month_number

            companies = get_unique_values_orm(
                session=db.session,
                model=TeachingSchedule,
                field_expr=TeachingSchedule.school,
                filters=filters_month,
                alias="school"
            ) 
            
            if len(companies) > 1:
                companies.append("ALL")

            filters_unpaid_month = filters_month.copy()
            filters_unpaid_month[TeachingSchedule.paid] = "no"

            companies_unpaid = get_unique_values_orm(
                session=db.session,
                model=TeachingSchedule,
                field_expr=TeachingSchedule.school,
                filters=filters_unpaid_month,
                alias="school"
            )
            if companies_unpaid and len(companies_unpaid) > 1:
                companies_unpaid.append("ALL")

            monthly_total_hours, monthly_total_salary, _ = get_totals_orm(
                session=db.session,
                year=selected_year,
                teacher_id=current_user.id,
                month=month_number if selected_month != "ALL" else None
            )
            print(monthly_total_hours, monthly_total_salary)
            monthly_total_hours_unpaid, monthly_total_salary_unpaid, _ = get_totals_orm(
                session=db.session,
                year=selected_year,
                teacher_id=current_user.id,
                paid="no",
                month=month_number if selected_month != "ALL" else None
            )
            print(monthly_total_hours_unpaid, monthly_total_salary_unpaid)

        if selected_company:
            filters_company = {
                extract('year', TeachingSchedule.date): selected_year,
                TeachingSchedule.teacher_id: current_user.id
            }
            if selected_month != "ALL":
                filters_company[extract('month', TeachingSchedule.date)] = month_number

            if selected_company != "ALL":
                filters_company[TeachingSchedule.school] = selected_company

            schools = get_unique_values_orm(
                session=db.session,
                model=TeachingSchedule,
                field_expr=func.substring(TeachingSchedule.class_name, 1, 3),
                filters=filters_company,
                alias="class_prefix"
            ) 
            
            if len(schools) > 1:
                schools.append("ALL")

             
            filters_unpaid_company = filters_company.copy()
            filters_unpaid_company[TeachingSchedule.paid] = "no"


            schools_unpaid = get_unique_values_orm(
                session=db.session,
                model=TeachingSchedule,
                field_expr=func.substring(TeachingSchedule.class_name, 1, 3),
                filters=filters_unpaid_company,
                alias="class_prefix"
            )

           # Preprocess optional filters
            month = month_number if selected_month != "ALL" else None
            school = None if selected_company == "ALL" else selected_company

            # Append "ALL" if there are unpaid schools
            if schools_unpaid and len(schools_unpaid) > 1:
                schools_unpaid.append("ALL")

            # Paid totals
            company_total_hours, company_total_salary, _ = get_totals_orm(
                session=db.session,
                year=selected_year,
                teacher_id=current_user.id,
                month=month,
                school=school
            )

            # Unpaid totals
            company_total_hours_unpaid, company_total_salary_unpaid, _ = get_totals_orm(
                session=db.session,
                year=selected_year,
                teacher_id=current_user.id,
                month=month,
                school=school,
                paid="no"
            )
        if selected_school:
            filters_school = {
                extract('year', TeachingSchedule.date): selected_year,
                TeachingSchedule.teacher_id: current_user.id
            }

            if selected_month != "ALL":
                filters_school[extract('month', TeachingSchedule.date)] = month_number

            if selected_company != "ALL":
                filters_school[TeachingSchedule.school] = selected_company

            # Paid query
            query_paid = db.session.query(
                TeachingSchedule.rate.label("rate_perhour"),
                (
                    func.time_to_sec(
                        func.timediff(TeachingSchedule.endtime, TeachingSchedule.starttime)
                    ) / 3600
                ).label("total_hour")
            ).filter(TeachingSchedule.paid == "yes")

            # Apply filters
            for condition, value in filters_school.items():
                query_paid = query_paid.filter(condition == value)

            # Filter by class prefix if selected_school != "ALL"
            if selected_school != "ALL":
                query_paid = query_paid.filter(
                    func.substring(TeachingSchedule.class_name, 1, 3) == selected_school
                )

            school_total_hours, school_total_salary, _ = calculate_totals(query_paid.all())

            # Unpaid query
            query_unpaid = db.session.query(
                TeachingSchedule.rate.label("rate_perhour"),
                (
                    func.time_to_sec(
                        func.timediff(TeachingSchedule.endtime, TeachingSchedule.starttime)
                    ) / 3600
                ).label("total_hour")
            ).filter(TeachingSchedule.paid == "no")

            # Apply filters
            for condition, value in filters_school.items():
                query_unpaid = query_unpaid.filter(condition == value)

            if selected_school != "ALL":
                query_unpaid = query_unpaid.filter(
                    func.substring(TeachingSchedule.class_name, 1, 3) == selected_school
                )

            school_total_hours_unpaid, school_total_salary_unpaid, _ = calculate_totals(query_unpaid.all())
            
    if request.form.get('action') == 'paid':
        selected_year = request.form.get('year')
        selected_month = request.form.get('month')
        selected_company = request.form.get('company')
        selected_school = request.form.get('school')

        month_names = {
            1: 'January', 2: 'February', 3: 'March', 4: 'April',
            5: 'May', 6: 'June', 7: 'July', 8: 'August',
            9: 'September', 10: 'October', 11: 'November', 12: 'December'
        }

        if selected_year and selected_month:
            conditions = [
                extract('year', TeachingSchedule.date) == int(selected_year),
                TeachingSchedule.teacher_id == current_user.id
            ]

            if selected_month != "ALL":
                month_number = next((k for k, v in month_names.items() if v == selected_month), None)
                conditions.append(extract('month', TeachingSchedule.date) == month_number)

            if selected_company and selected_company != "ALL":
                conditions.append(TeachingSchedule.school == selected_company)

            if selected_school and selected_school != "ALL":
                conditions.append(func.substring(TeachingSchedule.class_name, 1, 3) == selected_school)

            # Perform the update
            db.session.query(TeachingSchedule)\
                .filter(and_(*conditions))\
                .update({TeachingSchedule.paid: 'yes'}, synchronize_session=False)

            db.session.commit()
            return redirect(url_for('payments'))
        
    if request.form.get('action') == 'unpaid':
        selected_year = request.form.get('year')
        selected_month = request.form.get('month')
        selected_company = request.form.get('company')
        selected_school = request.form.get('school')

        month_names = {
            1: 'January', 2: 'February', 3: 'March', 4: 'April',
            5: 'May', 6: 'June', 7: 'July', 8: 'August',
            9: 'September', 10: 'October', 11: 'November', 12: 'December'
        }

        if selected_year and selected_month:
            conditions = [
                extract('year', TeachingSchedule.date) == int(selected_year),
                TeachingSchedule.teacher_id == current_user.id
            ]

            if selected_month != "ALL":
                month_number = next((k for k, v in month_names.items() if v == selected_month), None)
                conditions.append(extract('month', TeachingSchedule.date) == month_number)

            if selected_company and selected_company != "ALL":
                conditions.append(TeachingSchedule.school == selected_company)

            if selected_school and selected_school != "ALL":
                conditions.append(func.substring(TeachingSchedule.class_name, 1, 3) == selected_school)

            # Perform the update
            db.session.query(TeachingSchedule)\
                .filter(and_(*conditions))\
                .update({TeachingSchedule.paid: 'no'}, synchronize_session=False)

            db.session.commit()
            return redirect(url_for('payments'))
        
    return render_template('payments.html',
        page_title='Payments',
        years2=years2,
        years2_unpaid=years2_unpaid,
        yearly_total_salary=yearly_total_salary,
        yearly_total_salary_unpaid=yearly_total_salary_unpaid,
        monthly_total_salary=monthly_total_salary,
        monthly_total_salary_unpaid=monthly_total_salary_unpaid,
        company_total_salary=company_total_salary,
        company_total_salary_unpaid=company_total_salary_unpaid,
        school_total_salary=school_total_salary,
        school_total_salary_unpaid=school_total_salary_unpaid,
        months2=months2,
        months2_unpaid=months2_unpaid,
        selected_year=selected_year,
        selected_month=selected_month,
        selected_company=selected_company,
        selected_school=selected_school,
        companies=companies,
        companies_unpaid=companies_unpaid,
        schools=schools,
        schools_unpaid=schools_unpaid,
    )

@app.route('/calculate_hours', methods=['GET', 'POST'])
@login_required
def calculate_hours():

    years = db. session.query(
        distinct(extract('year', TeachingSchedule.date)).label('year')
    ).filter(
        TeachingSchedule.teacher_id == current_user.id
    ).order_by(
        desc(extract('year', TeachingSchedule.date))
    ).all()
    
    # Flatten the result
    years2 = [year.year for year in years]


    month_names = {
        1: 'January', 2: 'February', 3: 'March', 4: 'April',
        5: 'May', 6: 'June', 7: 'July', 8: 'August',
        9: 'September', 10: 'October', 11: 'November', 12: 'December'
    }

    months2, companies, schools = [], [], []
    summary_result = {}
    selected_year = selected_month = selected_company = selected_school = None

    if request.method == 'POST':
        selected_year = request.form.get('year')
        selected_month = request.form.get('month')
        selected_company = request.form.get('company')
        selected_school = request.form.get('school')
        selected_month2 = next((k for k, v in month_names.items() if v == selected_month), None)

        if selected_year:
            
            months = db.session.query(
                distinct(extract('month', TeachingSchedule.date)).label('month')
            ).filter(
                extract('year', TeachingSchedule.date) == selected_year,
                TeachingSchedule.teacher_id == current_user.id
            ).order_by(
                extract('month', TeachingSchedule.date)
            ).all()
            
            months2 = [month_names.get(month.month, 'Unknown') for month in months]
            print(months2)

        if selected_month:
            
            company = db.session.query(
                distinct(TeachingSchedule.school).label('school')
            ).filter(
                extract('year', TeachingSchedule.date) == selected_year,
                extract('month', TeachingSchedule.date) == selected_month2,
                TeachingSchedule.teacher_id == current_user.id
            ).order_by(
                TeachingSchedule.school
            ).all()
            
            companies = [row.school for row in company]
            if len(companies) > 1:
                companies.append("ALL")

        if selected_company:
            filter_conditions = [
                    extract('year', TeachingSchedule.date) == selected_year,
                    extract('month', TeachingSchedule.date) == selected_month2,
                    TeachingSchedule.teacher_id == current_user.id
                ]
            if selected_company == "ALL":
                school = db.session.query(
                    distinct(func.substring(TeachingSchedule.class_name, 1, 3)).label('class_prefix')
                ).filter(*filter_conditions).order_by(
                    func.substring(TeachingSchedule.class_name, 1, 3)
                ).all()
                
            else:
                filter_conditions.append(TeachingSchedule.school == selected_company)
                
                school = db.session.query(
                    distinct(func.substring(TeachingSchedule.class_name, 1, 3)).label('class_prefix')
                ).filter(
                    *filter_conditions
                ).order_by(
                    func.substring(TeachingSchedule.class_name, 1, 3)
                ).all()
            
            schools = [row[0] for row in school]
            if len(schools) > 1:
                schools.append("ALL")

        if request.form.get('action') == 'calculate':
    
            filter_conditions = [
                extract('year', TeachingSchedule.date) == selected_year,
                extract('month', TeachingSchedule.date) == selected_month2,
                TeachingSchedule.teacher_id == current_user.id
            ]

            if selected_company and selected_company != "ALL":
                filter_conditions.append(TeachingSchedule.school == selected_company)

            if selected_school and selected_school != "ALL":
                filter_conditions.append(
                    func.substring(TeachingSchedule.class_name, 1, 3) == selected_school
                )

            # Total minutes (using TIME_TO_SEC(TIMEDIFF(...)) / 60)
            total_minutes = db.session.query(
                func.sum(
                    func.time_to_sec(
                        func.timediff(TeachingSchedule.endtime, TeachingSchedule.starttime)
                    ) / 60
                ).label('total_minutes')
            ).filter(*filter_conditions).scalar() or 0

            print(f"Total minutes: {total_minutes}")

            total_hours = round(total_minutes / 60, 2)
            
            print(f"Total hours: {total_hours}")

            # Get rate + total hours
            result2 = db.session.query(
                TeachingSchedule.rate.label("rate_perhour"),
                (
                    func.time_to_sec(
                        func.timediff(TeachingSchedule.endtime, TeachingSchedule.starttime)
                    ) / 3600
                ).label("total_hour")
            ).filter(*filter_conditions).all()

            total_salary = round(sum(rate * hours for rate, hours in result2), 0)

            # Average rate
            avg_rate = db.session.query(
                func.avg(TeachingSchedule.rate)
            ).filter(*filter_conditions).scalar() or 0

            hourly_rate = round(avg_rate, 0)

            summary_result = {
                'total_hours': f"{total_hours:.2f} hours",
                'hourly_rate': f"{hourly_rate:,}".replace(",", ".") + current_user.currency,
                'total_salary': f"{int(total_salary):,}".replace(",", ".") + current_user.currency
            }


    return render_template('calculate_hours.html',
        page_title='Calculate Hours',
        years2=years2,
        months2=months2,
        companies=companies,
        schools=schools,
        summary_result=summary_result,
        selected_year=selected_year,
        selected_month=selected_month,
        selected_company=selected_company,
        selected_school=selected_school
    )


        
@app.route('/test_register_email') # type: ignore

def test_register_email():
    send_email(
            "admin@schedeye.com",
            "New Contact Form Submission",
            f"Email: {"deneme"}\nTopic: {"topic"}\nMessage: {"message"}"
        )

    return "Email sent successfully!"


if __name__ == '__main__':
    app.run(debug=True)