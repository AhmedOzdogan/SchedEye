from datetime import UTC, date, datetime, timedelta, timezone
from flask_mail import Mail, Message
from functools import wraps
import time
import uuid
import os
from dotenv import load_dotenv
from flask import Flask, abort, render_template, request, redirect, session, url_for, flash
from sqlalchemy import Date, cast, func
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from db_config import get_connection
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer




app = Flask(__name__)
app.secret_key = 'your_secret_key'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # type: ignore

app.secret_key = 'your_secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Ahmed.4091@localhost/shedeye'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app) 

load_dotenv()
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
      
def get_user(field, value):
    conn =  get_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT id, username, email, password_hash, user_type, currency FROM users  WHERE {field} = %s", (value,))
    row = cursor.fetchone()
    conn.close()
    if row:
        user = User()
        user.id, user.username, user.email, user.password_hash, user.user_type, user.currency = row
        return user
    return None

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
        
def format_timedelta_to_time_str(tdelta):
    total_seconds = int(tdelta.total_seconds())
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    return f"{hours:02}:{minutes:02}"

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
        
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        session_token = str(uuid.uuid4())
        ip = request.remote_addr
        user_agent = request.user_agent.string

        user = get_user_by_email(email)

        # Generate session meta
        session_token = str(uuid.uuid4())
        ip = request.remote_addr
        user_agent = request.user_agent.string
        now = datetime.now(UTC)

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
            token = serializer.dumps(email, salt='email-confirm')
            confirm_url = url_for('confirm_email', token=token, _external=True)
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
                flash("Account disabled after too many failed login attempts.", "danger")
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
        return redirect(url_for('dashboard'))


    return render_template('login.html')


@app.route('/')
def home():
    return render_template('home.html')

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
    conn = get_connection()
    cursor = conn.cursor()
    selected_date = request.args.get('selected_date')
    
    if selected_date:
        selected_date_dt = datetime.strptime(selected_date, "%Y-%m-%d")

        start_date = selected_date_dt - timedelta(
            days=selected_date_dt.weekday())
        
        end_date = start_date + timedelta(days=6)

    else:
        selected_date_dt = datetime.now()

        start_date = selected_date_dt - timedelta(days=selected_date_dt.weekday())

        end_date = start_date + timedelta(days=6)
        
    cursor.execute("SELECT * FROM teaching_schedule WHERE teacher_id = %s", (current_user.id,))
    
    query = """SELECT * FROM teaching_schedule 
                WHERE date BETWEEN %s 
                AND %s 
                AND teacher_id = %s
                ORDER BY date, starttime
    """
    cursor.execute(query, (start_date.date(), end_date.date(), current_user.id))
    teaching_schedule_data = cursor.fetchall()
    cursor.close()
    
    
    week_dates = []
    start_date2 = start_date
    for i in range(7):  # 7 days, Monday to Sunday
        week_dates.append({
            'day_name': start_date2.strftime('%A'),
            'day_date': start_date2.strftime('%d.%m.%Y')
        })
        start_date2 += timedelta(days=1)
        
    

    return render_template('dashboard.html',
                           teaching_schedule_data = teaching_schedule_data,
                           week_dates = week_dates,
                           start_date = start_date,
                           end_date = end_date,
                           selected_date = selected_date
)
    
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
    
    conn = get_connection()
    cursor = conn.cursor()

    for cls_id in lesson_ids:
        cursor.execute(
            "UPDATE teaching_schedule SET paid = 'yes' WHERE id = %s AND teacher_id = %s",
            (cls_id, current_user.id)
        )

    conn.commit()
    cursor.close()
    conn.close()

    return "Updated Paid", 200

@app.route('/toggle_unpaid', methods=['POST'])
@login_required
def toggle_unpaid():
    data = request.get_json()
    lesson_ids = data.get('lesson_ids', [])
    print(lesson_ids)

    if not lesson_ids:
        return "No lesson IDs provided", 400

    conn = get_connection()
    cursor = conn.cursor()

    for cls_id in lesson_ids:
        cursor.execute(
            "UPDATE teaching_schedule SET paid = 'no' WHERE id = %s AND teacher_id = %s",
            (cls_id, current_user.id)
        )

    conn.commit()
    cursor.close()
    conn.close()

    return "Updated Unpaid", 200

@app.route('/edit/<int:lesson_id>', methods=['POST', 'GET'])
@login_required
def edit_lesson(lesson_id):
    conn = get_connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        QUERY = """SELECT * FROM teaching_schedule 
                    WHERE id = %s
                    AND teacher_id = %s
        """
        cursor.execute(QUERY, (lesson_id, current_user.id))
        lesson = cursor.fetchone()
        lesson2 = []
        
        for row in lesson:

            if isinstance(row, timedelta):
                lesson2.append(format_timedelta_to_time_str(row))
            else:
                lesson2.append(row)
    
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

        query = """UPDATE teaching_schedule 
                    SET class = %s, date = %s, starttime = %s, endtime = %s, school = %s, rate = %s, paid = %s
                    WHERE id = %s AND teacher_id = %s
        """
        cursor.execute(query, (class_name, class_date, start_time, end_time, school, rate, paid, lesson_id, current_user.id))
        conn.commit()
        return redirect(url_for('dashboard'))
    

    conn.commit()
    cursor.close()
    conn.close() 
    return render_template('base_info.html',
                           lesson_id=lesson_id,
                           page_title='Edit Lesson', 
                           lesson=lesson2,
                           form_action = url_for('edit_lesson', lesson_id=lesson_id)
    )
    
@app.route('/add_lesson', methods=['POST', 'GET'])
@login_required
def add_lesson():
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

        conn = get_connection()
        cursor = conn.cursor()

        query = """INSERT INTO teaching_schedule (class, date, starttime, endtime, school, rate, paid, teacher_id)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        """

        cursor.execute(query, (class_name, class_date, start_time, end_time, school, rate, paid, current_user.id))
        conn.commit()
        cursor.close()
        conn.close()
        return redirect(url_for('dashboard'))

    return render_template('base_info.html',
                           lesson_id=None,
                           page_title='Add Lesson', 
                           lesson=None,
                           form_action = url_for('add_lesson')
    )
    
@app.route('/toggle_delete', methods=['POST'])
@login_required
def toggle_delete_bulk():
    data = request.get_json()
    lesson_ids = data.get('lesson_ids', [])

    if not lesson_ids:
        return "No lesson IDs provided", 400

    conn = get_connection()
    cursor = conn.cursor()

    for cls_id in lesson_ids:
        cursor.execute(
            "DELETE FROM teaching_schedule WHERE id = %s AND teacher_id = %s",
            (cls_id, current_user.id)
        )

    conn.commit()
    cursor.close()
    conn.close()
    
    return "Deleted", 200



    # return '', 204
    
@app.route('/duplicate/<int:lesson_id>', methods=['GET','POST'])
@login_required
def duplicate_lesson(lesson_id):
    conn = get_connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        QUERY = """SELECT * FROM teaching_schedule 
                    WHERE id = %s
                    AND teacher_id = %s
        """
        cursor.execute(QUERY, (lesson_id, current_user.id))
        lesson = cursor.fetchone()
        lesson2 = []
        
        for row in lesson:

            if isinstance(row, timedelta):
                lesson2.append(format_timedelta_to_time_str(row))
            else:
                lesson2.append(row)
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

        query = """INSERT INTO teaching_schedule (class, date, starttime, endtime, school, rate, paid, teacher_id)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        """

        cursor.execute(query, (class_name, class_date, start_time, end_time, school, rate, paid, current_user.id))
        conn.commit()
        cursor.close()
        conn.close()
        return redirect(url_for('dashboard'))

    return render_template('base_info.html',
                           lesson=lesson2,
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
    start_date = copy_date_dt - timedelta(days=copy_date_dt.weekday())
    end_date = start_date + timedelta(days=6)

    class_list = []
    
    for cls in lesson_ids:
        query = """SELECT * FROM teaching_schedule
                WHERE id = %s
                AND teacher_id = %s
                """
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute(query, (cls, current_user.id))
        result = cursor.fetchone()
        if result:
            result = list(result)  # Convert tuple to list for modification
            original_weekday = result[2].weekday()  # Assuming date is at index 2
            new_date = start_date + timedelta(days=original_weekday)
            
            result[2] = new_date  # Update the date to the new date
            class_list.append(result)

    for row in class_list:
        print("inserted row")
        query = """INSERT INTO teaching_schedule (class, date, starttime, endtime, school, rate, paid, teacher_id)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """
        cursor.execute(query, (row[1], row[2], row[3], row[4], row[5], row[6], "no", current_user.id))
        conn.commit()

    conn.commit()
    cursor.close()
    conn.close()
    
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
            
        elif user.disabled != new_disabled:
            user.disabled = new_disabled

            log = AdminActionLog(
                admin_id=current_user.id,  # type: ignore
                target_user_id=user.id, # type: ignore
                action='disable_user' if new_disabled else 'enable_user',  # type: ignore
                note=note_text or 'Changed from user edit page.' # type: ignore
            )
            db.session.add(log)

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


    

def get_unique_values(cursor, field_expr, filters, alias="value", table="teaching_schedule"):
    where_clause = " AND ".join([f"{key} = %s" for key in filters.keys()])
    query = f"SELECT DISTINCT {field_expr} AS {alias} FROM {table} WHERE {where_clause} ORDER BY {alias};"
    cursor.execute(query, tuple(filters.values()))
    return [row[0] for row in cursor.fetchall()]

def get_totals(cursor, year, teacher_id, paid="yes", month=None, school=None):
    conditions = ["YEAR(date) = %s", "teacher_id = %s", "paid = %s"]
    params = [year, teacher_id, paid]

    if month:
        conditions.append("MONTH(date) = %s")
        params.append(month)
    if school:
        conditions.append("school = %s")
        params.append(school)

    where_clause = " AND ".join(conditions)
    query = f"""
        SELECT RATE as rate_perhour,
               TIMESTAMPDIFF(MINUTE, CONCAT('2000-01-01 ',starttime), CONCAT('2000-01-01 ',endtime))/60 as total_hour
        FROM teaching_schedule
        WHERE {where_clause}
        ORDER BY MONTH(date);
    """
    cursor.execute(query, tuple(params))
    return calculate_totals(cursor.fetchall())

def get_month_names(month_nums, month_names_dict):
    return [month_names_dict.get(num, "Unknown") for num in month_nums]

@app.route('/payments', methods=['GET', 'POST'])
@login_required
def payments():
    conn = get_connection()
    cursor = conn.cursor()

    # Years data
    cursor.execute("""
        SELECT DISTINCT YEAR(date) AS year
        FROM teaching_schedule
        WHERE teacher_id = %s
        ORDER BY year DESC
    """, (current_user.id,))
    years2 = [year[0] for year in cursor.fetchall()]

    cursor.execute("""
        SELECT DISTINCT YEAR(date) AS year
        FROM teaching_schedule
        WHERE teacher_id = %s AND paid = 'no'
    """, (current_user.id,))
    years2_unpaid = [year[0] for year in cursor.fetchall()]

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
            months = get_unique_values(cursor, "MONTH(date)", {"YEAR(date)": selected_year, "teacher_id": current_user.id}, alias="month")
            months2 = get_month_names(months, month_names) + ["ALL"]

            months_unpaid = get_unique_values(cursor, "MONTH(date)", {
                "YEAR(date)": selected_year, "teacher_id": current_user.id, "paid": "no"
            }, alias="month")
            months2_unpaid = get_month_names(months_unpaid, month_names) + (["ALL"] if months_unpaid else [])

            yearly_total_hours, yearly_total_salary, _ = get_totals(cursor, selected_year, current_user.id)
            yearly_total_hours_unpaid, yearly_total_salary_unpaid, _ = get_totals(cursor, selected_year, current_user.id, paid="no")

        if selected_month:
            month_number = next((k for k, v in month_names.items() if v == selected_month), None)
            filters = {"YEAR(date)": selected_year, "teacher_id": current_user.id}
            if selected_month != "ALL":
                filters["MONTH(date)"] = month_number

            companies = get_unique_values(cursor, "school", filters, alias="school") + ["ALL"]
            filters_unpaid = filters.copy()
            filters_unpaid["paid"] = "no"
            companies_unpaid = get_unique_values(cursor, "school", filters_unpaid, alias="school")
            if companies_unpaid:
                companies_unpaid.append("ALL")

            monthly_total_hours, monthly_total_salary, _ = get_totals(cursor, selected_year, current_user.id, month=month_number)
            monthly_total_hours_unpaid, monthly_total_salary_unpaid, _ = get_totals(cursor, selected_year, current_user.id, paid="no", month=month_number)

        if selected_company:
            filters = {"YEAR(date)": selected_year, "teacher_id": current_user.id}
            if selected_month != "ALL":
                filters["MONTH(date)"] = month_number
            if selected_company != "ALL":
                filters["school"] = selected_company

            schools = get_unique_values(cursor, "SUBSTRING(class,1,3)", filters, alias="class_prefix") + ["ALL"]
            filters_unpaid = filters.copy()
            filters_unpaid["paid"] = "no"
            schools_unpaid = get_unique_values(cursor, "SUBSTRING(class,1,3)", filters_unpaid, alias="class_prefix")
            if schools_unpaid:
                schools_unpaid.append("ALL")
            print(schools_unpaid)
            
            company_total_hours, company_total_salary, _ = get_totals(
                cursor,
                selected_year,
                current_user.id,
                month=month_number
                if selected_month != "ALL" else None,
                school=None if selected_company == "ALL" else selected_company
)
            company_total_hours_unpaid, company_total_salary_unpaid, _ = get_totals(
                cursor,
                selected_year,
                current_user.id,
                paid="no",
                month=month_number
                if selected_month != "ALL" else None,
                school=None if selected_company == "ALL" else selected_company
            )
        if selected_school:
            filters = {"YEAR(date)": selected_year, "teacher_id": current_user.id}
            if selected_month != "ALL":
                filters["MONTH(date)"] = month_number
            if selected_company != "ALL":
                filters["school"] = selected_company

            # Get totals using filters + custom WHERE condition for class prefix
            conditions = [f"{key} = %s" for key in filters]
            params = list(filters.values())

            if selected_school != "ALL":
                conditions.append("SUBSTRING(class,1,3) = %s")
                params.append(selected_school)

            where_clause = " AND ".join(conditions)

            query_paid = f"""
                SELECT RATE as rate_perhour,
                    TIMESTAMPDIFF(MINUTE, CONCAT('2000-01-01 ',starttime), CONCAT('2000-01-01 ',endtime))/60 as total_hour
                FROM teaching_schedule
                WHERE {where_clause} AND paid = 'yes';
            """
            cursor.execute(query_paid, tuple(params))
            school_total_hours, school_total_salary, _ = calculate_totals(cursor.fetchall())

            query_unpaid = f"""
                SELECT RATE as rate_perhour,
                    TIMESTAMPDIFF(MINUTE, CONCAT('2000-01-01 ',starttime), CONCAT('2000-01-01 ',endtime))/60 as total_hour
                FROM teaching_schedule
                WHERE {where_clause} AND paid = 'no';
            """
            cursor.execute(query_unpaid, tuple(params))
            school_total_hours_unpaid, school_total_salary_unpaid, _ = calculate_totals(cursor.fetchall())
            
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

        update_query = ""
        params = []

        if selected_year and selected_month:
            update_query = "UPDATE teaching_schedule SET paid = 'yes' WHERE YEAR(date) = %s"
            params = [int(selected_year)]

            if selected_month != "ALL":
                month_number = next((k for k, v in month_names.items() if v == selected_month), None)
                update_query += " AND MONTH(date) = %s"
                params.append(month_number) # type: ignore

            update_query += " AND teacher_id = %s"
            params.append(current_user.id)

            if selected_company and selected_company != "ALL":
                update_query += " AND school = %s"
                params.append(selected_company) # type: ignore

            if selected_school and selected_school != "ALL":
                update_query += " AND SUBSTRING(class,1,3) = %s"
                params.append(selected_school) # type: ignore

            cursor.execute(update_query, tuple(params))
            conn.commit()
            flash("Marked as paid successfully.", "success")
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

        update_query = ""
        params = []

        if selected_year and selected_month:
            update_query = "UPDATE teaching_schedule SET paid = 'no' WHERE YEAR(date) = %s"
            params = [int(selected_year)]

            if selected_month != "ALL":
                month_number = next((k for k, v in month_names.items() if v == selected_month), None)
                update_query += " AND MONTH(date) = %s"
                params.append(month_number) # type: ignore

            update_query += " AND teacher_id = %s"
            params.append(current_user.id)

            if selected_company and selected_company != "ALL":
                update_query += " AND school = %s"
                params.append(selected_company) # type: ignore

            if selected_school and selected_school != "ALL":
                update_query += " AND SUBSTRING(class,1,3) = %s"
                params.append(selected_school) # type: ignore

            cursor.execute(update_query, tuple(params))
            conn.commit()
            flash("Marked as unpaid successfully.", "warning")
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
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT DISTINCT YEAR(date) FROM teaching_schedule
        WHERE teacher_id = %s
        ORDER BY YEAR(date) DESC
    """, (current_user.id,))
    years2 = [year[0] for year in cursor.fetchall()]

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
            cursor.execute("""
                SELECT DISTINCT MONTH(date) FROM teaching_schedule
                WHERE YEAR(date) = %s AND teacher_id = %s
                ORDER BY MONTH(date)
            """, (selected_year, current_user.id))
            months2 = [month_names.get(month[0], 'Unknown') for month in cursor.fetchall()]

        if selected_month:
            cursor.execute("""
                SELECT DISTINCT school FROM teaching_schedule
                WHERE MONTH(date) = %s AND YEAR(date) = %s AND teacher_id = %s
                ORDER BY school
            """, (selected_month2, selected_year, current_user.id))
            companies = [row[0] for row in cursor.fetchall()] + ["ALL"]

        if selected_company:
            if selected_company == "ALL":
                cursor.execute("""
                    SELECT DISTINCT SUBSTRING(class,1,3) as class_prefix FROM teaching_schedule
                    WHERE MONTH(date) = %s AND YEAR(date) = %s AND teacher_id = %s
                """, (selected_month2, selected_year, current_user.id))
            else:
                cursor.execute("""
                    SELECT DISTINCT SUBSTRING(class,1,3) as class_prefix FROM teaching_schedule
                    WHERE MONTH(date) = %s AND school = %s AND YEAR(date) = %s AND teacher_id = %s
                """, (selected_month2, selected_company, selected_year, current_user.id))
            schools = [row[0] for row in cursor.fetchall()] + ["ALL"]

        if request.form.get('action') == 'calculate':
            base_query = """
                FROM teaching_schedule
                WHERE MONTH(date) = %s AND YEAR(date) = %s AND teacher_id = %s
            """
            query_params = [selected_month2, selected_year, current_user.id]

            if selected_company != "ALL":
                base_query += " AND school = %s"
                query_params.append(selected_company)

            if selected_school != "ALL":
                base_query += " AND SUBSTRING(class,1,3) = %s"
                query_params.append(selected_school)

            cursor.execute(f"SELECT SUM(TIMESTAMPDIFF(MINUTE, CONCAT('2000-01-01 ',starttime), CONCAT('2000-01-01 ',endtime))) AS total_minutes {base_query}", query_params)
            total_minutes = cursor.fetchone()[0] or 0
            total_hours = round(total_minutes / 60, 2)

            cursor.execute(f"""
                SELECT RATE as rate_perhour,
                       TIMESTAMPDIFF(MINUTE, CONCAT('2000-01-01 ',starttime), CONCAT('2000-01-01 ',endtime))/60 as total_hour
                {base_query}
            """, query_params)
            result2 = cursor.fetchall()
            total_salary = round(sum(rate * hours for rate, hours in result2), 0)

            cursor.execute(f"SELECT AVG(RATE) as avg_rate {base_query}", query_params)
            avg_rate = cursor.fetchone()[0] or 0
            hourly_rate = round(avg_rate, 0)

            summary_result = {
                'total_hours': f"{total_hours:.2f} hours",
                'hourly_rate': f"{hourly_rate:,}".replace(",", ".") + current_user.currency,
                'total_salary': f"{int(total_salary):,}".replace(",", ".") + current_user.currency
            }

            cursor.close()
            conn.close()

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


        
@app.route('/test_register_email')
def test_register_email():
    dummy_email = 'ahmeddozdogan@gmail.com'  # Change this to your test address
    token = serializer.dumps(dummy_email, salt='email-confirm')
    confirm_url = url_for('confirm_email', token=token, _external=True)

    html = render_template('emails/reset_password_email.html', reset_url=confirm_url)
    send_email(dummy_email, 'Reset Your Password - SchedEye', html)

    return "✅ Test reset password email sent!"


if __name__ == '__main__':
    app.run(debug=True)