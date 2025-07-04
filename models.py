# Define the User model
# This model represents the users of the application, including their authentication details and other attributes.
from datetime import date, datetime
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func

db = SQLAlchemy()  # Assuming you have already initialized SQLAlchemy in your app


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True) # Unique ID for each user
    username = db.Column(db.String(50), nullable=False) # Username for each user
    email = db.Column(db.String(100), unique=True, nullable=False) # Unique email for each user
    password_hash = db.Column(db.String(255), nullable=False) # Store hashed password
    user_type = db.Column(db.String(20), default='regular')  # 'regular' or 'admin'
    currency = db.Column(db.String(10), default=' USD') # instead of another func just add a space before it.
    disabled = db.Column(db.Boolean, default=False)  # to disable user accounts
    confirmed = db.Column(db.Boolean, default=False)  # to confirm user accounts
    blocked = db.Column(db.Boolean, default=False)  # to block user accounts
    registration_date = db.Column(db.Date, default=date.today) # to track registration date
    login_attempts = db.Column(db.Integer, default=0)  # Track login attempts

    # Use string here
    sessions = db.relationship('UserSession', backref='user', lazy=True)
    schedules = db.relationship('TeachingSchedule', back_populates='teacher')

# Define the UserSession model
# This model represents user sessions, including login and logout times, IP addresses, and user agents etc.
class UserSession(db.Model):
    __tablename__ = 'user_sessions'

    id = db.Column(db.Integer, primary_key=True) # Unique ID for each session
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable = True) # Foreign key to the User model
    login_time = db.Column(db.DateTime, nullable=False, server_default=func.current_timestamp()) # Login time of the session
    logout_time = db.Column(db.DateTime) # Logout time of the session, can be null if user is still logged in
    ip_address = db.Column(db.String(45)) # IP address of the user during the session
    user_agent = db.Column(db.String(255)) # User agent of the user during the session
    session_token = db.Column(db.String(64)) # Unique session token for the user
    status = db.Column(db.String(32), default='success') # Status of the session, e.g., 'success', 'invalid_password', 'blocked', etc for malicious attempts
    
# Define the AdminActionLog model
# This model logs actions performed by admins, such as disabling users or other administrative tasks.
class AdminActionLog(db.Model):
    __tablename__ = 'admin_action_logs'

    id = db.Column(db.Integer, primary_key=True) # Unique ID for each log entry
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False) # Foreign key to the User model for the admin who performed the action
    target_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False) # Foreign key to the User model for the user affected by the action
    action = db.Column(db.String(50), nullable=False)  # e.g., 'disable_user'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow) # Timestamp of when the action was performed
    note = db.Column(db.Text) # Optional note or reason for the action

# Define the TeachingSchedule model
# This model represents the teaching schedule for users, including class details, date, time, and payment status.
class TeachingSchedule(db.Model):
    __tablename__ = 'teaching_schedule'

    id = db.Column(db.Integer, primary_key=True) # Unique ID for each teaching schedule entry
    class_name = db.Column("class", db.String(50), nullable=False) # Class name for the teaching schedule
    date = db.Column(db.Date, nullable=False) # Date of the class
    starttime = db.Column(db.Time, nullable=False) # Start time of the class
    endtime = db.Column(db.Time, nullable=False) # End time of the class
    school = db.Column(db.String(50), nullable=False) # School or institution where the class is held
    rate = db.Column(db.Numeric(10, 2), nullable=False, default=0.00) # Rate for the class
    paid = db.Column(db.String(3), nullable=False, default='no') # Payment status

    teacher_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    teacher = db.relationship('User', back_populates='schedules')