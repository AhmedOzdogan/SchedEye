#helpers.py
## Utility functions for SchedEye application



import os
from flask_login import current_user
from flask_mail import Message
from numpy import extract
from sqlalchemy import asc, distinct, func
from models import TeachingSchedule



def send_email(to, subject, html_body):
    from app import mail
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

# Function to format a timedelta to a time string (HH:MM)
def format_timedelta_to_time_str(value):
    """Convert a timedelta to a formatted time string."""
    return f"{value.hour:02d}:{value.minute:02d}"

# Function to add demo classes for a new user
def add_demo(user_id):
    """Add demo classes for a new user."""
    example_classes = [
        TeachingSchedule(
            class_name='Demo Class 1', # type: ignore
            date=date.today(), # type: ignore
            starttime=time(9, 0), # type: ignore
            endtime=time(10, 0), # type: ignore
            school='', # type: ignore
            rate=0.00, # type: ignore
            paid='no', # type: ignore
            teacher_id=user_id # type: ignore
        ),
        TeachingSchedule(
            class_name='Demo Class 2', # type: ignore
            date=date.today(), # type: ignore
            starttime=time(10, 30), # type: ignore
            endtime=time(11, 30), # type: ignore
            school='', # type: ignore
            rate=0.00, # type: ignore
            paid='no', # type: ignore
            teacher_id=user_id # type: ignore
        ),
        TeachingSchedule(
            class_name='Demo Class 3', # type: ignore 
            date=date.today(), # type: ignore
            starttime=time(13, 0), # type: ignore
            endtime=time(14, 0), # type: ignore
            school='', # type: ignore
            rate=0.00, # type: ignore
            paid='no', # type: ignore
            teacher_id=user_id # type: ignore
        )
    ]

    db.session.add_all(example_classes)  # type: ignore
    db.session.commit() # type: ignore
    

# Function to calculate total hours and salary from the teaching schedule data
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

# Function to get unique values from a field in a SQLAlchemy ORM model
def get_unique_values_orm(session, model, field_expr, filters, alias="value"):
    from app import TeachingSchedule
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

# Function to calculate totals from a list of results
def get_totals_orm(session, year, teacher_id, paid="yes", month=None, school=None):
    from app import TeachingSchedule
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

# Function to swap months with month numbers
def get_month_names(month_nums, month_names_dict):
    return [month_names_dict.get(num, "Unknown") for num in month_nums]