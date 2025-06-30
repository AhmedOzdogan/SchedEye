# 📅 SchedEye

SchedEye is a modern, mobile-friendly web application for managing teaching schedules, tracking payments, and viewing login history. Designed for freelance teachers or small institutes, it provides an efficient way to organize lessons, monitor activity, and streamline communication with schools and students.

🔗 **Live Site:** [https://schedule.com](https://schedule.com)

---

## 🔧 Features

- **User Authentication**
  - Secure login with hashed passwords
  - Rate-limiting after failed attempts
  - Admin panel with user management
- **Schedule Management**
  - Add/edit/delete lessons by date
  - Mobile-responsive table view with context menu
  - Bulk actions: mark multiple lessons as paid/unpaid
  - Calculate hours and payments per month, school, or year
- **Payment Tracking**
  - Calculate total payments earned, pending, or received
  - Visual indicators for paid/unpaid lessons
- **Login History**
  - Last login date & IP/location
  - Chart of recent login attempts
  - Suspicious activity notifications
- **User Experience**
  - Welcome tutorial for new users
  - Light and dark mode support (via Bootstrap)
  - Fully responsive design for mobile & desktop
  - Tooltips, toasts, and icons for improved UI

---

## 🛠️ Tech Stack

- **Backend:** Flask (Python), SQLAlchemy, MySQL
- **Frontend:** HTML, Bootstrap 5, JS (vanilla)
- **Auth:** Flask-Login, session-based authentication
- **Deployment:** Railway.app (production), Gunicorn
- **Extras:** Google reCAPTCHA, Flask-Mail, IP geolocation

---

## 📁 Project Structure (for developers)

```
SchedEye/
│
├── static/
│   ├── images/                     # Logos, icons, screenshots
│
├── templates/
│   ├── emails/                     # Email HTML templates
│   ├── about.html
│   ├── dashboard.html              # Main calendar view
│   ├── payments.html               # Payment tracking
│   ├── edit_user.html              # Admin - edit users
│   ├── calculate_hours.html        # Time/payment calculation
│   ├── features.html               # Site features overview
│   ├── settings.html               # Account settings
│   └── ...                         # Other user/admin pages
│
├── utils/
│   ├── __init__.py
│   ├── helpers.py                  # Utility functions (e.g., time calc, formatting)
│
├── app.py                          # App factory + route loader
├── db_config.py                    # SQLAlchemy DB config
├── models.py                       # SQLAlchemy models
├── requirements.txt
├── .env
├── Procfile
├── .gitignore
└── README.md

```

---

## ✨ Future Enhancements

📄 Export schedules to PDF/CSV
Create downloadable monthly reports via utils/reporting.py and export.html.

🔔 Push notifications
Implement browser-based or email alerts for:

-Upcoming lessons

-Payment due reminders

-Suspicious login activity
(Extend templates/emails/ and possibly use Web Push + background jobs)

📊 Advanced analytics
Add visual dashboards (charts, graphs) for:

-Monthly lesson trends

-Income tracking

School-specific insights
Use Chart.js and a new page like templates/analytics.html.

🛡️ CSRF protection
Integrate Flask-WTF for all forms.
Update relevant templates to include {{ form.csrf_token }} and validate in views.

---

## 🙋‍♂️ Contact

Created & maintained by [Ahmed Özdoğan](https://github.com/AhmedOzdogan).  
For feedback, suggestions, or bug reports — open an issue or contact via GitHub or "ahmeddozdogan@gmail.com".
