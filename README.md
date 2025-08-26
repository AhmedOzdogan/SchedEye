# 📅 SchedEye — Web-Based Teaching Schedule Manager

SchedEye is a modern, mobile-first web app that lets freelance teachers and small institutes plan weekly lessons, track payments, and audit login activity from a single dashboard. Built with Flask (Python), Bootstrap 5, and MySQL, it delivers secure, session-based authentication (hashed passwords and rate limiting), intuitive CRUD scheduling, and clear payment/status reporting in a fast, responsive UI. Designed for real-world use, SchedEye supports bulk actions, monthly/hourly rollups, and admin management, while remaining simple to deploy on platforms like Railway.

---

## 🔗 Quick Access

- **Live Site:** [schedeye.com](https://schedeye.com)
- **Demo Login:**  
  &nbsp;&nbsp;Email: `ahmed_ozdogan@gmail.com`  
  &nbsp;&nbsp;Password: `TeacherAhmed1`

---

## ✨ Features

| Category               | Highlights                                                                 |
| ---------------------- | -------------------------------------------------------------------------- |
| **Auth & Accounts**    | Secure login, rate-limiting, admin user management                         |
| **Schedule**           | Add/edit/delete lessons, weekly table view, bulk mark paid/unpaid          |
| **Payments**           | Earned/pending/received totals, clear payment status indicators            |
| **Login History**      | Last login info, IP/geolocation, suspicious activity flags, simple charts  |
| **UX & Accessibility** | Onboarding tips, light/dark mode, tooltips/toasts, fully responsive design |

---

## 🛠 Tech Stack

- **Backend:** Flask, SQLAlchemy, MySQL
- **Frontend:** HTML5, Bootstrap 5, Vanilla JS
- **Auth:** Flask-Login (session-based)
- **Email/Security:** Flask-Mail, Google reCAPTCHA (optional)
- **Deployment:** Railway.app + Gunicorn
- **Utilities:** IP geolocation, rate-limit guard

---

## 📁 Project Structure

```
SchedEye/
├── static/images/         # Logos, icons, screenshots
├── templates/             # HTML templates
│   ├── emails/
│   ├── about.html
│   ├── dashboard.html     # Weekly schedule view
│   ├── payments.html      # Payment tracking
│   ├── edit_user.html     # Admin: edit users
│   ├── calculate_hours.html
│   ├── features.html
│   ├── settings.html
│   └── ...                # Other pages
├── utils/
│   ├── init.py
│   └── helpers.py         # Utilities
├── app.py                 # App factory / route loader
├── db_config.py           # SQLAlchemy DB config
├── models.py              # SQLAlchemy models
├── requirements.txt
├── .env                   # Local environment variables
├── Procfile               # Gunicorn entry for production
├── .gitignore
└── README.md
```

---

## ⚙️ Local Setup

1. **Create & activate a virtual environment**

   **Windows (PowerShell):**

   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

   **macOS/Linux:**

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment**

   Create a `.env` file at the project root:

   ```ini
   FLASK_ENV=development
   SECRET_KEY=change-me
   SQLALCHEMY_DATABASE_URI=mysql+pymysql://user:password@localhost:3306/schedeye
   # or Railway style:
   # DATABASE_URL=mysql+pymysql://user:password@host:port/dbname

   MAIL_SERVER=smtp.gmail.com
   MAIL_PORT=587
   MAIL_USE_TLS=True
   MAIL_USERNAME=your_email@example.com
   MAIL_PASSWORD=your_app_password
   MAIL_DEFAULT_SENDER=your_email@example.com

   RECAPTCHA_SITE_KEY=your_site_key
   RECAPTCHA_SECRET_KEY=your_secret_key
   ```

   > **Tip:** If your config expects `DATABASE_URL`, set both `DATABASE_URL` and `SQLALCHEMY_DATABASE_URI` or map one to the other in `db_config.py`.

4. **Create the database**

   ```sql
   CREATE DATABASE schedeye CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   ```

5. **Run the app**
   ```bash
   python app.py
   # or
   flask run
   ```

---

## 🧮 Data Model (High-Level)

- **Users:**  
  `id`, `email`, `hashed_password`, `role`, `last_login_at`, `last_login_ip`, ...
- **Lessons:**  
  `id`, `user_id`, `school`, `class_name`, `date`, `start_time`, `end_time`, `rate`, `paid`
- **LoginAttempts:**  
  `id`, `user_id`, `timestamp`, `ip`, `location`, `success`

Calculations (hours, totals) are derived from Lessons with simple queries and time deltas.

---

## 🔐 Security Notes

- Passwords hashed (never stored in plain text)
- Session-based authentication (Flask-Login)
- Basic rate-limiting after repeated failed attempts
- reCAPTCHA support for high-risk forms (optional)
- **Never commit real credentials** — keep secrets in `.env`

---

## 🚀 Deployment (Railway + Gunicorn)

- **Procfile:**
  ```
  web: gunicorn app:app
  ```
- Set Railway environment variables (`SECRET_KEY`, `DATABASE_URL`, mail creds, etc.)
- Ensure `DATABASE_URL` points to your managed MySQL instance

---

## 🧭 Key User Flows

- **Add / Edit / Delete Lessons:** Weekly schedule view (`dashboard.html`)
- **Bulk Mark Paid/Unpaid:** Select multiple lessons → action menu
- **Calculate Hours / Payments:** By month / school / year (`calculate_hours.html`)
- **Track Logins:** Login history view with IP & location, simple charts
- **Manage Accounts:** Admin page for user management

---

## 🖼️ Screenshots

![Dashboard](static/images/screenshot-dashboard.png)
![Payments](static/images/screenshot-payments.png)
![Login History](static/images/screenshot-logins.png)

---

## 🛣️ Roadmap

- Export schedules (PDF/CSV)
- Push/email notifications (upcoming lessons, payment reminders, suspicious logins)
- Analytics dashboard (trends, income, school-level insights) with Chart.js
- CSRF protection via Flask-WTF for all forms
- Background jobs for scheduled tasks
- Role-based access and extended admin views

---

## 🙋‍♂️ Contact

Created & maintained by **Ahmed Özdoğan**  
GitHub: [@AhmedOzdogan](https://github.com/AhmedOzdogan)  
Feedback / bugs: open an issue or email [ahmeddozdogan@gmail.com](mailto:ahmeddozdogan@gmail.com)

---

## 📄 License

Personal/portfolio project.
