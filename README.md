# 🔐 AuthFlow – Modern Secure Authentication System

![AuthFlow](https://img.shields.io/badge/AuthFlow-Modern%20Authentication-blue)
![Django](https://img.shields.io/badge/Django-4.2-green)
![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3.3-blue)
![License](https://img.shields.io/badge/License-MIT-brightgreen)

AuthFlow is a **production-ready, secure authentication system** built with **Django** and **TailwindCSS**.  
It implements **email-based authentication**, **OTP verification with auto-submit**, **rate limiting**, and a **modern dashboard UI**, following real-world security best practices.

---

## 🚀 Features

### 🔐 Authentication
- Email-based authentication (no username required)
- OTP verification with **auto-submit** (6-digit code)
- Secure password reset via email
- Session-based authentication with *Remember Me*
- Rate limiting for login and registration attempts

### 🛡️ Security
- OTP expiry (1 minute) and attempt limits (max 3)
- Secure hashing for OTPs and reset tokens
- CSRF protection and secure cookies
- Account locking after multiple failed attempts
- Password strength validation with real-time feedback

### 🎨 User Interface
- Modern, colorful UI built with TailwindCSS
- Fully responsive design
- Dashboard with sidebar navigation
- Animated success and error messages
- Smooth OTP input experience (no submit button)

### 📧 Email System
- Mailtrap integration for email testing
- Styled HTML email templates
- OTP verification emails
- Password reset emails
- Welcome emails for new users

---

## 📋 Prerequisites

- Python **3.8+**
- Django **4.2+**
- Mailtrap account (for email testing)
- Modern web browser

---

## 🛠️ Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/Jeffmuturi45/Authflow-Django.git
cd authflow



2️⃣ Create Virtual Environment
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate


3️⃣ Install Dependencies
pip install -r requirements.txt


4️⃣ Configure Environment Variables
cp .env.example .env

Update .env with:

SECRET_KEY

EMAIL_HOST_USER

EMAIL_HOST_PASSWORD



5️⃣ Database Setup
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser


6️⃣ Run Development Server
python manage.py runserver


🏗️ Project Structure

authflow/
├── authflow/                # Project configuration
├── accounts/               # Authentication app
├── templates/              # HTML templates
│   ├── auth/
│   ├── dashboard/
│   └── emails/
├── static/                 # Static assets
├── media/                  # User uploads
├── .env
├── requirements.txt
└── README.md


🔄 System Flow
1️⃣ Registration

User registers using email and password

Account is created as inactive

OTP is generated and emailed

User redirected to OTP verification page

2️⃣ OTP Verification

6-digit OTP auto-submits on completion

OTP expires after 1 minute

Maximum 3 attempts allowed

Successful verification activates account and logs in user

3️⃣ Login

Email + password authentication

Rate limited (5 attempts per 10 minutes)

Unverified users blocked

4️⃣ Password Reset

Secure token-based reset via email

Token expires automatically

User sets a new password

🎨 Dashboard Features

Sidebar navigation

Profile management with avatar upload

Security settings

Session tracking

Account preferences

🚀 Deployment
Production Checklist

Set DEBUG=False

Generate a new SECRET_KEY

Use MySQL or PostgreSQL

Configure SSL

Use Redis for caching (recommended)

Configure production email service


🤝 Contributing

Fork the repo

Create a feature branch

Commit your changes

Push to your branch

Open a Pull Request

📄 License

This project is licensed under the MIT License — see the **https://github.com/Jeffmuturi45/Authflow-Django.git/License**
 file.

⭐ Acknowledgments

Django Community

TailwindCSS Team

Mailtrap

Built with ❤️ using Django & TailwindCSS
AuthFlow — Your secure authentication solution
