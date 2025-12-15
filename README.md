AuthFlow - Modern Secure Authentication System
https://img.shields.io/badge/AuthFlow-Modern%2520Authentication-blue
https://img.shields.io/badge/Django-4.2-green
https://img.shields.io/badge/TailwindCSS-3.3-blue
https://img.shields.io/badge/License-MIT-brightgreen

A production-ready, secure authentication system built with Django and TailwindCSS. AuthFlow provides email-based authentication, OTP verification, rate limiting, and a beautiful dashboard interface.

🚀 Features
🔐 Authentication
✅ Email-based authentication (no username required)

✅ OTP verification with auto-submit (6-digit code)

✅ Password reset via secure email links

✅ Session-based authentication with remember me

✅ Rate limiting for login/registration attempts

🛡️ Security
✅ OTP expiry (1 minute) and attempt limits (max 3)

✅ Password strength validation with real-time feedback

✅ Secure token hashing for OTPs and reset tokens

✅ CSRF protection and secure cookies

✅ Account locking after multiple failed attempts

🎨 User Interface
✅ Modern, colorful UI with TailwindCSS

✅ Responsive design for all devices

✅ Dashboard with sidebar navigation

✅ Animated success/error messages

✅ Auto-submit OTP fields (no submit button needed)

📧 Email System
✅ Mailtrap integration for email testing

✅ HTML email templates with styling

✅ Email verification with OTP codes

✅ Password reset emails with secure links

✅ Welcome emails for new users

📋 Prerequisites
Python 3.8+

Django 4.2+

Mailtrap account (for email testing)

Modern web browser

🛠️ Installation
1. Clone the Repository
bash
git clone https://github.com/yourusername/authflow.git
cd authflow
2. Create Virtual Environment
bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
3. Install Dependencies
bash
pip install -r requirements.txt
4. Configure Environment
bash
# Copy environment template
cp .env.example .env

# Edit .env with your configuration
# Update these values:
# - SECRET_KEY (generate a secure one)
# - EMAIL_HOST_USER (your Mailtrap username)
# - EMAIL_HOST_PASSWORD (your Mailtrap password)
5. Database Setup
bash
# Run migrations
python manage.py makemigrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser
6. Run Development Server
bash
python manage.py runserver
Visit http://localhost:8000 to see AuthFlow in action!

🏗️ Project Structure
text
authflow/
├── authflow/                  # Project configuration
│   ├── settings.py           # Django settings
│   ├── urls.py              # URL routing
│   └── wsgi.py              # WSGI configuration
├── accounts/                 # Authentication app
│   ├── models.py            # Custom User & OTP models
│   ├── views.py             # Authentication views
│   ├── forms.py             # Django forms
│   ├── urls.py              # App URLs
│   ├── utils.py             # Email utilities
│   ├── tokens.py            # Token generation
│   └── signals.py           # Django signals
├── templates/               # HTML templates
│   ├── auth/               # Authentication pages
│   │   ├── login.html
│   │   ├── register.html
│   │   ├── verify_otp.html
│   │   ├── forgot_password.html
│   │   └── reset_password.html
│   ├── dashboard/          # Dashboard pages
│   │   ├── dashboard.html
│   │   ├── profile.html
│   │   ├── security.html
│   │   └── settings.html
│   └── emails/             # Email templates
│       ├── otp_email.html
│       └── password_reset.html
├── static/                 # Static files
│   ├── css/
│   ├── js/
│   └── images/
├── media/                  # User uploads
├── .env                    # Environment variables
├── requirements.txt        # Python dependencies
└── README.md              # This file
🔧 Configuration
Email Configuration (Mailtrap)
Sign up at Mailtrap.io

Go to Email Testing → Inboxes

Copy your SMTP credentials

Update .env file:

env
EMAIL_HOST=sandbox.smtp.mailtrap.io
EMAIL_PORT=2525
EMAIL_HOST_USER=your_username
EMAIL_HOST_PASSWORD=your_password
EMAIL_USE_TLS=True
DEFAULT_FROM_EMAIL=authflow@example.com
Custom User Model
AuthFlow uses a custom user model with email as the username field:

python
# accounts/models.py
class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True, verbose_name='email address')
    is_active = models.BooleanField(default=False)  # Inactive until OTP verified
    # ... other fields
🔄 System Flow
1. Registration
User registers with email and password

Account is created as inactive

6-digit OTP is generated and emailed

User redirected to OTP verification page

2. OTP Verification
User enters 6-digit code (auto-submits when complete)

System verifies OTP hash and expiry (1 minute)

If valid: User activated and logged in

If invalid: Shows attempts remaining (max 3)

3. Login
User logs in with email and password

Unverified users are blocked

Rate limiting applied (5 attempts per 10 minutes)

Successful login redirects to dashboard

4. Password Reset
User requests password reset

Secure tokenized link sent via email

Token expires automatically (1 hour)

User sets new password

🎨 UI Components
Authentication Pages
Register: Email, password, confirm password with real-time validation

Login: Email, password, remember me option

OTP Verification: 6-digit auto-submit fields with countdown timer

Forgot Password: Email input with rate limiting

Reset Password: New password with strength meter

Dashboard
Main Dashboard: User stats, security score, quick actions

Profile Management: Update personal info, upload avatar

Security Settings: Session management, security tips

Account Settings: Notification preferences, data export

🚀 Deployment
Production Checklist
Set DEBUG=False in .env

Generate new SECRET_KEY

Configure production database (MySQL/PostgreSQL)

Set up SSL certificate

Configure production email service

Update ALLOWED_HOSTS

Set up proper cache backend (Redis recommended)

Docker Deployment
dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python manage.py collectstatic --noinput
RUN python manage.py migrate

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "authflow.wsgi:application"]
📝 API Endpoints
Authentication Endpoints
text
POST   /accounts/register/      # User registration
POST   /accounts/login/         # User login
POST   /accounts/logout/        # User logout
POST   /accounts/verify-otp/    # OTP verification (AJAX)
POST   /accounts/resend-otp/    # Resend OTP (AJAX)
POST   /accounts/forgot-password/ # Request password reset
GET    /accounts/reset-password/<token>/ # Reset password form
POST   /accounts/reset-password/<token>/ # Process password reset
Dashboard Endpoints
text
GET    /accounts/dashboard/     # Main dashboard
GET    /accounts/profile/       # User profile
POST   /accounts/profile/       # Update profile
GET    /accounts/security/      # Security settings
GET    /accounts/settings/      # Account settings
GET    /accounts/sessions/      # Session management
GET    /accounts/export-data/   # Export user data
POST   /accounts/delete-account/ # Delete account
🧪 Testing
Run Tests
bash
# Run all tests
python manage.py test accounts

# Run specific test
python manage.py test accounts.tests.AuthFlowTests
Test Coverage
bash
pip install coverage
coverage run manage.py test
coverage report
coverage html  # Generates HTML report
🔒 Security Features
Implemented
Password hashing with PBKDF2

CSRF protection on all forms

Rate limiting for sensitive endpoints

Secure session management

OTP hashing before storage

HTTPS enforcement in production

XSS protection headers

Recommended for Production
Enable HSTS

Use secure cookies only

Implement CSP headers

Regular security audits

Monitor login attempts

Enable 2FA (future enhancement)

🤝 Contributing
Fork the repository

Create a feature branch (git checkout -b feature/AmazingFeature)

Commit changes (git commit -m 'Add AmazingFeature')

Push to branch (git push origin feature/AmazingFeature)

Open a Pull Request

Code Style
Follow PEP 8 for Python code

Use Black for code formatting

Write docstrings for functions

Add type hints where possible

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

🆘 Support
📖 Documentation: Read the docs

🐛 Bug Reports: Create an issue

💬 Questions: Discussion forum

📧 Email: support@authflow.com

🙏 Acknowledgments
Django community for the excellent framework

TailwindCSS for the utility-first CSS framework

Mailtrap for email testing sandbox

All contributors who help improve AuthFlow

📊 Stats
https://img.shields.io/github/stars/yourusername/authflow?style=social
https://img.shields.io/github/forks/yourusername/authflow?style=social
https://img.shields.io/github/issues/yourusername/authflow
https://img.shields.io/github/issues-pr/yourusername/authflow

Built with ❤️ using Django & TailwindCSS

AuthFlow - Your secure authentication solution
