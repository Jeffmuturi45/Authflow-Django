"""
URL configuration for authflow project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

# authflow/urls.py
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from accounts import views
from django.conf.urls.static import static
from accounts import views as account_views  # Import account views

app_name = 'accounts'

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', account_views.home_view, name='home'),  # Add home page
    path('accounts/', include('accounts.urls')),

    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('verify-otp/', views.verify_otp_view, name='verify_otp'),
    path('resend-otp/', views.resend_otp_view, name='resend_otp'),
    path('forgot-password/', views.forgot_password_view, name='forgot_password'),
    path('reset-password/<str:token>/',
         views.reset_password_view, name='reset_password'),

    # Dashboard URLs
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('profile/', views.profile_view, name='profile'),
    path('security/', views.security_view, name='security'),
    path('settings/', views.settings_view, name='settings'),

    # Additional features
    path('delete-account/', views.delete_account_view, name='delete_account'),
    path('export-data/', views.export_data_view, name='export_data'),
    path('sessions/', views.session_management_view, name='session_management'),

    # API endpoints
    path('api/check-email/', views.check_email_availability, name='check_email'),
    path('api/check-password/', views.verify_password_strength,
         name='check_password'),
]

# Serve static and media files in development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL,
                          document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL,
                          document_root=settings.MEDIA_ROOT)
