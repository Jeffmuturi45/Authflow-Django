# accounts/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, OTP, PasswordResetToken, LoginAttempt
from .forms import UserCreationForm, UserChangeForm


class CustomUserAdmin(UserAdmin):
    add_form = UserCreationForm
    form = UserChangeForm
    model = CustomUser

    list_display = ('email', 'first_name', 'last_name', 'is_staff',
                    'is_active', 'email_verified', 'date_joined')
    list_filter = ('is_staff', 'is_active', 'email_verified', 'date_joined')

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('first_name',
         'last_name', 'avatar', 'phone_number')}),
        ('Permissions', {'fields': ('is_active', 'is_staff',
         'is_superuser', 'groups', 'user_permissions')}),
        ('Verification', {'fields': ('email_verified',
         'email_verified_at', 'otp_secret', 'otp_attempts')}),
        ('Important Dates', {
         'fields': ('last_login', 'date_joined', 'last_updated')}),
        ('Security', {'fields': ('is_locked',
         'locked_until', 'last_login_ip', 'login_count')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'first_name', 'last_name', 'is_staff', 'is_active')}
         ),
    )

    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('-date_joined',)
    readonly_fields = ('last_login', 'date_joined', 'last_updated')


class OTPAdmin(admin.ModelAdmin):
    list_display = ('user', 'purpose', 'created_at',
                    'expires_at', 'is_used', 'attempts')
    list_filter = ('purpose', 'is_used', 'created_at')
    search_fields = ('user__email',)
    readonly_fields = ('created_at', 'expires_at', 'otp_hash')

    def has_add_permission(self, request):
        return False  # Prevent manual creation of OTPs


class PasswordResetTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'created_at', 'expires_at', 'is_used')
    list_filter = ('is_used', 'created_at')
    search_fields = ('user__email', 'token')
    readonly_fields = ('created_at', 'expires_at')

    def has_add_permission(self, request):
        return False  # Prevent manual creation of tokens


class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ('email', 'ip_address', 'timestamp', 'success')
    list_filter = ('success', 'timestamp')
    search_fields = ('email', 'ip_address')
    readonly_fields = ('timestamp',)

    def has_add_permission(self, request):
        return False  # Prevent manual creation of login attempts


# Register models
admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(OTP, OTPAdmin)
admin.site.register(PasswordResetToken, PasswordResetTokenAdmin)
admin.site.register(LoginAttempt, LoginAttemptAdmin)
