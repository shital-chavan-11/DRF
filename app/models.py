
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.mail import send_mail
from django.conf import settings
import random
from django.contrib.auth import get_user_model
class CustomUser(AbstractUser):
    # Extend the default user model to include additional fields
    phone_number = models.CharField(max_length=15, blank=True, null=True, verbose_name='Phone Number')
    email_verified = models.BooleanField(default=False, verbose_name='Email Verified')
    
    # Specify unique=True to enforce email uniqueness
    email = models.EmailField(unique=True)

    # Specify related_name to avoid conflicts
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='custom_user_groups',
        blank=True,
        help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',
        verbose_name='Groups'
    )

    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='custom_user_permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='User Permissions'
    )

    def __str__(self):
        return self.username  # You can customize this to return any other string representation
# Get the CustomUser model dynamically to accommodate any custom user model
CustomUser = get_user_model()

class OTPVerification(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    otp_code = models.CharField(max_length=6)  # 6-digit OTP
    is_verified = models.BooleanField(default=False)  # Flag to check if the OTP has been verified
    created_at = models.DateTimeField(auto_now_add=True)  # Track when the OTP was created
    updated_at = models.DateTimeField(auto_now=True)  # Track when the OTP record was updated


    # def __str__(self):
    #     return f"User: {self.user.username}, OTP (last 3 digits): ***{self.otp_code[-3:]}"

    # def generate_otp(self):
    #     """Generate a random 6-digit OTP and save it."""
    #     self.otp_code = f"{random.randint(100000, 999999)}"
    #     self.save()
    #     return self.otp_code

    # def send_otp_via_email(self):
    #     """Send the OTP via email to the user."""
    #     subject = "Your OTP Code"
    #     message = f"Your OTP code is {self.otp_code}. It will expire in 5 minutes."
    #     from_email = settings.DEFAULT_FROM_EMAIL
    #     recipient_list = [self.user.email]
        
    #     send_mail(subject, message, from_email, recipient_list)
        
