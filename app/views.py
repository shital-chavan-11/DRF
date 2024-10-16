import random
import json
import logging
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import get_user_model, authenticate, login as auth_login, logout as auth_logout
from django.shortcuts import get_object_or_404
from .models import CustomUser, OTPVerification
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt



User = get_user_model()

# Set up logging
logger = logging.getLogger(__name__)

@csrf_exempt
def register(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        phone_number = data.get('phone_number')

        # Check if user already exists
        if User.objects.filter(email=email).exists():
            return JsonResponse({'error': 'User with this email already exists.'}, status=400)

        # Create the user
        user = User.objects.create_user(username=username, email=email, password=password, phone_number=phone_number)

        # Generate OTP
        otp = str(random.randint(100000, 999999))  # Convert OTP to string

        # Save OTP in the OTPVerification model
        OTPVerification.objects.create(user=user, otp_code=otp)

        # Send OTP to email
        send_mail(
            'Your OTP Code',
            f'Your OTP code is {otp}. It will expire in 5 minutes.',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )

        return JsonResponse({'message': 'OTP sent to your email. Please verify.'}, status=201)

    return JsonResponse({'error': 'Invalid request method.'}, status=400)


@csrf_exempt
def verify_otp(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        entered_otp = data.get('otp')

        # Check for missing fields
        if email is None or entered_otp is None:
            return JsonResponse({'error': 'Email and OTP are required.'}, status=400)

        # Get user and OTP record from the database
        user = get_object_or_404(User, email=email)
        try:
            otp_record = OTPVerification.objects.get(user=user, otp_code=entered_otp)

            # Verify OTP and mark it as used
            if not otp_record.is_verified:
                if timezone.now() > otp_record.created_at + timedelta(minutes=5):  # Check if OTP is expired
                    return JsonResponse({'error': 'OTP has expired.'}, status=400)
                otp_record.is_verified = True
                otp_record.save()
                return JsonResponse({'message': 'OTP verified successfully! You can now log in.'}, status=200)
            else:
                return JsonResponse({'error': 'OTP already verified.'}, status=400)

        except OTPVerification.DoesNotExist:
            return JsonResponse({'error': 'Invalid OTP or user not found.'}, status=400)

    return JsonResponse({'error': 'Invalid request method.'}, status=400)


@csrf_exempt
def user_login(request):
    if request.method == 'POST':
        try:
            # Load JSON data from the request body
            data = json.loads(request.body)
            logger.info(f"Received login data: {data}")
        except json.JSONDecodeError:
            logger.error("Invalid JSON data")
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        email = data.get('email')
        password = data.get('password')

        # Check for missing email or password
        if not email or not password:
            logger.warning("Missing email or password")
            return JsonResponse({'error': 'Email and password are required.'}, status=400)

        logger.info(f"Attempting to log in user: {email}")

        # Authenticate user using email
        user = authenticate(request, username=email, password=password)

        # Check if user exists and authentication succeeded
        if user is not None:
            auth_login(request, user)
            logger.info(f"User {email} logged in successfully.")
            return JsonResponse({'message': 'Login successful!'}, status=200)
        else:
            logger.warning(f"Invalid credentials for user: {email}")
            return JsonResponse({'error': 'Invalid credentials.'}, status=401)

    logger.warning(f"Invalid request method: {request.method}")
    return JsonResponse({'error': 'Invalid request method. Only POST allowed.'}, status=405)
from app.models import OTPVerification  # Replace with your actual app name

@csrf_exempt
def logout(request):
    if request.method == 'POST':
        auth_logout(request)
        return JsonResponse({'message': 'Logged out successfully.'}, status=200)
    return JsonResponse({'error': 'Invalid request method. Only POST allowed.'}, status=405)
@csrf_exempt  # Only for testing
@login_required(login_url='/login/')
def profile(request):
    if request.method == 'GET':
        user_data = {
            'username': request.user.username,
            'email': request.user.email,
            'phone_number': request.user.phone_number,
            'email_verified': request.user.email_verified,
        }
        return JsonResponse(user_data, status=200)
    return JsonResponse({'error': 'Invalid request method. Only GET allowed.'}, status=405)