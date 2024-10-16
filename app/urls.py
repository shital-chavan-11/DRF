# shop/urls.py

from django.urls import path
from .views import register, user_login, verify_otp,logout, profile

urlpatterns = [
    path('register/', register, name='register'),
    path('user_login/', user_login, name='login'),
    path('verify-otp/', verify_otp, name='verify_otp'),
    path('logout/', logout, name='logout'),
    path('profile/', profile, name='profile'),
]
