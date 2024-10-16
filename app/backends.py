from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
import logging

# Get the custom user model
User = get_user_model()

# Set up logging
logger = logging.getLogger(__name__)

class EmailBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            # Attempt to find the user by email
            user = User.objects.get(email=username)
            if user.check_password(password):
                return user
            else:
                logger.warning(f"Invalid password for user: {username}")
        except User.DoesNotExist:
            logger.warning(f"User not found: {username}")
        
        return None  # Return None if authentication fails

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None  # Return None if user does not exist
