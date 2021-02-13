from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import User

def get_user(email):
    try:
        return User.objects.get(email = email.lower())
    except User.DoesNotExist:
        return None


def authenticate_user(email, password):
    username = get_user(email)
    valid_user = authenticate(username = username, password = password)
    if valid_user is None:
        raise serializers.ValidationError("Invalid email or password!")
    return valid_user


def create_user(username, email, password, **extra_fields):
    user = get_user_model().objects.create_user(email=email, username=username, password=password, **extra_fields)
    return user
