from django.contrib.auth import password_validation
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from rest_framework import serializers


class LoginUserSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)


class UserAuthSerializer(serializers.ModelSerializer):
    auth_token = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ('email', 'password', 'auth_token')

    def get_auth_token(self, obj):
        token, _ = Token.objects.get_or_create(user=obj)
        return token.key


class RegisterUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username','email','password')

    def validate_username(self, username):
        existing_user = User.objects.filter(username=username)
        if existing_user:
            raise serializers.ValidationError("Username not available")
        return username

    def validate_email(self, email):
        existing_user = User.objects.filter(email=email)
        if existing_user:
            raise serializers.ValidationError("Email not available")
        return BaseUserManager.normalize_email(email)

    def validate_password(self, password):
        password_validation.validate_password(password)
        return password


class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_current_password(self, password):
        if not self.context['request'].user.check_password(password):
            raise serializers.ValidationError('Incorrect Current Password')
        return password

    def validate_new_password(self, password):
        password_validation.validate_password(password)
        return password


class ChangeUsernameSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('password', 'username')

    def validate_password(self, password):
        if not self.context['request'].user.check_password(password):
            raise serializers.ValidationError('Incorrect Current Password')
        return password

    def validate_username(self, username):
        existing_user = User.objects.filter(username=username)
        if existing_user:
            raise serializers.ValidationError("Username not available")
        return username


class ChangeEmailSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('password', 'email')

    def validate_password(self, password):
        if not self.context['request'].user.check_password(password):
            raise serializers.ValidationError('Incorrect Current Password')
        return password

    def validate_email(self, email):
        existing_user = User.objects.filter(email=email)
        if existing_user:
            raise serializers.ValidationError("Email not available")
        return BaseUserManager.normalize_email(email)


class EmptySerializer(serializers.Serializer):
    pass