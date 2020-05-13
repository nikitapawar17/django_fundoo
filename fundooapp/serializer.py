from rest_framework import serializers, fields
from django.contrib.auth.models import User
from rest_framework.validators import UniqueValidator
from django.utils import timezone

from .models import Note


class UserSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)
    email = serializers.EmailField(required=True, validators=[UniqueValidator(queryset=User.objects.all())])
    username = serializers.CharField(max_length=20, validators=[UniqueValidator(queryset=User.objects.all())])
    password = serializers.CharField(min_length=8)
    is_active = serializers.BooleanField(default=True)

    def create(self, validated_data):
        user = User.objects.create_user(first_name=validated_data['first_name'],
                                        last_name=validated_data['last_name'],
                                        username=validated_data['username'],
                                        email=validated_data['email'],
                                        password=validated_data['password'],
                                        is_active=validated_data['is_active'])
        return user

    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'email', 'username', 'password', 'is_active')
        # fields = '__all__'


class LoginSerializer(serializers.ModelSerializer):
    # username = serializers.CharField(max_length=20)
    # password = serializers.CharField(min_length=8)

    class Meta:
        model = User
        fields = ('username', 'password')


class ForgotPasswordSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=200)

    class Meta:
        model = User
        fields = ['email']


class ResetPasswordSerializer(serializers.ModelSerializer):
    new_pswd = serializers.CharField(min_length=8, max_length=50)
    confirm_pswd = serializers.CharField(min_length=8, max_length=50)

    class Meta:
        model = User
        fields = ('new_pswd', 'confirm_pswd')


class NoteSerializer(serializers.ModelSerializer):

    class Meta:
        model = Note
        fields = '__all__'

