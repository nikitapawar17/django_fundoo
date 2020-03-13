from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework.validators import UniqueValidator


class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True, validators=[UniqueValidator(queryset=User.objects.all())])
    username = serializers.CharField(max_length=20)
    password = serializers.CharField(min_length=8)

    def create(self, validated_data):
        user = User.objects.create_user(validated_data['username'], validated_data['email'], validated_data['password'])
        return user

    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'password')


class ResetPasswordSerializer(serializers.ModelSerializer):
    new_pswd = serializers.CharField(min_length=8, max_length=50)
    confirm_pswd = serializers.CharField(min_length=8, max_length=50)


    class Meta:
        model = User
        fields = ('new_pswd', 'confirm_pswd')
