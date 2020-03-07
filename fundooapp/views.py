import jwt
from django.contrib.auth.models import User
from django.http import HttpResponse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import login, logout, authenticate

from .serializer import UserSerializer
# Create your views here.


class Signup(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        print(serializer)
        if serializer.is_valid():
            user = serializer.save()
            if user:
                return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Login(APIView):
    def post(self, request):
        username = request.data['username']
        usr_pswd = request.data['password']
        user_obj = User.objects.all()
        print(user_obj)
        user = authenticate(username=username, password=usr_pswd)
        print(user, "====>", username, usr_pswd)
        if user:
            login(request, user)
            payload = {
                "id": user.id
            }
            jwt_token = {'token': jwt.encode(payload, "SECRET_KEY")}
            print(jwt_token)
        return HttpResponse("you are logged in")

