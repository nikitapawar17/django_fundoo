import jwt
from django.contrib import messages
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.views.generic import FormView
from rest_framework import status
from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import login, logout, authenticate

from .email_service import send_html_email
from .forms import ForgotPasswordForm
from .serializer import UserSerializer
# Create your views here.
from django.conf import settings


class Signup(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        print(serializer)
        if serializer.is_valid():
            user = serializer.save()
            if user:
                payload = {
                    "user_email": request.data["email"]
                }
                jwt_token = jwt.encode(payload, "SECRET_KEY", "HS256").decode('utf-8')
                print(jwt_token, "ENCODED TOKEN")
                # send_html_email(request.data["email"], "Reset Password", html)
                subject = "This email is for demo"
                message = "Welcome to fundooProject"
                to_list = request.data['email']
                # send_html_email(to_list, message, subject)
                send_mail(subject, message, settings.EMAIL_HOST_USER, [to_list])
                print("EMAIL SENT")
                return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Login(APIView):
    def post(self, request):
        username = request.data['username']
        usr_pswd = request.data['password']
        user = authenticate(username=username, password=usr_pswd)
        if user:
            login(request, user)
            payload = {
                "id": user.id
            }
            jwt_token = jwt.encode(payload, "SECRET_KEY", "HS256").decode('utf-8')
        return HttpResponse("you are logged in")


class ForgotPassword(FormView):
    serializer_class = UserSerializer
    form_class = ForgotPasswordForm
    template_name = "forgot_password.html"
    success_url = 'forgot_password/'

    def post(self, request, *args, **kwargs):
        if request.method == "POST":
            form = self.form_class(request.POST)
            if form.is_valid():
                email = form.cleaned_data.get("email")
                print(email)
                user_obj = User.objects.filter(email=email)
                print(user_obj, "---->")
                if user_obj:
                    payload = {
                        "user_email": email
                    }
                    jwt_token = jwt.encode(payload, "SECRET_KEY", "HS256").decode('utf-8')
                    print(jwt_token)
                    link = "http://127.0.0.1:8000/reset_password/" + jwt_token
                    print(link)
                    html = """<html><body><p>
                            Please <a href="{}">click here</a> to reset your password. 
                            </p></body></html>""".format(link)
                    send_html_email(email, "Reset Password", html)
                    result = self.form_valid(form)
                    messages.success(request, 'Email has been sent to ' + email + "'s email address. Please check inbox to continue reset password.")
                    return result
                # return HttpResponse({"message": "Forgot mail"})
                else:
                    # response = HttpResponse("Email not register, first register yourself")

                    return redirect('/signup')
        else:
            form = ForgotPasswordForm()
            result = self.form_valid(form)
            return result
        # return render(request, "forgot_password.html", {'form': form})

# class ResetPassword(APIView):
#     def post(self, request):
#         if request.method == "POST":
#             form = ResetPasswordForm()



