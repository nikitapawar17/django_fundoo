import jwt
from django.contrib import messages
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from django.views.generic import FormView
from rest_framework import status
from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash

from .email_service import send_html_email
from .forms import ForgotPasswordForm, ResetPasswordForm
from .serializer import UserSerializer, ResetPasswordSerializer
# Create your views here.
from django.conf import settings


class Signup(APIView):
    def post(self, request):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            if user:
                payload = {
                    "user_email": request.data["email"]
                }
                jwt_token = jwt.encode(payload, "SECRET_KEY", "HS256").decode('utf-8')
                # subject = "This email is for demo"
                # message = "Welcome to fundooProject"
                # to_list = request.data['email']
                # # send_html_email(to_list, message, subject)
                # send_mail(subject, message, settings.EMAIL_HOST_USER, [to_list])
                response = {
                    "success": True,
                    "message": "successfully Registered",
                    "data": [serializer.data]
                }
                return JsonResponse(data=response, status=status.HTTP_201_CREATED)
            else:
                return JsonResponse(data=response, status=status.HTTP_400_BAD_REQUEST)
        else:
            return JsonResponse(data=response, status=status.HTTP_204_NO_CONTENT)


class Login(APIView):
    def post(self, request):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        username = request.data['username']
        usr_pswd = request.data['password']
        user = authenticate(username=username, password=usr_pswd)
        if user:
            login(request, user)
            payload = {
                "id": user.id
            }
            jwt_token = jwt.encode(payload, "SECRET_KEY", "HS256").decode('utf-8')
            response = {
                "success": True,
                "message": "Successfully login",
                "data": [jwt_token]
            }
            return JsonResponse(data=response, status=status.HTTP_200_OK)
        else:
            return JsonResponse(data=response, status=status.HTTP_400_BAD_REQUEST)


class ForgotPassword(FormView):
    def get(self, request, *args, **kwargs):
        form = ResetPasswordForm()
        return render(request, 'forgot_password.html', {'form': form})

    form_class = ForgotPasswordForm
    template_name = "forgot_password.html"
    success_url = 'forgot_password/'

    def post(self, request, *args, **kwargs):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        if request.method == "POST":
            form = self.form_class(request.POST)
            if form.is_valid():
                email = form.cleaned_data.get("email")
                user_obj = User.objects.filter(email=email)
                if user_obj:
                    payload = {
                        "user_email": email
                    }
                    jwt_token = jwt.encode(payload, "SECRET_KEY", "HS256").decode('utf-8')

                    link = 'http://127.0.0.1:8000/reset_password/{}'.format(jwt_token)
                    html = """<html><body><p>
                            Please <a href="{}">click here</a> to reset your password. 
                            </p></body></html>""".format(link)
                    send_html_email(email, "Reset Password", html)
                    result = self.form_valid(form)
                    messages.success(request, 'Email has been sent to ' + email + "'s email address. Please check "
                                                                                  "inbox to continue reset password.")
                    # response = {
                    #     "success": True,
                    #     "message": "Email has been sent to  {} 's email address. Please check inbox to continue reset password.".format(email),
                    #     "data": []
                    # }
                    # return JsonResponse(data=response, status=status.HTTP_200_OK)
                    return result
                # return HttpResponse({"message": "Forgot mail"})
                else:
                    print("Email not register, first register yourself")
                    return redirect('/signup')
        else:
            form = ForgotPasswordForm()
            result = self.form_valid(form)
            return result
        # return render(request, "forgot_password.html", {'form': form})


class ResetPassword(APIView):
    # import pdb
    # pdb.set_trace()
    form_class = ResetPasswordForm

    def get(self, request, *args, **kwargs):
        form = ResetPasswordForm()
        return render(request, 'reset_password.html', {'form': form})

    def post(self, request, token):
        if request.method == "POST":
            form = ResetPasswordForm(request.POST)

            if form.is_valid():
                new_pswd = form.cleaned_data.get("new_pswd")
                print(new_pswd, "NEW PSWD")
                confirm_pswd = form.cleaned_data.get("confirm_pswd")
                if new_pswd == confirm_pswd:
                    user_email = jwt.decode(token, "SECRET_KEY", "HS256")
                    print(user_email["user_email"])
                    user_obj = User.objects.get(email=user_email['user_email'])
                    print(user_obj, type(user_obj))
                    user_obj.set_password(new_pswd)
                    user_obj.save()
                    return redirect('/login')
                else:
                    return HttpResponse('Password mismatch, try again')
            else:
                return HttpResponse('Password reset has not been unsuccessful.')
        else:
            form = ResetPasswordForm()
            return render(request, 'reset_password.html', {'form': form})

# class ResetPassword(APIView):
#     def post(self, request, token):
#         new_pswd = request.data['new_pswd']
#         print(new_pswd)
#         confirm_pswd = request.data['confirm_pswd']
#         if new_pswd == confirm_pswd:
#             user_email = jwt.decode(token, "SECRET_KEY", "HS256")
#             print(user_email)
#             user_obj = User.objects.filter(email=user_email)
#             password = new_pswd
#             user_obj.set_password(password)
#             user_obj.save()
#             return redirect('/login')
#         else:
#             return HttpResponse("Password Mismatch")






