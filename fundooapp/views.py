import jwt
from django.contrib import messages
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.views.generic import FormView
from rest_framework import status
from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash

from .email_service import send_html_email
from .forms import ForgotPasswordForm, ResetPasswordForm
from .serializer import UserSerializer, ResetPasswordSerializer, NoteSerializer
from .models import Note
import logging

logger = logging.getLogger(__name__)

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
                    "message": "Registered Successfully",
                    "data": [serializer.data]
                }
                logger.info("Registered Successfully")
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
            logger.info("Login Successfully")
            return JsonResponse(data=response, status=status.HTTP_200_OK)
        else:
            return JsonResponse(data=response, status=status.HTTP_400_BAD_REQUEST)


class ForgotPassword(FormView):
    def get(self, request, *args, **kwargs):
        form = ForgotPasswordForm()
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
                    #     "message": "Email has been sent to  {} 's email address. Please check " \
                    #                "inbox to continue reset password.".format(email),
                    #     "data": []
                    # }
                    logger.info("Email has sent to" + email + "'s email address. Please check inbox "
                                                              "to continue reset pswd ")
                    return result
                else:
                    print("Email not register, first register yourself")
                    return redirect('/signup')
        else:
            form = ForgotPasswordForm()
            result = self.form_valid(form)
            return result


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
                    logger.info("Password reset successfully")
                    return redirect('/login')
                else:
                    logger.error("Password mismatch")
                    return HttpResponse('Password mismatch, try again')
            else:
                logger.error("Password reset has not been unsuccessful.")
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


class NoteView(APIView):
    serializer_class = NoteSerializer

    def post(self, request, *args, **kwargs):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        serializer = NoteSerializer(data=request.data)
        if serializer.is_valid():
            note = serializer.save()
            if note:
                response = {
                    "success": True,
                    "message": "Note created successfully",
                    "data": [serializer.data]
                }
                logger.info("Note created successfully")
                return JsonResponse(data=response, status=status.HTTP_200_OK)
            else:
                logger.error("Note does not create")
                return JsonResponse(data=response, status=status.HTTP_400_BAD_REQUEST)
        return JsonResponse(data=response, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, *args, **kwargs):
        note_obj = Note.objects.all()
        if note_obj:
            data = NoteSerializer(note_obj, many=True).data  # serialize the data
            response = {
                "success": True,
                "message": "Get all notes successfully",
                "data": [data]
            }
            logger.info("All notes got successfully")
            return Response(data=response, status=status.HTTP_200_OK)
        else:
            logger.error("")
            return Response(data={"success": False, "message": "", "data": []}, status=status.HTTP_400_BAD_REQUEST)


class NoteUpdateView(APIView):
    serializer_class = NoteSerializer

    def get(self, request, pk):
        note_id_obj = get_object_or_404(Note, id=pk)
        if note_id_obj:
            data = NoteSerializer(note_id_obj).data
            logger.info("Note with id {} get successfully".format(pk))
            return Response(data={"success": True, "message": "Note with id {}" " " "get successfully".format(pk), "data": [data]},
                            status=status.HTTP_200_OK)
        else:
            logger.error("Note id not found")
            return Response(data={"success": False, "message": "Note id not found", "data": []},
                            status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        note_obj = Note.objects.get(id=pk)
        if note_obj:
            note_obj.delete()
            response = {
                "success": True,
                "message": "Note delete successfully",
                "data": []
            }
            logger.info("Note delete successfully")
            return Response(data=response, status=status.HTTP_200_OK)
        else:
            logger.error("Note id not found")
            return Response(data={"success": False, "message": "Note id not found", "data": []},
                            status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        note_obj = Note.objects.get(id=pk)
        data = request.data
        serializer = NoteSerializer(note_obj, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            response = {
                "success": True,
                "message": "Update Note successfully",
                "data": [serializer.data]
            }
            return Response(data=response, status=status.HTTP_200_OK)
        else:
            return Response(data=response, status=status.HTTP_400_BAD_REQUEST)


