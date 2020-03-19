import jwt
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.core.signing import SignatureExpired
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect, get_object_or_404
from django.template.loader import render_to_string
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash

from .email_service import send_html_email
from .forms import ForgotPasswordForm, ResetPasswordForm
from .serializer import UserSerializer, ResetPasswordSerializer, NoteSerializer, ForgotPasswordSerializer, \
    LoginSerializer
from .models import Note
import logging

from .tokens import get_user_access_token, decode_token

logger = logging.getLogger(__name__)

# Create your views here.
from django.conf import settings


class Signup(APIView):
    serializer_class = UserSerializer

    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            if user:
                main_url = get_current_site(request)
                mail_subject = "Activate your account"
                message = render_to_string('activate_account.html', {'user': user,  # pass the user
                'main_url': main_url,  # pass the url
                'token': get_user_access_token(user.id, user.email, user.username,)  # pass the token
                })
                to_email = serializer.validated_data.get('email')  # get the user email
                # email = EmailMessage(mail_subject, message, to=[to_email])
                # email.send()  # send the mail for activation of account
                send_html_email(to_email, mail_subject, message)
                logger.info("Registered Successfully")
                return Response({"success": True, "message": "Registered Successfully", "data": [serializer.data]},
                                status=status.HTTP_201_CREATED)
            else:
                return Response({"success": False, "message": "Registered Unsuccessful", "data": []},
                                status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"success": False, "message": "Enter required data", "data": []},
                            status=status.HTTP_204_NO_CONTENT)


def activate(request, token):
    try:
        email = decode_token(token)
        user = User.objects.filter(email=email['email']).first()
        user.save()
        print("Congratulations! Account is verified.")
        return HttpResponse('Thank you for your email confirmation. Now you can login your account.')
        # return redirect('/login')
    except SignatureExpired:
        return HttpResponse('The token is expired!')


class Login(APIView):
    serializer_class = LoginSerializer

    def post(self, request):
        res = {"message": "Invalid action happened",
               "data": {},
               "success": False,
               }
        try:
            username = request.data['username']
            usr_pswd = request.data['password']
            if username is None:
                return Response("Username is required")
            if usr_pswd is None:
                return Response("Password is required")
            user = authenticate(username=username, password=usr_pswd)
            if user:
                if user.is_active:
                    jwt_token = get_user_access_token(user.id, user.email)
                    logger.info("Login Successfully")
                    login(request, user)
                    return Response({"success": True, "message": "Successfully login", "data": [jwt_token]},
                                    status=status.HTTP_200_OK)
                else:
                    return Response({"success": False, "message": "User is inactive", "data": []},
                                    status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"success": False, "message": "Invalid login details given", "data": []},
                                status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            print(e)
            return Response(res)


# ForgotPswd with form
# class ForgotPassword(FormView):
#     def get(self, request, *args, **kwargs):
#         form = ForgotPasswordForm()
#         return render(request, 'forgot_password.html', {'form': form})
#
#     form_class = ForgotPasswordForm
#     template_name = "forgot_password.html"
#     success_url = 'forgot_password/'
#
#     def post(self, request, *args, **kwargs):
#         response = {
#             "success": False,
#             "message": "Something went wrong",
#             "data": []
#         }
#         if request.method == "POST":
#             form = self.form_class(request.POST)
#             if form.is_valid():
#                 email = form.cleaned_data.get("email")
#                 user_obj = User.objects.filter(email=email)
#                 if user_obj:
#                     payload = {
#                         "user_email": email
#                     }
#                     jwt_token = jwt.encode(payload, "SECRET_KEY", "HS256").decode('utf-8')
#
#                     link = 'http://127.0.0.1:8000/reset_password/{}'.format(jwt_token)
#                     html = """<html><body><p>
#                             Please <a href="{}">click here</a> to reset your password.
#                             </p></body></html>""".format(link)
#                     send_html_email(email, "Reset Password", html)
#                     result = self.form_valid(form)
#                     # response = {
#                     #     "success": True,
#                     #     "message": "Email has been sent to  {} 's email address. Please check " \
#                     #                "inbox to continue reset password.".format(email),
#                     #     "data": []
#                     # }
#                     logger.info("Email has sent to" + email + "'s email address. Please check inbox "
#                                                               "to continue reset pswd ")
#                     return result
#                 else:
#                     print("Email not register, first register yourself")
#                     return redirect('/signup')
#         else:
#             form = ForgotPasswordForm()
#             result = self.form_valid(form)
#             return result

# ForgotPassword with Serializer


class ForgotPassword(APIView):
    serializer_class = ForgotPasswordSerializer

    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = request.data["email"]
            obj = User.objects.filter(email=email)
            if obj:
                main_url = get_current_site(request)
                message = render_to_string('reset_password_confirm.html', {
                'main_url': main_url,  # pass the url
                'token': get_user_access_token(email)
                 })

                send_html_email(email, "Reset Password", message)
                logger.info("Email has sent to" + email + "'s email address. Please check inbox "
                                                          "to continue reset pswd ")
                return Response({"success": True, "message": "Email has sent to " + email + "'s email address. "
                 "Please check inbox to continue reset pswd", "data": []}, status=status.HTTP_200_OK)
            else:
                return Response({"success": False, "message": "Fail to sent email for reset password ", "data": []},
                                status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"success": False, "message": "Invalid data", "data": []},
                            status=status.HTTP_400_BAD_REQUEST)

# ResetPassword with form

# class ResetPassword(APIView):
#     # import pdb
#     # pdb.set_trace()
#     form_class = ResetPasswordForm
#
#     def get(self, request, *args, **kwargs):
#         form = ResetPasswordForm()
#         return render(request, 'reset_password.html', {'form': form})
#
#     def post(self, request, token):
#         if request.method == "POST":
#             form = ResetPasswordForm(request.POST)
#
#             if form.is_valid():
#                 new_pswd = form.cleaned_data.get("new_pswd")
#                 print(new_pswd, "NEW PSWD")
#                 confirm_pswd = form.cleaned_data.get("confirm_pswd")
#                 if new_pswd == confirm_pswd:
#                     user_email = jwt.decode(token, "SECRET_KEY", "HS256")
#                     print(user_email["user_email"])
#                     user_obj = User.objects.get(email=user_email['user_email'])
#                     print(user_obj, type(user_obj))
#                     user_obj.set_password(new_pswd)
#                     user_obj.save()
#                     logger.info("Password reset successfully")
#                     return redirect('/login')
#                 else:
#                     logger.error("Password mismatch")
#                     return HttpResponse('Password mismatch, try again')
#             else:
#                 logger.error("Password reset has not been unsuccessful.")
#                 return HttpResponse('Password reset has not been unsuccessful.')
#         else:
#             form = ResetPasswordForm()
#             return render(request, 'reset_password.html', {'form': form})


# ResetPassword with serializer
class ResetPassword(APIView):
    serializer_class = ResetPasswordSerializer

    def post(self, request, token):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            new_pswd = request.data['new_pswd']
            confirm_pswd = request.data['confirm_pswd']
            if new_pswd == confirm_pswd:
                token_obj = decode_token(token)
                user_obj = User.objects.get(email=token_obj['email'])
                password = new_pswd
                user_obj.set_password(password)
                user_obj.save()
                return Response({"success": True, "message": "Password successfully reset ", "data": []},
                                status=status.HTTP_200_OK)
            else:
                return Response({"success": False, "message": "Password Mismatch", "data": []},
                                status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"success": False, "message": "Invalid data", "data": []},
                            status=status.HTTP_400_BAD_REQUEST)


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
            return Response(data={"success": True, "message": "Note get successfully", "data": [data]},
                            status=status.HTTP_200_OK)
        else:
            logger.error("Note not found")
            return Response(data={"success": False, "message": "Note not found", "data": []},
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
            logger.error("Note not found")
            return Response(data={"success": False, "message": "Note not found", "data": []},
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


