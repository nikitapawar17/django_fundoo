import jwt
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.core.signing import SignatureExpired
from django.http import HttpResponse, JsonResponse, HttpResponseRedirect
from django.shortcuts import redirect, get_object_or_404
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
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


class Register(APIView):

    serializer_class = UserSerializer

    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)
        response = {
            "message": "Something went wrong",
            "data": [],
            "success": False,
        }
        if serializer.is_valid():
            user = serializer.save()
            if user:
                main_url = get_current_site(request)
                mail_subject = "Activate your account"
                message = render_to_string('activate_account.html', {'user': user,
                'main_url': main_url,  # pass the url
                'token': get_user_access_token(user.email, user.id, user.username, user.first_name, user.last_name)  # pass the token
                })
                to_email = serializer.validated_data.get('email')
                send_html_email(to_email, mail_subject, message)
                logger.info("Registered Successfully")
                response["success"] = True
                response["message"] = "Registered Successfully"
                response["data"] = [serializer.data]
                return Response(response, status=status.HTTP_201_CREATED)
            else:
                response["message"] = "Registered Unsuccessful"
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
        else:
            response["message"] = "Enter required data"
            return Response(response, status=status.HTTP_204_NO_CONTENT)


def activate(request, token):
    try:
        decoded_token = decode_token(token)
        user = User.objects.filter(email=decoded_token['email']).first()
        user.save()
        print("Congratulations! Account is verified.")
        return HttpResponse('Thank you for your email confirmation. Now you can login your account.')
    except SignatureExpired:
        return HttpResponse('The token is expired!')


class Login(APIView):
    serializer_class = LoginSerializer

    def post(self, request):
        response = {
            "message": "Something went wrong",
            "data": [],
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
                    jwt_token = get_user_access_token(user.email, user.id, user.username, user.first_name, user.last_name)
                    response_obj = {"token": jwt_token}
                    logger.info("Login Successfully")
                    login(request, user)
                    response["message"] = "Successfully login"
                    response["data"] = [response_obj]
                    response["success"] = True
                    return Response(response, status=status.HTTP_200_OK)
                else:
                    response["message"] = "User is inactive"
                    return Response(response, status=status.HTTP_400_BAD_REQUEST)
            else:
                response["message"] = "Invalid login details given"
                return Response(response, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            print(e)
            return Response(response)


# ForgotPassword with Serializer
class ForgotPassword(APIView):
    serializer_class = ForgotPasswordSerializer

    def post(self, request):
        response = {
            "message": "Something went wrong",
            "data": [],
            "success": False,
        }
        serializer = ForgotPasswordSerializer(data=request.data)

        if serializer.is_valid():
            email = request.data["email"]
            obj = User.objects.filter(email=email)
            if obj:
                url = settings.ANGULAR_URL
                message = render_to_string('reset_password_confirm.html', {
                    'main_url': url,  # pass the url
                    'token': get_user_access_token(email)
                })

                send_html_email(email, "Reset Password", message)
                logger.info("Email has sent to" + email + "'s email address. Please check inbox "
                                                          "to continue reset password ")
                response["success"] = True
                response["message"] = "Email has sent to " + email + "'s email address. " \
                                                                     "Please check inbox to continue reset password"
                return Response(response, status=status.HTTP_200_OK)
            else:
                response["message"] = "Email address is not register, Please register first"
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
        else:
            response["message"] = "Invalid data"
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

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
        response = {
            "message": "Something went wrong",
            "data": [],
            "success": False,
        }

        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            new_pswd = request.data['new_pswd']
            if new_pswd is None:
                return Response("Password must be required")
            confirm_pswd = request.data['confirm_pswd']
            if confirm_pswd is None:
                return Response("Confirm password must be required")
            if new_pswd == confirm_pswd:
                token_obj = decode_token(token)
                user_obj = User.objects.get(email=token_obj['email'])
                password = new_pswd
                user_obj.set_password(password)
                user_obj.save()
                response["success"] = True
                response["message"] = "Password successfully reset"
                return Response(response, status=status.HTTP_200_OK)
            else:
                response["message"] = "Password Mismatch"
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
        else:
            response["message"] = "Invalid data"
            return Response(response, status=status.HTTP_400_BAD_REQUEST)


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
            serializer.save()
            logger.info("Note created successfully")
            response["success"] = True
            response["message"] = "Note created successfully"
            response["data"] = serializer.data
            return Response(response, status=status.HTTP_200_OK)
        else:
            logger.error("Fail to create Note")
            response["message"] = "Fail to create Note"
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, *args, **kwargs):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        note_obj = Note.objects.all()
        try:
            if note_obj:
                data = NoteSerializer(note_obj, many=True).data  # serialize the data
                logger.info("All notes got successfully")
                response["success"] = True
                response["message"] = "All notes got successfully"
                response["data"] = [data]
                return Response(response, status=status.HTTP_200_OK)
        except:
                logger.error("Notes not present")
                response["message"] = "Notes not present"
                return Response(response, status=status.HTTP_400_BAD_REQUEST)


class NoteUpdateView(APIView):
    serializer_class = NoteSerializer

    def get(self, request, pk):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        note_id_obj = get_object_or_404(Note, id=pk)
        if note_id_obj:
            data = NoteSerializer(note_id_obj).data
            logger.info("Note with id {} get successfully".format(pk))
            response["success"] = True
            response["message"] = "Note get successfully"
            response["data"] = [data]
            return Response(response, status=status.HTTP_200_OK)
        else:
            logger.error("Note not found")
            response["message"] = "Note not found"
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        note_obj = Note.objects.get(id=pk)
        if note_obj:
            note_obj.delete()
            logger.info("Note delete successfully")
            response["success"] = True
            response["message"] = "Note delete successfully"
            return Response(response, status=status.HTTP_200_OK)
        else:
            logger.error("Note not found")
            response["message"] = "Fail to delete note"
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

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
            response["success"] = True
            response["message"] = "Note updated successfully"
            response["data"] = serializer.data
            return Response(response, status=status.HTTP_200_OK)
        else:
            response["message"] = "Fail to update Note"
            return Response(response, status=status.HTTP_400_BAD_REQUEST)


@login_required
def user_logout(request):
    logout(request)
    print('Successfully logout %r user.' % request.user)

    return HttpResponseRedirect('/users/login/')



