import jwt
import json
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
from rest_framework.generics import GenericAPIView, CreateAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash

from .decorators import app_login_required
from .email_service import send_html_email
from .forms import ForgotPasswordForm, ResetPasswordForm
from .serializer import UserSerializer, ResetPasswordSerializer, NoteSerializer, ForgotPasswordSerializer, \
    LoginSerializer, LabelSerializer
from .models import Note, Label
import logging

from .tokens import get_user_access_token, decode_token
from .redis_service import RedisService

redis_obj = RedisService()

logger = logging.getLogger(__name__)

# Create your views here.
from django.conf import settings


class Register(GenericAPIView):

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
                response["data"] = serializer.data
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
        return Response('Thank you for your email confirmation. Now you can login your account.')
    except SignatureExpired:
        return Response('The token is expired!')


class Login(GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request,*args, **kwargs):
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
                    redis_obj.set_value('token_key', jwt_token)
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
class ForgotPassword(GenericAPIView):
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
                logger.info("Email has sent to" + email + "'s email . Please check inbox "
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


# ResetPassword with serializer
class ResetPassword(GenericAPIView):
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


class NoteView(GenericAPIView):
    serializer_class = NoteSerializer

    @method_decorator(app_login_required)
    def post(self, request, *args, **kwargs):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        serializer = NoteSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            token_obj = redis_obj.get_value('token_key')
            decoded_token = decode_token(token_obj)
            decoded_id = decoded_token["id"]
            user = User.objects.get(id=decoded_id)
            serializer.save(created_by=user)
            logger.info("Note created successfully")
            response["success"] = True
            response["message"] = "Note created successfully"
            response["data"] = serializer.data
            # note_data = json.dumps(response)
            # for collaborated_id in serializer.data["collaborate"]:
            #     user_obj = User.objects.get(id=collaborated_id)
            #     if user_obj:
            #         send_html_email(user_obj.email, "Sending note to user", note_data)
            return Response(response, status=status.HTTP_200_OK)
        else:
            logger.error("Fail to create Note")
            response["message"] = "Fail to create Note"
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

    @method_decorator(app_login_required)
    def get(self, request, *args, **kwargs):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        # note_obj = Note.objects.all()
        note_obj = Note.objects.filter(is_trash=False)
        if note_obj:
            data = NoteSerializer(note_obj, many=True).data  # serialize the data
            logger.info("All notes got successfully")
            response["success"] = True
            response["message"] = "All notes get successfully"
            response["data"] = data
            return Response(response, status=status.HTTP_200_OK)
        else:
            logger.error("Notes not present")
            response["message"] = "Notes not present"
            return Response(response, status=status.HTTP_400_BAD_REQUEST)


class NoteUpdateView(GenericAPIView):
    serializer_class = NoteSerializer

    @method_decorator(app_login_required)
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

    @method_decorator(app_login_required)
    def put(self, request, pk):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        note_obj = Note.objects.get(id=pk)
        data = request.data
        serializer = NoteSerializer(note_obj, data=data, partial=True)   # partial=True means we want to be able
        # to update some fields but not necessarily all at once
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            response["success"] = True
            response["message"] = "Note updated successfully"
            response["data"] = serializer.data
            return Response(response, status=status.HTTP_200_OK)
        else:
            response["message"] = "Fail to update Note"
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

    @method_decorator(app_login_required)
    def delete(self, request, pk):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        try:
            note_obj = Note.objects.get(id=pk)
            if note_obj.is_deleted is False:
                note_obj.is_deleted = True
                note_obj.is_trash = True
                note_obj.save()
                logger.info("Note deleted successfully and added to trash")
                response["success"] = True
                response["message"] = "Note deleted successfully and added to trash"
                return Response(response, status=status.HTTP_200_OK)
            else:
                logger.info("Note already deleted")
                response["message"] = "Note already deleted"
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
        except:
            logger.error("Note not found")
            response["message"] = "Note not found"
            return Response(response, status=status.HTTP_404_NOT_FOUND)


class NoteAllDelete(GenericAPIView):
    @method_decorator(app_login_required)
    def delete(self, request):
        serializer_class = NoteSerializer
        response = {
           "success": False,
           "message": "Something went wrong",
           "data": []
        }
        try:
           note_obj = Note.objects.filter(is_trash=True)
           print(note_obj)
           if note_obj:
               note_obj.delete()
               logger.info("All notes delete successfully")
               response["success"] = True
               response["message"] = "All notes delete successfully"
               return Response(response, status=status.HTTP_200_OK)
           else:
               logger.error("Notes not present")
               response["message"] = "Notes not present"
               return Response(response, status=status.HTTP_400_BAD_REQUEST)
        except:
           logger.error("Notes not present")
           response["message"] = "Notes not present"
           return Response(response, status=status.HTTP_400_BAD_REQUEST)


# To set trash the note
class TrashNote(GenericAPIView):
    serializer_class = NoteSerializer

    @method_decorator(app_login_required)
    def get(self, request, pk):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        try:
            note_obj = Note.objects.get(id=pk)
            note_data = NoteSerializer(note_obj).data
            if note_obj.is_trash is False and note_obj.is_deleted is True:
                note_obj.is_trash = True
                note_obj.save()
                logger.info("Note trashed successfully")
                response["success"] = True
                response["message"] = "Note trashed successfully"
                response["data"] = note_data
                return Response(response, status=status.HTTP_200_OK)
            else:
                logger.info("Note already trashed")
                response["message"] = "Note already trashed"
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
        except:
            logger.error("Note not found")
            response["message"] = "Note not found"
            return Response(response, status=status.HTTP_404_NOT_FOUND)


# List out all the notes which are in trash
class TrashNoteView(GenericAPIView):
    @method_decorator(app_login_required)
    def get(self, request):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        try:
            trash_notes = Note.objects.filter(is_trash=True)
            trash_data = NoteSerializer(trash_notes, many=True).data
            logger.info("Notes are in trash")
            response["success"] = True
            response["message"] = "Notes are in trash"
            response["data"] = trash_data
            return Response(response, status=status.HTTP_200_OK)
        except:
            logger.error("Notes not available")
            response["message"] = "Notes not available"
            return Response(response, status=status.HTTP_404_NOT_FOUND)


# To set pin the note
class PinNote(APIView):
    serializer_class = NoteSerializer

    @method_decorator(app_login_required)
    def get(self, request, pk):
        """  This handles the request to pin particular note by note id  """
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        try:
            note_obj = Note.objects.get(id=pk)
            note_data = NoteSerializer(note_obj).data
            # check note is not pin
            if note_obj.is_pin is False:
                # update the record and set the pin
                note_obj.is_pin = True
                note_obj.save()
                logger.info("Note pinned Successfully")
                response["message"] = "Note pinned Successfully"
                response["success"] = True
                response["data"] = note_data
                return Response(response, status=status.HTTP_200_OK)
            else:
                logger.error("Note already pinned")
                response["message"] = "Note already pinned"
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
        except:
            response["message"] = "Note not found"
            logger.error("Note not found")
            return Response(response, status=status.HTTP_404_NOT_FOUND)


# List out pinned notes
class PinNoteView(GenericAPIView):

    @method_decorator(app_login_required)
    def get(self, request):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        try:
            note_obj = Note.objects.filter(is_pin=True)
            notes = NoteSerializer(note_obj, many=True).data
            logger.info("All pinned notes get successfully")
            response["success"] = True
            response["message"] = "All pinned notes get successfully"
            response["data"] = notes
            return Response(response, status=status.HTTP_200_OK)
        except:
            logger.error("Notes not available")
            response["message"] = "Notes not available"
            return Response(response, status=status.HTTP_404_NOT_FOUND)


# To set archive the note
class ArchiveNote(GenericAPIView):
    serializer_class = NoteSerializer

    @method_decorator(app_login_required)
    def get(self, request, pk):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        try:
            note_obj = Note.objects.get(id=pk)
            note_data = NoteSerializer(note_obj).data
            if note_obj.is_trash is False and note_obj.is_deleted:
                if note_obj.is_archive is False:
                    note_obj.is_archive = True
                    note_obj.save()
                    logger.info("Archive set successfully")
                    response["success"] = True
                    response["message"] = "Archive set successfully"
                    response["data"] = note_data
                    return Response(response, status=status.HTTP_200_OK)
                else:
                    logger.error("Note already archived")
                    response["message"] = "Note already archived"
                    return Response(response, status=status.HTTP_400_BAD_REQUEST)
            else:
                logger.error("Note is already deleted or trashed")
                response["message"] = "Note is already deleted or trashed"
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
        except:
            logger.error("Note not found")
            response["message"] = "Note not found"
            return Response(response, status=status.HTTP_404_NOT_FOUND)


# List out the archived the notes
class ArchiveNoteView(GenericAPIView):

    @method_decorator(app_login_required)
    def get(self, request):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        try:
            note_obj = Note.objects.filter(is_archive=True)
            notes = NoteSerializer(note_obj, many=True).data
            logger.info("All archived notes get successfully")
            response["success"] = True
            response["message"] = "All archived notes get successfully"
            response["data"] = notes
            return Response(response, status=status.HTTP_200_OK)
        except:
            logger.error("Notes not available")
            response["message"] = "Notes not available"
            return Response(response, status=status.HTTP_404_NOT_FOUND)


class NoteCollaborator(GenericAPIView):
    serializer_class = NoteSerializer

    @method_decorator(app_login_required)
    def get(self, request, pk=None):
        notes = Note.objects.get(id=pk)
        serializer = NoteSerializer(notes).data
        return Response(serializer)

    @method_decorator(app_login_required)
    def get_by_object(self, pk=None):
        obj = Note.objects.get(id=pk)
        return obj

    @method_decorator(app_login_required)
    def put(self, request, pk=None):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        try:
            colloborate_data = request.data
            collaborator_email = colloborate_data["collaborate"]
            colloborate_user = User.objects.filter(email=collaborator_email) & User.objects.filter(is_active=1)
            user_id = []
            for i in colloborate_user:
                user_id.append(i.id)
            collaborate_id = user_id[0]
            note_obj = Note.objects.get(id=pk)
            if not note_obj:
                return Response("Note not found")
            token_obj = redis_obj.get_value('token_key')
            decoded_token = decode_token(token_obj)
            decoded_id = decoded_token['id']
            decoded_email = decoded_token['email']
            user = User.objects.get(id=decoded_id)
            if collaborator_email:
                if collaborator_email == decoded_email:
                    print(collaborator_email, decoded_email, "<<<<<<", note_obj)
                    response["message"] = "with same email id can not be collaborate, Please pass the correct email id"
                    response["success"] = False
                    return Response(response, status=status.HTTP_400_BAD_REQUEST)
                else:
                    note_obj.collaborate.add(int(collaborate_id))
                    note_obj.save()
                    current_site = get_current_site(request)
                    mail_subject = "Check collaborated note"
                    message = render_to_string('collaborate_email.html', {'user': user, 'domain': current_site.domain})
                    to_email = collaborator_email
                    send_html_email(to_email, mail_subject, message)
                    logger.info("Note Collaborated Successfully")
                    response["success"] = True
                    response["message"] = "Note Collaborated Successfully"
                    response["data"] = colloborate_data
                    return Response(response, status=status.HTTP_201_CREATED)
            else:
                response["message"] = "Given collaborated email not found in database"
                return Response(response, status=status.HTTP_404_NOT_FOUND)
        except :
            response["message"] = "Note id can't be blank"
            return Response(response, status=status.HTTP_400_BAD_REQUEST)


# To set reminder
class RemainderNote(GenericAPIView):
    serializer_class = NoteSerializer

    @method_decorator(app_login_required)
    def get(self, request, pk=None):
        notes = Note.objects.get(id=pk)
        serializer = NoteSerializer(notes).data
        return Response(serializer)

    @method_decorator(app_login_required)
    def put(self, request, pk=None):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        try:
            note_data = request.data
            obj = Note.objects.get(id=pk)
            if not obj:
                response["message"] = "Note not present"
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
            if not obj.is_trash:
                # update the record and set the reminder
                obj.remainder = note_data
                obj.save()
                created_id = obj.created_by
                user = User.objects.get(id=created_id.id)
                send_html_email(user.email, "Sending Notification", "Reminder is set")
                logger.info("Successfully sent reminder notification")
                response['message'] = 'Successfully sent reminder notification'
                # response["message"] = "Remainder set successfully"
                response['success'] = True
                return Response(response, status=status.HTTP_200_OK)
            else:
                logger.info("Note deleted or trashed")
                response["message"] = "Note deleted or trashed"
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
        except:
            logger.info("Note not found")
            response["message"] = "Note not found"
            return Response(response, status=status.HTTP_404_NOT_FOUND)


class RemainderNoteView(GenericAPIView):
    @method_decorator(app_login_required)
    def get(self, request):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        notes_obj = Note.objects.filter(remainder__isnull=False, is_trash=False)
        serializer = NoteSerializer(notes_obj, many=True).data
        logger.info("All notes with reminder get successfully")
        response['message'] = 'All notes with reminder get successfully',
        response['success'] = True
        response['data'] = serializer
        return Response(response, status=status.HTTP_200_OK)


class RemoveRemainderNote(GenericAPIView):
    @method_decorator(app_login_required)
    def get(self, request, pk):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        notes_obj = Note.objects.get(id=pk)
        if notes_obj.remainder is not None:
            notes_obj.remainder = None
            notes_obj.save()
            logger.info("Note reminder remove successfully")
            response['message'] = 'Note reminder remove successfully'
            response['success'] = True
            return Response(response, status=status.HTTP_200_OK)
        else:
            logger.info("Note not present")
            response['message'] = 'Note not present'
            return Response(response, status=status.HTTP_404_NOT_FOUND)


# to create the label and list of labels
class LabelList(GenericAPIView):
    serializer_class = LabelSerializer

    # list of labels
    @method_decorator(app_login_required)
    def get(self, request, is_deleted=None):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        label_obj = Label.objects.filter(is_deleted=False)
        if label_obj:
            serializer = LabelSerializer(label_obj, many=True).data
            logger.info("All labels get successfully")
            response["success"] = True
            response["message"] = "All labels get successfully"
            response["data"] = serializer
            return Response(response, status=status.HTTP_200_OK)
        else:
            logger.error("Labels not present")
            response["message"] = "Labels not present"
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

    # creating the new label
    @method_decorator(app_login_required)
    def post(self, request):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        serializer = LabelSerializer(data=request.data)
        try:
            if serializer.is_valid():
                serializer.save()
                logger.info("Label created successfully")
                response["success"] = True
                response["message"] = "Label created successfully"
                response["data"] = serializer.data
                return Response(response, status=status.HTTP_200_OK)
            else:
                logger.info("Fail to create label")
                response["message"] = "Fail to create label"
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
        except:
            return Response(response, status=status.HTTP_400_BAD_REQUEST)


# perform operations like edit, delete on labels
class LabelViewDetails(GenericAPIView):
    serializer_class = LabelSerializer

    # to get id wise label
    @method_decorator(app_login_required)
    def get(self, request, pk=None):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        try:
            obj = Label.objects.get(id=pk)
            label_obj = LabelSerializer(obj).data
            logger.info("Label get successfully")
            response["success"] = True
            response["message"] = "Label get successfully"
            response["data"] = label_obj
            return Response(response, status=status.HTTP_200_OK)
        except:
            response["message"] = "label not available of this id"
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

    # editing the label
    @method_decorator(app_login_required)
    def put(self, request, pk=None):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        try:
            data = request.data
            instance = Label.objects.get(id=pk)
            serializer = LabelSerializer(instance, data=data)
            if serializer.is_valid():
                serializer.save()
                response["success"] = True
                response["message"] = "Label updated successfully"
                response["data"] = serializer.data
                return Response(response, status=status.HTTP_200_OK)
            else:
                response["message"] = "Fail to update label"
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
        except:
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

    # deleting the label
    @method_decorator(app_login_required)
    def delete(self, request, pk):
        response = {
            "success": False,
            "message": "Something went wrong",
            "data": []
        }
        try:
            instance = Label.objects.get(id=pk)
            if instance.is_deleted is False:
                instance.is_deleted = True
                instance.save()
                response["success"] = True
                response["message"] = "Label Deleted Successfully"
                logger.info("Label Deleted Successfully")
                return Response(response, status=status.HTTP_200_OK)
            else:
                logger.error("Label already deleted")
                response["message"] = "Label already deleted"
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
        except:
            logger.error("Label Does Not Exist Or Deleted.")
            response["message"] = "Label Does Not Exist Or Deleted."
            return Response(response, status=status.HTTP_400_BAD_REQUEST)






