import jwt

from django.conf import settings
from rest_framework.response import Response


def get_user_access_token(email, id=None, username=None, first_name=None,  last_name=None):
    payload = {
        "id": id,
        "name": username,
        "email": email,
        "first_name": first_name,
        "last_name": last_name
    }
    token = jwt.encode(payload, settings.JWT_KEY, settings.JWT_ALGORITHM).decode("utf-8")
    return token


def decode_token(token):
    try:
        decoded_token = jwt.decode(token, settings.JWT_KEY, settings.JWT_ALGORITHM)
        return decoded_token
    except jwt.ExpiredSignatureError:
        return Response("Signature Expired. Please register again.")
    except jwt.InvalidTokenError:
        return Response("Invalid Token. Please register again.")
    return Response("Something went wrong")
