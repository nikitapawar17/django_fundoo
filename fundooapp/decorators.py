from django.contrib.auth.models import User
from importlib_metadata import PermissionError

from .redis_service import RedisService
from .tokens import decode_token
from django.http import HttpResponse

import jwt
from self import self


def app_login_required(function):

    def verification(varg, *args, **kwargs):
        redis_obj = RedisService.get_value(self, 'token_key')
        decoded_token = decode_token(redis_obj)
        decoded_id = decoded_token['id']
        user = User.objects.get(id=decoded_id)
        if user:
            # if it is present then go to next stp
            return function(varg, *args, **kwargs)
        else:
            raise PermissionError  # raises the permission error
    return verification


