import jwt


def get_user_access_token(email, id=None, username=None):
    payload = {
        "id": id,
        "name": username,
        "email": email
    }
    token = jwt.encode(payload, "SECRET_KEY", "HS256").decode("utf-8")
    return token


def decode_token(token):
    try:
        decoded_token = jwt.decode(token, "SECRET_KEY", "HS256")
        return decoded_token
    except jwt.ExpiredSignatureError:
        return "Signature Expired. Please register again."
    except jwt.InvalidTokenError:
        return "Invalid Token. Please register again."
