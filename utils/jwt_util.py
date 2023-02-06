import jwt
import redis
import datetime

secret_key = 'secret-key'
# connecting to redis
redis_conn = redis.Redis(host='localhost', port=6379)


def generate_access_token(username):

    access_payload = {
        'username': username,
        'type': 'access',  # to denote access token
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
    }

    access_token = jwt.encode(access_payload, secret_key, algorithm='HS256')

    # store access token in redis for validation
    redis_conn.set(access_token, username)
    redis_conn.expire(access_token, 300)

    return access_token


def generate_refresh_token(username):

    refresh_payload = {
        'username': username,
        'type': 'refresh',  # to denote refresh token
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }

    refresh_token = jwt.encode(refresh_payload, secret_key, algorithm='HS256')

    # store refresh token in redis for validation
    redis_conn.set(refresh_token, username)
    redis_conn.expire(refresh_token, 604800)

    return refresh_token


def verify_access_token(access_token):

    # cross checking the incoming access token in redis
    username = redis_conn.get(access_token)
    if username is None:
        return None
    else:
        username = username.decode("utf-8")

    try:
        access_payload = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        if access_payload['type'] != 'access':
            return None
    except jwt.exceptions.InvalidSignatureError:
        return None
    except jwt.exceptions.ExpiredSignatureError:
        return None
    except jwt.exceptions.DecodeError:
        return None

    return username


def verify_refresh_token(refresh_token):

    # cross checking the incoming refresh token in redis
    username = redis_conn.get(refresh_token)
    if username is None:
        return None
    else:
        username = username.decode("utf-8")

    try:
        refresh_payload = jwt.decode(refresh_token, secret_key, algorithms=['HS256'])
        if refresh_payload['type'] != 'refresh':
            return None
    except jwt.exceptions.InvalidSignatureError:
        return None
    except jwt.exceptions.ExpiredSignatureError:
        return None
    except jwt.exceptions.DecodeError:
        return None

    return username


def invalidate_access_token(access_token, username):
    # removing access_token from redis when logged out
    redis_conn.delete(access_token, username)

