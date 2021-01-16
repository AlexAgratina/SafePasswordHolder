import os
from secrets import token_hex
from redis import Redis
basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    """Configuration of app properties"""
    FLASK_ENV = os.environ.get('FLASK_ENV') or 'production'
    REDIS_HOST = os.environ.get('REDIS_HOST') or 'localhost'

    SESSION_TYPE = 'redis'
    SESSION_REDIS = Redis(REDIS_HOST)
    PERMANENT_SESSION_LIFETIME = 60 * 15
    SESSION_COOKIE_SECURE = FLASK_ENV == 'production'
    USE_SESSION_FOR_NEXT = True

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'sqlite.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SECRET_KEY = os.environ.get('SECRET_KEY') or token_hex(1024)

    GMAIL_LOGIN = os.environ.get('GMAIL_LOGIN') or ''
    GMAIL_PASSWORD = os.environ.get('GMAIL_PASSWORD') or ''
