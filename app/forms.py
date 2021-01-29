from flask_wtf.form import FlaskForm
from flask import current_app
from wtforms import StringField, PasswordField, ValidationError, FileField, Form, IntegerField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, NumberRange, Regexp
from wtforms.csrf.session import SessionCSRF
from datetime import timedelta
from config import Config
from models import User
import bcrypt


class BaseForm(FlaskForm):
    class Meta:
        csrf = True
        csrf_class = SessionCSRF
        csrf_secret = Config.SECRET_KEY.encode()
        csrf_time_limit = timedelta(minutes=20)


class UniqueLogin(object):
    def __init__(self, message=None):
        if not message:
            message = 'Wybrany login jest zajęty'
        self.message = message

    def __call__(self, form, field):
        login = field.data
        with current_app.app_context():
            result = User.query.filter(User.login == login).first()
            if result is not None:
                raise ValidationError(self.message)


class UniqueEmail(object):
    def __init__(self, message=None):
        if not message:
            message = 'Wybrany email jest zajęty'
        self.message = message

    def __call__(self, form, field):
        email = field.data
        with current_app.app_context():
            result = User.query.filter(User.email == email).first()
            if result is not None:
                raise ValidationError(self.message)


class RegisterForm(BaseForm):
    def my_entropy_check(form, field):
        if entropy(field.data.encode()) < 0.9:
            raise ValidationError('Za słabe hasło')

    login = StringField('login', validators=[
        DataRequired('Brak loginu'),
        Length(min=4, message='Login musi mieć co najmniej 4 znaki'),
        Regexp('^[A-Za-z0-9_-]*$',
               message='Login może składać się tylko z liter łacińskich liczb i znaków _ -'),
        UniqueLogin()
    ])

    password = PasswordField('password', validators=[
        DataRequired('Wpisz hasło'),
        Length(min=6, message='Hasło musi mieć co najmniej 6 znaków'),
        Length(max=72, message='Hasło może mieć co najwyżej 72 znaki'),
        my_entropy_check
    ])
    password2 = PasswordField('Password', validators=[
        EqualTo('password', 'Hasła się różnią')
    ])

    email = StringField('Mail', validators=[
        DataRequired('Brak maila'),
        Email('Nieprawidłowy mail'),
        UniqueEmail()
    ])

    lucky_number = IntegerField('Lucky number', validators=[
        DataRequired('Brak szczęśliwej liczby :('),
        NumberRange(-10000000, 10000000,
                    'Liczba musi być z przedziału od -10000000 do 10000000')
    ])


class LoginInDatabase(object):
    def __init__(self, message=None):
        if not message:
            message = 'Podany login nie istnieje'
        self.message = message

    def __call__(self, form, field):
        login = field.data
        with current_app.app_context():
            result = User.query.filter(User.login == login).first()
            if result is None:
                raise ValidationError(self.message)


class CorrectPassword(object):
    def __init__(self, message=None):
        if not message:
            message = 'Błędne hasło'
        self.message = message

    def __call__(self, form, field):
        login = form.login.data
        password = field.data
        with current_app.app_context():
            user = User.query.filter(User.login == login).first()
            if user is None:
                return
            if not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
                raise ValidationError(self.message)


class LoginForm(BaseForm):
    login = StringField('login', validators=[
        DataRequired('Brak loginu'),
        LoginInDatabase()
    ])
    password = StringField('password', validators=[
        DataRequired('Brak hasła'),
        CorrectPassword()
    ])


class ChangePasswordForm(BaseForm):
    login = StringField('login')

    old_password = PasswordField('Old password', validators=[
        DataRequired('Brak starego hasła'),
        CorrectPassword()
    ])

    password = PasswordField('password', validators=[
        DataRequired('Brak hasła'),
        Length(min=6, message='Hasło musi mieć co najmniej 6 znaków'),
        Length(max=72, message='Hasło może mieć co najwyżej 72 znaki')
    ])
    password2 = PasswordField('password2', validators=[
        EqualTo('password', 'Hasła się różnią')
    ])


class CreatePasswordForm(BaseForm):
    name = StringField(validators=[
        Length(max=30, message='Nazwa hasła może mieć najwyżej 30 znaków')
    ])
    password = StringField(validators=[
        DataRequired('Hasło jest wymagane'),
        Length(max=50, message='Hasło może mieć najwyżej 50 znaków')
    ])
    url = StringField(validators=[
        DataRequired('Adress URL jest wymagany'),
        Length(max=200, message='Adress URL może mieć najwyżej 200 znaków')
    ])


class CorrectLuckyNumber(object):
    def __init__(self, message=None):
        if not message:
            message = 'Nieprawidłowa liczba'
        self.message = message

    def __call__(self, form, field):
        login = form.login.data
        lucky_number = field.data
        with current_app.app_context():
            user = User.query.filter(User.login == login).first()
            if user is None:
                return
            if user.lucky_number != lucky_number:
                raise ValidationError(self.message)


class RecoverPasswordForm(BaseForm):
    login = StringField('login', validators=[
        DataRequired('Brak loginu'),
        LoginInDatabase()
    ])

    lucky_number = IntegerField('Lucky number', validators=[
        DataRequired('Brak szczęśliwej liczby'),
        CorrectLuckyNumber()
    ])


class ResetPasswordForm(BaseForm):
    password = PasswordField('password', validators=[
        DataRequired('Brak hasła'),
        Length(min=6, message='Hasło musi mieć co najmniej 6 znaków'),
        Length(max=72, message='Hasło może mieć co najwyżej 72 znaki')
    ])
    password2 = PasswordField('password2', validators=[
        EqualTo('password', 'Hasła się różnią')
    ])

def entropy(data : bytes) -> float:
    if not data:
        return 0
    count = {i : 0 for i in range(256)}
    for b in data: count[b] += 1
    p = lambda b: count[b] / len(data)
    entropy = sum((p(b) * count[b] for b in range(256)))
        
    return 1 - entropy / len(data)
