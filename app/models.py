from flask_sqlalchemy import SQLAlchemy
from flask import current_app
from flask_login import UserMixin
import bcrypt
from datetime import datetime, timedelta
from secrets import token_urlsafe

db = SQLAlchemy()

TOKEN_VALID_TIME = timedelta(minutes=30)
TOKEN_LENGTH = 50

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(), index=True, unique=True)
    email = db.Column(db.String(), unique=True)
    password_hash = db.Column(db.String())
    lucky_number = db.Column(db.Integer)
    passwords = db.relationship('Password', backref='owner', lazy=True)
    login_attempts = db.relationship('Login', backref='user', lazy=True)
    recovery_tokens = db.relationship(
        'RecoveryToken', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(
            password.encode(), bcrypt.gensalt()).decode()

    def __repr__(self):
        return f'{self.login}'


class RecoveryToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    expiration = db.Column(
        db.DateTime, default=(lambda: datetime.utcnow() + TOKEN_VALID_TIME))
    token = db.Column(db.String(), index=True, default=(
        lambda: token_urlsafe(TOKEN_LENGTH)))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String())
    password = db.Column(db.String())
    nonce = db.Column(db.String())
    url = db.Column(db.String())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def set_password(self, password):
        self.password = password

    def __repr__(self):
        return f'<Password id={self.id} name={self.name}>'


class Login(db.Model):
    """Log user login attempts"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    successful = db.Column(db.Boolean())
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip = db.Column(db.String())


def fill_db_with_values():
    test_user = User(
        login='sasha', email='sasha.agratina@gmail.com', lucky_number=5)
    test_user.set_password('Password.123')
    db.session.add(test_user)
    db.session.commit()
