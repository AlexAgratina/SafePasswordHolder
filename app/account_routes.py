"""Routes connected to users accounts"""

from flask import Blueprint, render_template, flash, redirect, url_for, request, session, current_app, abort
from flask_login import current_user, login_user, logout_user, login_required
from forms import RegisterForm, LoginForm, ChangePasswordForm, RecoverPasswordForm, ResetPasswordForm
from models import db, User, Login, RecoveryToken
import bcrypt
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from urllib.parse import urlsplit, urlunsplit
from datetime import datetime, timedelta
from time import sleep

users = Blueprint('account', __name__, template_folder='templates')


def calculate_login_delay(login_count: int) -> int:
    if login_count <= 3:
        return 0
    if login_count <= 10:
        return 1
    if login_count <= 100:
        return 5

    return 20


def send_email(adres: str, title: str, content: str) -> None:
    port = 465  # For SSL
    mail_login = current_app.config['GMAIL_LOGIN']
    mail_password = current_app.config['GMAIL_PASSWORD']

    if not mail_login or not mail_password:
        abort(500)

    sender_email = mail_login
    receiver_email = adres
    message = MIMEMultipart("alternative")
    message["Subject"] = title
    message["From"] = sender_email
    message["To"] = receiver_email

    part1 = MIMEText(content, "plain")
    message.attach(part1)

    with smtplib.SMTP_SSL("smtp.gmail.com", port, context=ssl.create_default_context()) as server:
        server.login(mail_login, mail_password)
        server.sendmail(sender_email, receiver_email, message.as_string())


@users.route('/register', methods=['GET', 'POST'])
def register():
    logout_user()

    form = RegisterForm(meta={'csrf_context': session})
    if form.validate_on_submit():
        flash('Konto zostało utworzone', 'alert-success')

        login = form.login.data
        password = form.password.data
        email = form.email.data
        lucky_number = form.lucky_number.data

        password_hash = bcrypt.hashpw(
            password.encode(), bcrypt.gensalt()).decode()

        user = User(login=login, password_hash=password_hash,
                    email=email, lucky_number=lucky_number)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('register.html', form=form)


@users.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm(meta={'csrf_context': session})
    user = User.query.filter_by(login=form.login.data).first()

    if user and form.password.data:  # A login attempt
        ip = request.remote_addr
        login = Login(successful=form.validate(), ip=ip, user=user)
        db.session.add(login)
        db.session.commit()

        # Slow down brute force attempts
        time_boundary = datetime.utcnow() - timedelta(minutes=5)
        recent_login_attempts = len(
            [a for a in user.login_attempts if a.timestamp > time_boundary and not a.successful])

        sleep(calculate_login_delay(recent_login_attempts))

    if form.validate_on_submit():
        login_user(user)

        next_page = session.get('next', None)
        session['next'] = None
        if not next_page:
            next_page = url_for('passwords.view_passwords')
        return redirect(next_page)

    return render_template('login.html', form=form)


@users.route('/logout')
def logout():
    logout_user()
    flash('Nastąpiło poprawne wylogowanie', 'alert-success')

    return redirect(url_for('index'))


@users.route('/account')
@login_required
def account():
    user = User.query.filter_by(id=current_user.id).first()
    login_attempts = sorted(user.login_attempts,
                            key=lambda a: a.timestamp, reverse=True)
    time_format = r'%d/%m/%Y %H:%M:%S'
    login_attempts = [{'ip': a.ip, 'successful': a.successful, 'time': a.timestamp.strftime(time_format)}
                      for a in login_attempts]

    return render_template('account.html', login_attempts=login_attempts)


@login_required
@users.route('/account/changePassword', methods=['GET', 'POST'])
def change_password():
    form = ChangePasswordForm(meta={'csrf_context': session})
    form.login.data = current_user.login
    if form.validate_on_submit():
        password = form.password.data
        current_id = current_user.id
        user = User.query.filter_by(id=current_id).first()
        user.set_password(password)
        db.session.commit()

        flash('Hasło zostało zmienione', 'alert-success')
        return redirect(url_for('account.account'))

    return render_template('change_password.html', form=form)


@users.route('/recoverPassword', methods=['GET', 'POST'])
def recover_password():
    form = RecoverPasswordForm(meta={'csrf_context': session})
    if form.validate_on_submit():
        login = form.login.data
        user = User.query.filter_by(login=login).first()
        email = user.email

        recovery_token = RecoveryToken(user=user)
        db.session.add(recovery_token)
        db.session.commit()

        # Build link
        app_url_parts = urlsplit(request.base_url)
        url_path = url_for('account.validate_password_token')
        url_query = f'user={login}&token={recovery_token.token}'
        recovery_link = urlunsplit(
            (app_url_parts.scheme, app_url_parts.netloc, url_path, url_query, ''))

        topic = 'Recover password'
        message = f'Żeby zresetować hasło przejdź pod ten link: {recovery_link}'

        send_email(email, topic, message)

        flash('Na adres email podany przy rejestracji został wysłany email z linkiem do resetu hasła',
              'alert alert-success')
        return redirect(url_for('account.login'))

    return render_template('recover_password.html', form=form)


@users.route('/validatePasswordToken')
def validate_password_token():
    token = request.args.get('token', None)
    login = request.args.get('user', None)
    if not token or not login:
        abort(400)

    user = User.query.filter_by(login=login).first()
    if not user:
        abort(404)

    recovery_token = [t for t in user.recovery_tokens if t.token == token]
    if len(recovery_token) < 1:
        abort(404)
    if len(recovery_token) > 1:
        abort(500)

    recovery_token = recovery_token[0]
    if recovery_token.expiration < datetime.utcnow():
        flash('Przeterminowany token', 'alert alert-danger')
        abort(400)

    session['can_reset_password'] = True
    session['login'] = login
    return redirect(url_for('account.reset_password'))


@users.route('/resetPassword', methods=['GET', 'POST'])
def reset_password():
    login = session.get('login', None)
    if not session.get('can_reset_password', None) or not login:
        abort(400)

    form = ResetPasswordForm(meta={'csrf_context': session})
    if form.validate_on_submit():
        password = form.password.data
        user = User.query.filter_by(login=login).first()
        user.set_password(password)
        db.session.commit()

        session['can_reset_password'] = False
        flash('Hasło zostało zmienione', 'alert alert-success')
        return redirect(url_for('account.login'))

    return render_template('reset_password.html', form=form)
