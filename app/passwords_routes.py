from flask import Blueprint, render_template, redirect, flash, url_for, request, session, Response, abort
from flask_login import current_user, login_required
from forms import CreatePasswordForm
from models import db, User, Password
import base64
import hashlib

passwords = Blueprint('passwords', __name__, template_folder='templates')

@passwords.route('/myPasswords', methods=['GET', 'POST'])
@login_required
def my_passwords():
    user = User.query.filter_by(id=current_user.id).first()
    form = CreatePasswordForm(meta={'csrf_context': session})
    message = form.password.data
    print (type(user.password_hash))
    print (user.password_hash)

    test = str(form.password.data)
    testText = test.encode()
    hashed = hashlib.pbkdf2_hmac('sha256', testText, (user.password_hash).encode(), 100000)

    if form.validate_on_submit():
        name = form.name.data
        password = hashed.hex()
        url = form.url.data
        new_password = Password(name=name, password=password,
                    url=url, owner=user)
        db.session.add(new_password)
        db.session.commit()

        flash('Hasło zostało dodane', 'alert alert-success')

    passwords = user.passwords
    return render_template('my_passwords.html', form=form, passwords=passwords)

@passwords.route('/myPasswords/delete/<int:id>')
@login_required
def delete_password(id):
    user = User.query.filter_by(id=current_user.id).first()
    passwords = [password for password in user.passwords if password.id == id]
    if len(passwords) > 1:
        abort(500)
    if len(passwords) < 1:
        abort(404)

    password = passwords[0]
    db.session.delete(password)
    db.session.commit()

    return redirect(url_for('passwords.my_passwords'))

@passwords.route('/unhash')
@login_required
def unhash_password():
    passwords = Password.query.filter_by(user_id=current_user.id).all()
    return render_template('unhash_passwords.html', passwords=passwords)