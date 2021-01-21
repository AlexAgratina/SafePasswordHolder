from flask import Blueprint, render_template, redirect, flash, url_for, request, session, Response, abort
from flask_login import current_user, login_required
from forms import CreatePasswordForm
from models import db, User, Password
import base64
import hashlib
from Crypto.Cipher import AES

passwords = Blueprint('passwords', __name__, template_folder='templates')

@passwords.route('/myPasswords', methods=['GET', 'POST'])
@login_required
def my_passwords():
    user = User.query.filter_by(id=current_user.id).first()
    form = CreatePasswordForm(meta={'csrf_context': session})
    message = form.password.data

    if not message:
        message = b''
    else:
        message = message.encode()

    # encryption
    key = user.password_hash.encode()

    aes = AES.new(key[:16], AES.MODE_EAX)

    nonce = aes.nonce

    ciphertext, tag = aes.encrypt_and_digest(message)
    # decryption
    # ciphered = AES.new(key[:16], AES.MODE_EAX, nonce=nonce)

    # plaintext = ciphered.decrypt(ciphertext)
    # try:
    #     ciphered.verify(tag)
    #     print("The message is authentic:", plaintext)
    # except ValueError:
    #     print("Key incorrect or message corrupted")


    # print('CIPHERTEXT', ciphertext.decode('utf-16'))
    # print('NONCEBEFORE1', nonce)
    # print('NONCEBEFORE', nonce.decode('utf-16'))
    # print('NONCEAFTER', str(nonce).encode('utf-16')[2:])

    if form.validate_on_submit():
        name = form.name.data
        password = ciphertext.decode('utf-16')
        url = form.url.data
        new_password = Password(name=name, password=password,
                                nonce=nonce.decode('utf-16'),
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


@passwords.route('/unhash/<int:id>/<string:password>/<string:nonce>')
@login_required
def unhash_password(id, password, nonce):

    user = User.query.filter_by(id=current_user.id).first()
    key = user.password_hash.encode()
    # print('password', password)
    # print('nonce', nonce)
    # print('nonce', str(nonce).encode('utf-16')[2:])
    ciphered = AES.new(key[:16], AES.MODE_EAX,
                       nonce=nonce.encode('utf-16')[2:])
    plaintext = ciphered.decrypt(password.encode("utf-16")[2:])
    current_password = plaintext.decode('utf-16')
    pass_obj = Password.query.filter_by(id=id).first()
    pass_obj.set_password(current_password)
    db.session.commit()
    return redirect(url_for('passwords.my_passwords'))
