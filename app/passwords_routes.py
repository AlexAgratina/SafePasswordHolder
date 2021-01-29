from flask import Blueprint, render_template, redirect, flash, url_for, request, session, Response, abort
from flask_login import current_user, login_required
from forms import CreatePasswordForm
from models import db, User, Password
import hashlib
from Crypto.Cipher import AES
from base64 import b64encode
from base64 import b64decode

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

    aes = AES.new(key[16:32], AES.MODE_EAX)

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

    print("!!!WYPISANY KLUCZ!!!")
    print(key)
    print("!!!WYPISANY CIPHERTEXT!!!")
    print(b64encode(ciphertext))
    print("!!!WYPISANY NONCE!!!")
    print(nonce) 
    print("!!!WYPISANY message!!!")
    print(message)

    if form.validate_on_submit():
        name = form.name.data
        password = b64encode(ciphertext)
        url = form.url.data
        new_password = Password(name=name, password=password,
                                nonce=b64encode(nonce),
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
    print('password', password)
    print('nonce', nonce)
    print('nonce decoded', (b64decode(nonce))[3:-1])
    ciphered = AES.new(key[16:32], AES.MODE_EAX,
                       nonce=b64decode(nonce))
    plaintext = ciphered.decrypt(password.encode('utf-8'))
    current_password = plaintext.encode('utf-8').strip()
    pass_obj = Password.query.filter_by(id=id).first()
    pass_obj.set_password(current_password)
    db.session.commit()
    return redirect(url_for('passwords.my_passwords'))
