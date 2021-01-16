from flask import Flask, request, render_template, current_app, session, redirect, url_for
from flask_session import Session
from flask_login import current_user
from flask_misaka import Misaka
from config import Config
from models import db, User, fill_db_with_values
from login import login_manager
from account_routes import users
from passwords_routes import passwords

app = Flask(__name__)
app.config.from_object(Config)
Session(app)
Misaka(app, escape=True)

db.init_app(app)
with app.app_context():
    db.drop_all()
    db.create_all()
    db.session.commit()
    fill_db_with_values()
login_manager.init_app(app)

app.register_blueprint(users)
app.register_blueprint(passwords)


@app.route('/')
def index():
    return render_template('index.html')
