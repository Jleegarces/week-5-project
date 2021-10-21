from flask import Blueprint, render_template, request
from flask_wtf import form
from podcast_api.forms import UserLoginForm
from podcast_api.models import User, db
from flask_login import login_user, login_required, logout_user

auth = Blueprint('auth', __name__, template_folder='auth_templates')


@auth.route('/signup', methods = ['GET', 'POST'])
def signup():
    form = UserLoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        print(email, password)

        new_user = User(email, password)
        db.session.add(new_user)
        db.session.commit()
    
    return render_template('signup.html', form = form)

@auth.route('/signin', methods = ['GET', 'POST'])
def signin():
    form = UserLoginForm()
    return render_template('signin.html', form = form)

@auth.route('/shop')
def shop():
    return render_template('shop.html')


