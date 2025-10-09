from market import app
from flask import render_template, redirect, url_for, flash, request
from market.models import Item, User
from market.forms import RegisterForm, LoginForm
from market import db
from flask_login import login_user, logout_user, login_required

@app.route('/')
@app.route('/home')
def home_page():
    return render_template('home.html')
