from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required
from app.models import Company
from app import db

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        if Company.query.filter_by(email=email).first():
            flash('Email already registered')
            return render_template('register.html')
        company = Company(name=name, email=email)
        company.set_password(password)
        db.session.add(company)
        db.session.commit()
        login_user(company)
        return redirect(url_for('dashboard.index'))
    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        company = Company.query.filter_by(email=email).first()
        if company and company.check_password(password):
            login_user(company)
            return redirect(url_for('dashboard.index'))
        flash('Invalid email or password')
    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
