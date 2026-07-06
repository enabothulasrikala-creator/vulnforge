from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

class Company(UserMixin, db.Model):
    __tablename__ = 'companies'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scopes = db.relationship('Scope', backref='company', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Scope(db.Model):
    __tablename__ = 'scopes'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    target_url = db.Column(db.String(500), nullable=False)
    ip_ranges = db.Column(db.Text, default='')
    excluded_paths = db.Column(db.Text, default='')
    rate_limit = db.Column(db.Integer, default=10)
    policy_rules = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scan_jobs = db.relationship('ScanJob', backref='scope', lazy='dynamic')

class ScanJob(db.Model):
    __tablename__ = 'scan_jobs'
    id = db.Column(db.Integer, primary_key=True)
    scope_id = db.Column(db.Integer, db.ForeignKey('scopes.id'), nullable=False)
    status = db.Column(db.String(50), default='pending')
    scan_type = db.Column(db.String(100), default='full')
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    error = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    findings = db.relationship('Finding', backref='scan_job', lazy='dynamic')

class Finding(db.Model):
    __tablename__ = 'findings'
    id = db.Column(db.Integer, primary_key=True)
    scan_job_id = db.Column(db.Integer, db.ForeignKey('scan_jobs.id'), nullable=False)
    title = db.Column(db.String(500), nullable=False)
    severity = db.Column(db.String(50), default='info')
    cvss_score = db.Column(db.Float, default=0.0)
    description = db.Column(db.Text, default='')
    url = db.Column(db.String(1000), default='')
    tool = db.Column(db.String(100), default='')
    evidence = db.Column(db.Text, default='')
    remediation = db.Column(db.Text, default='')
    status = db.Column(db.String(50), default='open')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Report(db.Model):
    __tablename__ = 'reports'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    scan_job_id = db.Column(db.Integer, db.ForeignKey('scan_jobs.id'))
    summary = db.Column(db.Text, default='')
    file_path = db.Column(db.String(500))
    format = db.Column(db.String(20), default='markdown')
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    company = db.relationship('Company', backref='reports')
    scan_job = db.relationship('ScanJob', backref='reports')

@login_manager.user_loader
def load_user(user_id):
    return Company.query.get(int(user_id))
