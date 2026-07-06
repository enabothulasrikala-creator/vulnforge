from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import os

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'auth.login'

def create_app():
    app = Flask(__name__)
    app.config.from_object('config')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "vulnforge.db")}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'vulnforge-dev-key-change-in-prod'

    db.init_app(app)
    login_manager.init_app(app)

    with app.app_context():
        from app import models
        db.create_all()

    from app.routes.auth import auth_bp
    from app.routes.scope import scope_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.findings import findings_bp
    from app.routes.reports import reports_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(scope_bp, url_prefix='/scope')
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
    app.register_blueprint(findings_bp, url_prefix='/findings')
    app.register_blueprint(reports_bp, url_prefix='/reports')

    @app.route('/')
    def index():
        from flask import redirect
        return redirect('/dashboard')

    return app
