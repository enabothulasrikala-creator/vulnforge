import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

SECRET_KEY = os.environ.get('SECRET_KEY', 'vulnforge-dev-key-change-in-prod')
SQLALCHEMY_DATABASE_URI = f'sqlite:///{os.path.join(BASE_DIR, "vulnforge.db")}'
SQLALCHEMY_TRACK_MODIFICATIONS = False

SCANS_DIR = os.path.join(BASE_DIR, 'scans')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
AGENTS_DIR = os.path.join(BASE_DIR, 'agents')
OPCODE_CONFIG_DIR = os.path.expanduser('~/.config/opencode')
