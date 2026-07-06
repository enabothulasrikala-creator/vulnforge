from flask import Blueprint, render_template
from flask_login import login_required, current_user
from app.models import Scope, ScanJob, Finding
from app import db

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@login_required
def index():
    scopes = Scope.query.filter_by(company_id=current_user.id).count()
    scan_jobs = ScanJob.query.join(Scope).filter(Scope.company_id == current_user.id)
    total_scans = scan_jobs.count()
    active_scans = scan_jobs.filter(ScanJob.status == 'running').count()
    findings = Finding.query.join(ScanJob).join(Scope).filter(Scope.company_id == current_user.id)

    critical = findings.filter(Finding.severity == 'critical').count()
    high = findings.filter(Finding.severity == 'high').count()
    medium = findings.filter(Finding.severity == 'medium').count()
    low = findings.filter(Finding.severity == 'low').count()

    recent_findings = findings.order_by(Finding.created_at.desc()).limit(5).all()

    return render_template('dashboard.html',
        scopes=scopes, total_scans=total_scans,
        active_scans=active_scans,
        critical=critical, high=high, medium=medium, low=low,
        recent_findings=recent_findings)
