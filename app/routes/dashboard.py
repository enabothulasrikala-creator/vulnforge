from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from app.models import Scope, ScanJob, Finding
from app import db
from app.utils.scanner import scan_scope
import threading

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        scope_id = request.form.get('scope_id')
        if scope_id:
            thread = threading.Thread(target=scan_scope, args=(int(scope_id),), daemon=True)
            thread.start()
            flash('Scan started!')
            return redirect(url_for('scope.detail', id=scope_id))
        flash('No scope specified')
        return redirect(url_for('dashboard.index'))
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
