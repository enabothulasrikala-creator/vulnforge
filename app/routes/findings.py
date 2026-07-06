from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
from app.models import Finding, ScanJob, Scope

findings_bp = Blueprint('findings', __name__)

@findings_bp.route('/')
@login_required
def list_findings():
    severity = request.args.get('severity')
    status = request.args.get('status')
    scope_id = request.args.get('scope_id', type=int)

    query = Finding.query.join(ScanJob).join(Scope).filter(Scope.company_id == current_user.id)

    if severity:
        query = query.filter(Finding.severity == severity)
    if status:
        query = query.filter(Finding.status == status)
    if scope_id:
        query = query.filter(Scope.id == scope_id)

    findings = query.order_by(Finding.created_at.desc()).all()
    scopes = Scope.query.filter_by(company_id=current_user.id).all()

    return render_template('findings.html', findings=findings, scopes=scopes)

@findings_bp.route('/<int:id>')
@login_required
def detail(id):
    finding = Finding.query.join(ScanJob).join(Scope)\
        .filter(Finding.id == id, Scope.company_id == current_user.id).first_or_404()
    return render_template('finding_detail.html', finding=finding)
