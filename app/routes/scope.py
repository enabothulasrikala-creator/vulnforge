from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from app.models import Scope, ScanJob
from app import db
from datetime import datetime

scope_bp = Blueprint('scope', __name__)

@scope_bp.route('/new', methods=['GET', 'POST'])
@login_required
def new():
    if request.method == 'POST':
        scope = Scope(
            company_id=current_user.id,
            name=request.form.get('name'),
            target_url=request.form.get('target_url'),
            ip_ranges=request.form.get('ip_ranges', ''),
            excluded_paths=request.form.get('excluded_paths', ''),
            rate_limit=int(request.form.get('rate_limit', 10)),
            policy_rules=request.form.get('policy_rules', '')
        )
        db.session.add(scope)
        db.session.commit()
        flash('Scope created successfully')
        return redirect(url_for('scope.detail', id=scope.id))
    return render_template('scope_form.html')

@scope_bp.route('/<int:id>')
@login_required
def detail(id):
    scope = Scope.query.filter_by(id=id, company_id=current_user.id).first_or_404()
    scan_jobs = ScanJob.query.filter_by(scope_id=scope.id).order_by(ScanJob.created_at.desc()).all()
    return render_template('scope_detail.html', scope=scope, scan_jobs=scan_jobs)

@scope_bp.route('/list')
@login_required
def list_scopes():
    scopes = Scope.query.filter_by(company_id=current_user.id).order_by(Scope.created_at.desc()).all()
    return render_template('scope_list.html', scopes=scopes)

@scope_bp.route('/<int:id>/delete', methods=['POST'])
@login_required
def delete(id):
    scope = Scope.query.filter_by(id=id, company_id=current_user.id).first_or_404()
    db.session.delete(scope)
    db.session.commit()
    flash('Scope deleted')
    return redirect(url_for('scope.list_scopes'))
