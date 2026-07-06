from flask import Blueprint, render_template, send_file, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app.models import Finding, ScanJob, Scope, Report
from app import db
from app.utils.report_gen import generate_report
from datetime import datetime
import os

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/')
@login_required
def list_reports():
    reports = Report.query.filter_by(company_id=current_user.id).order_by(Report.generated_at.desc()).all()
    return render_template('reports.html', reports=reports)

@reports_bp.route('/generate', methods=['GET', 'POST'])
@login_required
def generate():
    if request.method == 'POST':
        scan_job_id = request.form.get('scan_job_id', type=int)
        report_format = request.form.get('format', 'markdown')

        findings_query = Finding.query.join(ScanJob).join(Scope).filter(Scope.company_id == current_user.id)
        scan_job = None

        if scan_job_id:
            findings_query = findings_query.filter(Finding.scan_job_id == scan_job_id)
            scan_job = ScanJob.query.filter_by(id=scan_job_id).first()

        findings = findings_query.all()
        if not findings:
            flash('No findings to report')
            return redirect(url_for('reports.generate'))

        scope = Scope.query.filter_by(company_id=current_user.id).first()
        report_data = {
            'company_name': current_user.name,
            'generated_at': datetime.utcnow().isoformat(),
            'scope': scope,
            'scan_job': scan_job,
            'findings': findings,
            'critical': sum(1 for f in findings if f.severity == 'critical'),
            'high': sum(1 for f in findings if f.severity == 'high'),
            'medium': sum(1 for f in findings if f.severity == 'medium'),
            'low': sum(1 for f in findings if f.severity == 'low'),
        }

        file_path = generate_report(report_data, report_format)
        report = Report(
            company_id=current_user.id,
            scan_job_id=scan_job.id if scan_job else None,
            summary=f"Report with {len(findings)} findings",
            file_path=file_path,
            format=report_format
        )
        db.session.add(report)
        db.session.commit()

        return redirect(url_for('reports.list_reports'))

    scan_jobs = ScanJob.query.join(Scope).filter(Scope.company_id == current_user.id).order_by(ScanJob.created_at.desc()).all()
    return render_template('report_generate.html', scan_jobs=scan_jobs)

@reports_bp.route('/<int:id>/download')
@login_required
def download(id):
    report = Report.query.filter_by(id=id, company_id=current_user.id).first_or_404()
    if report.file_path and os.path.exists(report.file_path):
        return send_file(report.file_path, as_attachment=True)
    flash('Report file not found')
    return redirect(url_for('reports.list_reports'))
