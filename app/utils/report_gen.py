import os
import csv
from datetime import datetime

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'reports')

def generate_markdown_report(data):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'report_{timestamp}.md'
    filepath = os.path.join(REPORTS_DIR, filename)

    with open(filepath, 'w') as f:
        f.write(f'# Vulnerability Report: {data["company_name"]}\n\n')
        f.write(f'**Generated:** {data["generated_at"]}\n\n')
        if data.get('scope'):
            f.write(f'**Target:** {data["scope"].target_url}\n')
            f.write(f'**Scope:** {data["scope"].name}\n\n')

        f.write('## Executive Summary\n\n')
        f.write(f'- **Total Findings:** {len(data["findings"])}\n')
        f.write(f'- **Critical:** {data["critical"]}\n')
        f.write(f'- **High:** {data["high"]}\n')
        f.write(f'- **Medium:** {data["medium"]}\n')
        f.write(f'- **Low:** {data["low"]}\n\n')

        if data['findings']:
            f.write('## Findings by Severity\n\n')

            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                sev_findings = [f for f in data['findings'] if f.severity == severity]
                if not sev_findings:
                    continue

                f.write(f'### {severity.upper()}\n\n')
                for idx, finding in enumerate(sev_findings, 1):
                    f.write(f'#### {idx}. {finding.title}\n\n')
                    f.write(f'- **URL:** {finding.url}\n')
                    f.write(f'- **Tool:** {finding.tool}\n')
                    f.write(f'- **CVSS:** {finding.cvss_score}\n')
                    f.write(f'- **Status:** {finding.status}\n\n')
                    f.write(f'**Description:**\n{finding.description}\n\n')
                    if finding.remediation:
                        f.write(f'**Remediation:**\n{finding.remediation}\n\n')
                    if finding.evidence:
                        f.write(f'**Evidence:**\n```\n{finding.evidence[:500]}\n```\n\n')
                    f.write('---\n\n')

    return filepath

def generate_csv_report(data):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'report_{timestamp}.csv'
    filepath = os.path.join(REPORTS_DIR, filename)

    with open(filepath, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Title', 'Severity', 'CVSS', 'URL', 'Tool', 'Description', 'Remediation', 'Status'])
        for finding in data['findings']:
            writer.writerow([
                finding.title,
                finding.severity,
                finding.cvss_score,
                finding.url,
                finding.tool,
                finding.description,
                finding.remediation,
                finding.status,
            ])

    return filepath

def generate_json_report(data):
    import json
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'report_{timestamp}.json'
    filepath = os.path.join(REPORTS_DIR, filename)

    report = {
        'company': data['company_name'],
        'generated_at': data['generated_at'],
        'summary': {
            'total': len(data['findings']),
            'critical': data['critical'],
            'high': data['high'],
            'medium': data['medium'],
            'low': data['low'],
        },
        'findings': [{
            'title': f.title,
            'severity': f.severity,
            'cvss': f.cvss_score,
            'url': f.url,
            'tool': f.tool,
            'description': f.description,
            'remediation': f.remediation,
            'evidence': f.evidence[:500] if f.evidence else '',
        } for f in data['findings']]
    }

    with open(filepath, 'w') as f:
        json.dump(report, f, indent=2)

    return filepath

GENERATORS = {
    'markdown': generate_markdown_report,
    'csv': generate_csv_report,
    'json': generate_json_report,
}

def generate_report(data, fmt='markdown'):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    generator = GENERATORS.get(fmt, generate_markdown_report)
    return generator(data)
