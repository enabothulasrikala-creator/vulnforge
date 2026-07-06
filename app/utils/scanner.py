import subprocess
import json
import os
import re
from datetime import datetime
from app import db
from app.models import ScanJob, Finding, Scope
from app.utils.analyzer import analyze_findings

SCANS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'scans')

TOOL_PATHS = {
    'nuclei': '/usr/local/bin/nuclei',
    'httpx': '/home/sricharansiddu29/.local/bin/httpx',
    'subfinder': '/home/sricharansiddu29/.local/bin/subfinder',
    'katana': '/usr/local/bin/katana',
    'ffuf': '/usr/bin/ffuf',
    'nmap': '/usr/bin/nmap',
    'dnsx': '/usr/local/bin/dnsx',
    'sqlmap': '/usr/bin/sqlmap',
}

def run_command(cmd, timeout=300):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return '', 'TIMEOUT', -1
    except FileNotFoundError:
        return '', f'Tool not found: {cmd[0]}', -1

def parse_nuclei_output(output):
    findings = []
    for line in output.splitlines():
        try:
            data = json.loads(line)
            findings.append({
                'title': data.get('info', {}).get('name', 'Unknown'),
                'severity': data.get('info', {}).get('severity', 'info'),
                'description': data.get('info', {}).get('description', ''),
                'url': data.get('matched-at', ''),
                'tool': 'nuclei',
                'evidence': line,
                'remediation': data.get('info', {}).get('remediation', ''),
            })
        except json.JSONDecodeError:
            continue
    return findings

def parse_nmap_output(output):
    findings = []
    current_host = ''
    for line in output.splitlines():
        if match := re.search(r'Nmap scan report for (.+)', line):
            current_host = match.group(1)
        if match := re.search(r'(\d+)/tcp\s+open\s+(\S+)\s+(.*)', line):
            port = match.group(1)
            service = match.group(2)
            version = match.group(3).strip()
            findings.append({
                'title': f'Open Port: {port}/{service}',
                'severity': 'info',
                'description': f'Port {port} ({service}) is open on {current_host}. Version: {version}',
                'url': f'{current_host}:{port}',
                'tool': 'nmap',
                'evidence': line.strip(),
                'remediation': f'Review if port {port}/{service} needs to be exposed. Restrict access if not required.',
            })
    return findings

def run_nuclei_scan(target, scan_dir):
    nuclei = TOOL_PATHS.get('nuclei')
    if not os.path.exists(nuclei):
        return [], 'nuclei not installed'
    outfile = os.path.join(scan_dir, 'nuclei_output.json')
    cmd = [nuclei, '-u', target, '-json', '-o', outfile, '-silent']
    stdout, stderr, rc = run_command(cmd, timeout=600)
    findings = []
    if os.path.exists(outfile):
        with open(outfile) as f:
            findings = parse_nuclei_output(f.read())
    return findings, stderr if rc != 0 else ''

def run_nmap_scan(target, scan_dir):
    nmap = TOOL_PATHS.get('nmap')
    if not os.path.exists(nmap):
        return [], 'nmap not installed'
    outfile = os.path.join(scan_dir, 'nmap_output.txt')
    target_ip = target.replace('https://', '').replace('http://', '').split('/')[0]
    cmd = [nmap, '-sV', '-T4', '-F', target_ip, '-oN', outfile]
    stdout, stderr, rc = run_command(cmd, timeout=600)
    if os.path.exists(outfile):
        with open(outfile) as f:
            findings = parse_nmap_output(f.read())
    return findings, stderr if rc != 0 else ''

def run_subfinder_scan(target, scan_dir):
    subfinder = TOOL_PATHS.get('subfinder')
    if not os.path.exists(subfinder):
        return [], 'subfinder not installed'
    outfile = os.path.join(scan_dir, 'subdomains.txt')
    cmd = [subfinder, '-d', target, '-o', outfile, '-silent']
    stdout, stderr, rc = run_command(cmd, timeout=300)
    subdomains = []
    if os.path.exists(outfile):
        with open(outfile) as f:
            subdomains = [line.strip() for line in f if line.strip()]
    return subdomains, stderr if rc != 0 else ''

def run_httpx_scan(subdomains, scan_dir):
    httpx = TOOL_PATHS.get('httpx')
    if not os.path.exists(httpx) or not subdomains:
        return []
    sublist = os.path.join(scan_dir, 'subdomains.txt')
    outfile = os.path.join(scan_dir, 'live_hosts.txt')
    cmd = [httpx, '-l', sublist, '-o', outfile, '-silent']
    stdout, stderr, rc = run_command(cmd, timeout=300)
    live_hosts = []
    if os.path.exists(outfile):
        with open(outfile) as f:
            live_hosts = [line.strip() for line in f if line.strip()]
    return live_hosts

def run_dnsx_scan(target, scan_dir):
    dnsx = TOOL_PATHS.get('dnsx')
    if not os.path.exists(dnsx):
        return []
    outfile = os.path.join(scan_dir, 'dns_records.txt')
    cmd = [dnsx, '-d', target, '-a', '-aaaa', '-cname', '-mx', '-ns', '-txt', '-o', outfile, '-silent']
    stdout, stderr, rc = run_command(cmd, timeout=300)
    records = []
    if os.path.exists(outfile):
        with open(outfile) as f:
            records = [line.strip() for line in f if line.strip()]
    findings = []
    for record in records:
        findings.append({
            'title': f'DNS Record: {record}',
            'severity': 'info',
            'description': f'DNS record found: {record}',
            'url': '',
            'tool': 'dnsx',
            'evidence': record,
            'remediation': '',
        })
    return findings

def run_lostfuzzer(target, scan_dir):
    fuzzer_script = os.path.expanduser('~/scripts/lostfuzzer.sh')
    if not os.path.exists(fuzzer_script):
        return [], 'lostfuzzer not found'
    outfile = os.path.join(scan_dir, 'lostfuzzer_output.txt')
    cmd = ['bash', fuzzer_script, target]
    stdout, stderr, rc = run_command(cmd, timeout=600)
    with open(outfile, 'w') as f:
        f.write(stdout)
    findings = []
    for line in stdout.splitlines():
        if '[critical]' in line.lower() or '[high]' in line.lower() or '[medium]' in line.lower():
            findings.append({
                'title': f'Fuzzer Finding: {line.strip()[:100]}',
                'severity': 'high' if '[critical]' in line.lower() else 'medium',
                'description': line.strip(),
                'url': '',
                'tool': 'lostfuzzer',
                'evidence': line.strip(),
                'remediation': 'Investigate the identified vulnerability',
            })
    return findings, stderr if rc != 0 else ''

SCANNERS = {
    'subdomain': run_subfinder_scan,
    'dns': run_dnsx_scan,
    'ports': run_nmap_scan,
    'vulns': run_nuclei_scan,
    'fuzzer': run_lostfuzzer,
}

SCAN_ORDER = ['subdomain', 'dns', 'ports', 'vulns', 'fuzzer']

def scan_scope(scope_id):
    scope = Scope.query.get(scope_id)
    if not scope:
        return

    scan_job = ScanJob(scope_id=scope_id, status='running', started_at=datetime.utcnow())
    db.session.add(scan_job)
    db.session.commit()

    target = scope.target_url
    domain = target.replace('https://', '').replace('http://', '').split('/')[0]
    scan_dir = os.path.join(SCANS_DIR, f'scan_{scan_job.id}')
    os.makedirs(scan_dir, exist_ok=True)

    all_findings = []
    errors = []

    for scan_type in SCAN_ORDER:
        if scan_type == 'subdomain':
            subdomains, err = SCANNERS[scan_type](domain, scan_dir)
            if subdomains:
                live_hosts = run_httpx_scan(subdomains, scan_dir)
                for host in live_hosts:
                    host_vulns, verr = run_nuclei_scan(host, scan_dir)
                    all_findings.extend(host_vulns)
                    if verr:
                        errors.append(verr)
            if err:
                errors.append(err)
        else:
            findings, err = SCANNERS[scan_type](target, scan_dir)
            all_findings.extend(findings)
            if err:
                errors.append(err)

    all_findings = analyze_findings(all_findings)

    for fdata in all_findings:
        finding = Finding(
            scan_job_id=scan_job.id,
            title=fdata.get('title', 'Unknown'),
            severity=fdata.get('severity', 'info'),
            cvss_score=fdata.get('cvss', 0.0),
            description=fdata.get('description', ''),
            url=fdata.get('url', ''),
            tool=fdata.get('tool', 'manual'),
            evidence=fdata.get('evidence', ''),
            remediation=fdata.get('remediation', ''),
            status='open'
        )
        db.session.add(finding)

    scan_job.status = 'completed' if not errors else 'completed_with_errors'
    scan_job.completed_at = datetime.utcnow()
    scan_job.error = '\n'.join(errors[:10]) if errors else None
    db.session.commit()
