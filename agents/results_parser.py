import re

def parse_tool_output(tool_name, output, target):
    findings = []
    output = output or ''

    if tool_name == 'nuclei':
        import json
        for line in output.splitlines():
            try:
                data = json.loads(line)
                findings.append({
                    'title': data.get('info', {}).get('name', 'Unknown'),
                    'severity': data.get('info', {}).get('severity', 'info'),
                    'description': data.get('info', {}).get('description', ''),
                    'url': data.get('matched-at', ''),
                    'tool': 'nuclei',
                    'evidence': line[:500],
                    'remediation': data.get('info', {}).get('remediation', ''),
                })
            except (json.JSONDecodeError, AttributeError):
                continue

    elif tool_name in ('nmap', 'ports'):
        current_host = ''
        for line in output.splitlines():
            if m := re.search(r'Nmap scan report for (.+)', line):
                current_host = m.group(1)
            if m := re.search(r'(\d+)/tcp\s+open\s+(\S+)\s+(.*)', line):
                port = m.group(1)
                service = m.group(2)
                version = m.group(3).strip()
                findings.append({
                    'title': f'Open Port: {port}/{service}',
                    'severity': 'info',
                    'description': f'Port {port} ({service}) is open on {current_host}. Version: {version}',
                    'url': f'{current_host}:{port}',
                    'tool': 'nmap',
                    'evidence': line.strip(),
                    'remediation': f'Review if port {port}/{service} needs to be exposed.',
                })

    elif tool_name == 'opencode':
        current = {}
        for line in output.splitlines():
            if line.startswith('TITLE:'):
                if current.get('title'):
                    findings.append(current)
                current = {'title': line[6:].strip(), 'tool': 'opencode'}
            elif line.startswith('SEVERITY:'):
                current['severity'] = line[9:].strip().lower()
            elif line.startswith('URL:'):
                current['url'] = line[4:].strip()
            elif line.startswith('DESCRIPTION:'):
                current['description'] = line[12:].strip()
            elif line.startswith('EVIDENCE:'):
                current['evidence'] = line[9:].strip()
            elif line.startswith('REMEDIATION:'):
                current['remediation'] = line[12:].strip()
            elif line.strip() == '---' and current.get('title'):
                findings.append(current)
                current = {}
        if current.get('title'):
            findings.append(current)

    return findings

def parse_subdomain_list(output):
    subdomains = []
    for line in (output or '').splitlines():
        line = line.strip()
        if line and not line.startswith('[') and not line.startswith('#'):
            subdomains.append(line)
    return subdomains
