import re

SEVERITY_ORDER = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}

CVSS_MAP = {
    'critical': 9.5,
    'high': 7.5,
    'medium': 5.5,
    'low': 2.5,
    'info': 0.0,
}

def deduplicate(findings):
    seen = set()
    unique = []
    for f in findings:
        key = f"{f.get('title', '')}|{f.get('url', '')}|{f.get('description', '')[:100]}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique

def enrich_severity(findings):
    for f in findings:
        title = f.get('title', '').lower()
        desc = f.get('description', '').lower()

        existing = f.get('severity', 'info')
        if existing != 'info' and existing in SEVERITY_ORDER:
            continue

        critical_keywords = ['rce', 'remote code', 'sql injection', 'sqli', 'authentication bypass',
                            'auth bypass', 'privilege escalation', 'privesc', 'deserialization',
                            'command injection', 'file upload', 'ssrf', 'xxe']
        high_keywords = ['xss', 'cross-site', 'csrf', 'idor', 'path traversal', 'lfi',
                        'information disclosure', 'open redirect', 'subdomain takeover',
                        'idor', 'broken access', 'ssti', 'template injection']
        medium_keywords = ['misconfiguration', 'missing header', 'cors', 'clickjacking',
                          'verbose error', 'directory listing', 'weak password', 'default credential']

        for kw in critical_keywords:
            if kw in title or kw in desc:
                f['severity'] = 'critical'
                break
        else:
            for kw in high_keywords:
                if kw in title or kw in desc:
                    f['severity'] = 'high'
                    break
            else:
                for kw in medium_keywords:
                    if kw in title or kw in desc:
                        f['severity'] = 'medium'
                        break

        f['cvss'] = CVSS_MAP.get(f.get('severity', 'info'), 0.0)

    return findings

def categorize_tool(findings):
    for f in findings:
        title = f.get('title', '').lower()
        if not f.get('tool'):
            if 'cve-' in title or 'nuclei' in f.get('evidence', '') or 'template' in f.get('evidence', ''):
                f['tool'] = 'nuclei'
            elif 'nmap' in f.get('evidence', ''):
                f['tool'] = 'nmap'
            elif 'subdomain' in title:
                f['tool'] = 'subfinder'
            else:
                f['tool'] = 'manual'
    return findings

def analyze_findings(findings):
    if not findings:
        return []
    findings = deduplicate(findings)
    findings = categorize_tool(findings)
    findings = enrich_severity(findings)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get('severity', 'info'), 0), reverse=True)
    return findings
