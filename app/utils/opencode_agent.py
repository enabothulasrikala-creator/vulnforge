import subprocess
import json
import os
import sys
import tempfile

OPCODE_DIR = os.path.expanduser('~/.config/opencode')

AGENT_TYPES = {
    'recon': 'dns-recon',
    'explore': 'explore',
    'general': 'general',
}

def run_opencode_agent(agent_type, prompt, timeout=300):
    agent = AGENT_TYPES.get(agent_type, 'general')

    prompt_file = tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False)
    prompt_file.write(prompt)
    prompt_file_path = prompt_file.name
    prompt_file.close()

    try:
        npx_path = os.path.expanduser('~/.config/nvm/versions/node/v24.15.0/bin/npx')
        if not os.path.exists(npx_path):
            npx_path = 'npx'

        cmd = [
            npx_path, '-y', 'opencode',
            '--subagent', agent,
            '--message', f'@tasks/{os.path.basename(prompt_file_path)}',
        ]

        env = os.environ.copy()
        env['OPCODE_DIR'] = OPCODE_DIR

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            cwd=os.path.expanduser('~')
        )

        return {
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {'stdout': '', 'stderr': 'TIMEOUT', 'returncode': -1}
    except FileNotFoundError:
        return {'stdout': '', 'stderr': 'opencode CLI not found', 'returncode': -1}
    finally:
        os.unlink(prompt_file_path)

def create_scan_plan(target, excluded_paths, policy):
    return f"""## Scan Plan for {target}

### Scope
- Target: {target}
- Excluded paths: {excluded_paths or 'None'}
- Policy constraints: {policy or 'None'}

### Phases
1. **Reconnaissance** - Find subdomains, DNS records, live hosts
2. **Surface Discovery** - Find all endpoints, parameters, JS files
3. **Vulnerability Scanning** - Run nuclei templates, port scan
4. **Analysis** - Analyze results, deduplicate, assign severity
5. **Reporting** - Generate findings report

### Rules
- Stay within scope: {target}
- DO NOT scan excluded paths: {excluded_paths or 'None'}
- Respect rate limits
- Log all findings with evidence
"""

def run_recon_agent(target):
    prompt = f"""Perform reconnaissance on {target}.
1. Find subdomains using subfinder
2. Check DNS records using dnsx
3. Find live hosts using httpx
4. Return all discovered assets as a list

Rules: Use tools at ~/.local/bin/subfinder, /usr/local/bin/dnsx, ~/.local/bin/httpx
Output format: One asset per line, prefixed with type (subdomain/dns/live)
"""
    return run_opencode_agent('recon', prompt)

def run_scan_agent(target, findings_file):
    prompt = f"""Perform vulnerability scanning on {target}.
1. Run nuclei vulnerability scanner
2. Check for:
   - Critical: RCE, SQLi, Auth bypass, SSRF
   - High: XSS, LFI, IDOR, Subdomain takeover
   - Medium: Misconfigurations, Missing headers
3. Save all findings with severity, URL, description, evidence, and remediation

Rules:
- Use /usr/local/bin/nuclei for scanning
- Use JSON output format
- Do NOT scan targets outside scope

Output format per finding:
TITLE: <title>
SEVERITY: <critical|high|medium|low|info>
URL: <url>
DESCRIPTION: <description>
EVIDENCE: <evidence>
REMEDIATION: <remediation>
---
"""
    return run_opencode_agent('explore', prompt)
