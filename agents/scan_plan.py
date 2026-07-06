PLAN_TEMPLATE = """## Scan Plan

### Target
{target}

### Exclusions
{exclusions}

### Rate Limit
{rate_limit} req/s

### Phases
1. **Recon** (subfinder + dnsx) — find all subdomains, DNS records
2. **Discovery** (httpx) — find live hosts
3. **Port Scan** (nmap) — identify open ports and services
4. **Vulnerability Scan** (nuclei) — run all templates against live hosts
5. **Deep Scan** — fuzz endpoints, check for common vulns

### Rules
- Only scan targets within scope
- Respect excluded paths
- Apply rate limiting
- Report all findings with severity

### Output
Per finding: TITLE | SEVERITY | URL | DESCRIPTION | EVIDENCE | REMEDIATION
"""

def generate_plan(scope):
    exclusions = scope.excluded_paths if scope.excluded_paths else 'None'
    return PLAN_TEMPLATE.format(
        target=scope.target_url,
        exclusions=exclusions,
        rate_limit=scope.rate_limit or 10,
    )
