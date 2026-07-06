import re

def parse_scope_target(target_url):
    target_url = target_url.strip()
    if not target_url.startswith(('http://', 'https://')):
        target_url = f'https://{target_url}'
    domain = re.sub(r'https?://', '', target_url).split('/')[0]
    domain = domain.split(':')[0]
    return target_url, domain

def parse_ip_ranges(ip_ranges_text):
    ranges = []
    for line in ip_ranges_text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        ranges.append(line)
    return ranges

def parse_excluded_paths(excluded_text):
    paths = []
    for line in excluded_text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        paths.append(line)
    return paths

def build_nuclei_exclude(excluded_paths):
    if not excluded_paths:
        return ''
    excludes = []
    for path in excluded_paths:
        path = path.strip()
        if path:
            excludes.append(f"-exc '{path}'")
    return ' '.join(excludes)

def policy_to_openai_prompt(scope):
    prompt = f"""You are scanning: {scope.target_url}

## Scope Rules
- Target: {scope.target_url}
- Rate limit: {scope.rate_limit} requests/second
"""
    if scope.excluded_paths:
        prompt += f"- Excluded paths: {scope.excluded_paths}\n"
    if scope.policy_rules:
        prompt += f"- Policy: {scope.policy_rules}\n"
    return prompt
