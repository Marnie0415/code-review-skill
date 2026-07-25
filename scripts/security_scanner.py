#!/usr/bin/env python3
"""Security scanner for code files. Detects hardcoded secrets, SQL injection, XSS, and other vulnerabilities."""

import re
import sys
import json
from pathlib import Path

PATTERNS = {
    "CRITICAL": [
        (r'(?:password|passwd|pwd|pass)\s*=\s*["\'][^"\']{4,}["\']', "Hardcoded password"),
        (r'(?:api_key|apikey|api[-_]?secret|access_key)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded API key"),
        (r'(?:secret|token|auth_token|bearer)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded secret/token"),
        (r'(?:aws_access_key_id|aws_secret_access_key|AWS_SECRET)\s*=\s*["\'][^"\']+["\']', "AWS credentials"),
        (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "Private key in source"),
        (r'(?:mysql|postgres|mongodb)://[^"\s]+', "Database connection string with credentials"),
        (r'(?:ghp_|gho_|github_pat_)[A-Za-z0-9_]{36,}', "GitHub personal access token"),
        (r'sk-[A-Za-z0-9]{20,}', "Possible OpenAI/Stripe API key"),
    ],
    "HIGH": [
        (r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*{.*}.*["\']', "SQL injection via f-string"),
        (r'(?:execute|cursor\.execute|query)\s*\(\s*f["\']', "SQL injection via f-string in query"),
        (r'(?:execute|cursor\.execute)\s*\(\s*["\'].*%s', "SQL injection via printf formatting"),
        (r'(?:execute|cursor\.execute)\s*\(\s*["\'].*\+', "SQL injection via string concatenation"),
        (r'eval\s*\([^)]*\)', "Use of eval() - code injection"),
        (r'exec\s*\([^)]*\)', "Use of exec() - code injection"),
        (r'os\.system\s*\(', "Use of os.system() - command injection"),
        (r'subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True', "Shell injection via subprocess"),
        (r'innerHTML\s*=', "XSS via innerHTML assignment"),
        (r'document\.write\s*\(', "XSS via document.write"),
        (r'(?:innerHTML|outerHTML)\s*[+\s]*=', "DOM-based XSS"),
        (r'child_process\.exec\s*\(', "Node.js command injection"),
        (r'__import__\s*\(', "Dynamic import - potential code injection"),
    ],
    "MEDIUM": [
        (r'debug\s*=\s*True', "Debug mode enabled in code"),
        (r'print\s*\(.*(?:password|secret|token|key|credential)', "Sensitive data in print statement"),
        (r'logging\.\w+\(.*(?:password|secret|token|key|credential)', "Sensitive data in log output"),
        (r'http://[a-zA-Z0-9]', "HTTP instead of HTTPS"),
        (r'(?:pickle\.loads?|yaml\.load)\s*\(', "Insecure deserialization"),
        (r'marshal\.loads?\s*\(', "Insecure marshal deserialization"),
        (r'XMLParser.*(?:resolve_entities|no_network)\s*=\s*False', "XXE vulnerability"),
        (r'(?:chmod|chown)\s+0?777', "World-writable permissions"),
        (r'TEMP|TMPDIR|TMP.*\/', "Temp file path in code"),
        (r'assert\s+', "Assertion used for validation (removed in production)"),
    ],
    "LOW": [
        (r'TODO|FIXME|HACK|XXX|WORKAROUND', "TODO/FIXME marker found"),
        (r'except\s*:', "Bare except clause - catches all exceptions"),
        (r'except\s+Exception\s*:', "Broad exception catching"),
        (r'pass\s*$', "Empty except block (swallowed exception)"),
        (r'(?:==|!=)\s*["\'](?:true|false|yes|no|1|0)["\']', "Loose string comparison"),
    ],
}

WHITELIST_PATTERNS = [
    r'test.*password',
    r'mock.*secret',
    r'example.*key',
    r'dummy.*token',
    r'placeholder',
    r'changeme',
    r'your[-_]?here',
    r'xxx',
    r'\*\*\*',
]

def is_whitelisted(line, description):
    """Check if a finding is a known false positive."""
    line_lower = line.lower()
    for pattern in WHITELIST_PATTERNS:
        if re.search(pattern, line_lower):
            return True
    # Whitelist if value is clearly a placeholder
    if any(v in line.lower() for v in ['example', 'sample', 'test', 'mock', 'fake', 'dummy']):
        return True
    return False

def scan_file(filepath, whitelist=True):
    """Scan a single file for security issues."""
    findings = []
    try:
        content = Path(filepath).read_text(encoding="utf-8", errors="ignore")
        lines = content.split("\n")
    except Exception as e:
        return [{"severity": "ERROR", "file": str(filepath), "line": 0, "issue": f"Cannot read file: {e}"}]

    for severity, patterns in PATTERNS.items():
        for pattern, description in patterns:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    if whitelist and is_whitelisted(line, description):
                        continue
                    findings.append({
                        "severity": severity,
                        "file": str(filepath),
                        "line": i,
                        "issue": description,
                        "code": line.strip()[:120],
                    })
    return findings

def scan_directory(dirpath, extensions=None):
    """Scan all files in a directory."""
    if extensions is None:
        extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".rs", ".cs"}

    all_findings = []
    for ext in extensions:
        for filepath in Path(dirpath).rglob(f"*{ext}"):
            if any(skip in str(filepath) for skip in [".git", "node_modules", "__pycache__", ".venv", "venv"]):
                continue
            all_findings.extend(scan_file(filepath))
    return all_findings

def format_report(findings):
    """Format findings as a readable report."""
    if not findings:
        return "## Security Scan Report\n\nNo security issues found."

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "ERROR": 4}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 5))

    report = ["## Security Scan Report"]
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    report.append(f"\n**Total findings**: {len(findings)}")
    report.append(f"**Breakdown**: {', '.join(f'{k}: {v}' for k, v in sorted(counts.items(), key=lambda x: severity_order.get(x[0], 5)))}\n")

    for f in findings:
        report.append(f"### [{f['severity']}] {f['file']}:{f['line']}")
        report.append(f"**Issue**: {f['issue']}")
        if f.get("code"):
            report.append(f"**Code**: `{f['code']}`")
        report.append("")

    return "\n".join(report)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: security_scanner.py <file_or_directory> [--no-whitelist]")
        sys.exit(1)

    target = sys.argv[1]
    whitelist = "--no-whitelist" not in sys.argv
    path = Path(target)

    if path.is_file():
        findings = scan_file(path, whitelist)
    elif path.is_dir():
        findings = scan_directory(path)
    else:
        print(f"Error: {target} not found")
        sys.exit(1)

    print(format_report(findings))

    if any(f["severity"] == "CRITICAL" for f in findings):
        sys.exit(1)
