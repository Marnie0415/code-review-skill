#!/usr/bin/env python3
"""Security scanner for code files. Detects hardcoded secrets, SQL injection, XSS, and other vulnerabilities."""

import re
import sys
import json
from pathlib import Path

PATTERNS = {
    "CRITICAL": [
        (r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']+["\']', "Hardcoded password"),
        (r'(?:api_key|apikey|api[-_]?secret)\s*=\s*["\'][^"\']+["\']', "Hardcoded API key"),
        (r'(?:secret|token)\s*=\s*["\'][^"\']+["\']', "Hardcoded secret/token"),
        (r'(?:aws_access_key_id|aws_secret_access_key)\s*=\s*["\'][^"\']+["\']', "AWS credentials"),
        (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "Private key in source"),
    ],
    "HIGH": [
        (r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*{.*}.*["\']', "SQL injection via f-string"),
        (r'(?:execute|cursor\.execute)\s*\(\s*f["\']', "SQL injection via f-string in execute"),
        (r'(?:execute|cursor\.execute)\s*\(\s*["\'].*%s', "SQL injection via % formatting"),
        (r'eval\s*\(', "Use of eval() - code injection risk"),
        (r'exec\s*\(', "Use of exec() - code injection risk"),
        (r'os\.system\s*\(', "Use of os.system() - command injection"),
        (r'subprocess\.call.*shell\s*=\s*True', "Shell injection via subprocess"),
        (r'innerHTML\s*=', "XSS via innerHTML"),
        (r'document\.write\s*\(', "XSS via document.write"),
    ],
    "MEDIUM": [
        (r'debug\s*=\s*True', "Debug mode enabled"),
        (r'print\s*\(.*(?:password|secret|token|key)', "Sensitive data in print statement"),
        (r'logging\.\w+\(.*(?:password|secret|token|key)', "Sensitive data in log"),
        (r'http://', "HTTP instead of HTTPS"),
        (r'(?:pickle\.loads?|yaml\.load)\s*\(', "Insecure deserialization"),
    ],
    "LOW": [
        (r'TODO|FIXME|HACK|XXX', "TODO/FIXME marker found"),
        (r'except\s*:', "Bare except clause"),
        (r'except\s+Exception\s*:', "Broad exception catching"),
    ],
}

def scan_file(filepath):
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
                    findings.append({
                        "severity": severity,
                        "file": str(filepath),
                        "line": i,
                        "issue": description,
                        "code": line.strip()[:100],
                    })
    return findings

def scan_directory(dirpath, extensions=None):
    """Scan all files in a directory."""
    if extensions is None:
        extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".rs"}

    all_findings = []
    for ext in extensions:
        for filepath in Path(dirpath).rglob(f"*{ext}"):
            if ".git" in str(filepath) or "node_modules" in str(filepath):
                continue
            all_findings.extend(scan_file(filepath))
    return all_findings

def format_report(findings):
    """Format findings as a readable report."""
    if not findings:
        return "No security issues found."

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "ERROR": 4}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 5))

    report = []
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    report.append(f"## Security Scan Report")
    report.append(f"\n**Total findings**: {len(findings)}")
    report.append(f"**Severity breakdown**: {', '.join(f'{k}: {v}' for k, v in counts.items())}\n")

    for f in findings:
        report.append(f"### [{f['severity']}] {f['file']}:{f['line']}")
        report.append(f"**Issue**: {f['issue']}")
        if f.get("code"):
            report.append(f"**Code**: `{f['code']}`")
        report.append("")

    return "\n".join(report)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: security_scanner.py <file_or_directory>")
        sys.exit(1)

    target = sys.argv[1]
    path = Path(target)

    if path.is_file():
        findings = scan_file(path)
    elif path.is_dir():
        findings = scan_directory(path)
    else:
        print(f"Error: {target} not found")
        sys.exit(1)

    print(format_report(findings))

    if any(f["severity"] == "CRITICAL" for f in findings):
        sys.exit(1)
