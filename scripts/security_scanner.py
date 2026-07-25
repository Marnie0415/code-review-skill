#!/usr/bin/env python3
"""Security scanner with language-specific analysis and context awareness."""

import re
import sys
import json
from pathlib import Path
from collections import defaultdict

PATTERNS = {
    "CRITICAL": [
        (r'(?:password|passwd|pwd|pass)\s*=\s*["\'][^"\']{4,}["\']', "Hardcoded password"),
        (r'(?:api_key|apikey|api[-_]?secret|access_key)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded API key"),
        (r'(?:secret|token|auth_token|bearer)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded secret/token"),
        (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "Private key in source"),
        (r'(?:ghp_|gho_|github_pat_)[A-Za-z0-9_]{36,}', "GitHub token"),
        (r'sk-[A-Za-z0-9]{20,}', "Possible API key"),
    ],
    "HIGH": [
        (r'(?:execute|cursor\.execute|query)\s*\(\s*f["\']', "SQL injection via f-string"),
        (r'(?:execute|cursor\.execute)\s*\(\s*["\'].*%s', "SQL injection via printf"),
        (r'eval\s*\([^)]*\)', "Use of eval()"),
        (r'exec\s*\([^)]*\)', "Use of exec()"),
        (r'os\.system\s*\(', "Use of os.system()"),
        (r'subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True', "Shell injection"),
        (r'innerHTML\s*=', "XSS via innerHTML"),
        (r'document\.write\s*\(', "XSS via document.write"),
        (r'child_process\.exec\s*\(', "Node.js command injection"),
    ],
    "MEDIUM": [
        (r'debug\s*=\s*True', "Debug mode enabled"),
        (r'print\s*\(.*(?:password|secret|token)', "Sensitive data in print"),
        (r'logging\.\w+\(.*(?:password|secret|token)', "Sensitive data in log"),
        (r'http://[a-zA-Z0-9]', "HTTP instead of HTTPS"),
        (r'(?:pickle\.loads?|yaml\.load)\s*\(', "Insecure deserialization"),
        (r'assert\s+', "Assertion used for validation"),
    ],
    "LOW": [
        (r'TODO|FIXME|HACK|XXX', "TODO marker"),
        (r'except\s*:', "Bare except clause"),
        (r'except\s+Exception\s*:', "Broad exception"),
    ],
}

LANGUAGE_SPECIFIC = {
    "python": {
        "HIGH": [
            (r'pickle\.loads?\s*\(', "Insecure pickle deserialization"),
            (r'yaml\.load\s*\([^)]*\)', "Unsafe yaml.load (use safe_load)"),
            (r'tempfile\.mktemp\s*\(', "Insecure temp file (use mkstemp)"),
            (r'subprocess\.call\s*\(\s*["\']', "Shell command via string"),
        ],
        "MEDIUM": [
            (r'from\s+os\s+import\s+\*', "Wildcard import from os"),
            (r'except\s*:\s*pass', "Swallowed exception"),
            (r'global\s+', "Global variable usage"),
        ],
    },
    "javascript": {
        "HIGH": [
            (r'innerHTML\s*\+', "DOM XSS via concatenation"),
            (r'outerHTML\s*=', "DOM XSS via outerHTML"),
            (r'location\s*=\s*[^h]', "Open redirect"),
            (r'postMessage\s*\(', "postMessage without origin check"),
        ],
        "MEDIUM": [
            (r'console\.log\s*\(.*(?:password|secret|token)', "Sensitive data in console"),
            (r'localStorage\.setItem\s*\(', "Sensitive data in localStorage"),
        ],
    },
    "java": {
        "HIGH": [
            (r'ObjectInputStream\s*\(', "Insecure deserialization"),
            (r'Runtime\.getRuntime\(\)\.exec', "Command injection"),
            (r'ServletRequest\.getParameter', "Unvalidated user input"),
        ],
        "MEDIUM": [
            (r'printStackTrace\s*\(', "Stack trace exposure"),
            (r'System\.out\.print', "Information disclosure"),
        ],
    },
    "go": {
        "HIGH": [
            (r'exec\.Command\s*\(', "Command injection"),
            (r'template\.HTML\s*\(', "Unescaped HTML (XSS)"),
            (r'http\.ListenAndServe\s*\(', "HTTP without TLS"),
        ],
        "MEDIUM": [
            (r'fmt\.Print\s*\(', "Potential information disclosure"),
        ],
    },
}

WHITELIST_PATTERNS = [
    r'test', r'mock', r'example', r'sample', r'dummy', r'placeholder',
    r'changeme', r'xxx', r'\*\*\*', r'fake', r'stub',
]

def detect_language(filepath):
    ext = Path(filepath).suffix.lower()
    lang_map = {
        ".py": "python", ".js": "javascript", ".ts": "javascript",
        ".jsx": "javascript", ".tsx": "javascript",
        ".java": "java", ".go": "go",
    }
    return lang_map.get(ext, "unknown")

def is_whitelisted(line):
    line_lower = line.lower()
    for pattern in WHITELIST_PATTERNS:
        if re.search(pattern, line_lower):
            return True
    return False

def check_context(lines, line_num, pattern_desc):
    """Check surrounding context for mitigations."""
    start = max(0, line_num - 3)
    end = min(len(lines), line_num + 3)
    context = "\n".join(lines[start:end])

    if "sanitize" in context.lower() or "escape" in context.lower():
        return "POSSIBLE mitigation (sanitize/escape found nearby)"
    if "parameterized" in context.lower() or "prepared" in context.lower():
        return "POSSIBLE mitigation (parameterized query found nearby)"
    return None

def scan_file(filepath):
    findings = []
    try:
        content = Path(filepath).read_text(encoding="utf-8", errors="ignore")
        lines = content.split("\n")
    except Exception as e:
        return [{"severity": "ERROR", "file": str(filepath), "line": 0, "issue": f"Cannot read: {e}"}]

    lang = detect_language(filepath)
    all_patterns = defaultdict(list)

    for severity, patterns in PATTERNS.items():
        for pattern, desc in patterns:
            all_patterns[severity].append((pattern, desc))

    if lang in LANGUAGE_SPECIFIC:
        for severity, patterns in LANGUAGE_SPECIFIC[lang].items():
            for pattern, desc in patterns:
                all_patterns[severity].append((pattern, desc))

    for severity, patterns in all_patterns.items():
        for pattern, description in patterns:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    if is_whitelisted(line):
                        continue
                    mitigation = check_context(lines, i - 1, description)
                    finding = {
                        "severity": severity,
                        "file": str(filepath),
                        "line": i,
                        "issue": description,
                        "code": line.strip()[:120],
                        "language": lang,
                    }
                    if mitigation:
                        finding["note"] = mitigation
                    findings.append(finding)
    return findings

def scan_directory(dirpath, extensions=None):
    if extensions is None:
        extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go"}
    all_findings = []
    for ext in extensions:
        for filepath in Path(dirpath).rglob(f"*{ext}"):
            if any(skip in str(filepath) for skip in [".git", "node_modules", "__pycache__", ".venv"]):
                continue
            all_findings.extend(scan_file(filepath))
    return all_findings

def format_report(findings):
    if not findings:
        return "## Security Scan Report\n\nNo issues found."

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "ERROR": 4}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 5))

    by_lang = defaultdict(list)
    for f in findings:
        by_lang[f.get("language", "unknown")].append(f)

    report = ["## Security Scan Report\n"]
    counts = defaultdict(int)
    for f in findings:
        counts[f["severity"]] += 1

    report.append(f"**Total**: {len(findings)} | " + " | ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
    report.append(f"**Languages**: {', '.join(by_lang.keys())}\n")

    for lang, lang_findings in by_lang.items():
        report.append(f"### {lang.upper()}")
        for f in lang_findings:
            note = f" ⚠️ {f['note']}" if f.get("note") else ""
            report.append(f"- **[{f['severity']}]** {f['file']}:{f['line']} — {f['issue']}{note}")
            if f.get("code"):
                report.append(f"  `{f['code']}`")
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
