---
slug: code-review-skill
name: code-review
displayName: Code Review
version: 1.1.0
summary: 审查代码的安全漏洞、性能问题和风格问题
description: "Use when the user wants to review code or check for security issues. Triggers on 'review this code', 'check security', 'audit code'."
license: MIT
---

# Code Review

Reviews code for security vulnerabilities, performance issues, and style problems using both automated scanning and AI analysis.

## When to use

- Review code before merging a PR
- Check for security vulnerabilities
- Audit a codebase for quality issues

## When NOT to use

- Writing new code
- Debugging runtime errors
- Setting up CI/CD

## Workflow

### Step 1: Identify input type

Use `read` tool to examine the code:

```
read <file_path>
```

If the user provides a directory, use `glob` to find all code files:

```
glob **/*.py
glob **/*.js
```

### Step 2: Run security scanner

Always run the bundled scanner first for deterministic findings:

```bash
python <skill_dir>/scripts/security_scanner.py <file_or_directory>
```

This produces a structured report with severity levels and line numbers. Save the output:

```bash
python <skill_dir>/scripts/security_scanner.py <target> > /tmp/security-scan.md
```

### Step 3: AI deep analysis

After the scanner runs, perform your own analysis:

- Read each file with the `read` tool
- Check for performance patterns (N+1 queries, unbounded loops)
- Check for correctness (null access, resource leaks, race conditions)
- Check style (long functions, deep nesting, magic numbers)

### Step 4: Merge results

Combine scanner findings (deterministic) with your analysis (contextual). Deduplicate — if the scanner already found it, don't repeat it.

### Step 5: Generate report

Write the final report to a file:

```bash
# Save to project root
write review-report.md <report_content>
```

## Output format

```markdown
# Code Review Report

**Verdict**: BLOCK | CHANGES REQUESTED | APPROVE WITH SUGGESTIONS | APPROVE
**Scanner findings**: X (from security_scanner.py)
**AI findings**: Y (from manual review)

## Findings

### [CRITICAL] file.py:42 - Hardcoded password
**Source**: scanner
**Fix**: Use environment variable
**Code**: `password = "secret"` → `os.environ.get("PASSWORD")`

### [HIGH] file.py:88 - N+1 query pattern
**Source**: AI analysis
**Fix**: Batch queries or use select_related
```

## Severity rules

| Level | Criteria |
|-------|----------|
| CRITICAL | Hardcoded secrets, SQL injection, command injection |
| HIGH | XSS, resource leaks, race conditions |
| MEDIUM | Missing validation, broad exceptions, debug mode |
| LOW | Style issues, TODOs, magic numbers |

## Error handling

- **No code provided**: Ask user to paste code or give file path
- **File too large** (>1000 lines): Review security scanner output first, then sample key functions
- **Unknown language**: Run scanner only (it works on any text), skip AI language-specific analysis
- **Scanner fails**: Fall back to pure AI analysis with a note that scanner was unavailable

## Known limitations

- Scanner is regex-based, may miss context-dependent vulnerabilities
- Cannot run code or test dynamically
- Does not check dependency vulnerabilities (only source code patterns)
- AI analysis quality depends on code readability
