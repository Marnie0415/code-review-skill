---
slug: code-review-skill
name: code-review
displayName: Code Review
version: 1.3.0
summary: 审查代码的安全漏洞、性能问题和风格问题
description: "Use when the user wants to review code or check for security issues. Triggers on 'review this code', 'check security', 'audit code'."
license: MIT
---

# Code Review

Reviews code using automated security scanning + AI analysis with smart adaptation.

## When to use

- Review code before merging a PR
- Check for security vulnerabilities
- Audit codebase quality

## When NOT to use

- Writing new code
- Debugging runtime errors
- Setting up CI/CD

## Workflow

### Step 1: Detect context

Identify what to review AND adapt strategy:

```
# Detect language from file extension
.py → Python rules (SQL injection, pickle, subprocess)
.js/.ts → JavaScript rules (XSS, eval, prototype pollution)
.java → Java rules (deserialization, XXE, SSRF)
.go → Go rules (unsafe pointer, command injection)
```

Ask the user:
- "Should I focus on security, performance, or style?"
- "Any specific concerns?"

### Step 2: Read and scan

```
read <file_path>
bash: python <skill_dir>/scripts/security_scanner.py <target>
```

For large projects (>50 files), use `grep` to find high-risk patterns first:

```
grep -r "password\|secret\|token" --include="*.py" .
grep -r "execute\|query" --include="*.py" .
```

### Step 3: AI deep analysis

Adapt analysis based on language:

| Language | Focus areas |
|----------|-------------|
| Python | pickle, subprocess, SQL injection, type hints |
| JavaScript | XSS, prototype pollution, eval, async patterns |
| Java | deserialization, XXE, thread safety |
| Go | unsafe, race conditions, error handling |

### Step 4: Multi-turn interaction

After initial report, support follow-ups:

- User asks "Explain finding #3" → expand that finding
- User asks "Only show CRITICAL" → filter by severity
- User asks "Fix this" → provide specific code fix
- User asks "What about line 42?" → analyze that specific line

### Step 5: Save and cache

```
write review-report.md <report>
```

If reviewing the same project later, reference the previous report:

```
read review-report.md
```

Skip findings already reported unless code changed.

## Severity rules

| Level | Criteria |
|-------|----------|
| CRITICAL | Hardcoded secrets, SQL injection, command injection |
| HIGH | XSS, resource leaks, race conditions |
| MEDIUM | Missing validation, broad exceptions, debug mode |
| LOW | Style issues, TODOs, magic numbers |

## Error handling

- **Scanner fails**: Continue with AI-only analysis
- **File too large**: Sample key functions, scan rest with grep
- **Unknown language**: Scanner works on any text; use generic rules
