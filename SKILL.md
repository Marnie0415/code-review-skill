---
slug: code-review-skill
name: code-review
displayName: Code Review
version: 1.2.0
summary: 审查代码的安全漏洞、性能问题和风格问题
description: "Use when the user wants to review code or check for security issues. Triggers on 'review this code', 'check security', 'audit code'."
license: MIT
---

# Code Review

Reviews code using automated security scanning + AI analysis.

## When to use

- Review code before merging a PR
- Check for security vulnerabilities
- Audit codebase quality

## When NOT to use

- Writing new code
- Debugging runtime errors
- Setting up CI/CD

## Workflow (follow these exact steps)

### Step 1: Identify what to review

Ask the user OR detect from context:
- If user pasted code → review the pasted code
- If user gave a file path → use that file
- If user gave a directory → scan all code files

### Step 2: Read the code

Use the `read` tool to load the file:

```
read <file_path>
```

If multiple files, use `glob` to find them:

```
glob **/*.py
```

Then read each one with `read`.

### Step 3: Run security scanner

Execute the bundled scanner using `bash`:

```
bash: python <skill_dir>/scripts/security_scanner.py <file_or_directory>
```

This returns a Markdown report with findings sorted by severity.

Save the scanner output to a temp file for reference:

```
write /tmp/security-scan.md <scanner_output>
```

### Step 4: AI analysis

After scanner runs, analyze the code yourself:

1. Re-read the code with `read` tool
2. Check for performance patterns the scanner missed
3. Check for correctness issues (null access, resource leaks)
4. Check style (long functions, deep nesting)

### Step 5: Merge and deduplicate

Combine scanner findings with your analysis:
- If scanner already found it, don't repeat it
- Add your findings that the scanner couldn't detect
- Prioritize by severity

### Step 6: Save report

```
write review-report.md <final_report>
```

Tell the user: "Review saved to review-report.md"

## Severity rules

| Level | Criteria |
|-------|----------|
| CRITICAL | Hardcoded secrets, SQL injection, command injection |
| HIGH | XSS, resource leaks, race conditions |
| MEDIUM | Missing validation, broad exceptions, debug mode |
| LOW | Style issues, TODOs, magic numbers |

## Error handling

- **Scanner fails**: Continue with AI-only analysis, note "scanner unavailable"
- **File too large** (>1000 lines): Review scanner output first, then sample key functions
- **Unknown language**: Scanner works on any text; skip language-specific AI analysis
