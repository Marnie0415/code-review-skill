---
name: code-review
version: "1.0.0"
description: "Use when the user wants to review code, check for security issues, audit a codebase, or get feedback on a pull request. Triggers on 'review this code', 'check for security issues', 'audit this codebase', 'review my PR', 'what's wrong with this code', or when the user pastes code for evaluation."
---

# Code Review

Performs comprehensive code review covering security vulnerabilities, performance issues, code style, and common bug patterns with actionable feedback.

## When to use

- Review code before merging a PR
- Check for security vulnerabilities
- Audit a codebase for quality issues
- Get feedback on code patterns

## When NOT to use

- Writing new code or implementing features
- Debugging specific runtime errors
- Optimizing database queries
- Setting up CI/CD pipelines
- Creating code from scratch (this reviews existing code only)

## Workflow

1. Identify the input: code snippet, diff, or file path.
2. Run security checks first (highest priority).
3. Check for performance issues.
4. Check for correctness and error handling.
5. Review style and maintainability.
6. Generate findings with severity levels.
7. Provide a verdict and actionable fix suggestions.

## Review categories

### 1. Security (Critical)
- Hardcoded secrets, API keys, passwords
- SQL injection, XSS, CSRF vulnerabilities
- Insecure deserialization
- Path traversal
- Command injection
- Insecure cryptography usage
- Missing authentication/authorization checks

### 2. Performance (High)
- N+1 query patterns
- Unbounded loops or recursion
- Missing index hints for known queries
- Large object allocation in hot paths
- Blocking I/O in async contexts
- Missing caching opportunities

### 3. Correctness (High)
- Null/undefined access without guards
- Race conditions
- Off-by-one errors
- Incorrect error handling (swallowed exceptions)
- Resource leaks (unclosed connections, files)
- Type mismatches

### 4. Style and Maintainability (Medium)
- Functions exceeding 50 lines
- Deep nesting (more than 3 levels)
- Magic numbers without constants
- Dead code
- Missing error messages
- Inconsistent naming conventions

## Output format

For each finding:
```
[SEVERITY] FILE:LINE - ISSUE
  Description: What is wrong
  Fix: How to fix it
  Example: Code snippet showing the fix (when helpful)
```

Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO

## Rules

- Always check for secrets first. If found, flag as CRITICAL.
- Group findings by file, then by severity.
- Provide concrete fix suggestions, not just descriptions.
- If code looks clean, say so. Do not invent issues.
- Max 20 findings per review. Prioritize by severity.
- For large codebases, focus on changed files first.

## Handling different inputs

- **Single file**: Full review
- **Multiple files**: Review each, cross-reference for consistency
- **Diff/patch**: Focus on changes, check for regression patterns
- **Long code**: Prioritize security and correctness, mention style in summary

## Error handling

- **No code provided**: Ask user to paste the code or provide a file path.
- **Code too short** (under 5 lines): Note that meaningful review requires more context.
- **Unknown language**: Review for general patterns (secrets, error handling) only.
- **Obfuscated code**: Report inability to review and suggest readable version.
- **Binary/non-text content**: Reject and ask for source code.

## Examples

### Example 1: Python function review
Input: A Flask endpoint with SQL queries
Output: Findings for hardcoded credentials (CRITICAL), missing input validation (HIGH), no rate limiting (MEDIUM), with fix suggestions.

### Example 2: JavaScript codebase review
Input: 3 files from a React application
Output: Findings grouped by file, covering XSS risks, prop validation, state management issues.

### Example 3: Diff review
Input: A git diff adding a new API endpoint
Output: Focused review on the changes — authentication check, input sanitization, error response format.

## Known limitations

- Cannot run the code or test it dynamically
- Pattern-based detection may miss context-dependent vulnerabilities
- Cannot assess runtime behavior or actual performance
- Does not check dependency vulnerabilities (only code patterns)
- Review quality depends on code readability

## Output format

Grouped by severity, then by file. Each finding includes description, fix suggestion, and example when helpful. Final verdict: BLOCK, CHANGES REQUESTED, APPROVE WITH SUGGESTIONS, or APPROVE.
