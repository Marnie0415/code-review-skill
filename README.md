# Code Review

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.txt)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-Skill-D97757)](SKILL.md)
[![Codex](https://img.shields.io/badge/Codex-Skill-000000)](SKILL.md)
[![Version](https://img.shields.io/badge/Version-1.0.0-blue)]()

> Review code for security vulnerabilities, performance issues, and style problems.

## What it does

Analyzes code for security flaws, performance bottlenecks, correctness issues, and style problems. Each finding includes severity level, file/line reference, description, and a concrete fix with code example.

## Why this exists

Code review is time-consuming and easy to miss things. Security vulnerabilities, SQL injections, and hardcoded secrets often slip through. This skill catches them all — with severity ratings and fix suggestions you can copy-paste.

## Prerequisites

- Claude Code, Codex, or any LLM agent that supports SKILL.md
- Git (to clone the repository)
- No Python, Node.js, or other runtime required

## Installation

### Step 1: Clone the repository

```bash
git clone https://github.com/Marnie0415/code-review-skill.git
```

### Step 2: Copy to your skills directory

**macOS / Linux:**

```bash
# For Claude Code
cp -r code-review-skill ~/.claude/skills/

# For Codex
cp -r code-review-skill ~/.codex/skills/
```

**Windows (PowerShell):**

```powershell
# For Claude Code
Copy-Item -Path "code-review-skill" -Destination "$env:USERPROFILE\.claude\skills\code-review-skill" -Recurse

# For Codex
Copy-Item -Path "code-review-skill" -Destination "$env:USERPROFILE\.codex\skills\code-review-skill" -Recurse
```

### Step 3: Restart your agent

Restart Claude Code or Codex to pick up the new skill.

## Usage

In Claude Code or Codex, simply ask:

```text
Review this code for issues
```

The agent will automatically detect and use this skill.

## What you get

| Input | Output |
|-------|--------|
| Python function | Security findings + fix code |
| JavaScript file | Style issues + performance tips |
| Git diff | Change-focused review with regression check |
| Full codebase | Prioritized findings by severity |

## Review categories

| Category | Severity | Examples |
|----------|----------|----------|
| Security | CRITICAL | Hardcoded secrets, SQL injection, XSS |
| Performance | HIGH | N+1 queries, unbounded loops |
| Correctness | HIGH | Null access, resource leaks |
| Style | MEDIUM | Long functions, deep nesting |

## Output format

```
[CRITICAL] auth.py:42 - Hardcoded password
  Description: Password in source code
  Fix: Use environment variable
  Example: os.environ.get('DB_PASSWORD')
```

## Verdict

- **BLOCK** — Critical issues, must fix before merge
- **CHANGES REQUESTED** — High severity, should fix
- **APPROVE WITH SUGGESTIONS** — Minor improvements
- **APPROVE** — Code looks good

## Acknowledgments

README structure inspired by [sovereign-skills](https://github.com/AlexZio00/sovereign-skills), [claude-code-skills](https://github.com/levnikolaevich/claude-code-skills), and [html-to-editable-pptx](https://github.com/Hasasasa/html-to-editable-pptx). All referenced projects are MIT licensed.

## License

MIT
