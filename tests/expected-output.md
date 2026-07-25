# Code Review Report

**Verdict**: BLOCK
**Scanner findings**: 5
**AI findings**: 3

## Findings

### [CRITICAL] example-input.py:6 - Hardcoded password
**Source**: scanner
**Fix**: Use environment variable
**Code**: `password = "admin123"` → `os.environ.get("PASSWORD")`

### [CRITICAL] example-input.py:7 - Hardcoded API key
**Source**: scanner
**Fix**: Use environment variable
**Code**: `api_key = "sk-1234567890abcdef"` → `os.environ.get("API_KEY")`

### [CRITICAL] example-input.py:22 - SQL injection via f-string
**Source**: scanner
**Fix**: Use parameterized queries
**Code**: `f"SELECT * FROM users WHERE username='{username}'"` → `cursor.execute("SELECT * FROM users WHERE username=?", (username,))`

### [HIGH] example-input.py:33 - Path traversal
**Source**: scanner
**Fix**: Sanitize filename
**Code**: `file.save(os.path.join('/tmp/uploads', filename))` → use `secure_filename()`

### [MEDIUM] example-input.py:39 - O(n³) nested loop
**Source**: AI analysis
**Fix**: Flatten with list comprehension or add early exits

### [MEDIUM] example-input.py:14 - Database connection leak
**Source**: AI analysis
**Fix**: Use context manager `with sqlite3.connect(...) as conn:`

### [LOW] example-input.py:44 - Debug mode in production
**Source**: scanner
**Fix**: Use environment variable for debug flag
