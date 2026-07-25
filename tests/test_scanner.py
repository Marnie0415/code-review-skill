#!/usr/bin/env python3
"""Tests for security_scanner.py"""

import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from security_scanner import scan_file, is_whitelisted

def test_hardcoded_password():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('password = "admin123"')
        name = f.name
    try:
        findings = scan_file(name)
        assert any("Hardcoded password" in f["issue"] for f in findings)
    finally:
        os.unlink(name)

def test_whitelist():
    assert is_whitelisted('password = "test_password"', "Hardcoded password") == True
    assert is_whitelisted('password = "real_secret_123"', "Hardcoded password") == False

def test_sql_injection():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('cursor.execute(f"SELECT * FROM users WHERE id={user_id}")')
        name = f.name
    try:
        findings = scan_file(name)
        assert any("SQL injection" in f["issue"] for f in findings)
    finally:
        os.unlink(name)

def test_no_false_positive():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('password = "changeme"')
        name = f.name
    try:
        findings = scan_file(name)
        assert not any("Hardcoded password" in f["issue"] for f in findings)
    finally:
        os.unlink(name)

if __name__ == "__main__":
    test_hardcoded_password()
    test_whitelist()
    test_sql_injection()
    test_no_false_positive()
    print("All tests passed!")
