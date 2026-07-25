# Contributing

Contributions welcome! Here's how:

## Reporting Issues

Open a GitHub issue with:
- What you expected
- What actually happened
- Steps to reproduce

## Adding Security Rules

Edit `scripts/security_scanner.py` and add patterns to the `PATTERNS` dict:

```python
"SEVERITY": [
    (r"regex_pattern", "Description of the issue"),
],
```

## Testing

```bash
python scripts/security_scanner.py tests/example-input.py
```

Compare output with `tests/expected-output.md`.

## Pull Requests

1. Fork the repo
2. Create a branch (`git checkout -b fix/my-improvement`)
3. Make changes
4. Test locally
5. Submit PR with clear description

## License

By contributing, you agree your code will be released under MIT.
