# 故障排除

## 常见问题

### 1. 安全扫描器报错 "No module named 'xxx'"

扫描器只使用 Python 标准库，不需要额外安装。如果报错，检查 Python 版本：

```bash
python --version
```

需要 Python 3.8+。

### 2. 扫描结果误报太多

使用白名单排除测试文件中的已知模式：

```bash
python scripts/security_scanner.py <目录>
```

白名单自动排除包含 `test`、`mock`、`example`、`changeme` 等关键词的代码。

### 3. 扫描大目录很慢

扫描器会跳过 `.git`、`node_modules`、`__pycache__` 等目录。如果仍然很慢，指定特定文件：

```bash
python scripts/security_scanner.py src/main.py
```

### 4. 无法识别某种语言的漏洞

扫描器使用通用正则模式，适用于大多数语言。对于特定语言的深度分析，建议配合专业工具（如 Semgrep）使用。

### 5. 输出格式想要 JSON

扫描器默认输出 Markdown。如需 JSON，修改脚本中的 `format_report` 函数或自行解析输出。

## 性能基准

- 单文件（<100 行）：< 1 秒
- 中型项目（1000 行）：< 5 秒
- 大型项目（10,000 行）：< 30 秒
