# Code Review - 代码审查

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.txt)
[![Version](https://img.shields.io/badge/Version-1.1.0-blue)]()

> 审查代码的安全漏洞、性能问题和风格问题。

## 功能

使用自动化扫描和 AI 分析，检测代码中的安全漏洞、性能瓶颈和风格问题。每个发现包含严重等级、文件行号、描述和修复建议。

## 安装

### 步骤 1：克隆仓库

```bash
git clone https://github.com/Marnie0415/code-review-skill.git
```

### 步骤 2：复制到 skills 目录

**macOS / Linux：**

```bash
cp -r code-review-skill ~/.claude/skills/
```

**Windows (PowerShell)：**

```powershell
Copy-Item -Path "code-review-skill" -Destination "$env:USERPROFILE\.claude\skills\code-review-skill" -Recurse
```

### 步骤 3：重启 Agent

重启 Claude Code 或 Codex。

## 使用方法

在 Claude Code 或 Codex 中：

```text
审查这段代码
```

## 包含工具

### 安全扫描器 (`scripts/security_scanner.py`)

基于正则表达式扫描器，检测硬编码密钥、SQL 注入、XSS 等漏洞：

```bash
python scripts/security_scanner.py <文件或目录>
```

## 故障排除

详见 [故障排除指南](docs/troubleshooting.md)
