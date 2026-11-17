---
alwaysApply: true
scene: git_message
---

## Git 提交信息规范

### 编码要求
- 提交信息必须使用 **UTF-8** 编码
- 禁止 GBK/GB2312 等非 UTF-8 编码的中文

### 语言选择
- 首选 **英文** 提交信息（推荐）
- 如需使用中文，必须确保 UTF-8 编码且简洁

### 格式
```
<type>: <summary>

[可选] 详细说明，空一行后写正文
```

### Type 分类
- `feat`: 新功能
- `fix`: Bug 修复
- `refactor`: 代码重构（不改行为）
- `perf`: 性能优化
- `security`: 安全加固
- `docs`: 文档更新
- `style`: 格式调整（不影响代码逻辑）
- `chore`: 构建工具/依赖/配置

### 示例
```
security: fix HMAC key fallback — add multiple layers
refactor: translate all Chinese comments to English across 16 .cs files
fix: remove backup-pre-refactor directory and temp validate_json.ps1
chore: update audit report — 14 items verified fixed in prior refactors
```
