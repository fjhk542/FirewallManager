# 安全编码规范

## 1. 输入验证

### 1.1 路径规范化
所有文件路径输入必须经过 `Path.GetFullPath()` 规范化处理后再使用。
```csharp
string normalizedPath = Path.GetFullPath(inputPath);
```

### 1.2 路径前缀过滤
拒绝以下特殊路径前缀：
- `\\?\` - 扩展长度路径（可绕过 MAX_PATH 限制）
- `\??\` - 对象管理器路径
- `\\?\UNC\` - 扩展长度 UNC 路径
- `\\` - UNC 网络路径（除非明确允许）

### 1.3 符号链接检测
所有文件操作前必须检测符号链接：
```csharp
if (IsSymbolicLink(normalizedPath))
{
    LogManager.Warning("拒绝符号链接路径: " + normalizedPath);
    return;
}
```
使用 `FileSystemInfo.LinkTarget` 属性（.NET 5+）进行检测，避免将挂载点或联接点误判为符号链接。

### 1.4 大小限制
- 剪贴板内容: 最大 10MB
- 一次性处理的路径数量: 最多 1000 条
- 白名单文件大小: 最大 10MB
- 白名单条目数: 最多 100000 条

### 1.5 系统根目录保护
拒绝添加系统根目录（如 `C:\`）作为监控目标。

## 2. 输出编码

### 2.1 日志过滤
所有日志消息必须经过 `FilterSensitiveInfo` 方法过滤：
- 移除控制字符（0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F, 0x7F）
- 移除 Unicode 控制字符（零宽空格、双向文本覆盖等）
- 替换换行符为安全占位符（[CRLF]、[CR]、[LF]）
- 过滤密码、令牌、密钥等敏感信息
- 隐藏用户目录路径

## 3. 认证与授权

### 3.1 管理员权限检查
- 所有防火墙操作在启动时检查管理员权限
- 非管理员模式下禁用所有防火墙管理功能
- 权限拆分架构确保功能与权限匹配

### 3.2 调用者验证
通过 `IsCallerProcessValid()` 验证调用者身份，防止恶意进程注入调用。

## 4. COM 对象安全

### 4.1 安全属性访问
使用 `SafeGetProperty` 和 `SafeSetProperty` 方法访问 COM 对象属性：
```csharp
SafeSetProperty(newRule, "Name", ruleName);
string name = SafeGetProperty<string>(rule, "Name", "");
```

### 4.2 类型验证
使用 `ValidateComObjectType` 验证 COM 对象类型。

### 4.3 资源释放
- 正确实现 Dispose 模式
- 区分托管资源和非托管资源
- 使用 `Marshal.ReleaseComObject` 释放 COM 对象

## 5. 加密与哈希

### 5.1 哈希算法
- 使用 SHA256（而非 MD5）计算路径哈希值
- HMAC-SHA256 用于配置文件完整性校验

### 5.2 密钥管理
- HMAC 密钥从 MachineGuid 派生，不同机器使用不同密钥
- 不硬编码密钥

## 6. 竞争条件防护

### 6.1 TOCTOU 防护
文件系统事件处理使用 `WaitForFileReady` 方法：
- 最大重试 5 次
- 重试间隔 200ms
- 检查文件大小稳定性（连续两次大小相同表示写入完成）
- 处理前再次验证文件存在性

### 6.2 线程安全
- 使用 `lock` 保护共享资源访问
- 使用 `ConcurrentDictionary` 实现线程安全的缓存
- 资源释放使用双重检查锁定模式

## 7. 错误处理

- 不在 catch 块中暴露敏感信息
- 所有外部输入异常使用通用错误消息
- 异常记录使用 `LogManager.Error` 进行安全过滤
- 不向用户显示原始异常堆栈

## 8. 配置文件完整性

### 8.1 完整性校验
配置文件加载时必须使用 `Config.VerifyConfigIntegrity` 验证完整性：
- 使用 HMAC-SHA256 计算文件哈希
- 完整性校验文件保存为 `.hmac` 扩展名
- 校验失败时拒绝加载配置

### 8.2 写入时更新
配置文件保存后立即调用 `Config.SaveConfigIntegrityHash` 更新校验值。

## 9. 日志安全

### 9.1 频率限制
- 每秒最多写入 100 条日志
- 超过限制的日志被静默丢弃

### 9.2 大小限制
- 单个日志文件最大 10MB
- 超过限制时自动清理，保留最新 5000 行

## 10. 调试安全

- 所有调试输出方法添加 `[Conditional("DEBUG")]` 属性
- Release 版本不包含调试输出