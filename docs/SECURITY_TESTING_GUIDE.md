# 安全测试指南

## 概述

本文档为 FirewallManager 项目提供安全测试指南，包括测试方法、测试用例编写规范和安全回归测试流程。

---

## 1. 测试环境

### 要求
- Windows 10/11 操作系统
- .NET 10.0 SDK
- 管理员权限（运行测试）
- Visual Studio 2022 或 JetBrains Rider（推荐）

### 测试框架
- **单元测试**: xUnit (v2.9.3+)
- **模拟框架**: 使用 .NET 内置模拟能力
- **代码覆盖率**: coverlet

---

## 2. 安全测试分类

### 2.1 路径安全测试

#### 测试要点
- 路径规范化验证
- 特殊路径前缀拒绝（`\\?\`、`\??\`、UNC路径）
- 符号链接检测
- 系统根目录拒绝
- 路径存在性检查
- 路径大小写敏感性

#### 示例测试用例

```csharp
[Fact]
public void NormalizeAndValidatePath_SystemRoot_ReturnsNull()
{
    using (var form = new Form1())
    {
        var method = typeof(Form1).GetMethod("NormalizeAndValidatePath",
            BindingFlags.NonPublic | BindingFlags.Instance);
        string rootPath = Path.GetPathRoot(Environment.SystemDirectory);
        object result = method.Invoke(form, new object[] { rootPath, true });
        Assert.Null(result);
    }
}
```

### 2.2 日志安全测试

#### 测试要点
- 控制字符过滤（ASCII控制字符和Unicode控制字符）
- 敏感信息过滤（密码、令牌、密钥）
- 换行符替换为安全占位符
- 日志消息长度限制
- 日志频率限制
- 敏感信息不泄露到日志文件

#### 示例测试用例

```csharp
[Fact]
public void FilterSensitiveInfo_ReplacesPasswordValue()
{
    var method = typeof(LogManager).GetMethod("FilterSensitiveInfo",
        BindingFlags.NonPublic | BindingFlags.Static);
    string input = "password=mySecret123";
    object result = method.Invoke(null, new object[] { input });
    string filtered = (string)result;
    Assert.DoesNotContain("mySecret123", filtered);
}
```

### 2.3 COM 对象安全测试

#### 测试要点
- COM 对象空值处理
- COM 对象类型验证
- 属性访问异常处理
- 资源释放正确性
- Dispose 模式实现

#### 示例测试用例

```csharp
[Fact]
public void SafeGetProperty_NullObject_ReturnsDefault()
{
    var method = typeof(FirewallService).GetMethod("SafeGetProperty",
        BindingFlags.NonPublic | BindingFlags.Static);
    var genericMethod = method.MakeGenericMethod(typeof(string));
    object result = genericMethod.Invoke(null, new object[] { null, "Name", null });
    Assert.Null(result);
}
```

### 2.4 防火墙规则安全测试

#### 测试要点
- 规则名称清理（特殊字符替换）
- 路径哈希一致性
- 规则存在性检查
- 白名单检查
- 系统关键程序保护

#### 示例测试用例

```csharp
[Fact]
public void SanitizeRuleName_RemovesSpecialCharacters()
{
    var service = new FirewallService();
    string result = service.SanitizeRuleName("my\"app'/test:*.exe");
    Assert.DoesNotContain("\"", result);
    Assert.DoesNotContain("/", result);
}
```

### 2.5 白名单安全测试

#### 测试要点
- 空路径处理
- 路径规范化匹配
- 大小写不敏感匹配
- 缓存一致性
- 多次调用结果稳定性

#### 示例测试用例

```csharp
[Fact]
public void IsInWhitelist_MultipleCalls_ReturnsConsistentResults()
{
    string testPath = @"C:\Windows\System32\notepad.exe";
    bool result1 = WhitelistForm.IsInWhitelist(testPath);
    bool result2 = WhitelistForm.IsInWhitelist(testPath);
    Assert.Equal(result1, result2);
}
```

### 2.6 配置文件完整性测试

#### 测试要点
- HMAC-SHA256 校验值计算
- 文件被篡改后校验失败
- 校验文件不存在时自动创建
- 密钥从 MachineGuid 派生

#### 示例测试用例

```csharp
[Fact]
public void VerifyConfigIntegrity_UnmodifiedFile_ReturnsTrue()
{
    string tempFile = Path.GetTempFileName();
    try
    {
        File.WriteAllText(tempFile, "test content");
        Config.SaveConfigIntegrityHash(tempFile);
        Assert.True(Config.VerifyConfigIntegrity(tempFile));
    }
    finally
    {
        if (File.Exists(tempFile)) File.Delete(tempFile);
    }
}

[Fact]
public void VerifyConfigIntegrity_ModifiedFile_ReturnsFalse()
{
    string tempFile = Path.GetTempFileName();
    try
    {
        File.WriteAllText(tempFile, "original content");
        Config.SaveConfigIntegrityHash(tempFile);
        File.WriteAllText(tempFile, "modified content");
        Assert.False(Config.VerifyConfigIntegrity(tempFile));
    }
    finally
    {
        if (File.Exists(tempFile)) File.Delete(tempFile);
    }
}
```

---

## 3. 安全回归测试

### 3.1 执行流程

1. 运行安全回归测试套件
2. 检查所有测试是否通过
3. 验证无新增构建警告
4. 确认代码覆盖率达到要求

### 3.2 命令行执行

```powershell
# 运行所有测试
dotnet test

# 运行特定安全测试
dotnet test --filter "FullyQualifiedName~PathSecurity"
dotnet test --filter "FullyQualifiedName~LogManagerTests"

# 运行带覆盖率收集的测试
dotnet test --collect:"XPlat Code Coverage"
```

### 3.3 CI/CD 集成

在 CI/CD 流水线中添加安全测试阶段：
```yaml
- name: Run Security Tests
  run: dotnet test --verbosity normal
```

---

## 4. 测试用例编写规范

### 4.1 命名规范

```
[方法名]_[测试场景]_[预期结果]
```

示例：
- `NormalizeAndValidatePath_NullPath_ReturnsNull`
- `FilterSensitiveInfo_RemovesControlCharacters`
- `IsInWhitelist_EmptyPath_ReturnsFalse`

### 4.2 组织结构

```
测试类
├── 正常路径测试
├── 边界值测试
├── 空值/空输入测试
├── 异常输入测试
└── 并发测试
```

### 4.3 断言原则

- 每个测试用例只测试一个关注点
- 使用明确的断言方法
- 测试正向场景和负向场景
- 测试边缘条件和边界值

---

## 5. 安全测试覆盖要求

### 5.1 强制覆盖模块
- [ ] 路径验证方法（100% 安全逻辑覆盖）
- [ ] 日志过滤方法（100% 覆盖）
- [ ] COM 对象安全访问方法（100% 覆盖）
- [ ] 规则名称清理方法（100% 覆盖）
- [ ] 白名单检查方法（100% 覆盖）
- [ ] 配置文件完整性校验（100% 覆盖）

### 5.2 推荐覆盖模块
- [ ] 错误处理路径
- [ ] 并发访问场景
- [ ] 资源释放路径

---

## 6. 漏洞验证测试

修复安全漏洞后，必须编写验证测试：

1. **复现测试**: 验证漏洞确实存在（修复前）
2. **修复测试**: 验证漏洞已被修复
3. **回归测试**: 确认修复未引入新问题

### 验证测试示例

```csharp
[Fact]
public void PathInjection_ExtendedPrefix_IsRejected()
{
    using (var form = new Form1())
    {
        var method = typeof(Form1).GetMethod("NormalizeAndValidatePath",
            BindingFlags.NonPublic | BindingFlags.Instance);
        string maliciousPath = @"\\?\C:\Windows\System32\malware.exe";
        object result = method.Invoke(form,
            new object[] { maliciousPath, false });
        Assert.Null(result);
    }
}
```

---

## 7. 测试数据管理

### 敏感数据保护
- 不得在测试中使用真实密码或密钥
- 使用 `Guid.NewGuid().ToString()` 生成唯一测试路径
- 测试完成后清理所有临时文件

### 临时文件管理
```csharp
string tempFile = Path.GetTempFileName();
try
{
    // 测试逻辑
}
finally
{
    if (File.Exists(tempFile))
        File.Delete(tempFile);
}
```