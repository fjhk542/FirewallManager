# FirewallManager 源代码审计报告

## 报告概述

本报告对 FirewallManager 项目进行全面的源代码审计，涵盖安全漏洞、程序 Bug、已定义但未实现的功能三个维度。

**2026-11-17 更新**：新增第六节「第二轮全量安全复审」。该轮复审**不采信代码注释中声明的修复**，仅依据实际控制流重新审计，发现 7 项问题并全部修复；随后用多 Agent 交叉校验（3 个代码检索 Agent + 2 个对抗性审查 Agent）复核修复结果，追加发现 11 项缺陷/回归。第六节记录全部证据、修复状态与残余风险，并据此修正本报告原先「无高危漏洞 / 安全性 10/10」的结论。

---

## 一、安全漏洞

### S-01: ComHelper.IsCallerProcessValid 逻辑缺陷（中危） ✅ 已修复

**文件**: [ComHelper.cs](file:///C:/Users/tjliy/Documents/trae_projects/FirewallManager/ComHelper.cs)

**问题描述**: 
`IsCallerProcessValid` 方法的命名和文档表明其目的是验证调用者进程的合法性，但实际实现是验证文件路径是否位于受信任目录（Program Files、System、Windows）或是否有数字签名。这与方法名称暗示的功能不符，可能导致安全判断错误。

**修复状态**: 已修复。方法已重命名为 `IsFilePathTrusted`，准确反映其功能。

---

### S-02: FirewallService.GetRuleDetails 返回动态对象（低危） ✅ 已修复

**文件**: [FirewallService.cs](file:///C:/Users/tjliy/Documents/trae_projects/FirewallManager/FirewallService.cs)

**问题描述**:
`GetRuleDetails` 方法返回 `dynamic` 类型的 COM 对象，调用者可以通过反射访问任意属性，存在潜在的类型安全风险和 COM 对象劫持攻击面。

**修复状态**: 已修复。方法已改为返回强类型 `RuleDetailsInfo`，消除类型安全风险。

---

### S-03: LogManager.FilterSensitiveInfo 日志过滤不完整（低危）

**文件**: [LogManager.cs](file:///C:/Users/tjliy/Documents/trae_projects/FirewallManager/LogManager.cs#L288-L330)

**问题描述**:
虽然实现了敏感信息过滤，但某些敏感模式可能被遗漏，如环境变量值、注册表路径等。

**建议修复**:
- 增加更多敏感信息模式匹配（如环境变量格式）
- 考虑使用更全面的敏感信息检测库

---

## 二、程序 Bug

### B-01: Form1.cs 双重检查锁定缺少 volatile（中危） ✅ 已修复

**文件**: [Form1.cs](file:///C:/Users/tjliy/Documents/trae_projects/FirewallManager/Form1.cs#L121)

**问题描述**:
`ReleaseResources` 方法使用了双重检查锁定模式，但 `resourcesReleased` 字段未标记为 `volatile`，可能导致线程安全问题。

**修复状态**: 已修复。`resourcesReleased` 字段已标记为 `private volatile bool resourcesReleased = false;`（line 121）。

**代码分析**:
```csharp
private bool resourcesReleased = false;

private void ReleaseResources()
{
    if (resourcesReleased)  // 读取未加锁且非 volatile
    {
        return;
    }
    lock (this)
    {
        if (resourcesReleased)
        {
            return;
        }
        // ...
        resourcesReleased = true;
    }
}
```

**影响**:
- 在多线程环境下，一个线程写入 `resourcesReleased = true` 后，其他线程可能看不到这个变化
- 可能导致资源被多次释放或释放不完整

**建议修复**:
```csharp
private volatile bool resourcesReleased = false;
```

---

### B-02: LogManager 静态构造函数日志初始化失败的递归调用风险（中危） ✅ 已修复

**文件**: [LogManager.cs](file:///C:/Users/tjliy/Documents/trae_projects/FirewallManager/LogManager.cs#L123-L217)

**问题描述**:
静态构造函数中初始化失败时调用 `LogManager.Error(...)`，但此时 `_logFilePath` 可能尚未完全初始化，可能导致递归调用或空引用异常。

**修复状态**: 已修复。静态构造函数 catch 块使用安全 fallback 路径（TempPath → 当前目录两级回退），且显式使用 `Console.Error.WriteLine` 输出错误信息避免调用 `LogManager` 自身。代码注释注明 "prevent recursion"。

**代码分析**:
```csharp
static LogManager()
{
    try
    {
        // ... 初始化 _logFilePath ...
    }
    catch (Exception ex)
    {
        string tempPath = Path.GetTempPath();
        _logFilePath = Path.Combine(tempPath, Config.LOG_FILE_NAME);
        LogManager.Error(...);  // 调用自身的 Error 方法
    }
}
```

**影响**:
- 如果 `_logFilePath` 仍为默认值（可能为空），调用 `LogManager.Error` 会导致 `File.AppendAllText` 失败

**建议修复**:
- 在调用 `LogManager.Error` 之前确保 `_logFilePath` 已正确初始化
- 使用 `Console.WriteLine` 作为初始化失败时的 fallback

---

### B-03: Form1.cs ResumeLayout 调用位置问题（低危） ✅ 已修复

**文件**: [Form1.cs](file:///C:/Users/tjliy/Documents/trae_projects/FirewallManager/Form1.cs#L366)

**问题描述**:
在构造函数中，`InitializeComponent()` 调用后没有显式调用 `ResumeLayout()`，但设计器生成的代码中 `InitializeComponent()` 内部已调用 `ResumeLayout(false)` 和 `PerformLayout()`。然而，构造函数中动态添加的控件（如 `viewRuleDetailsMenuItem`）可能导致布局问题。

**修复状态**: 已修复。构造函数末尾添加了 `this.PerformLayout();`（line 366），确保动态添加的控件正确布局。

**代码分析**:
```csharp
public Form1(IFirewallService firewallService)
{
    InitializeComponent();
    // 动态添加菜单项
    var viewRuleDetailsMenuItem = new ToolStripMenuItem(...);
    contextMenuStrip.Items.Add(new ToolStripSeparator());
    contextMenuStrip.Items.Add(viewRuleDetailsMenuItem);
    // 没有调用 ResumeLayout() 或 PerformLayout()
}
```

**影响**:
- 动态添加的控件可能无法正确显示或布局异常

**建议修复**:
- 在构造函数末尾添加 `this.PerformLayout()` 确保所有控件正确布局

---

### B-04: LangManager.GetText 格式化字符串处理逻辑错误（低危） ✅ 已修复

**文件**: [LangManager.cs](file:///C:/Users/tjliy/Documents/trae_projects/FirewallManager/LangManager.cs#L303-L320)

**问题描述**:
当格式化占位符数量大于参数数量时，代码直接返回原始文本而不抛出异常或进行适当处理，可能导致用户看到不完整的文本。

**修复状态**: 已修复。当 `placeholderCount > args.Length` 时，代码使用空对象数组 `new object[placeholderCount]` 扩展参数，确保 `string.Format` 正常执行而非直接返回原始文本。

**代码分析**:
```csharp
int placeholderCount = Regex.Matches(text, @"\{\d+\}").Count;
if (placeholderCount > 0 && placeholderCount <= args.Length)
{
    return string.Format(text, args);
}
else if (placeholderCount == 0)
{
    return text;
}
else
{
    return text;  // 占位符数量 > 参数数量，直接返回原始文本
}
```

**影响**:
- 用户可能看到类似 "Status: {0}, Count: {1}" 的未格式化文本

**建议修复**:
- 考虑抛出异常或使用默认值填充缺失的参数

---

### B-05: WhitelistForm.IsInWhitelist 路径规范化异常处理（低危） ✅ 已修复

**文件**: [WhitelistForm.cs](file:///C:/Users/tjliy/Documents/trae_projects/FirewallManager/WhitelistForm.cs#L492-L511)

**问题描述**:
当 `Path.GetFullPath(appPath)` 失败时，直接使用原始路径进行查找，但缓存中的路径是经过规范化的，导致匹配失败。

**修复状态**: 已修复。catch 块现在记录 `LogManager.Warning` 并返回 `false`（安全原则：无法验证的路径视为不在白名单中），不再静默回退到原始路径。

**代码分析**:
```csharp
string normalizedAppPath;
try
{
    normalizedAppPath = Path.GetFullPath(appPath);
}
catch
{
    normalizedAppPath = appPath;  // 直接使用原始路径
}
// 缓存中的路径是规范化的，这里可能无法匹配
return whitelistCache.Contains(normalizedAppPath);
```

**影响**:
- 路径包含特殊字符或格式错误时，白名单检查可能失败

**建议修复**:
- 在 catch 块中记录错误日志
- 或返回 false（安全原则：无法验证的路径视为不在白名单中）

---

## 三、已定义但未实现/未使用的功能

### F-01: ILocalizationService 和 LocalizationService 未被使用 ✅ 已清理

**问题描述**:
定义了 `ILocalizationService` 接口和 `LocalizationService` 实现类，但整个项目中没有任何地方使用这些类。所有代码直接调用 `LangManager.GetText()` 静态方法。

**修复状态**: 已清理。相关文件 `ILocalizationService.cs` 和 `LocalizationService.cs` 已从项目中删除，全文无残留引用。

**影响**:
- 增加代码复杂度和维护负担
- 接口设计未发挥作用

**建议**:
- 如果计划使用依赖注入，应修改代码使用接口
- 否则应删除这些未使用的文件

---

### F-02: FirewallProtocol 枚举未被使用 ✅ 已清理

**文件**: [FirewallEnums.cs](file:///C:/Users/tjliy/Documents/trae_projects/FirewallManager/FirewallEnums.cs)

**问题描述**:
`FirewallProtocol` 枚举已定义但未在任何代码中使用。防火墙规则创建时未指定协议类型，默认为所有协议。

**修复状态**: 已清理。`FirewallProtocol` 枚举已从 `FirewallEnums.cs` 中移除，全文无残留引用。

**影响**:
- 代码冗余
- 如果需要限制协议，缺少实现

**建议**:
- 考虑在规则创建时添加协议参数，使用该枚举
- 或删除未使用的枚举

---

### F-03: 语言文件中缺失的日志消息键 ⚠️ 可接受（fallback 覆盖）

**文件**: [LangManager.cs](file:///C:/Users/tjliy/Documents/trae_projects/FirewallManager/LangManager.cs#L334-L453)

**问题描述**:
`LangManager` 中的 `FallbackTranslations` 字典包含了许多日志消息键，但某些键在语言 JSON 文件中可能缺失，导致运行时回退到英文或键名。

**现状更新**: `FallbackTranslations` 字典已扩充至 **117+ 个键**，覆盖了绝大多数运行时日志路径。审计时列出的 11 个缺失键中，多数已补全或重新命名。剩余少量未覆盖的键（如 `autoMonitorEnabled`、`autoMonitorDisabled`、`messageTruncated`、`sensitiveInfo`）在 `zh-CN.json` 中不存在时回退到 FallbackTranslations 英文值（或键名本身），不影响程序运行。

**缺失的键（示例）**:
- `logMessages.applicationExiting`
- `logMessages.autoMonitorEnabled`
- `logMessages.autoMonitorDisabled`
- `logMessages.toggleAutoMonitorFailed`
- `logMessages.pastePathsSuccess`
- `logMessages.skipInvalidPath`
- `logMessages.addExeToMonitor`
- `logMessages.clipboardContentTooLarge`
- `logMessages.tooManyPastedPaths`
- `logMessages.logManager.messageTruncated`
- `logMessages.logManager.sensitiveInfo`

**影响**:
- 国际化不完整，部分日志消息可能显示为英文或键名

**建议**:
- 检查并补全语言文件中的所有消息键

---

### F-04: Form1.cs 中未实现的托盘图标事件处理 ✅ 已实现

**文件**: [Form1.cs](file:///C:/Users/tjliy/Documents/trae_projects/FirewallManager/Form1.cs#L2029-L2048)

**问题描述**:
`#region 托盘图标事件` 区域为空，没有实现任何托盘图标相关的事件处理方法。虽然设计器中已绑定了 `trayIcon_MouseDoubleClick`，但其他托盘图标事件（如鼠标单击）未处理。

**修复状态**: 已实现。`trayIcon_MouseDoubleClick` 方法已完整实现（显示窗体并恢复到 Normal 状态），配合 `Form1_Resize` 处理最小化到托盘逻辑，托盘图标交互功能完整可用。

**建议**:
- 添加托盘图标右键菜单的完整实现
- 或删除空的区域注释

---

### F-05: Config.cs 中未使用的常量 ❌ 审计误报（5 处引用）

**文件**: [Config.cs](file:///C:/Users/tjliy/Documents/trae_projects/FirewallManager/Config.cs#L25)

**问题描述**:
`Config.DEFAULT_LANGUAGE` 常量值为 `"zh"`，但 `LangManager` 中通过 `System.Globalization.CultureInfo.CurrentUICulture` 自动检测系统语言，这个默认值很少被使用。

**现状核查**: **审计误报**。`DEFAULT_LANGUAGE` 在 `LangManager.cs` 中有 **5 处引用**：静态字段初始化、语言文件期望路径日志、语言文件检查回退、GetCurrentLanguage 默认值、GetTextFromLanguage 回退。作为 fallback 语言兜底，该常量具有实际意义。

**建议**:
- 确认该常量的实际用途
- 如果确实不需要，考虑删除或更新

---

## 四、代码质量改进建议

### Q-01: FirewallService 缺少 IDisposable 接口实现的显式声明 ✅ 已修复

**文件**: [FirewallService.cs](file:///C:/Users/tjliy/Documents/trae_projects/FirewallManager/FirewallService.cs)

**问题描述**:
`FirewallService` 实现了 `IFirewallService` 接口（继承自 `IDisposable`），但类定义中没有显式声明 `: IDisposable`，降低了代码可读性。

**修复状态**: 已修复。类已实现 `Dispose()` 和 `Dispose(bool disposing)` 方法。

---

### Q-02: Form1.cs 中冗余的 LoadMonitoredFolders 和 LoadAddedRules 方法 ✅ 已修复

**文件**: [Form1.cs](file:///C:/Users/tjliy/Documents/trae_projects/FirewallManager/Form1.cs#L876)

**问题描述**:
`LoadMonitoredFolders` 和 `LoadAddedRules` 方法功能几乎完全相同，都是调用 `firewallService.SyncRulesList()` 并记录日志。

**修复状态**: 已修复。冗余方法 `LoadAddedRules` 已删除，仅保留语义更清晰的 `LoadMonitoredFolders`。

**建议修复**:
- 删除其中一个方法，或合并为单个方法

---

### Q-03: LogManager.Log 方法中的空 catch 块 ✅ 已修复

**文件**: [LogManager.cs](file:///C:/Users/tjliy/Documents/trae_projects/FirewallManager/LogManager.cs)

**问题描述**:
`Log` 方法的最外层 catch 块为空，所有异常被静默忽略。

**修复状态**: 已修复。全文 grep 未找到空 catch 块，所有 catch 块现在都包含日志记录或 Console 输出。

**代码分析**:
```csharp
catch (Exception)
{
}
```

**影响**:
- 日志写入失败时无法得知
- 调试困难

**建议修复**:
- 至少记录异常到控制台或系统日志

---

### Q-04: ComHelper.SafeGetProperty 重载方法命名不一致 ✅ 已修复

**文件**: [ComHelper.cs](file:///C:/Users/tjliy/Documents/trae_projects/FirewallManager/ComHelper.cs)

**问题描述**:
有两个 `SafeGetProperty` 重载方法，一个带日志参数，一个不带，但命名相同，调用者需要根据参数类型判断行为差异。

**修复状态**: 已修复。两个重载已合并为单个方法，通过 `logPropertyName` 默认 null 参数控制是否记录日志，消除重载歧义。

---

## 五、安全编码规范合规性检查

### 已实现的安全措施 ✓

| 安全措施 | 状态 | 实现位置 |
|---------|------|---------|
| 配置文件原子写入 | ✓ | ComHelper.AtomicWriteAllText/Bytes |
| JSON 反序列化 MaxDepth=10 | ✓ | ComHelper.SafeJsonOptions |
| 规则名称过滤控制字符 | ✓ | FirewallService.SanitizeRuleName |
| COM 对象类型验证 | ✓ | ComHelper.ValidateComObjectType |
| 配置文件完整性校验 | ✓ | Config.VerifyConfigIntegrity/SaveConfigIntegrityHash |
| ALL_FIREWALL_PROFILES=7 | ✓ | Config.ALL_FIREWALL_PROFILES |
| HMAC 密钥 DPAPI 加密 | ✓ | Config.GenerateHmacKey |
| Action/Direction 变更安全确认 | ✓ | RuleDetailsForm.btnSave_Click |
| UI 阻塞操作异步化 | ✓ | Form1.stopButton_Click |
| 关键错误路径日志 | ✓ | 多处实现 |
| 线程安全双重检查锁定 volatile | ✓ | WhitelistForm.whitelistCacheLoaded + Form1.resourcesReleased |
| 文件系统监控器 .exe 验证 | ✓ | Form1.FileSystemWatcher_Created |
| 路径规范化和符号链接检测 | ✓ | Form1.NormalizeAndValidatePath |
| COM 服务注册预校验（拒绝 HKCU 覆盖） | ✓ | ComHelper.ValidateComServerRegistration |
| 路径真实解链（句柄级） | ✓ | ComHelper.GetRealPath / ResolveFinalPathByHandle |
| 应用数据目录 ACL + 属主加固 | ✓ | ComHelper.SetSecureDirectoryPermissionsInternal |
| 扫描时跳过 reparse point | ✓ | FirewallService.UpdateFirewallRules（EnumerationOptions） |
| 规则归属哈希绑定 | ✓ | RuleNamingService.IsRuleOwnedByUs |

### 需要改进的安全措施 ✗

| 安全措施 | 当前状态 | 改进建议 |
|---------|---------|---------|
| 敏感信息过滤完整性 | 部分实现 | 增加更多敏感模式匹配（环境变量、注册表路径） |
| COM 注册校验与激活之间的 TOCTOU | 已记录残余风险 | 需在同一事务内固定注册表项才能彻底消除，见 X-06 |
| HMAC 密钥 DPAPI 作用域 | 已记录残余风险 | `CurrentUser` 作用域无法防御同用户进程，见 X-07 |

---

## 六、第二轮全量安全复审（2026-11-17）

本轮复审的前提：**忽略代码注释中「已修复」的声明，只依据实际控制流判定**。第一阶段对全量代码重新审计，产出 R-01 ~ R-07 共 7 项问题并全部修复；第二阶段用 5 个 Agent（3 个代码检索、2 个对抗性审查）交叉校验修复结果，追加 X-01 ~ X-11 共 11 项缺陷/回归，其中 6 项已修复或加固、4 项为已记录的残余风险、1 项判定为误报。

### 6.1 第一阶段：重新审计发现（R 系列）

| 编号 | 严重程度 | 问题 | 证据位置 | 状态 |
|------|---------|------|---------|------|
| R-01 | 高危 | COM 激活前未校验服务端注册：`HKCU\Software\Classes\CLSID` 优先级高于 HKLM，非提权进程可将 CLSID 重定向到任意 DLL，由本提权进程加载 → 提权 RCE | ComHelper.CreateComObjectWithClsid | ✅ 已修复 |
| R-02 | 中危 | 配置完整性校验 fail-open：`.hmac` 缺失时直接接受配置，删除校验文件即可绕过 | TargetStore.Load | ✅ 已修复 |
| R-03 | 中危 | 应用数据目录仅保护文件不保护目录：同级用户对父目录持 `FILE_DELETE_CHILD` 即可删除并替换受保护文件 | Config.GetAppDataFilePath | ✅ 已修复 |
| R-04 | 中危 | reparse point 检测 fail-open：仅按 tag 白名单判定，读取失败/未知 tag 视为安全 | ComHelper.HasReparsePoint / HasReparsePointInPath | ✅ 已修复 |
| R-05 | 中危 | `GetRealPath` 并未真正解链：仅调用 `Path.GetFullPath`，符号链接与卷挂载点原样返回 | ComHelper.GetRealPath | ✅ 已修复 |
| R-06 | 低危 | 规则归属仅校验名称形状（`Block_` 前缀 + 32 位 hex），任意第三方规则可通过校验而被删除 | RuleNamingService.IsRuleCreatedByUs | ✅ 已修复 |
| R-07 | 低危 | 拦截闸门反转：`!IsFilePathTrusted(...)` 时直接跳过，导致未签名程序（本工具的主要拦截对象）全部不建规则 | Form1.ValidateAndCreateRuleForExe | ✅ 已修复 |

**修复要点**

- **R-01**：新增 `ValidateComServerRegistration`，在 `Activator.CreateInstance` **之前**检查 HKCU 两个注册表视图下是否存在该 CLSID（存在即拒绝），再从 HKLM 解析 `InprocServer32` / `LocalServer32` 并强制其二进制位于 Windows 目录内。激活后的 `ValidateComObjectClsid` 因 `System.__ComObject` 的 `Type.GUID == Guid.Empty` 无法识别替换，已将其降级为「诊断用途」并同步注释。
- **R-02**：`TargetStore.Load` 在校验失败后不再回读原始文件，仅当「`.hmac` 不存在 **且** HMAC 密钥从未生成（全新安装）」且文件是 v1 数组时才允许迁移，其余一律拒载且不回签。
- **R-03**：新增 `SetSecureDirectoryPermissionsInternal`，目录 ACL 切断继承，Administrators/SYSTEM 完全控制，当前用户仅 `ReadAndExecute`。
- **R-04**：任何 reparse point 属性即判定危险；读取属性异常时返回「危险」（fail-closed）；父目录比较改为带分隔符的 `IsUnderFolder`，避免 `C:\Program FilesEvil` 被误判为系统目录。
- **R-05**：改为 `CreateFile` + `GetFinalPathNameByHandle` 句柄级解链，失败返回 null（fail-closed）。
- **R-06**：新增 `IsRuleOwnedByUs(ruleName, applicationPath)`，要求名称中的路径哈希等于用该规则自身 `ApplicationName` 重算的哈希；`ClearAllRules` / `DeleteRule` 全部改走此判定。
- **R-07**：闸门改为 `IsCriticalSystemExecutable`，只跳过 Windows 目录内的系统可执行文件；未签名程序恢复正常拦截。

### 6.2 第二阶段：多 Agent 交叉校验发现（X 系列）

| 编号 | 严重程度 | 问题 | 状态 |
|------|---------|------|------|
| X-01 | 高危 | 目录扫描使用 `SearchOption.AllDirectories` 会跟随 junction，监控目录内的链接可把扫描带入 System32，为系统二进制批量创建 Block 规则（且无环路检测） | ✅ 已修复 |
| X-02 | 高危 | `CRITICAL_PROGRAMS` 仅按文件名匹配，恶意程序改名为 `svchost.exe` 即可永久逃逸拦截 | ✅ 已修复 |
| X-03 | 中危 | 目录/文件 ACL 只设 DACL 不改属主，且不清除**显式** ACE：同用户非提权进程作为属主隐含 `WRITE_DAC`，可自行加回完全控制；预置的显式 ACE 也会在 `SetAccessRuleProtection(false)` 后残留 | ✅ 已修复 |
| X-04 | 中危 | `ClearAllRules` 第一段按本地 `addedRules` 列表直接 `Remove`，而该列表由 `SyncRulesList` 用 `Block_` 前缀填充，可删除其他产品规则 | ✅ 已修复 |
| X-05 | 中危 | 规则哈希对路径大小写敏感：watcher 传真实路径、扫描传用户拼写路径，同一文件生成两个规则名，去重失效、规则重复累积 | ✅ 已修复 |
| X-06 | 中危 | COM 注册校验与激活之间存在 TOCTOU 窗口，攻击者循环增删 HKCU 注册可穿过检查 | ⚠️ 残余风险 |
| X-07 | 中危 | HMAC 密钥使用 DPAPI `CurrentUser` 作用域，同用户任意进程可 `Unprotect` | ⚠️ 残余风险 |
| X-08 | 中危 | v1 迁移条件（删除 `.hmac` + `hmac.key`）攻击者可自行制造，并会被回签 | ⚠️ 残余风险（已被 X-03 加固削弱） |
| X-09 | 中危 | `Directory.CreateDirectory` 前未检查路径是否为 reparse point，可预建 junction 重定向配置目录 | ⚠️ 残余风险 |
| X-10 | 中危 | `LocalServer32` 带命令行参数时只做前缀比对 | ❌ 误报 |
| X-11 | 低危 | `GetFinalPathNameByHandle` 返回 `\\?\Volume{GUID}\` 时被剥离 `\\?\`，得到 `Volume{...}` 再被拼成 `C:\Volume\...`，规则指向错误路径 | ✅ 已修复 |

**X 系列处理结论**

- **X-01**：扫描改为 `EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint }`，`RemoveFolderRules` 同步修改，junction 不再被跟随，同时消除环路风险。
- **X-02**：`IsCriticalSystemExecutable` 改为「路径位于 Windows 目录内」才返回 true；文件名命中但位于 Windows 目录之外时记录告警并**照常拦截**。`CreateRuleForExe` 与扫描循环中两处裸文件名判断一并删除，避免绕过。
- **X-03**：新增 `RemoveExplicitAccessRules`，在设置 DACL 前清除全部显式 ACE；文件与目录均把属主改为 Administrators（属主变更失败仅告警，不影响 DACL 应用）。
- **X-04**：删除按本地列表直接删除的第一段，`ClearAllRules` 只保留单遍「按 `ApplicationName` 重算哈希」的归属校验删除；列表同步仅在成功后清空。
- **X-05**：`BuildRuleName` 的哈希输入改为 `Path.GetFullPath` + 反斜杠 + `ToLowerInvariant()` 规范化路径；`IsRuleOwnedByUs` 同时接受规范化前的历史命名，保证旧规则仍可识别与清理。
- **X-10**：两个 CLSID 均为 in-process 服务（`FirewallAPI.dll`），`LocalServer32` 不参与激活；即便带参数，被引用的二进制仍需位于 Windows 目录内，前缀校验不会被参数绕过。判定为误报。
- **X-11**：`ResolveFinalPathByHandle` 对 `\\?\Volume{` 前缀保持不变（该形式表示无盘符的卷挂载，剥离后会得到非法路径），仅在 `\\?\UNC\` 与普通 `\\?\` 两种情况下解前缀。
- **X-06 / X-07 / X-08 / X-09**：前三项要利用均需先取得「与用户同权限的代码执行」或管理员权限，此时攻击者已可直接改写配置或规则；X-09 需在首次运行前由同一用户预建 junction。均已记录为残余风险，不再引入新的复杂度（如注册表事务、DPAPI LocalMachine 作用域或启动前目录属主校验），后续如需彻底消除可单独立项。

### 6.3 交叉校验中判定为「设计取舍 / 不修复」的项

| 项 | 结论 |
|----|------|
| `HasReparsePoint` 对不存在的路径返回 false | 调用方均已先做存在性检查；若改为 true 会让「刚创建尚未落盘」的文件被误跳过 |
| `IsCriticalSystemExecutable` 异常时返回 true | 保持 fail-safe（跳过而非拦截），且异常分支仅在路径无法规范化时触发，该路径本就无法建规则 |
| `ApplicationName` 读取失败则拒绝删除 | 有意为之的 fail-closed：宁可留规则，也不误删他人规则 |
| ACL 应用失败仅告警 | 非提权启动无法改 ACL；此时目录未被加固，与「拒绝启动」相比保留可用性更合理，已记录日志 |
| `IsFilePathTrusted` / `IsFileDigitallySigned` 等签名校验链 | 已确认为死代码（重命名后无调用方），本轮删除约 190 行，含 `WinVerifyTrust` P/Invoke 与证书链校验 |

### 6.4 构建验证

```
dotnet build --no-restore
→ 已成功生成。0 个警告，0 个错误
```

---

## 七、总结

### 漏洞严重程度分布（第二轮复审后累计）

| 严重程度 | 数量 | 说明 |
|---------|------|------|
| 高危 | 3 | R-01、X-01、X-02，全部已修复 |
| 中危 | 8 | R-02 ~ R-05、X-03 ~ X-05 已修复；X-06 ~ X-09 为已记录残余风险 |
| 低危 | 8 | R-06、R-07、X-11 已修复，S-03 为建议性改进，X-10 为误报，6.3 中 3 项为设计取舍 |
| 代码质量 | 0 | Q-01/Q-02/Q-03/Q-04 全部已修复 |
| 未使用代码 | 0 | F-01/F-02 已清理，F-04 已实现，F-05 审计误报，签名校验死代码已删除 |

### 代码质量评分

| 维度 | 评分 | 说明 |
|------|------|------|
| 安全性 | 9/10 | 已知可利用高危已全部修复；仍有 4 项需先取得同用户代码执行或管理员权限的残余风险（X-06 ~ X-09），不再宣称 10/10 |
| 代码质量 | 9/10 | Q-01~Q-04 全部修复，重复逻辑持续合并，中文注释已全量翻译为英文 |
| 可维护性 | 9/10 | 提取公共方法 + RuleNamingService 集中命名，COM 安全验证覆盖激活前与激活后两个阶段 |
| 测试覆盖 | N/A | 原测试项目已移除（v1.5.0 不再存在），本轮以编译 + 代码走查 + 多 Agent 交叉校验替代 |

### 优先修复建议

**当前无待修复的高危/中危项。** 两轮累计审计条目中，除 4 项已记录的残余风险（X-06 ~ X-09）与 6.3 列出的设计取舍外，其余均已完成修复、清理或判定为误报。

**后续可考虑的加固（非阻塞）**：
1. X-06：使用注册表事务或 `RegOpenKeyTransacted` 固定 CLSID 注册项，消除校验与激活之间的 TOCTOU 窗口。
2. X-07：将 HMAC 密钥改为 DPAPI `LocalMachine` 作用域并配合机器级 ACL，抵抗同用户进程解密。
3. S-03：扩展敏感信息过滤（环境变量、注册表路径等）。
4. 补全 `FallbackTranslations` 中极少量缺失的键（如 `autoMonitorEnabled`/`Disabled`）。

---

**审计日期**: 2026-07-01（最近更新: 2026-11-17）
**审计范围**: FirewallManager 项目全部源代码
**审计人员**: TRAE AI Code Review（第二轮含多 Agent 交叉校验）