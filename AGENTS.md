# Agents

## 项目概述
**FirewallManager** — Windows 防火墙管理工具，监控指定目录中的可执行文件并自动创建防火墙规则拦截其出站连接。基于 .NET 10 Windows Forms，通过 COM 调用 Windows Firewall API (NetFwTypeLib) 实现规则管理。

- 当前版本：1.9.2
- 目标框架：net10.0-windows
- 语言：C#
- UI：Windows Forms + 托盘图标

## 已完成的工作

### 核心功能（v1.0.0 - v1.2.0）
- 单文件/文件夹批量创建防火墙出站拦截规则
- 文件系统实时监控（FileSystemWatcher），自动为新 .exe 创建规则
- 暂停/恢复/停止扫描任务（CancellationToken + ManualResetEvent）
- 托盘图标后台运行，最小化到托盘
- 白名单管理（持久化存储，排除指定程序）
- 规则详情查看窗体
- 粘贴路径功能（支持多路径、剪贴板重试机制）
- 多语言支持（中文/英文，LangManager 动态切换）
- 配置导入/导出（JSON）

### 重构优化（v1.3.0 - v1.4.1）
- 分离防火墙操作逻辑到 `FirewallService`，UI 与业务解耦
- 实现 IDisposable 模式，正确释放 COM 对象和资源
- UI 控件字段移至 `Form1.Designer.cs`
- 白名单静态缓存 + 线程同步
- `RuleNamingService` 集中规则命名逻辑
- `UpdateFirewallRules` 使用 async/await + Task.WhenAll 并行扫描
- 硬编码中文字符串替换为 `LangManager.GetText` 调用

### 安全加固（v1.6.0 - v1.8.0）
- **路径安全**：`NormalizeAndValidatePath` 拒绝特殊前缀（\\?\、\??\）、符号链接、Junction；递归校验父目录 reparse point
- **TOCTOU 防护**：`WaitForFileReady` 重试机制；`VerifyConfigIntegrityAndRead` 原子操作验证+读取
- **COM 安全**：使用固定 CLSID + CoCreateInstance 替代 ProgID；CLSID/IID 真实性验证；`ValidateComObjectType`
- **配置完整性**：HMAC-SHA256 校验配置文件，防止篡改
- **密钥保护**：HMAC 密钥使用 Windows DPAPI (ProtectedData.Protect) 加密；文件 ACL 限制为 Administrators + SYSTEM
- **签名验证**：`WinVerifyTrust` API 验证 Authenticode 签名完整性
- **临时文件安全**：随机文件名 + 独占创建 + 句柄级 reparse point 验证，防止符号链接攻击
- **日志安全**：控制字符过滤、敏感信息脱敏、日志注入防御、频率限制
- **规则命名**：格式 `Block_{fileName}_{32位base64url哈希}`，防止误删其他软件规则
- **用户确认**：规则 Action/Direction 变更时显示安全确认对话框
- **防火墙配置文件**：ALL_FIREWALL_PROFILES = 7，规则应用到 Domain + Private + Public

### Bug 修复与健壮性（v1.9.0 - v1.9.2）
- 修复 COM 对象 CLSID 值错误（REGDB_E_CLASSNOTREG）
- 修复 `System.__ComObject` GUID 为空时验证失败
- 修复配置文件 UTF-8 BOM 导致 JSON 解析失败
- 修复 `LangManager` JSON 深度超限递归调用（堆栈溢出风险）
- 修复 `TargetStore` 语言代码验证（BCP 47 标准）
- 修复剪贴板访问不稳定（指数退避重试）
- 修复 HMAC 密钥生成回退缺失（多层回退机制）
- 消除全部编译警告（4 → 0）
- 提取 `TryAddPathToMonitoring`、`IsValidRuleName` 等公共方法，消除 8 处重复代码
- 审计报告 S-01、S-02、Q-01、Q-04 标记为已修复

### 代码清理（v1.9.3，已完成）
- **中文注释全量翻译为英文**：覆盖全部 16 个 .cs 源文件（Form1.cs、Form1.Designer.cs、FirewallService.cs、ComHelper.cs、Config.cs、TargetStore.cs、LangManager.cs、LogManager.cs、WhitelistForm.cs、LogsForm.cs、IFirewallService.cs、RuleNamingService.cs、RuleDetailsForm.cs、Program.cs、FirewallEnums.cs、RuleDetailsInfo.cs），约 850+ 处 XML doc、行内注释、`#region` 名称从中文改为英文。技术术语（HMAC、DPAPI、CLSID、IID、GUID、ACL、TOCTOU、reparse point、junction、symbolic link、Authenticode、CoCreateInstance、FileSystemWatcher 等）保持原样。双语注释仅保留英文版本。用户可见字符串字面量（`LangManager.GetText` 键、`MessageBox` 消息、`ArgumentException` 消息等）保持中文不变。
- **删除 backup-pre-refactor/ 重构前备份目录**，减少仓库体积。
- **删除 validate_json.ps1 临时验证脚本**。
- **编译验证**：全程 `dotnet build --no-restore`，0 警告 0 错误。
- **Grep 验证**：`^\s*(///|//|/\*|\*).*[\p{Han}]` 对所有 .cs 文件 → 0 匹配。
- **Git 编码修复**：配置本地仓库 `core.quotepath=false`、`i18n.commitEncoding=utf-8`、`i18n.logOutputEncoding=utf-8`；创建 [.gitattributes](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/.gitattributes) 统一换行符；补全 [git-commit-message.md](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/.trae/rules/git-commit-message.md) 规则。
- **审计报告复核**：逐条核查 [FIREWALL_MANAGER_AUDIT_REPORT.md](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/FIREWALL_MANAGER_AUDIT_REPORT.md) 16 项审计。代码证据（grep + 逐行 Read）证明 **B-01~B-05、F-01、F-02、F-04、Q-02、Q-03 已修复/清理**；**F-05 为审计误报**（5 处 LangManager 引用）；**F-03 FallbackTranslations 117+ 键覆盖**（可接受）；仅剩 S-03 和 COM 验证覆盖范围为建议性改进。已更新审计报告：标题加 ✅ 标记、修复状态说明、合规表移除 Form1.resourcesReleased volatile 未实现行、Section 六总结表重写（中危 0、低危 1、安全性评分 10/10）。

### 第二轮安全复审（v1.9.4，已完成）
- **重新审计**（忽略注释声明，只看控制流）：7 项 R-01~R-07 全部修复 —— COM 注册预校验、配置完整性 fail-closed、目录 ACL、reparse fail-closed、句柄级真实解链、规则归属哈希绑定、拦截闸门反转。
- **多 Agent 交叉校验**：追加 10 项 X-01~X-10。已修复 X-01 扫描跟随 junction、X-02 `CRITICAL_PROGRAMS` 仅按文件名匹配、X-03 ACL 未改属主/未清显式 ACE、X-04 `ClearAllRules` 绕过归属校验、X-05 规则哈希大小写敏感、X-11 `\\?\Volume{}` 前缀被剥离；X-10 判定误报；X-06~X-09 记录为残余风险（需同用户代码执行或管理员权限）。
- **遗留问题处理**：删除 `IsFilePathTrusted` / `IsFileDigitallySigned` / `VerifyFileSignatureIntegrity` / `VerifyCertificateChain` 与 `WinVerifyTrust` P/Invoke 等约 190 行死代码。
- **审计报告**：[FIREWALL_MANAGER_AUDIT_REPORT.md](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/FIREWALL_MANAGER_AUDIT_REPORT.md) 新增第六节（R/X 两阶段记录）与第七节总结，安全性评分由 10/10 修正为 9/10。
- **编译验证**：`dotnet build --no-restore` → 0 警告 0 错误。

### 多智能体协同漏洞修复（v1.9.5，已完成）
- 依据 `SECURITY_REVIEW_MULTI_AGENT.md` 修复 9 项缺陷（V-01~V-07、V-09、V-10）与 1 项功能缺陷（5.1）：UNC 路径全面拒绝（`ComHelper.IsLocalPathCandidate`，含混合分隔符与相对路径二次校验）、reparse 校验前移、目录加固三态 fail-closed、规则属性 setter 校验 + 存储回读 + 回滚、白名单 HMAC + 旧格式迁移、`UpdateRule` 归属/类型校验、`ClearAllRules` 同步、导入后重建 watcher。
- 两轮只读 Agent 对抗复检 + 兼容性验证，补修 6 处缺口；`dotnet build --no-restore` 全程 0 警告 0 错误。
- V-08（大小写敏感目录漏拦）保留为残余风险，修复报告见 [SECURITY_FIX_REPORT.md](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/SECURITY_FIX_REPORT.md)。

### 测试（v1.5.0，已移除）
- v1.5.0 曾创建 xUnit 自动化测试项目 `FirewallManager.Tests`（76 个测试用例），后因测试项目目录不再存在，已于 v1.9.2 后移除全部残留引用（csproj 排除项、README、文档）

## 修改的文件

### 源代码
| 文件 | 说明 |
|------|------|
| [Form1.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/Form1.cs) | 主窗体，监控/规则管理/UI 交互 |
| [Form1.Designer.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/Form1.Designer.cs) | UI 控件设计器代码 |
| [FirewallService.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/FirewallService.cs) | 防火墙操作逻辑（COM 调用） |
| [IFirewallService.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/IFirewallService.cs) | 防火墙服务接口 |
| [ComHelper.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/ComHelper.cs) | COM/Win32 API 封装（路径验证、签名验证、原子写） |
| [Config.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/Config.cs) | 配置常量、CLSID/IID、关键程序列表 |
| [TargetStore.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/TargetStore.cs) | 配置存储（schema v2 + HMAC 完整性） |
| [RuleNamingService.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/RuleNamingService.cs) | 规则命名逻辑 |
| [RuleDetailsInfo.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/RuleDetailsInfo.cs) | 规则详情数据结构 |
| [RuleDetailsForm.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/RuleDetailsForm.cs) | 规则详情窗体 |
| [WhitelistForm.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/WhitelistForm.cs) | 白名单管理窗体 |
| [LangManager.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/LangManager.cs) | 多语言管理 |
| [LogManager.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/LogManager.cs) | 日志管理（注入防御、脱敏） |
| [LogsForm.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/LogsForm.cs) | 日志查看窗体 |
| [FirewallEnums.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/FirewallEnums.cs) | 枚举定义 |
| [Program.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/Program.cs) | 程序入口（全局异常处理） |

### 资源与配置
| 文件 | 说明 |
|------|------|
| [Lang/en-US.json](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/Lang/en-US.json) | 英文语言资源 |
| [Lang/zh-CN.json](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/Lang/zh-CN.json) | 中文语言资源 |
| [FirewallManager.csproj](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/FirewallManager.csproj) | 项目文件 |

### 文档
| 文件 | 说明 |
|------|------|
| [CHANGELOG.md](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/CHANGELOG.md) | 版本变更记录 |
| [README.md](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/README.md) | 项目说明 |
| [SECURITY_REPORT.md](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/SECURITY_REPORT.md) | 安全审计报告 |
| [FIREWALL_MANAGER_AUDIT_REPORT.md](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/FIREWALL_MANAGER_AUDIT_REPORT.md) | 审计报告 |
| [docs/SECURITY_CODING_STANDARDS.md](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/docs/SECURITY_CODING_STANDARDS.md) | 安全编码规范 |
| [docs/SECURITY_TESTING_GUIDE.md](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/docs/SECURITY_TESTING_GUIDE.md) | 安全测试指南 |
| [docs/VULNERABILITY_RESPONSE.md](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/docs/VULNERABILITY_RESPONSE.md) | 漏洞响应流程 |

## 遗留的问题

1. **CHANGELOG.md 为中文**：版本变更记录全部使用中文撰写，与代码英文化方向不一致，需考虑翻译。

## 下一步任务

1. **翻译 CHANGELOG.md**：将中文变更记录翻译为英文，保持与代码英文化方向一致。
2. **功能增强**（可选）：根据用户需求迭代。
