# Changelog

所有对此项目的重要更改都将记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
此项目遵循 [语义化版本控制](https://semver.org/lang/zh-CN/)。

## [1.8.0] - 2026-07-23

### 新增
- 添加 `WinVerifyTrust` API 调用，验证文件签名完整性（不仅仅是证书链）
- 添加 `VerifyConfigIntegrityAndRead` 方法，原子操作验证配置文件完整性并读取内容
- 添加 `Win32Native` 静态类，封装 Windows API 调用（`CreateFile`, `WinVerifyTrust` 等）

### 修改
- 更新 `IsFileDigitallySigned` 方法，先验证签名完整性再验证证书链
- 更新 `ValidateComObjectType` 方法，改用 CLSID/IID 验证，移除 ProgID 依赖
- 更新 `HasDangerousReparseTag` 方法，使用 `CreateFile` API 打开目录并添加 `FILE_FLAG_BACKUP_SEMANTICS` 标志
- 更新 `UpdateRule` 和 `DeleteRule` 方法，添加规则名称验证（空检查 + 长度限制 256 字符）
- 更新 `GetRuleDetails` 方法，使用 CLSID/IID 验证 COM 对象类型
- 更新 `Form1.cs` 和 `WhitelistForm.cs`，使用新的 `VerifyConfigIntegrityAndRead` 方法防止 TOCTOU 攻击

### 高危漏洞修复
- **Authenticode 签名验证不完整 (H-006)**: 添加 `WinVerifyTrust` API 验证文件内容与签名匹配，防止篡改攻击
- **COM 对象验证 ProgID 劫持 (H-007)**: 修改 `ValidateComObjectType` 使用 CLSID/IID 验证，防止 ProgID 劫持绕过 COM 安全模型
- **配置文件 TOCTOU 竞态条件 (H-008)**: 添加 `VerifyConfigIntegrityAndRead` 方法，在锁定状态下完成验证和读取

### 中危漏洞修复
- **规则名称验证不一致 (M-008)**: 在 `UpdateRule` 和 `DeleteRule` 中添加与 `GetRuleDetails` 一致的规则名称验证
- **目录打开缺少 FILE_FLAG_BACKUP_SEMANTICS (M-009)**: 使用 `CreateFile` API 打开目录并设置必要标志

### 低危漏洞修复
- **多语言支持增强**: 添加 `signatureIntegrityCheckFailed` 日志消息

## [1.7.0] - 2026-06-30

### 新增
- 添加 HMAC 密钥加密功能，使用 Windows DPAPI (ProtectedData.Protect) 加密 HMAC 密钥
- 添加安全确认对话框，修改防火墙规则 Action/Direction 时要求用户确认
- 添加异步操作超时处理，使用 Task.WhenAny 防止 UI 阻塞
- 添加 HMAC 密钥文件安全 ACL，仅允许 Administrators 和 SYSTEM 账户访问
- 添加 NTFS Junction 点检测方法 (IsJunction)，使用 DeviceIoControl 检测重解析点
- 添加 ALL_FIREWALL_PROFILES 常量，设置为 7 使规则应用到所有配置文件（Domain+Private+Public）
- 添加 FileSystemWatcher_Created 事件中 .exe 扩展名验证
- 添加 removeFolderButton_Click 中 RemoveFolderRules 调用，删除文件夹时同步删除关联规则

### 修改
- 增强 COM 对象验证，使用 IsAssignableFrom() 和 GUID 比较替代直接类型相等检查
- 改进原子写操作 (AtomicWriteAllText/AtomicWriteAllBytes)，添加 try-finally 清理临时文件
- 更新 Config.VerifyConfigIntegrity() 返回 false 处理不存在的文件
- 更新 ComHelper.AtomicWriteAllText() 处理不存在的文件使用 File.Move
- 更新 FirewallService，在创建 FirewallPolicy 和 FirewallRule COM 对象后调用 ValidateComObjectType()
- 更新 Form1.cs，在配置加载和保存时调用 VerifyConfigIntegrity() 和 SaveConfigIntegrityHash()
- 更新 LangManager，添加 6 个新的安全相关消息键

### 高危漏洞修复
- **ALL_FIREWALL_PROFILES 配置错误 (H-005)**: 修正 ALL_FIREWALL_PROFILES 从 2 改为 7，确保规则应用到所有防火墙配置文件

### 中危漏洞修复
- **HMAC 密钥明文存储风险 (M-005)**: 使用 Windows DPAPI 加密存储 HMAC 密钥，防止密钥泄露
- **关键操作缺乏用户确认 (M-006)**: 规则 Action/Direction 变更时显示安全确认对话框，防止误操作
- **UI 阻塞操作缺乏超时处理 (M-007)**: 关键操作使用 async/await + Task.WhenAny 实现超时控制

### 低危漏洞修复
- **COM 对象验证不足 (L-006)**: 使用 IsAssignableFrom() 和 GUID 比较增强 COM 对象类型验证
- **原子写操作资源泄漏 (L-007)**: 添加 try-finally 块确保临时文件清理
- **HMAC 密钥文件权限过宽 (L-008)**: 使用 SetSecureFilePermissions() 限制文件访问权限
- **Junction 点检测缺失 (L-009)**: 添加 IsJunction() 方法检测 NTFS 重解析点
- **规则删除不完整 (L-010)**: 删除文件夹时同步删除关联的防火墙规则

## [1.6.0] - 2026-05-22

### 新增
- 全面的安全漏洞风险评估与修复，覆盖所有源代码文件
- 添加配置文件完整性校验保护（HMAC-SHA256），防止配置文件被篡改
- 创建安全漏洞修复报告（SECURITY_REPORT.md），包含 13 个漏洞的详细信息
- 创建安全编码规范文档（docs/SECURITY_CODING_STANDARDS.md），涵盖 10 个安全领域
- 创建漏洞响应流程文档（docs/VULNERABILITY_RESPONSE.md），定义完整漏洞生命周期
- 创建安全测试指南文档（docs/SECURITY_TESTING_GUIDE.md），包含测试方法和用例规范

### 修改
- 更新 README.md，添加安全文档章节和 v1.6.0 版本历史
- 更新 CHANGELOG.md，记录 v1.6.0 所有变更

### 高危漏洞修复
- **路径注入漏洞 (H-001)**: 添加 `NormalizeAndValidatePath` 方法，拒绝特殊路径前缀和符号链接
- **重命名事件路径验证缺失 (H-002)**: 添加路径规范化和符号链接检测
- **TOCTOU 竞态条件 (H-003)**: 添加 `WaitForFileReady` 重试机制
- **白名单加载路径校验缺失 (H-004)**: 添加路径验证、大小限制和完整性校验

### 中危漏洞修复
- **日志导出路径遍历 (M-001)**: 添加路径规范化和 UNC 路径拒绝
- **COM 对象动态调用风险 (M-002)**: 添加安全属性访问和类型验证方法
- **日志注入攻击 (M-003)**: 添加控制字符过滤、敏感信息脱敏
- **日志频率限制缺失 (M-004)**: 添加日志频率限制和文件大小管理

### 低危漏洞修复
- **MD5 哈希算法风险 (L-001)**: 替换为 SHA256
- **调试输出信息泄露 (L-002)**: 添加 Conditional 属性
- **JSON 反序列化验证不足 (L-003)**: 添加格式验证和语言代码检查
- **资源释放不完整 (L-004)**: 正确实现 Dispose 模式
- **配置文件完整性校验缺失 (L-005)**: 添加 HMAC-SHA256 校验

## [1.5.0] - 2026-05-21

### 新增
- 创建 xUnit 自动化测试项目 (`FirewallManager.Tests`)，包含 76 个测试用例
- 添加 FirewallService 单元测试（规则管理、COM 类型安全验证、路径哈希）
- 添加 LogManager 单元测试（日志注入防御、控制字符过滤、敏感信息脱敏）
- 添加 LangManager 单元测试（翻译回退机制、格式化参数、语言切换）
- 添加 PathSecurity 单元测试（符号链接检测、路径规范化、TOCTOU 缓解）
- 添加 WhitelistForm 单元测试（白名单查找、空值防护、缓存一致性）
- 添加 Config 单元测试（关键程序列表完整性、配置常量验证）

### 修改
- 更新 FirewallManager.csproj，排除测试项目文件避免编译冲突
- 更新 README.md，添加测试项目文档和 Release 编译说明
- Release 编译（去除全部调试符号和 DEBUG 条件代码）
- 项目版本号更新到 1.5.0

### 修复
- 修复 LangManager.FallbackTranslations 中的重复键问题（重复的 `logMessages.whitelistFileChangedCacheRefreshed` 条目）

## [1.4.1] - 2026-04-28

### 新增
- 在 Program.cs 中添加了 `Application.ApplicationExit` 事件处理程序，确保应用程序退出时正确释放资源
- 添加了应用程序退出消息的语言条目 (`applicationExiting`, `exitCleanupFailed`)

### 修改
- 修改了 `Form1_FormClosing` 事件，处理非用户触发的关闭事件（如任务管理器、系统关机）
- 更新了 README.md，添加中英文双语文档
- 更新了 CHANGELOG.md，补充详细版本历史

### 修复
- 修复了应用程序意外退出时的资源清理问题
- 删除了 Form1.cs 中重复的 `GetPathHash()` 和 `SanitizeRuleName()` 方法
- 删除了 Form1.cs 中未使用的 `addedRules` 和 `addedRulesLock` 字段
- 删除了 Form1.cs 中废弃的 `SyncRulesList()` 方法
- 将 UI 控件字段声明从 Form1.cs 移动到 Form1.Designer.cs

## [1.4.0] - 2026-04-27

### 新增
- 在 Form1.cs 中添加了 Dispose 方法，用于释放资源
- 为 WhitelistForm.IsInWhitelist 方法添加了静态缓存机制
- 创建了 FirewallService 类，分离防火墙操作逻辑与 UI 代码
- 为文件名/路径添加合法性校验，防止 COM 异常

### 修改
- 优化白名单检查效率，使用静态缓存避免重复读取文件
- 清理 Form1.cs 中重复的 COM 接口定义，使用 Config.cs 中的定义
- 改进异常处理，为加载操作添加用户反馈
- 优化 UpdateFirewallRules 方法，使用 async/await 和 Task.WhenAll 进行并行扫描
- 将所有用户可见的硬编码中文字符串替换为 LangManager.GetText 调用

### 修复
- 删除 Form1.cs 中的 UI 控件字段声明，避免与 Form1.Designer.cs 中的声明冲突
- 修复 whitelistButton 文本硬编码问题，使用 LangManager
- 修复 UpdateFirewallRules 方法中的变量命名冲突
- 修复线程安全问题，为 addedRules 列表添加了线程同步
- 修复防火墙策略对象空保护问题，初始化失败时禁用相关功能
- 修复 LogManager.cs 中的日志清理竞争条件问题
- 为 WhitelistForm.cs 中的 IsInWhitelist 静态缓存添加线程同步
- 修复 Form1.cs 中 CancellationTokenSource 未释放的问题
- 实现 Form1.cs 的 Dispose 模式，确保资源正确释放
- 修复多处硬编码中文字符串，使用国际化

## [1.3.0] - 2026-04-21

### 新增
- 白名单保存事件，当白名单保存时自动更新防火墙规则

### 修改
- 优化白名单管理窗口布局，按钮排列更合理
- 改进白名单检查逻辑，确保白名单正确应用

### 修复
- 修复白名单管理功能，移除白名单中的程序后自动更新防火墙规则
- 修复语言文件关联问题，确保所有按钮文本正确显示
- 修复变量名冲突问题

## [1.2.0] - 2026-04-21

### 新增
- 新增自动监控功能，实时监控文件夹变化并自动创建规则
- 新增规则详情窗体，查看和编辑规则详细信息
- 新增白名单管理功能，排除不需要阻止的应用程序
- 新增托盘菜单更新规则功能，无需打开主窗口
- 完善多语言支持，包括中文和英文
- 支持白名单持久化存储
- 支持自动监控状态记忆

### 修改
- 优化用户界面，添加白名单管理和自动监控控件
- 改进自动监控算法，提高监控效率
- 优化白名单检查逻辑，确保白名单正确应用
- 改进规则详情显示，提供更详细的规则信息

### 修复
- 修复自动监控时的文件系统事件处理问题
- 修复白名单管理时的路径验证问题
- 修复规则详情编辑时的状态同步问题
- 修复多语言切换时的界面更新问题

## [1.1.0] - 2026-04-21

### 新增
- 新增粘贴路径功能，支持从剪贴板粘贴多个路径
- 完善日志系统，详细记录所有操作
- 支持查看和管理日志
- 日志文件自动管理和清理
- 支持文件路径哈希值，避免同名文件冲突

### 修改
- 优化用户界面，调整按钮布局
- 优化日志窗口布局，按钮位于底部
- 改进扫描算法，提高扫描效率
- 优化多线程处理，减少资源占用
- 改进规则检查逻辑，确保规则状态准确

### 修复
- 修复扫描过程中可能出现的崩溃问题
- 修复规则删除时的线程安全问题
- 修复日志查看窗口的显示问题
- 修复清空规则后更新时的计数问题
- 修复手动删除规则后更新时的状态同步问题

## [1.0.0] - 2025-12-17

### 新增
- 初始版本发布
- 支持为单个可执行文件创建防火墙规则
- 支持扫描文件夹，为所有可执行文件批量创建防火墙规则
- 支持删除单个或所有防火墙规则
- 支持监控指定文件夹，自动为新添加的可执行文件创建规则
- 支持暂停、恢复和终止扫描过程
- 实时显示扫描进度
- 支持托盘图标，方便后台运行
- 支持白名单管理
- 支持查看规则详情
