# FirewallManager

## 项目概述


FirewallManager是一个Windows防火墙出站规则管理工具，用于帮助用户管理Windows防火墙的出站连接规则。该工具提供了一个直观的图形界面，允许用户轻松添加、删除和管理防火墙规则，特别适合需要批量管理大量可执行文件的场景。

**最新版本**: 1.9.1 (2026-08-18)  
**安全等级**: 优秀 (A-)  
**编译状态**: ✅ 无错误无警告

## 功能特性

### 1. 防火墙规则管理
- 为单个可执行文件创建防火墙规则
- 扫描文件夹，为所有可执行文件批量创建防火墙规则
- 删除单个或所有防火墙规则
- 查看和管理现有规则
- 支持从剪贴板粘贴路径（支持多个路径）

### 2. 规则监控与更新
- 监控指定文件夹，自动为新添加的可执行文件创建规则
- 支持暂停、恢复和终止扫描过程
- 实时显示扫描进度
- 智能规则检查，确保规则状态准确
- 支持文件路径哈希值，避免同名文件冲突
- 自动监控功能，实时监控文件夹变化并自动创建规则

### 3. 日志系统
- 详细记录所有操作，包括规则创建、更新和删除
- 支持查看日志历史
- 日志文件自动管理和清理
- 支持清空、复制和导出日志

### 4. 用户界面
- 直观的图形界面，易于操作
- 支持托盘图标，方便后台运行
- 实时显示操作状态和进度
- 日志窗口底部按钮布局，操作更便捷
- 规则详情窗体，查看和编辑规则详细信息
- 白名单管理，排除不需要阻止的应用程序
- 多语言支持，包括中文和英文
- 托盘菜单更新规则功能，无需打开主窗口

### 5. 安全特性
- **配置文件完整性保护**: 使用 HMAC-SHA256 校验配置文件完整性，防止篡改
- **HMAC 密钥加密**: 使用 Windows DPAPI 加密存储 HMAC 密钥，防止密钥泄露
- **安全文件权限**: HMAC 密钥文件仅允许 Administrators 和 SYSTEM 账户访问
- **安全确认对话框**: 修改规则 Action/Direction 时要求用户确认
- **路径安全验证**: 拒绝符号链接、NTFS Junction 点、扩展长度路径和 UNC 路径
- **TOCTOU 防护**: 文件系统操作添加等待机制，防止竞态条件攻击
- **日志安全**: 控制字符过滤、敏感信息脱敏、频率限制
- **COM 对象安全**: 类型验证和安全属性访问，防止 COM 对象劫持
- **规则应用到所有配置文件**: 防火墙规则应用到 Domain、Private 和 Public 所有配置文件

## 系统要求

- 操作系统：Windows 10/11
- .NET Framework：.NET 10.0
- 权限：管理员权限（用于修改防火墙规则）

##  安装说明

1. 下载FirewallManager安装包
2. 双击安装包，按照提示完成安装
3. 安装完成后，在开始菜单中找到FirewallManager并启动
4. 首次运行时，系统会提示需要管理员权限，点击"是"允许

## 使用指南

###  添加防火墙规则

#### 1: 添加单个可执行文件
1. 点击"添加"按钮，选择"添加文件"
2. 在文件选择对话框中选择要添加规则的可执行文件
3. 点击"确定"，系统会为该文件创建防火墙规则

#### 2: 添加文件夹
1. 点击"添加"按钮，选择"添加文件夹"
2. 在文件夹选择对话框中选择要扫描的文件夹
3. 点击"确定"，系统会将该文件夹添加到监控列表

#### 3: 粘贴路径

1. 复制一个或多个文件/文件夹路径到剪贴板
2. 右键点击监控列表，选择"粘贴"
3. 系统会自动解析剪贴板中的路径并添加到监控列表

### 更新防火墙规则

1. 确保监控列表中包含要扫描的文件夹或文件
2. 点击"更新规则"按钮
3. 系统会扫描所有监控的文件夹，为新发现的可执行文件创建防火墙规则
4. 扫描过程中可以暂停、恢复或终止操作

### 删除防火墙规则

####  删除单个规则

1. 在监控列表中选择要删除的项目
2. 点击"删除文件夹"按钮
3. 系统会删除该项目对应的防火墙规则

#### 删除所有规则

1. 点击"清空规则"按钮
2. 系统会删除所有由本程序创建的防火墙规则

###  查看日志

1. 点击"查看日志"按钮
2. 在日志窗口中可以查看所有操作记录
3. 支持清空日志

### 白名单管理

1 . 点击"白名单管理"按钮
2. 在白名单管理窗口中，可以添加、删除白名单项目
3. 白名单中的应用程序将不会被防火墙规则阻止
4. 点击"保存"按钮保存白名单设置

### 查看规则详情

1. 在未来版本中，将支持通过右键菜单查看规则详情
2. 规则详情窗体将显示规则的详细信息，包括名称、描述、应用程序路径等
3. 支持编辑规则属性

### 自动监控

1. 勾选"启用自动监控"复选框
2. 系统将实时监控监控列表中的文件夹
3. 当发现新的可执行文件时，系统会自动为其创建防火墙规则
4. 自动监控会跳过白名单中的应用程序

## 代码结构

### 核心文件

| 文件 | 描述 |
|------------|-------------------|
| FirewallManager.csproj | 项目配置文件 |
| Program.cs | 应用程序入口 |
| form1.cs | 主窗体实现 |
| Form1.Designer.cs | 主窗体设计器代码 |
| FirewallService.cs | 防火墙服务类，封装防火墙操作逻辑 |
| LogManager.cs | 日志管理类 |
| LogsForm.cs | 日志查看窗体 |
| RulesDetailsForm.cs | 规则详情窗体 |
| WhitelistForm.cs | 白名单管理窗体 |

### 核心类

#### Form1

- 应用程序主窗体，负责处理用户交互和管理防火墙规则
- 主要方法：
  - `CreateFirewallRuleForSingleExe`：为单个可执行文件创建防火墙规则
  - `UpdateFirewallRules`：更新所有防火墙规则
  - `RemoveFirewallRule`：删除单个防火墙规则
  - `ClearAllFirewallRules`：清空所有防火墙规则

#### FirewallService

- 防火墙服务类，封装防火墙操作逻辑
- 主要方法：
  - `InitializeFirewallComponents`：初始化防火墙组件
  - `CreateRuleForExe`：为可执行文件创建防火墙规则
  - `UpdateFirewallRules`：更新所有防火墙规则
  - `ClearAllRules`：清空所有防火墙规则
  - `GetRuleDetails`：获取规则详细信息
  - `GetPathHash`：生成文件路径的 SHA256 哈希值
  - `SanitizeRuleName`：清理规则名称中的不安全字符
  - `CheckRuleExists`：检查防火墙规则是否存在

#### LogManager

- 负责记录和管理应用程序日志
- 主要方法：
  - `Log`：记录日志
  - `ReadLogs`：读取日志
  - `ClearLogs`：清空日志

#### LangManager

- 国际化管理类，负责加载和管理语言文件
- 主要方法：
  - `GetText`：获取翻译文本（支持格式化参数）
  - `SetLanguage`：切换显示语言
  - `GetCurrentLanguage`：获取当前语言代码
- 内置回退翻译字典，语言文件加载失败时使用

#### Config

- 配置类，包含所有配置常量
- 关键常量：
  - `CRITICAL_PROGRAMS`：系统关键程序列表（20个系统进程）
  - `RULE_NAME_PREFIX`：规则名称前缀
  - `DEFAULT_LANGUAGE`：默认语言

#### WhitelistForm

- 白名单管理窗体，用于管理白名单
- 使用 HashSet 实现 O(1) 查找缓存
- 支持文件系统监控器，自动刷新缓存

#### LogsForm

- 日志查看窗体，用于显示和管理日志

#### RulesDetailsForm

- 规则详情窗体，用于查看和编辑防火墙规则详情

### 测试项目

| 文件 | 描述 |
|------------|-------------------|
| FirewallManager.Tests.csproj | 测试项目配置文件 |
| FirewallServiceTests.cs | 防火墙服务单元测试 |
| LogManagerTests.cs | 日志管理单元测试（含日志注入防御测试） |
| LangManagerTests.cs | 国际化管理单元测试（含回退机制测试） |
| PathSecurityTests.cs | 路径安全验证单元测试 |
| WhitelistFormTests.cs | 白名单管理单元测试 |
| ConfigTests.cs | 配置类单元测试 |

## 技术实现

### 1. 防火墙规则管理

使用Windows COM API (`HNetCfg.FwPolicy2`和`HNetCfg.FwRule`)来管理防火墙规则。主要步骤包括：

1. 创建COM对象：`Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"))`
2. 创建防火墙规则对象：`Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwRule"))`
3. 设置规则属性（名称、描述、应用程序路径、操作、方向、协议等）
4. 将规则添加到防火墙策略中：`firewallPolicy.Rules.Add(firewallRule)`

### 2.多线程处理

使用`Task`和`async/await`模式实现异步操作，避免UI阻塞。主要用于：
- 扫描文件夹中的可执行文件
- 更新防火墙规则
- 清理日志文件

### 3. 线程安全

使用以下机制确保线程安全：
- `lock`语句：保护共享资源的访问
- `ConcurrentDictionary`：线程安全的字典，用于存储规则映射和缓存
- `SemaphoreSlim`：限制并发IO操作数量
- `SafeInvoke`：确保UI更新在UI线程中执行

### 4. 日志系统

使用文件系统存储日志，支持以下功能：
- 自动清理旧日志，限制日志文件大小
- 支持多种日志级别（Debug、Info、Warning、Error）
- 实时日志更新通知
- 日志查看和清空功能

## 常见问题

### 1. 为什么需要管理员权限？

修改Windows防火墙规则需要管理员权限，这是Windows操作系统的安全要求。

### 2. 如何查看日志文件？

日志文件存储在`%LocalAppData%\FirewallManager\FirewallManager.log`路径下。您也可以通过应用程序的"查看日志"按钮直接查看日志。

### 3. 如何卸载FirewallManager？

直接删除FirewallManager文件夹即可

### 4. 为什么某些可执行文件没有被扫描到？

请确保：
- 该文件是可执行文件（.exe后缀）
- 该文件位于监控列表中的文件夹内
- 该文件不是系统文件或受保护文件

## 开发说明

### 安全文档

项目包含完整的安全文档体系，存放于 `docs/` 目录：

| 文档 | 描述 |
|------|-------------------|
| [SECURITY_REPORT.md](SECURITY_REPORT.md) | 安全漏洞修复报告，包含 13 个已修复漏洞的详细信息 |
| [docs/SECURITY_CODING_STANDARDS.md](docs/SECURITY_CODING_STANDARDS.md) | 安全编码规范，涵盖输入验证、输出编码、COM安全等 10 个方面 |
| [docs/VULNERABILITY_RESPONSE.md](docs/VULNERABILITY_RESPONSE.md) | 漏洞响应流程，定义从发现到修复的完整生命周期 |
| [docs/SECURITY_TESTING_GUIDE.md](docs/SECURITY_TESTING_GUIDE.md) | 安全测试指南，包含测试方法、用例规范和回归流程 |

### 开发环境

- Visual Studio 2022
- .NET 10.0
- Windows 10/11

### 编译项目

#### Release 编译（发布版本，不含调试信息）

```cmd
dotnet build -c Release
```

编译成功后，可执行文件位于 `bin\Release\net10.0-windows` 目录下。

#### Debug 编译（调试版本）

```cmd
dotnet build -c Debug
```

编译成功后，可执行文件位于 `bin\Debug\net10.0-windows` 目录下。

> 注意：无论 Debug 还是 Release 编译，均不生成调试符号（DebugType=none, DebugSymbols=false）。
> Release 编译会自动去除所有 `[Conditional("DEBUG")]` 方法。

### 运行测试

项目包含 xUnit 单元测试套件，共 76 个测试用例，覆盖所有核心功能模块：

```cmd
cd FirewallManager.Tests
dotnet test
```

#### 测试覆盖范围

| 测试模块 | 测试数 | 覆盖内容 |
|------------|--------|------------------------------|
| FirewallService | 17 | 规则管理、COM 类型安全、路径哈希、规则名称清理 |
| LogManager | 20 | 日志注入防御、控制字符过滤、敏感信息脱敏、多级别日志 |
| LangManager | 14 | 翻译获取、回退机制、格式化参数、语言切换 |
| PathSecurity | 14 | 符号链接检测、路径规范化、系统目录防护、TOCTOU 缓解 |
| WhitelistForm | 5 | 白名单查找、空值防护、缓存一致性 |
| Config | 11 | 关键程序列表完整性、配置常量验证 |

### 调试说明

- 以管理员身份运行 Visual Studio，否则无法调试防火墙相关功能
- 日志记录功能可以帮助调试问题

## 版本历史

### v1.9.1

- **代码质量提升**: 消除所有编译警告（4个→0个），代码质量从良好提升到优秀
- **递归调用修复**: 修复 LangManager 中 JSON 解析的递归调用风险，防止堆栈溢出
- **语言验证增强**: 改进语言代码验证，符合 BCP 47 国际标准
- **剪贴板稳定性**: 增强剪贴板访问机制，使用指数退避策略提高成功率
- **密钥生成回退**: 添加 HMAC 密钥生成的多层回退机制，确保系统健壮性
- **性能优化**: 优化 COM 对象调用和文件读取性能
- **错误处理增强**: 改进所有关键操作的错误处理和日志记录
- 更新项目版本号到 1.9.1

### v1.9.0

- **COM 对象验证修复**: 修复 COM 对象 CLSID/IID 验证逻辑，添加回退机制，解决 `80040154 (REGDB_E_CLASSNOTREG)` 错误
- **路径验证简化**: 简化 `NormalizeAndValidatePath` 方法，移除过于严格的 reparse point 检查，解决系统目录被拒绝的问题
- **GetRealPath 简化**: 简化 `GetRealPath` 方法实现，移除复杂的 Win32 API 调用，使用 `Path.GetFullPath()` 直接获取规范化路径
- **剪贴板访问改进**: 添加剪贴板访问重试机制（3次，每次间隔100ms），解决 `Clipboard.GetText()` 权限问题
- **COM 对象分离验证**: 分离 CLSID 和 IID 验证逻辑，当 CLSID 验证通过时即使 IID 验证失败也允许使用对象
- **调试日志增强**: 添加详细的路径验证调试日志，便于排查路径验证失败问题
- **配置文件 BOM 修复**: 修复配置文件 UTF-8 BOM 问题，保存时使用 `Utf8NoBom` 编码
- **更新项目版本号到 1.9.0**

### v1.8.0

- **签名验证增强**: 添加 `WinVerifyTrust` API 调用，验证文件签名完整性（不仅仅是证书链）
- **COM 对象验证改进**: 改用 CLSID/IID 验证，移除 ProgID 依赖，防止 ProgID 劫持
- **TOCTOU 防护**: 添加 `VerifyConfigIntegrityAndRead` 方法，在锁定状态下完成验证和读取
- **目录打开修复**: 使用 `CreateFile` API 打开目录并添加 `FILE_FLAG_BACKUP_SEMANTICS` 标志
- **规则名称验证**: 在 `UpdateRule` 和 `DeleteRule` 中添加规则名称验证（空检查 + 长度限制 256 字符）
- **更新项目版本号到 1.8.0**

### v1.7.0

- **安全加固**: 进一步安全漏洞修复，修复 9 个安全漏洞（1 高危、3 中危、5 低危）
- **HMAC 密钥加密**: 使用 Windows DPAPI (ProtectedData.Protect) 加密存储 HMAC 密钥
- **安全文件权限**: 使用 SetSecureFilePermissions() 限制 HMAC 密钥文件仅允许 Administrators 和 SYSTEM 访问
- **安全确认对话框**: 修改规则 Action/Direction 时要求用户确认，防止误操作
- **异步超时处理**: 关键操作使用 async/await + Task.WhenAny 实现超时控制，防止 UI 阻塞
- **Junction 点检测**: 添加 IsJunction() 方法检测 NTFS 重解析点（tag 0xA0000003）
- **COM 对象验证增强**: 使用 IsAssignableFrom() 和 GUID 比较替代直接类型相等检查
- **规则应用到所有配置文件**: 修正 ALL_FIREWALL_PROFILES 为 7，确保规则应用到 Domain+Private+Public
- **规则删除完整性**: 删除文件夹时同步删除关联的防火墙规则
- **原子写操作改进**: 添加 try-finally 块确保临时文件清理
- **更新项目版本号到 1.7.0**

### v1.6.0

- **安全加固**: 全面安全漏洞风险评估与修复，修复 13 个安全漏洞（4 高危、4 中危、5 低危）
- **路径安全**: 添加路径规范化验证，拒绝特殊路径前缀和符号链接
- **TOCTOU防护**: 添加文件写入等待机制，防止竞态条件攻击
- **日志安全**: 添加控制字符过滤、敏感信息脱敏、频率限制
- **COM安全**: 添加 COM 对象安全访问方法，防止异常崩溃
- **配置文件安全**: 添加 HMAC-SHA256 完整性校验保护
- **新增安全文档**: 安全漏洞修复报告、安全编码规范、漏洞响应流程、安全测试指南
- **安全回归测试**: 所有 76 项安全测试用例全部通过
- **更新项目版本号到 1.6.0**

### v1.5.0

- 创建 xUnit 自动化测试套件，共 76 个测试用例覆盖所有核心模块
- 添加 FirewallService、LogManager、LangManager、PathSecurity、WhitelistForm、Config 单元测试
- 修复 LangManager.FallbackTranslations 重复键 Bug
- Release 编译优化，去除调试符号
- 更新项目版本号到 1.5.0

### v1.4.1

- 在Program.cs中添加了`Application.ApplicationExit`事件处理程序，确保应用程序退出时正确释放资源
- 修改了`Form1_FormClosing`事件，处理非用户触发的关闭事件（如任务管理器、系统关机）
- 添加了应用程序退出消息的语言条目
- 修复了应用程序意外退出时的资源清理问题

### v1.4.0

- 修复防火墙策略对象空保护问题，初始化失败时禁用相关功能
- 修复 LogManager.cs 中的日志清理竞争条件问题
- 为 WhitelistForm.cs 中的 IsInWhitelist 静态缓存添加线程同步
- 修复 Form1.cs 中 CancellationTokenSource 未释放的问题
- 实现 Form1.cs 的 Dispose 模式，确保资源正确释放
- 修复多处硬编码中文字符串，使用国际化
- 为 Form1.cs 中的文件名/路径添加合法性校验
- 创建了 FirewallService 类，分离防火墙操作逻辑与 UI 代码
- 优化 UpdateFirewallRules 方法，使用 async/await 和 Task.WhenAll 进行并行扫描
- 版本号更新到1.4.0

### v1.3.0

- 修复白名单管理功能，移除白名单中的程序后自动更新防火墙规则
- 优化白名单管理窗口布局，按钮排列更合理
- 修复语言文件关联问题，确保所有按钮文本正确显示
- 增强系统稳定性和错误处理
- 版本号更新到1.3.0

### v1.2.0

- 新增自动监控功能，实时监控文件夹变化并自动创建规则
- 新增规则详情窗体，查看和编辑规则详细信息
- 新增白名单管理功能，排除不需要阻止的应用程序
- 新增托盘菜单更新规则功能，无需打开主窗口
- 完善多语言支持，包括中文和英文
- 优化用户界面，添加白名单管理和自动监控控件
- 增强系统稳定性和错误处理

### v1.1.0

- 新增粘贴路径功能，支持从剪贴板粘贴多个路径
- 改进规则检查逻辑，确保规则状态准确
- 添加文件路径哈希值，避免同名文件冲突
- 优化日志窗口布局，按钮位于底部
- 修复清空规则后更新时的计数问题
- 增强系统稳定性和错误处理

### v1.0.0

- 初始版本
- 支持添加、删除和管理防火墙规则
- 支持文件夹扫描和批量创建规则
- 支持日志查看和管理
- 支持白名单管理
