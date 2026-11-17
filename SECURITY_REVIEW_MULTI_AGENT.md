# FirewallManager 多 Agent 协同安全审查报告

| 项目 | 内容 |
|------|------|
| 审查对象 | FirewallManager v1.9.4（.NET 10 WinForms，本地 Windows 防火墙规则管理工具） |
| 审查范围 | 全量源代码（16 个 `.cs` 文件 + 语言资源 + 项目配置），非 diff |
| 审查日期 | 2026-11-17 |
| 审查方式 | 静态代码分析 + 控制流/数据流追踪 + 信任边界校验 + 多 Agent 交叉验证 |
| 代码变更 | 本次审查 **未修改任何代码**，仅产出问题与建议 |
| 关联文档 | [FIREWALL_MANAGER_AUDIT_REPORT.md](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/FIREWALL_MANAGER_AUDIT_REPORT.md)（第二轮复审 R/X 系列） |

---

## 一、审查方法与团队分工

### 1.1 多 Agent 角色分工

| 角色 | 覆盖职责 | 主要审查文件 |
|------|---------|-------------|
| **A. COM 与密码学审计员** | COM 激活信任链、注册表视图/重定向、HMAC 完整性、DPAPI 密钥、reparse point、ACL、原子写 | [ComHelper.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/ComHelper.cs)、[Config.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/Config.cs)、[TargetStore.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/TargetStore.cs) |
| **B. 规则生命周期审计员** | 规则归属判定、扫描/删除路径、并发与 COM 亲和性、失败语义 | [FirewallService.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/FirewallService.cs)、[RuleNamingService.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/RuleNamingService.cs) |
| **C. 输入边界与信息流审计员** | UI 输入、配置导入导出、白名单、语言资源、日志、异常处理 | [Form1.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/Form1.cs)、[WhitelistForm.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/WhitelistForm.cs)、[LangManager.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/LangManager.cs)、[LogManager.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/LogManager.cs)、[Program.cs](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/Program.cs) |
| **主审（交叉验证）** | 对三组 Findings 逐条读码复核 source→sink，剔除误报、统一定级 | 全部 |

### 1.2 多维度检测手段与覆盖情况

| 维度 | 是否执行 | 说明 |
|------|---------|------|
| 静态代码分析 | ✅ 已执行 | 全量逐文件阅读 + 跨文件调用链追踪（UI → Service → COM / 文件系统） |
| 逻辑缺陷分析 | ✅ 已执行 | 归属判定、失败分支、状态机、验证顺序、规范化一致性 |
| 边界校验 | ✅ 已执行 | 路径前缀、UNC、reparse point、大小写、ACL 属主、注册表视图 |
| 渗透测试验证 | ⚠️ 逻辑推演 | 以「攻击者可控输入 → 危险 sink」的完整链路推演替代实机利用；未在用户机器上创建真实防火墙规则 |
| 动态行为监测 | ❌ 未执行 | 需交互式提权 GUI 会话；且修改真实防火墙规则会违反「不影响业务运行」的要求 |
| 流量审计 | ❌ 不适用 | 程序无网络监听/无 HTTP 客户端；唯一网络行为是 UNC 路径触发的 SMB 认证（见 V-01），已通过代码路径确认 |

> 「0day」在本报告语境中指**该代码库中尚未被记录、未公开的缺陷**，而非第三方组件的未知 CVE。未进行依赖组件 CVE 比对（属另一类工具职责）。

---

## 二、结论摘要

共确认 **10 项** 安全缺陷（去重并剔除 9 项误报后）：

| 严重度 | 数量 | 编号 |
|--------|------|------|
| 高危 | 1 | V-01 |
| 中危 | 5 | V-02 ~ V-06 |
| 低危 | 4 | V-07 ~ V-10 |

**总体判断**：上一轮修复（R/X 系列）显著提升了 COM 激活信任链、配置完整性与规则归属判定的强度，**未发现可绕过 COM 预校验或 HMAC 的直接提权链**。本次新发现的问题集中在三类：

1. **路径信任边界不完整**（V-01 ~ V-03）：UNC 未被拒绝、reparse 检查顺序颠倒、监控根目录未校验，导致「提权进程被诱导去操作用户指定之外的路径或主机」。
2. **失败语义不安全**（V-04、V-06）：加固失败被静默吞掉、关键 COM 属性写入返回值被忽略，使安全控制在失败时不是「阻断」而是「降级」。
3. **完整性/自动化流程绕过**（V-05、V-07）：系统目录白名单过宽、白名单编辑器绕过 HMAC 校验。

---

## 三、漏洞详情

### V-01 【高危】监控路径接受 UNC，校验阶段即以管理员凭据连接任意 SMB 主机

- **位置**：[Form1.cs:215-281](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/Form1.cs#L215-L281)（关键点 [L247](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/Form1.cs#L247)、[L267](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/Form1.cs#L267)）；导入路径 [Form1.cs:1721](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/Form1.cs#L1721)
- **类别**：信任边界 / 凭据泄露（CWE-73、CWE-522）
- **证据（Source → Sink）**
  - Source：粘贴框 / 配置导入 JSON 中的路径字符串。
  - 处理：`NormalizeAndValidatePath` 只剥离 `\\?\` 前缀，**在第 237-240 行还会把 `\\?\UNC\server\share` 主动还原成 `\\server\share`**；第 267 行用 `Path.IsPathRooted` 判断「本地盘符」，而 UNC 路径同样返回 `true`，该检查形同虚设。
  - Sink：[L247](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/Form1.cs#L247) 的 `Directory.Exists(realPath)` 在校验阶段就发起 SMB 连接；加入监控后 `Directory.GetFiles`、`FileSystemWatcher`、`RemoveFolderRules` 会以管理员身份持续访问该共享。
  - 对照基线：[WhitelistForm.cs:574-579](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/WhitelistForm.cs#L574-L579) 明确拒绝所有 `\\` 前缀，说明「拒绝 UNC」是本项目既定安全策略，监控路径上属于遗漏。
- **利用条件**：管理员执行一次粘贴或导入（社交工程即可，无需代码执行）；攻击者控制一个 SMB 主机/共享。
- **复现路径**
  1. 攻击者提供目录字符串 `\\attacker.example\share\payload`（伪装成「共享目录」）。
  2. 管理员粘贴后程序校验通过（`Directory.Exists` 触发），日志显示「路径验证成功」。
  3. 攻击者在 SMB 服务器侧收到管理员账号的 NetNTLMv2 认证，可离线破解或中继到其他主机。
  4. 程序继续对该 UNC 路径递归枚举、创建 `ApplicationName` 为 UNC 的 Block 规则——该规则对本地路径不生效，界面上却显示「已监控」。
- **影响范围**：管理员凭据泄露（可导致域内横向移动）；同时产生「看似已保护、实际未拦截」的安全假象。
- **修复建议**：在 `NormalizeAndValidatePath` 的规范化之后、任何文件系统 API 调用之前，拒绝 `\\`/`//` 开头的路径与 `\\?\UNC\` 形式；把「本地固定盘」判定从 `IsPathRooted` 改为 `Path.GetPathRoot(...)` 为单字母盘符，并对卷挂载/映射网络驱动器单独定义策略；导入流程复用同一校验函数（目前已复用，但需要补上拒绝逻辑）。

---

### V-02 【中危】watcher 先解链再检查 reparse，符号链接检测恒为假，可借提权进程封锁任意第三方程序

- **位置**：[Form1.cs:655-668](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/Form1.cs#L655-L668)
- **类别**：路径边界 / 权限边界绕过（CWE-59、CWE-863）
- **证据（Source → Sink）**
  - Source：攻击者在被监控目录内创建 `evil.exe` 符号链接，指向 `C:\Program Files\Vendor\edr.exe`。
  - 处理：第 656 行先用 `GetRealPath`（句柄级 `GetFinalPathNameByHandle`）把路径解析成 EDR 的真实路径；第 664 行才对**解析后的路径**调用 `HasReparsePointInPath`。解析结果链上已不含任何 reparse 组件，因此检查**永远返回 false**。
  - Sink：`CreateRuleForExe(fullPath)` 用真实路径生成规则并写入防火墙 → 提权进程为 EDR 创建出站 Block 规则。
- **利用条件**：攻击者对被监控目录（或其子目录）有写权限；创建**文件符号链接**需要 `SeCreateSymbolicLinkPrivilege`（启用「开发者模式」的非管理员默认具备）或管理员权限。目录 junction 无此门槛，但 watcher 只会为新建文件触发事件。
- **复现路径**
  1. 用户监控 `D:\Shared\Uploads`（该目录对普通用户可写）。
  2. 攻击者执行 `mklink D:\Shared\Uploads\update.exe "C:\Program Files\Vendor\edr.exe"`。
  3. watcher 触发 `FileSystemWatcher_Created` → 解链 → reparse 检查通过 → 以管理员权限把 `edr.exe` 的真实路径写入 Block 规则。
  4. EDR/更新器出站连接被切断，且日志显示这是「正常规则」。
- **影响范围**：任意第三方安全软件/业务程序可被静默断网；`IsCriticalSystemExecutable` 只保护 `%SystemRoot%`，`Program Files` 不受保护。
- **修复建议**：先对**原始路径**（`rawPath`，即用户/攻击者实际提交的对象）调用 `HasReparsePointInPath`，通过后再解链；解链后额外断言「解析结果仍位于该监控目标根目录之下」，两者任一失败即拒绝。

---

### V-03 【中危】监控根目录从不做 reparse 校验，扫描与监视会跟随 junction 越界

- **位置**：[Form1.cs:215-281](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/Form1.cs#L215-L281)、[Form1.cs:523-547](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/Form1.cs#L523-L547)；[FirewallService.cs:676](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/FirewallService.cs#L676)、[FirewallService.cs:811-816](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/FirewallService.cs#L811-L816)
- **类别**：路径边界（CWE-59）
- **证据（Source → Sink）**
  - Source：监控目标路径（用户输入或配置导入）。
  - 处理：`NormalizeAndValidatePath` 全程不调用 `HasReparsePoint`/`GetRealPath`；`CreateFileWatcher` 直接 `new FileSystemWatcher { Path = path, IncludeSubdirectories = true }`。
  - 关键点：`EnumerationOptions.AttributesToSkip = FileAttributes.ReparsePoint` **只过滤枚举出的子项，不过滤枚举根**。因此根目录本身是 junction 时，`Directory.GetFiles(root, ..., options)` 会整棵树跟随。
  - Sink：扫描结果被批量写入 Block 规则（[FirewallService.cs:676](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/FirewallService.cs#L676) 及后续 `CreateRuleForExe`）。
- **利用条件**：攻击者对**被监控目录的父目录**有写权限（如 `C:\Users\Public`、共享盘），把该目录替换为指向 `C:\Program Files\<目标>` 的 junction；随后用户触发「更新规则」或重启程序。
- **复现路径**
  1. 用户监控 `D:\Shared\Uploads`；攻击者拥有 `D:\Shared` 写权限。
  2. 删除并重建 `Uploads` 为 `mklink /J D:\Shared\Uploads "C:\Program Files\Vendor"`。
  3. 用户点击「更新规则」→ 管理员进程枚举 `C:\Program Files\Vendor` 全部 exe 并批量建 Block 规则。
- **影响范围**：监控范围越界，任意应用可被批量断网；与 V-02 叠加可掩盖攻击痕迹。
- **修复建议**：在 `NormalizeAndValidatePath` 中对目录型目标执行 `HasReparsePointInPath`（fail-closed）并在解链后断言路径未发生变化；`CreateFileWatcher` 与 `UpdateFirewallRules` 入口复用同一校验，避免三条路径（添加、扫描、监视）策略不一致。

---

### V-04 【中危】应用数据目录加固失败被静默忽略且进程内不重试，可稳定绕过配置完整性

- **位置**：[Config.cs:156-166](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/Config.cs#L156-L166)；[ComHelper.cs:861-924](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/ComHelper.cs#L861-L924)；[TargetStore.cs:88-125](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/TargetStore.cs#L88-L125)
- **类别**：权限边界 / 完整性绕过（CWE-732、CWE-703）
- **证据（Source → Sink）**
  - Source：攻击者在提权进程首次运行前，在自己 Profile 下预建 `%LOCALAPPDATA%\FirewallManager`，并为 `Administrators`/`SYSTEM` 添加一条 **Deny `WRITE_DAC`** 的显式 ACE，同时保留自身 FullControl。
  - 处理：`Config.GetAppDataFilePath` 第 164 行**先**置 `_appDataDirSecured = true`，第 165 行才调用 `SetSecureDirectoryPermissionsInternal`；后者内部 `SetAccessControl` 抛 `UnauthorizedAccessException` 后只 `LogManager.Warning`（[ComHelper.cs:918-924](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/ComHelper.cs#L918-L924)）。由于标志位已置真，本进程内不会重试，目录继续保持对当前用户可写。
  - Sink：攻击者删除 `config.json`、`config.json.hmac`、`hmac.key`，写入 v1 数组 `["C:\\任意目录"]`；`TargetStore.Load` 第 88 行判定 `!IntegrityFileExists && !HmacKeyFileExists` 成立 → 第 111 行接受数组迁移 → [L125](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/TargetStore.cs#L125) 为其重新签名。提权进程随后按攻击者指定的目录创建 Block 规则。
- **利用条件**：攻击者与运行程序的用户相同（可在 Profile 下建目录并设置 ACE）；程序以管理员身份启动一次。
- **复现路径**
  1. `mkdir %LOCALAPPDATA%\FirewallManager`（普通权限）。
  2. 用 `icacls` 给目录加 `Administrators:(D,WDAC)` 等拒绝 ACE，自身保留 `(F)`。
  3. 以管理员启动 FirewallManager → 日志出现「Failed to set owner / 权限加固失败」告警，但界面正常。
  4. 删除三个文件，写入 v1 数组配置，重启 → 配置被接受并回签，监控目标被劫持。
- **影响范围**：非管理员获得「控制提权进程监控目标」的能力，可让管理员权限的防火墙为任意目录批量建规则；HMAC 防篡改在事实上失效。
- **修复建议**：加固结果必须校验（读回 DACL/属主，或尝试以受限句柄验证写权限已消失），失败时不要置 `_appDataDirSecured`，并在 UI 上给出明确告警；`TargetStore` 的 v1 迁移应要求「目录加固成功 + 首次运行」双重前提，或通过一次性随机迁移令牌区分「升级」与「被清空」。

---

### V-05 【中危】规则属性写入返回值被忽略，可产生空 `ApplicationName` 的全局 Block 规则或不生效规则

- **位置**：[FirewallService.cs:81-119](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/FirewallService.cs#L81-L119)
- **类别**：失败语义不安全 / 安全控制失效（CWE-754、CWE-636）
- **证据（Source → Sink）**
  - Source：被监控目录中的 `.exe` 路径（可包含超长路径、攻击者可控文件名）。
  - 处理：`CreateAndAddFirewallRule` 对 `Name`/`Description`/`ApplicationName`/`Direction`/`Action`/`Enabled`/`Profiles` 的 `SafeSetProperty` **返回值全部丢弃**，随后无条件 `firewallPolicy.Rules.Add(newRule)` 并 `return true`（[L103-L114](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/FirewallService.cs#L103-L114)）。
  - Sink：
    - `ApplicationName` 写入失败 → 规则 `Action=Block`、`Enabled=true`、无应用限定 → **本机全部出站流量被阻断**，而目标 exe 反而未被针对性拦截；
    - `Action`/`Direction`/`Enabled` 写入失败 → 规则以 `Allow`/`Inbound`/`Disabled` 状态入库 → **目标程序未被拦截**；
    - 两种情况下 `addedRules` 都会记录该名称，后续 `CheckRuleExists` 返回 true，不再重建，程序无法自愈。
- **利用条件**：攻击者能在被监控目录放置一个使 `put_ApplicationName` 失败的路径（如超出 `MAX_PATH` 且系统未启用长路径、含非法字符），或 COM 调用瞬时失败。
- **影响范围**：全域断网（可用性）或目标恶意程序逃逸（完整性）；空 `ApplicationName` 的规则因 `IsRuleOwnedByUs` 恒为 false，`ClearAllRules` 也无法清理。
- **修复建议**：逐个校验 setter 结果，任一关键属性（`ApplicationName`、`Direction`、`Action`、`Enabled`）失败即放弃 `Add` 并记录错误；`Add` 之后回读 `ApplicationName` 断言等于预期路径；失败时不要把名称放入 `addedRules`。

---

### V-06 【中危】白名单编辑器不验证 HMAC 即回写并重签名，篡改内容被「合法化」

- **位置**：[WhitelistForm.cs:304-328](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/WhitelistForm.cs#L304-L328)、[WhitelistForm.cs:339-359](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/WhitelistForm.cs#L339-L359)
- **类别**：完整性校验绕过（CWE-345）
- **证据（Source → Sink）**
  - Source：被篡改的 `whitelist.json`（写入前提见 V-04，或程序被放在 FAT/非 ACL 介质上）。
  - 处理：`LoadWhitelist` 直接 `File.ReadAllText` + `JsonSerializer.Deserialize`，**完全不调用** `VerifyConfigIntegrityAndRead`（与 `RefreshWhitelistCache` 中经过 HMAC 校验的读取路径不一致）；`SaveWhitelist` 把 ListBox 内容整体序列化后写入，并调用 `SaveConfigIntegrityHash` 重新计算签名（返回值被忽略）。
  - Sink：被注入的任意 exe 路径在保存后获得「已签名 + 白名单」身份，`IsWhitelisted` 返回 true → 永不拦截。
- **利用条件**：攻击者能修改一次 `whitelist.json`；管理员随后打开「白名单」窗口并点击保存（打开即载入，改任意一项或直接保存均可）。
- **影响范围**：HMAC 防篡改设计在 UI 流程上被实质性绕过，任意程序可被静默放行。
- **修复建议**：`LoadWhitelist` 改用 `VerifyConfigIntegrityAndRead`，校验失败时拒绝载入并以只读/空状态提示；`SaveConfigIntegrityHash` 失败必须中断保存并回滚；ACL 加固应在写入之前应用到临时文件（原子写路径内完成），而不是写完之后再补。

---

### V-07 【低危】`UpdateRule` 缺少归属校验与 COM 类型校验

- **位置**：[FirewallService.cs:920-946](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/FirewallService.cs#L920-L946)
- **类别**：授权缺失（CWE-862）
- **证据（Source → Sink）**：`ruleName` 直接 `firewallPolicy.Rules.Item(ruleName)`，随后写入 `Description`/`Enabled`/`Direction`/`Action`；既没有 `DeleteRule` 中的 `IsRuleOwnedByCurrentProgram` 校验，也没有 `GetRuleDetails` 中的 `ValidateComObjectType`。规则列表来自 `SyncRulesList`，而它收录**任何** `Block_` 前缀规则。
- **利用条件**：需要存在与本程序命名完全一致的外部规则（128 bit 哈希碰撞不可行，只能是他方复刻命名或用户手工创建）；命中后可在「规则详情」窗体把 Block 改为 Allow 或直接取消启用。
- **影响范围**：阻断被静默解除；因可达性苛刻，定级低危。
- **修复建议**：`UpdateRule` 复用 `IsRuleOwnedByCurrentProgram` 与 COM 类型校验；`RuleDetailsForm` 对「取消启用」也加入二次确认。

---

### V-08 【低危】规则哈希与白名单均忽略大小写，在区分大小写的目录中可漏拦

- **位置**：[RuleNamingService.cs:43-46](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/RuleNamingService.cs#L43-L46)；[WhitelistForm.cs:42](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/WhitelistForm.cs#L42)、[WhitelistForm.cs:506](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/WhitelistForm.cs#L506)
- **类别**：逻辑缺陷导致策略绕过（CWE-178）
- **证据（Source → Sink）**：`NormalizePath` 用 `ToLowerInvariant()` 作为哈希输入；`whitelistCache` 使用 `StringComparer.OrdinalIgnoreCase`。在被 `fsutil file setCaseSensitiveInfo` 标记为区分大小写的目录中，`app.exe` 与 `APP.exe` 是两个真实文件，但生成**同一个**规则名、匹配**同一条**白名单项。
- **利用条件**：监控目录已启用大小写敏感（WSL/容器挂载、显式开启）；攻击者对该目录有写权限。
- **复现路径**：目录内已有 `app.exe`（被拦截并登记白名单或已建规则）→ 攻击者写入 `APP.exe` → `CheckRuleExists` 命中同名规则 → 新文件不建规则；若 `app.exe` 在白名单中，`APP.exe` 也一并免拦截。
- **影响范围**：单一目录内的漏拦；因前置条件特殊，定级低危。
- **修复建议**：以文件系统语义为准而不是无条件小写——先通过 `FileSystemInfo` 所在卷的大小写敏感性决定是否折叠大小写；或在规则名哈希中保留原始大小写，仅在比较时使用 `OrdinalIgnoreCase`。

---

### V-09 【低危】清空/删除失败后仍清空本地状态，规则视图与真实防火墙脱节

- **位置**：[FirewallService.cs:464-496](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/FirewallService.cs#L464-L496)
- **类别**：状态一致性 / 安全控制失效（CWE-664）
- **证据（Source → Sink）**：`ClearAllRules` 对单条删除失败只记 warning，随后在 [L494](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/FirewallService.cs#L494) **无条件** `addedRules.Clear()`；`addedRulesLookup` 同样清空。残留规则从本地视图消失，界面显示「已清空」，但防火墙中仍有 Block 规则；后续 `CheckRuleExists` 也不再识别它们。
- **利用条件**：删除过程中出现 COM 异常（策略服务繁忙、规则被组策略锁定）。
- **影响范围**：用户误判「已解除封锁」；残留规则导致程序持续断网且难以定位。
- **修复建议**：仅对确认删除成功的条目更新本地列表；失败条目保留并汇总提示；「清空」结束后重新 `SyncRulesList` 对齐真实状态。

---

### V-10 【低危】导入配置后不重建文件监视器

- **位置**：[Form1.cs:1703-1745](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/Form1.cs#L1703-L1745)
- **类别**：安全控制状态不同步（CWE-1059）
- **证据（Source → Sink）**：导入时清空 `monitoredTargets` 与列表（L1704-1705），但没有调用 `StopFileWatchers` / `InitializeFileWatchers`（对比「移除目标」路径 L1366-1391 与启动路径 L495-517）。
- **影响范围**：被移除目录的 watcher 继续以管理员权限为新 exe 建规则（用户不可见、无法按目录清理）；新导入目录在自动监控开启时也不会被监视，产生「应拦截而未拦截」的窗口。
- **修复建议**：导入成功后统一调用 `InitializeFileWatchers()`（内部会先 `StopFileWatchers`），并在 UI 上刷新监控状态。

---

## 四、交叉验证与误报排除

以下为 Agent 提出、经主审读码后**判定不成立或不可利用**的项：

| # | 被提出的问题 | 排除理由 |
|---|-------------|---------|
| 1 | `GetRuleDetails` 的 COM 类型校验可被绕过 | 反向问题：`ValidateComObjectType` 要求 `Type.GUID == 期望 CLSID`，而 `Rules.Item()` 返回 `System.__ComObject`（GUID 为空），因此**恒返回 false**，属功能缺陷（见 5.1），不构成安全绕过 |
| 2 | 激活后 `ValidateComObjectClsid` 失效导致可加载恶意 DLL | 该函数已明确降级为诊断用途；真正的信任判定在激活**之前**由 `ValidateComServerRegistration` 完成，恶意 DLL 无法被加载 |
| 3 | HMAC 验证与读取之间存在 TOCTOU | 二者使用同一个 `configBytes` 缓冲区，`.hmac` 与配置均以 `FileShare.None` 打开，无可插入的替换窗口 |
| 4 | DPAPI `CurrentUser` 作用域可被同用户进程解密 | 已作为残余风险记录；单独利用需要同用户代码执行，且密钥文件已被 ACL 限制，无增量提权 |
| 5 | COM 校验与激活之间的 TOCTOU 竞争 | 需要攻击者持续写 `HKCU\...\CLSID` 且恰好命中窗口；无确定性利用路径，维持「已记录残余风险」 |
| 6 | 日志包含未净化输入导致日志注入 | 已实现 CR/LF 转义与敏感字段脱敏；日志注入本身不构成可利用漏洞（仅日志伪造） |
| 7 | 语言文件可被篡改以改写安全确认文案 | 前置条件是安装目录可写，此时攻击者可直接替换主程序；无增量权限，属纵深防御建议 |
| 8 | `CreateRuleForExe` 与扫描并发导致重复规则 | 属竞态/可用性问题，未证明可用于解除阻断；按规则不作为漏洞上报 |
| 9 | 日志 `File.Replace` 失败后回退 `AppendAllText`（不再校验 reparse） | 需要管理员对日志目录的写权限，前置过高，且无越权收益 |

**关于 UNC（V-01）的交叉验证**：Agent C 报为 HIGH、Agent B 报为 MEDIUM。主审确认代码路径成立（`IsPathRooted` 对 UNC 返回 true，`Directory.Exists` 在校验阶段即连接），且白名单模块已有明确的 UNC 拒绝策略，属于同一项目内的策略不一致，故按**凭据泄露**定为 HIGH。

---

## 五、补充发现（非漏洞，但影响安全可用性）

### 5.1 规则详情功能实际不可用

[FirewallService.cs:897](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/FirewallService.cs#L897) 调用 `ValidateComObjectType`，其 [ComHelper.cs:993-1000](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/ComHelper.cs#L993-L1000) 要求 `obj.GetType().GUID == expectedClsid`。但 `Rules.Item(name)` 经 IDispatch 返回的 RCW 是 `System.__ComObject`，`Type.GUID` 恒为 `Guid.Empty`，因此校验必然失败，`GetRuleDetails` 永远返回 `null`，规则详情窗体无法显示内容。

- 安全影响：**fail-safe**（不会泄露信息、不会误改规则），但会让用户误以为「规则不存在」，与 V-07 的「无归属校验」形成不一致的实现标准。
- 建议：与 `ValidateComObjectClsid` 一致，对 `Guid.Empty` 走 `QueryInterface` 分支，而不是直接判定失败。

### 5.2 注释与实现不符

[ComHelper.cs:720-724](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/ComHelper.cs#L720-L724) 附近注释声称原子写执行「句柄级 reparse 校验」，实际是 `FileInfo.Attributes` 的路径级检查。鉴于临时文件名使用加密随机数且 `FileMode.CreateNew` 独占创建，当前无可利用路径，但注释应改为如实描述，避免下一轮审计被误导。

---

## 六、整体安全态势评估

| 维度 | 评分 | 依据 |
|------|------|------|
| 提权防护（COM/服务注册） | 强 | 激活前校验 HKCU/双视图/HKLM 路径，未发现绕过 |
| 配置与凭据完整性 | 中 | HMAC/DPAPI 设计正确，但加固失败处理（V-04）与白名单编辑器（V-06）可绕过 |
| 路径与文件系统边界 | 中偏弱 | UNC（V-01）、检查顺序（V-02）、根目录（V-03）三处缺口集中在同一模块 |
| 规则生命周期与授权 | 中 | 删除路径已绑定归属哈希，更新路径（V-07）与失败语义（V-05、V-09）仍有缺口 |
| 信息泄露 | 良好 | 日志转义与脱敏到位；唯一泄露面是 V-01 的 NTLM |
| 注入类风险（SQL/命令/模板） | 无 | 程序不构造 SQL/命令行/模板，无相关 sink |
| 反序列化 | 良好 | 统一使用 `SafeJsonOptions`（`MaxDepth=10`），无类型化反序列化 |

**与上一轮对比**：R/X 系列修复消除了 COM CLSID 劫持、配置 fail-open、规则误删等高危项；本轮**未发现新的提权链**，新问题主要集中在「路径信任边界」与「失败安全性」两个主题，属于需要系统性收口的同类缺陷，而非孤立的单点漏洞。

**残余风险（已接受）**：COM 校验/激活 TOCTOU、DPAPI `CurrentUser` 作用域、v1 迁移条件、配置目录预建 junction（与 V-04 叠加时风险上升，建议优先处理 V-04）。

---

## 七、修复优先级建议

| 优先级 | 项 | 理由 |
|--------|-----|------|
| P0 | V-01 | 唯一的凭据泄露面，一次社交工程即可触发 |
| P0 | V-04 | 是 V-06 与「配置完整性失效」的共同前提，修复收益最高 |
| P1 | V-02、V-03 | 同一根因（reparse 校验位置/覆盖不全），建议一次性统一到「原始路径校验 + 解链后归属断言」 |
| P1 | V-05 | 单个 COM setter 失败即可造成全局断网或规则失效，修复成本低 |
| P2 | V-06、V-07、V-09 | 纵深防御与状态一致性 |
| P3 | V-08、V-10 | 前置条件特殊，可与相关重构一并处理 |

---

## 八、合规与业务影响声明

- 本次审查**只读**执行：未运行程序、未创建/修改/删除任何防火墙规则、未访问外部网络、未在用户机器上执行漏洞利用代码。
- 所有「复现路径」均为基于代码控制流的推演，实际验证需在隔离测试机上进行，并事先备份防火墙策略。
- 审查过程中未对生产配置、日志、白名单文件做任何写入。
- 报告中的行号均以当前工作区文件为准（2026-11-17 版本），后续代码变更后需重新定位。

---

**报告结束**
