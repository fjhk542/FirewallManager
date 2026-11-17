# 多智能体协同漏洞修复报告

- 项目：FirewallManager（.NET 10 Windows Forms / C# / NetFwTypeLib COM）
- 修复依据：[SECURITY_REVIEW_MULTI_AGENT.md](file:///c:/Users/tjliy/Documents/trae_projects/FirewallManager/SECURITY_REVIEW_MULTI_AGENT.md)
- 修复日期：2026-11-17
- 编译状态：`dotnet build --no-restore` → **0 警告 0 错误**

---

## 一、漏洞清单与根因

| 编号 | 漏洞类型 | 影响范围 | 等级 | 根因 |
|------|----------|----------|------|------|
| V-01 | 敏感凭据泄露（CWE-522） | 粘贴路径、配置导入、启动加载、白名单添加 | 高 | 对用户输入路径直接调用 `Directory.Exists` / `File.Exists` / `new FileInfo` / `File.Open`，UNC 路径会向任意远程主机发起 SMB 认证并泄露当前用户 NetNTLM 哈希 |
| V-02 | 校验失效（逻辑缺陷） | 单文件规则创建 | 低 | reparse point 检查位于 `GetRealPath` 解链之后，此时路径已被解析为真实路径，检查恒为 false |
| V-03 | 链接跟随（CWE-59） | 目录监控、扫描 | 中 | 仅过滤子项 reparse 属性，未校验监控根目录自身；`FileSystemWatcher` 与目录枚举均会跟随根 junction |
| V-04 | 信任门禁失效（CWE-693） | 配置完整性、v1 迁移 | 中 | 应用数据目录 ACL 加固失败仅告警；属主设置失败仍返回成功，当前用户作为属主保留隐式 `WRITE_DAC`，可恢复写权限并植入伪造配置 |
| V-05 | 安全属性丢失（CWE-754） | 防火墙规则创建 | 中 | 6 个安全语义属性（Name/ApplicationName/Direction/Action/Enabled/Profiles）的 setter 结果未校验；`ApplicationName` 被丢弃时会生成"全机拦截"规则 |
| V-06 | 完整性校验缺失（CWE-345） | 白名单 | 中 | 白名单读取不复用 HMAC 校验；保存后不检查签名是否成功，篡改内容可被加载 |
| V-07 | 越权修改（CWE-639） | 规则更新 | 中 | `UpdateRule` 未校验规则归属与 COM 接口类型，同名外部规则可被改写 |
| V-08 | 大小写不一致（CWE-178） | 规则命名、白名单匹配 | 低 | 哈希与白名单匹配统一忽略大小写，在启用大小写敏感的目录上可漏拦 —— **本次未修复，见第五节** |
| V-09 | 状态不一致（CWE-664） | 规则批量清理 | 低 | `ClearAllRules` 尾部无条件 `addedRules.Clear()`，部分删除失败时本地列表与真实规则不一致 |
| V-10 | 资源未重建（CWE-665） | 配置导入 | 低 | 导入配置写入监控目标后未重建 `FileSystemWatcher`，新目标在重启前不会被自动监控 |
| 5.1 | 功能缺陷 | 规则详情 | 低 | `ValidateComObjectType` 对 `System.__ComObject`（`GUID` 为空）恒判失败，`GetRuleDetails` 恒返回 null |

---

## 二、多智能体协同与同步机制

| 阶段 | 角色 | 产出 |
|------|------|------|
| 定位 | 3 个只读审查 Agent（COM/密码学、规则生命周期、UI 与输入） | 缺陷候选清单 V-01~V-10 |
| 定级 | 主控交叉复核（逐条读码验证 source→sink） | 排除 9 项误报，确定 1 高 / 5 中 / 4 低 |
| 修复 | 主控统一实现（避免多 Agent 并发写同一文件产生冲突） | 6 个文件、9 项修复 |
| 验证 | 2 个只读 Agent 并行（对抗性安全复检 + 兼容性/回归验证） | 发现 6 个修复缺口与 3 个可用性回归 |
| 补修 | 主控按缺口逐条读码确认后二次修复 | 3 个文件补修 |
| 终检 | 第 3 个只读对抗 Agent + 主控读码复核 | 发现混合分隔符旁路，再次修复 |

**同步机制**：所有 Agent 结论必须先落到「文件:行号」证据，再由主控打开对应行确认后才进入修复队列；同一文件只由主控单一写入，写前重新读取当前内容，避免并发覆盖。存在分歧时以代码控制流为准，不以注释声明为准。

---

## 三、修复步骤（逐文件）

### 3.1 Form1.cs

| 位置 | 修改 |
|------|------|
| `NormalizeAndValidatePath` | ① 抽取统一的本地路径判定 `ComHelper.IsLocalPathCandidate`；② 归一化后**再次**校验（防止相对路径在 UNC 工作目录下解析为 UNC）；③ 改用 Trim 后路径剥离前缀；④ 增加根路径 reparse 校验 `HasReparsePointInPath` |
| 粘贴路径处理 | 在 `Directory.Exists` **之前**拦截网络/设备路径 |
| 配置导入 | 在 `new FileInfo` **之前**拦截网络/设备路径（OpenFileDialog 允许手输 UNC） |
| `LoadMonitoredTargets` | 改为「先校验、后存在性检查」，避免对 UNC 调用 `Directory.Exists` |
| 导入完成 | `SaveMonitoredTargets()` 后按勾选状态调用 `InitializeFileWatchers()`（内部先停旧 watcher） |
| `ValidateAndCreateRuleForExe` | reparse 检查前移到 `GetRealPath` 之前 |

### 3.2 ComHelper.cs

| 位置 | 修改 |
|------|------|
| 新增 `IsLocalPathCandidate` | 首两个字符各自判定是否为分隔符（`\/`、`/\`、`\//` 均视为网络路径），仅放行 `\\?\C:` 扩展本地盘符 |
| `SetSecureDirectoryPermissionsInternal` | 属主改派 Administrators 失败时由「告警后返回 true」改为「记录错误并返回 false」（fail-closed） |
| `ValidateComObjectType` | `Guid.Empty` 时不再直接判失败，交由 QueryInterface 校验 |

### 3.3 Config.cs

`_appDataDirSecured` 改为三态 `_appDataDirState`（0 未尝试 / 1 已加固 / 2 失败），`IsAppDataDirectorySecured` 仅在 1 时为真；置位顺序保证日志失败不会造成递归。

### 3.4 TargetStore.cs

v1 遗留配置迁移新增第三前提：`Config.IsAppDataDirectorySecured` 必须为真，否则拒绝迁移并 fail-closed。

### 3.5 FirewallService.cs

| 位置 | 修改 |
|------|------|
| `CreateAndAddFirewallRule` | 6 个安全属性 setter 全部校验；Add 后从 `firewallPolicy.Rules.Item(ruleName)` **回读** `ApplicationName`（不再读自身实例），不匹配则 Remove 回滚 |
| `UpdateFirewallRules` | 每个监控目标扫描前做 reparse 守卫 |
| `UpdateRule` | 新增归属校验 `IsRuleOwnedByCurrentProgram` → COM 类型校验 → 4 个属性 setter 结果校验 |
| `ClearAllRules` | 尾部改为 `SyncRulesList()`，清理前逐条归属校验 |

### 3.6 WhitelistForm.cs

| 位置 | 修改 |
|------|------|
| `LoadWhitelist` | 先 `VerifyConfigIntegrityAndRead`；新增 `TryReadLegacyUnsignedWhitelist` 迁移通道（无 .hmac 且数据目录已加固才允许，读取后立即签名） |
| `RefreshWhitelistCache` | 复用同一迁移通道，避免旧用户白名单在启动时整体失效 |
| `SaveWhitelist` | 校验 `SaveConfigIntegrityHash` 返回值；新增加载失败时拒绝保存（防止空列表覆盖用户数据） |
| `btnAdd_Click` | 在 `Path.GetFullPath` / 符号链接探测前拦截网络路径 |

### 3.7 Lang/zh-CN.json、Lang/en-US.json

补充 3 个缺失键：`whitelistRejectExtendedPath`、`whitelistRejectUncPath`、`configDirCreated`（此前会直接显示原始键名）。

---

## 四、验证结果

### 4.1 编译与资源

| 项目 | 结果 |
|------|------|
| `dotnet build --no-restore` | 0 警告 0 错误（三轮） |
| `Lang/zh-CN.json` / `en-US.json` | `ConvertFrom-Json` 解析通过 |

### 4.2 边界用例（静态走查判定）

| 输入 | 期望 | 结果 |
|------|------|------|
| `\\attacker\share` | 拒绝 | 拒绝（粘贴 / 导入 / 加载 / 白名单添加） |
| `//attacker/share` | 拒绝 | 拒绝 |
| `\/server\share`、`/\server\share`、`\//server\share` | 拒绝 | 拒绝（混合分隔符修复后） |
| `\\?\C:\Tools` | 放行并归一为 `C:\Tools` | 放行 |
| `\\?\UNC\server\share` | 拒绝 | 拒绝（不满足 `[4]字母 + [5]冒号`） |
| `\\?\Volume{GUID}\` | 拒绝 | 拒绝 |
| `\\.\PhysicalDrive0` | 拒绝 | 拒绝 |
| 相对路径 + UNC 工作目录 | 拒绝 | `GetFullPath` 后二次校验拒绝 |
| `C:\`（系统根） | 拒绝 | 拒绝 |
| 父链含 junction / 目录挂载点 | 拒绝（fail-closed） | 拒绝 |
| `D:\Games`、`C:\Program Files\Foo`、`C:\Users\x\a.exe` | 放行 | 放行 |

### 4.3 回归验证（只读 Agent + 主控复核）

| 场景 | 结论 |
|------|------|
| 全新安装首次启动（无配置 / 无密钥 / 无白名单） | OK，不误拦 |
| 添加普通本地目录与单个 exe | OK |
| 老用户无 `.hmac` 白名单 | 经迁移通道加载并签名；若加载失败则拒绝保存，不再丢数据 |
| 规则创建（含回读校验） | OK，普通本地 exe 恒通过 |
| 规则详情 `GetRuleDetails` | 恢复正常返回（不再恒 null） |
| 非管理员启动 | `app.manifest` 为 `requireAdministrator`；ACL 失败仅进入受限模式，不崩溃 |
| 配置导入 / watcher 重建 | 先停旧 watcher 再建新，无重复、无句柄泄漏 |
| 语言资源 | 本次使用的键全部存在，无原始键名泄漏 |

### 4.4 未修复项

V-08 保留为残余风险，理由见第五节。

---

## 五、残余风险（已确认、已记录）

1. **V-08 大小写敏感目录**：规则哈希与白名单均忽略大小写。简单改为保留原始大小写会重新引入上一轮已修复的「同一 exe 因路径大小写不同产生重复规则」问题；正确做法是调用 `GetFileInformationByHandleEx(FileCaseSensitiveInfo)` 按目录判定，属于独立立项改造。
2. **回读异常时的可用性**：`Rules.Item` 抛异常会按「无法验证」处理并回滚刚创建的规则，最坏结果是该 exe 未被拦截（fail-closed），不会产生过宽规则。
3. **配置导出到 UNC**：导出为显式用户保存动作，保留原行为，不作为漏洞处理。
4. **迁移签名失败**：非管理员运行时无法写入 `.hmac`，旧白名单会在下次启动再次走迁移通道。因 `app.manifest` 强制提权，实际触发概率极低。
5. **合法挂载点被拒**：监控目标位于目录挂载点或 junction 之下时会被拒绝，属 fail-closed 设计取舍，日志会明确记录。
6. **json 与 .hmac 分两次写入**：进程在两次写入之间终止会留下「内容已更新、签名未更新」的状态，下次加载会被判为完整性失败（fail-closed，不会信任错误内容）。

---

## 六、后续防护建议

1. **V-08 立项**：按目录探测大小写敏感属性，替换全局忽略大小写的比较策略。
2. **完整性容器化**：将 `json + hmac` 合并为单一文件（内容与签名同一次原子写入），消除第五节第 6 项的非原子窗口。
3. **统一入口**：所有用户路径必须先过 `ComHelper.IsLocalPathCandidate`，再调用任何文件系统 API；建议在代码评审清单中加入该项。
4. **补充自动化测试**：当前仓库无测试工程，本轮验证全部为静态走查 + 编译验证；建议至少覆盖路径校验、规则命名、HMAC 校验、旧格式迁移四类纯函数。
5. **运行时告警**：完整性校验失败目前仅写日志 + 弹窗，建议在托盘图标上给出持久状态提示，避免用户忽略。
6. **最小权限运行**：长期看可将规则写入拆分为受限的本地服务，主程序不再常驻提权。

---

## 七、结论

- 9 项缺陷（V-01~V-07、V-09、V-10）与 1 项功能缺陷（5.1）已修复并通过两轮对抗复检；V-01 的三条旁路（粘贴、导入、白名单添加）与混合分隔符绕过均已闭合。
- 未引入新的安全缺陷；新增的可用性限制（白名单加载失败时禁止保存、挂载点目标被拒）均为 fail-closed 取舍，已在第五节记录。
- V-08 与 5 项残余风险已明确记录并给出整改方向。
