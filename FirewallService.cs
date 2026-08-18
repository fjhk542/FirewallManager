using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FirewallManager
{
    /// <summary>
    /// 防火墙服务类
    /// 负责处理与防火墙相关的操作
    /// </summary>
    public class FirewallService : IFirewallService
    {
        /// <summary>
        /// 防火墙策略对象（使用 object 存储以支持 volatile，提供 dynamic 访问）
        /// </summary>
        private volatile object _firewallPolicy;

        /// <summary>
        /// 已添加的规则列表（用于有序遍历和持久化）
        /// </summary>
        private List<string> addedRules;

        /// <summary>
        /// 已添加规则的 HashSet 集合（用于 O(1) 快速查找）
        /// 与 addedRules 保持同步，避免 CheckRuleExists 在大规则集下退化为 O(n)
        /// </summary>
        private HashSet<string> addedRulesLookup;

        /// <summary>
        /// 用于确保线程安全的锁对象
        /// </summary>
        private readonly object addedRulesLock;

        /// <summary>
        /// 资源释放标志（线程安全）
        /// </summary>
        private volatile bool _disposed;

        /// <summary>
        /// 获取 firewallPolicy 的 dynamic 视图（线程安全读取 _firewallPolicy）
        /// </summary>
        private dynamic firewallPolicy
        {
            get { return _firewallPolicy; }
            set { _firewallPolicy = value; }
        }

        /// <summary>
        /// 构造函数
        /// </summary>
        public FirewallService()
        {
            addedRules = new List<string>();
            addedRulesLookup = new HashSet<string>(StringComparer.Ordinal);
            addedRulesLock = new object();
        }

        private static bool SafeSetProperty(dynamic obj, string propertyName, object value)
        {
            return ComHelper.SafeSetProperty(obj, propertyName, value);
        }

        private static void ReleaseComObject(dynamic obj)
        {
            ComHelper.ReleaseComObject(obj);
        }

        /// <summary>
        /// 创建防火墙规则 COM 对象并添加到防火墙策略与本地列表
        /// 抽取自 CreateRuleForExe 与 UpdateFirewallRules，消除重复的属性设置/添加/释放逻辑
        /// </summary>
        /// <param name="ruleName">规则名称</param>
        /// <param name="exePath">可执行文件路径</param>
        /// <param name="descriptionPrefix">描述前缀（区分自动监控与手动更新）</param>
        /// <returns>是否创建并添加成功</returns>
        private bool CreateAndAddFirewallRule(string ruleName, string exePath, string descriptionPrefix)
        {
            dynamic newRule = ComHelper.CreateComObjectWithClsid(
                Config.FIREWALL_RULE_CLSID,
                Config.FIREWALL_RULE_IID,
                Config.FIREWALL_RULE_PROGID);
            if (newRule == null)
            {
                LogManager.Error(LangManager.GetText("logMessages.createFirewallRuleInstanceFailed"));
                return false;
            }

            try
            {
                SafeSetProperty(newRule, "Name", ruleName);
                SafeSetProperty(newRule, "Description", descriptionPrefix + ": " + exePath);
                SafeSetProperty(newRule, "ApplicationName", exePath);
                SafeSetProperty(newRule, "Direction", (int)FirewallDirection.Outbound);
                SafeSetProperty(newRule, "Action", (int)FirewallAction.Block);
                SafeSetProperty(newRule, "Enabled", true);
                SafeSetProperty(newRule, "Profiles", Config.ALL_FIREWALL_PROFILES);

                firewallPolicy.Rules.Add(newRule);

                // 添加到本地列表（HashSet 与 List 保持同步）
                lock (addedRulesLock)
                {
                    if (addedRulesLookup.Add(ruleName))
                    {
                        addedRules.Add(ruleName);
                    }
                }

                return true;
            }
            finally
            {
                ReleaseComObject(newRule);
            }
        }

        /// <summary>
        /// 释放资源
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// 释放资源
        /// 释放托管资源和COM对象
        /// </summary>
        /// <param name="disposing">是否释放托管资源</param>
        protected virtual void Dispose(bool disposing)
        {
            // 使用 volatile 字段 + 锁定确保线程安全
            if (_disposed)
            {
                return;
            }

            lock (addedRulesLock)
            {
                if (_disposed)
                {
                    return;
                }

                if (disposing)
                {
                    // 释放托管资源
                    if (addedRules != null)
                    {
                        addedRules.Clear();
                    }
                    addedRulesLookup?.Clear();

                    // 释放COM对象（只在显式Dispose时释放，避免在析构函数中访问托管资源）
                    if (_firewallPolicy != null)
                    {
                        try
                        {
                            System.Runtime.InteropServices.Marshal.ReleaseComObject(_firewallPolicy);
                            _firewallPolicy = null;
                            LogManager.Info(LangManager.GetText("logMessages.firewallPolicyCOMObjectReleased"));
                        }
                        catch (Exception ex)
                        {
                            LogManager.Error(LangManager.GetText("logMessages.releaseFirewallPolicyCOMObjectFailed"), ex);
                        }
                    }
                }
                else
                {
                    // 从析构函数调用时，只释放非托管资源（COM对象）
                    // 注意：此时不能访问托管资源（如 LogManager），因为它们可能已被 GC 回收
                    if (_firewallPolicy != null)
                    {
                        try
                        {
                            System.Runtime.InteropServices.Marshal.ReleaseComObject(_firewallPolicy);
                            _firewallPolicy = null;
                        }
                        catch
                        {
                            // 在析构函数中不能记录日志，因为 LogManager 可能已被回收
                            // 静默忽略异常
                        }
                    }
                }

                _disposed = true;
            }
        }

        /// <summary>
        /// 析构函数
        /// </summary>
        ~FirewallService()
        {
            Dispose(false);
        }

        /// <summary>
        /// 初始化防火墙组件
        /// 创建COM对象并测试防火墙策略接口，同步本地规则列表
        /// </summary>
        /// <returns>是否初始化成功</returns>
        public bool InitializeFirewallComponents()
        {
            try
            {
                LogManager.Info(LangManager.GetText("logMessages.startInitializeFirewallComponents"));
                LogManager.Info(LangManager.GetText("logMessages.tryCreateFirewallPolicyObject", Config.FIREWALL_POLICY_PROGID));

                firewallPolicy = ComHelper.CreateComObjectWithClsid(
                    Config.FIREWALL_POLICY_CLSID, 
                    Config.FIREWALL_POLICY_IID, 
                    Config.FIREWALL_POLICY_PROGID);

                if (firewallPolicy == null)
                {
                    LogManager.Error(LangManager.GetText("logMessages.firewallPolicyTypeNotFound"));
                    throw new Exception(LangManager.GetText("logMessages.firewallPolicyTypeNotFound"));
                }

                LogManager.Info(LangManager.GetText("logMessages.firewallPolicyInstanceCreated"));

                // 测试获取 CurrentProfileTypes 属性
                try
                {
                    var currentProfileTypes = firewallPolicy.CurrentProfileTypes;
                    LogManager.Info(LangManager.GetText("logMessages.currentProfileTypes", currentProfileTypes));
                }
                catch (Exception ex)
                {
                    LogManager.Error(LangManager.GetText("logMessages.gettingCurrentProfileTypesFailed", ex.Message));
                }

                // 测试获取 Rules 属性
                try
                {
                    var rules = firewallPolicy.Rules;
                    LogManager.Info(LangManager.GetText("logMessages.rulesObjectGetSuccess", rules.GetType().FullName));
                }
                catch (Exception ex)
                {
                    LogManager.Error(LangManager.GetText("logMessages.gettingRulesPropertyFailed", ex.Message));
                }

                // 同步本地规则列表与实际防火墙规则
                SyncRulesList();

                LogManager.Info(LangManager.GetText("logMessages.firewallInitialized"));
                return true;
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.initializeFirewallFailed") + $": {ex.GetType().Name}: {ex.Message}");
                LogManager.Error(LangManager.GetText("logMessages.stackTrace", ex.StackTrace));
                return false;
            }
        }

        /// <summary>
        /// 同步本地规则列表与实际防火墙规则
        /// </summary>
        public void SyncRulesList()
        {
            try
            {
                // 检查防火墙策略是否已初始化
                if (firewallPolicy == null)
                {
                    LogManager.Warning(LangManager.GetText("logMessages.firewallPolicyNotInitialized"));
                    return;
                }

                var rules = firewallPolicy.Rules;
                var currentRules = new List<string>();

                // 收集所有规则名称
                foreach (var rule in rules)
                {
                    try
                    {
                        dynamic fwRule = rule;
                        string ruleName = fwRule.Name;
                        if (ruleName.StartsWith(Config.RULE_NAME_PREFIX))
                        {
                            currentRules.Add(ruleName);
                        }
                    }
                    catch (Exception ex)
                    {
                        LogManager.Warning(LangManager.GetText("logMessages.readRuleNameFailed", ex.Message));
                    }
                }

                // 更新本地规则列表
                lock (addedRulesLock)
                {
                    addedRules.Clear();
                    addedRules.AddRange(currentRules);
                    addedRulesLookup = new HashSet<string>(currentRules, StringComparer.Ordinal);
                }

                LogManager.Info(LangManager.GetText("logMessages.syncRulesListCompleted", currentRules.Count));
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.syncRulesListFailed"), ex);
            }
        }

        /// <summary>
        /// 检查防火墙规则是否存在
        /// 使用 HashSet 实现 O(1) 查找，避免大规则集下的性能退化
        /// </summary>
        /// <param name="ruleName">规则名称</param>
        /// <returns>是否存在</returns>
        public bool CheckRuleExists(string ruleName)
        {
            try
            {
                lock (addedRulesLock)
                {
                    return addedRulesLookup != null && addedRulesLookup.Contains(ruleName);
                }
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.checkRuleExistsFailed", ruleName), ex);
                return false;
            }
        }

        /// <summary>
        /// 为可执行文件创建防火墙规则
        /// 检查白名单和系统关键程序后，创建出站阻止规则
        /// </summary>
        /// <param name="exePath">可执行文件路径</param>
        /// <returns>是否创建成功</returns>
        public bool CreateRuleForExe(string exePath)
        {
            try
            {
                // 检查对象是否已释放
                if (_disposed)
                {
                    throw new ObjectDisposedException(nameof(FirewallService));
                }

                // 检查防火墙策略是否已初始化
                if (firewallPolicy == null)
                {
                    LogManager.Error(LangManager.GetText("logMessages.firewallPolicyNotInitialized"));
                    throw new InvalidOperationException(LangManager.GetText("logMessages.firewallPolicyNotInitialized"));
                }

                // 检查应用程序是否在白名单中
                if (WhitelistForm.IsInWhitelist(exePath))
                {
                    LogManager.Info(LangManager.GetText("logMessages.appInWhitelistSkipped", exePath));
                    return false;
                }

                // 检查是否为系统关键程序
                string fullFileName = System.IO.Path.GetFileName(exePath);
                if (Config.CRITICAL_PROGRAMS.Contains(fullFileName))
                {
                    LogManager.Warning(LangManager.GetText("logMessages.skipCriticalProgram", exePath));
                    return false;
                }

                // 生成规则名称（统一调用 RuleNamingService）
                string ruleName = RuleNamingService.BuildRuleName(exePath);

                // 检查规则是否已存在
                if (!CheckRuleExists(ruleName))
                {
                    if (CreateAndAddFirewallRule(ruleName, exePath, LangManager.GetText("firewall.ruleDescriptionAuto")))
                    {
                        LogManager.Info(LangManager.GetText("logMessages.autoCreateFirewallRule", ruleName, exePath));
                        return true;
                    }
                    return false;
                }
                return false;
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.createRuleForExeFailed", exePath), ex);
                return false;
            }
        }

        /// <summary>
        /// 清除所有由本程序创建的防火墙规则
        /// 删除本地列表中的规则，并扫描防火墙中所有以Block_前缀开头的规则进行删除
        /// 修复：添加规则名格式校验，防止误删其他软件创建的规则
        /// </summary>
        /// <returns>删除的规则数量</returns>
        public int ClearAllRules()
        {
            int deletedCount = 0;
            var rulesToDelete = new List<string>();

            try
            {
                LogManager.Info(LangManager.GetText("logMessages.clearingAllRules"));

                // 检查防火墙策略是否已初始化
                if (firewallPolicy == null)
                {
                    LogManager.Warning(LangManager.GetText("logMessages.firewallPolicyNotInitialized"));
                    return deletedCount;
                }

                // 1. 首先删除本地列表中的规则（这些是由本程序创建的，已验证）
                List<string> rulesToProcess;
                lock (addedRulesLock)
                {
                    rulesToProcess = addedRules.ToList();
                }

                foreach (var ruleName in rulesToProcess)
                {
                    try
                    {
                        firewallPolicy.Rules.Remove(ruleName);
                        rulesToDelete.Add(ruleName);
                        deletedCount++;
                        LogManager.Info(LangManager.GetText("logMessages.deleteFirewallRule", ruleName));
                    }
                    catch (Exception ex)
                    {
                        LogManager.Warning(LangManager.GetText("logMessages.deleteRuleFailed", ruleName, ex.Message));
                    }
                }

                // 2. 然后扫描防火墙中的所有规则，只删除符合本程序创建格式的规则
                try
                {
                    var rules = firewallPolicy.Rules;
                    var allRuleNames = new List<string>();

                    // 收集所有规则名称
                    foreach (var rule in rules)
                    {
                        try
                        {
                            dynamic fwRule = rule;
                            string ruleName = fwRule.Name;
                            allRuleNames.Add(ruleName);
                        }
                        catch (Exception ex)
                        {
                            LogManager.Warning(LangManager.GetText("logMessages.readRuleNameFailed", ex.Message));
                        }
                    }

                    // 只删除符合本程序创建格式的规则
                    foreach (var ruleName in allRuleNames)
                    {
                        // 验证规则名确实是由本程序创建的（格式校验）
                        if (RuleNamingService.IsRuleCreatedByUs(ruleName) && !rulesToDelete.Contains(ruleName))
                        {
                            try
                            {
                                firewallPolicy.Rules.Remove(ruleName);
                                rulesToDelete.Add(ruleName);
                                deletedCount++;
                                LogManager.Info(LangManager.GetText("logMessages.deleteFirewallRule", ruleName));
                            }
                            catch (Exception ex)
                            {
                                LogManager.Warning(LangManager.GetText("logMessages.deleteRuleFailed", ruleName, ex.Message));
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    LogManager.Error(LangManager.GetText("logMessages.scanFirewallRulesFailed"), ex);
                }

                // 清空本地规则列表
                lock (addedRulesLock)
                {
                    addedRules.Clear();
                    addedRulesLookup.Clear();
                }

                LogManager.Info(LangManager.GetText("logMessages.clearRulesSuccess", deletedCount));
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.clearFirewallRulesFailed"), ex);
            }

            return deletedCount;
        }

        /// <summary>
        /// 验证规则名称是否有效
        /// 规则名称不能为空且长度不超过 256 字符，防止注入攻击
        /// </summary>
        /// <param name="ruleName">规则名称</param>
        /// <returns>是否有效</returns>
        private static bool IsValidRuleName(string ruleName)
            => !string.IsNullOrEmpty(ruleName) && ruleName.Length <= 256;

        /// <summary>
        /// 删除防火墙规则
        /// </summary>
        /// <param name="ruleName">规则名称</param>
        /// <returns>是否删除成功</returns>
        public bool DeleteRule(string ruleName)
        {
            try
            {
                // 验证规则名称，防止注入攻击（与 GetRuleDetails 保持一致）
                if (!IsValidRuleName(ruleName))
                {
                    return false;
                }

                firewallPolicy.Rules.Remove(ruleName);
                
                lock (addedRulesLock)
                {
                    addedRules.Remove(ruleName);
                    addedRulesLookup.Remove(ruleName);
                }
                
                LogManager.Info(LangManager.GetText("logMessages.deleteFirewallRule", ruleName));
                return true;
            }
            catch (Exception ex)
            {
                LogManager.Warning(LangManager.GetText("logMessages.deleteRuleFailed", ruleName, ex.Message));
                return false;
            }
        }

        /// <summary>
        /// 获取所有由本程序创建的规则名称
        /// </summary>
        /// <returns>规则名称列表</returns>
        public List<string> GetAllRuleNames()
        {
            lock (addedRulesLock)
            {
                return new List<string>(addedRules);
            }
        }

        /// <summary>
        /// 更新防火墙规则
        /// 扫描监控目标中的所有可执行文件，为每个文件创建或更新防火墙规则
        /// </summary>
        /// <param name="monitoredTargets">监控目标列表</param>
        /// <param name="cancellationToken">取消令牌</param>
        /// <param name="updateUI">更新UI的回调函数</param>
        /// <returns>处理结果，包含添加的规则数和跳过的规则数</returns>
        public async Task<(int addedCount, int skippedCount)> UpdateFirewallRules(List<dynamic> monitoredTargets, CancellationToken cancellationToken, Action<object, string> updateUI)
        {
            int addedCount = 0;
            int skippedCount = 0;

            try
            {
                LogManager.Info(LangManager.GetText("logMessages.updatingRules"));
                updateUI("Running", LangManager.GetText("status.scanningTargets"));

                // 检查防火墙策略是否已初始化
                if (firewallPolicy == null)
                {
                    LogManager.Warning(LangManager.GetText("logMessages.firewallPolicyNotInitialized"));
                    updateUI("Idle", LangManager.GetText("status.firewallNotInitialized"));
                    return (addedCount, skippedCount);
                }

                // 同步本地规则列表与实际防火墙规则
                SyncRulesList();

                // 收集所有需要处理的EXE文件
                List<string> exeFiles = new List<string>();

                // 并行扫描文件，提高性能
                var scanTasks = monitoredTargets.Select(target => Task.Run(() =>
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (target.IsExe)
                    {
                        if (File.Exists(target.Path))
                        {
                            return new List<string> { target.Path };
                        }
                    }
                    else if (Directory.Exists(target.Path))
                    {
                        try
                        {
                            LogManager.Info(LangManager.GetText("logMessages.startScanningFolder", target.Path));
                            string[] files = Directory.GetFiles(target.Path, Config.EXE_SEARCH_PATTERN, SearchOption.AllDirectories);
                            LogManager.Info(LangManager.GetText("logMessages.scanCompleted", target.Path, files.Length));
                            return new List<string>(files);
                        }
                        catch (Exception ex)
                        {
                            LogManager.Warning(LangManager.GetText("logMessages.scanFolderFailed", target.Path, ex.Message));
                        }
                    }
                    return new List<string>();
                }, cancellationToken)).ToArray();

                // 等待所有扫描任务完成
                await Task.WhenAll(scanTasks);

                // 合并结果并去重，避免重复处理
                exeFiles = scanTasks.SelectMany(t => t.Result).Distinct().ToList();

                LogManager.Info(LangManager.GetText("logMessages.foundExeFiles", exeFiles.Count));
                updateUI("Running", LangManager.GetText("status.creatingRules", exeFiles.Count));

                // 为每个EXE文件创建防火墙规则
                int processedCount = 0;
                foreach (var exeFile in exeFiles)
                {
                    // 检查取消请求
                    cancellationToken.ThrowIfCancellationRequested();

                    processedCount++;
                    updateUI("Running", LangManager.GetText("status.processingFile", processedCount, exeFiles.Count, System.IO.Path.GetFileName(exeFile)));

                    try
                    {
                        // 信任检查：确保文件路径可信（系统目录或已签名）
                        // 与自动监控策略保持一致，防止恶意文件注入
                        if (!ComHelper.IsFilePathTrusted(exeFile))
                        {
                            LogManager.Warning(LangManager.GetText("logMessages.invalidCallerDetected", exeFile));
                            skippedCount++;
                            continue;
                        }

                        // 生成包含文件路径哈希值的规则名称，确保唯一性（统一调用 RuleNamingService）
                        string ruleName = RuleNamingService.BuildRuleName(exeFile);

                        // 检查应用程序是否在白名单中
                        if (WhitelistForm.IsInWhitelist(exeFile))
                        {
                            LogManager.Info(LangManager.GetText("logMessages.appInWhitelistSkipped", exeFile));

                            // 检查是否存在针对该应用程序的规则，如果存在则删除
                            bool whitelistRuleExists = CheckRuleExists(ruleName);
                            if (whitelistRuleExists)
                            {
                                try
                                {
                                    firewallPolicy.Rules.Remove(ruleName);
                                    lock (addedRulesLock)
                                    {
                                        addedRules.Remove(ruleName);
                                        addedRulesLookup.Remove(ruleName);
                                    }
                                    LogManager.Info(LangManager.GetText("logMessages.deleteWhitelistAppRule", ruleName));
                                }
                                catch (Exception ex)
                                {
                                    LogManager.Warning(LangManager.GetText("logMessages.deleteWhitelistAppRuleFailed", ruleName, ex.Message));
                                }
                            }
                            skippedCount++;
                            continue;
                        }

                        // 检查是否为系统关键程序
                        string fullFileName = System.IO.Path.GetFileName(exeFile);
                        if (Config.CRITICAL_PROGRAMS.Contains(fullFileName))
                        {
                            LogManager.Warning(LangManager.GetText("logMessages.skipCriticalProgram", exeFile));
                            skippedCount++;
                            continue;
                        }

                        // 检查规则是否已存在
                        if (!CheckRuleExists(ruleName))
                        {
                            if (CreateAndAddFirewallRule(ruleName, exeFile, LangManager.GetText("firewall.ruleDescription")))
                            {
                                addedCount++;
                                LogManager.Info(LangManager.GetText("logMessages.createFirewallRule", ruleName, exeFile));
                            }
                            else
                            {
                                skippedCount++;
                            }
                        }
                        else
                        {
                            skippedCount++;
                            LogManager.Info(LangManager.GetText("logMessages.ruleExistsSkip", ruleName));
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        throw; // 重新抛出取消异常
                    }
                    catch (Exception ex)
                    {
                        LogManager.Error(LangManager.GetText("logMessages.processExeFailed", exeFile), ex);
                        skippedCount++;
                    }
                }

                LogManager.Info(LangManager.GetText("logMessages.updateCompleted", addedCount, skippedCount));
            }
            catch (OperationCanceledException)
            {
                LogManager.Info(LangManager.GetText("logMessages.updateCanceled"));
                throw;
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.updateError", ex.Message), ex);
            }

            return (addedCount, skippedCount);
        }

        /// <summary>
        /// 移除指定文件夹的防火墙规则
        /// </summary>
        /// <param name="folderPath">文件夹路径</param>
        /// <returns>删除的规则数量</returns>
        public int RemoveFolderRules(string folderPath)
        {
            int deletedCount = 0;

            try
            {
                // 收集该文件夹下所有可执行文件的路径
                var exeFiles = new List<string>();
                if (Directory.Exists(folderPath))
                {
                    try
                    {
                        string[] files = Directory.GetFiles(folderPath, Config.EXE_SEARCH_PATTERN, SearchOption.AllDirectories);
                        exeFiles = new List<string>(files);
                    }
                    catch (Exception ex)
                    {
                        LogManager.Error(LangManager.GetText("logMessages.scanFolderFailed", folderPath, ""), ex);
                        return 0;
                    }
                }

                LogManager.Info(LangManager.GetText("logMessages.removingFolderRules", folderPath, exeFiles.Count));

                // 为每个可执行文件生成规则名称并删除（使用 RuleNamingService 保证一致性）
                foreach (var exeFile in exeFiles)
                {
                    try
                    {
                        string ruleName = RuleNamingService.BuildRuleName(exeFile);

                        // 检查规则是否存在
                        if (CheckRuleExists(ruleName))
                        {
                            try
                            {
                                firewallPolicy.Rules.Remove(ruleName);
                                lock (addedRulesLock)
                                {
                                    addedRules.Remove(ruleName);
                                    addedRulesLookup.Remove(ruleName);
                                }
                                deletedCount++;
                                LogManager.Info(LangManager.GetText("logMessages.deleteFirewallRule", ruleName));
                            }
                            catch (Exception ex)
                            {
                                LogManager.Warning(LangManager.GetText("logMessages.deleteRuleFailed", ruleName, ex.Message));
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        LogManager.Error(LangManager.GetText("logMessages.processFileFailed", exeFile), ex);
                    }
                }

                LogManager.Info(LangManager.GetText("logMessages.removingFolderRulesCompleted", folderPath));
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.removingFolderRulesFailed", ex.Message), ex);
            }

            return deletedCount;
        }

        /// <summary>
        /// 获取防火墙规则详情
        /// 根据规则名称获取防火墙规则的详细信息
        /// </summary>
        /// <param name="ruleName">规则名称</param>
        /// <returns>规则对象</returns>
        public RuleDetailsInfo GetRuleDetails(string ruleName)
        {
            try
            {
                // 验证规则名称，防止注入攻击
                if (!IsValidRuleName(ruleName))
                {
                    return null;
                }

                if (_disposed || firewallPolicy == null)
                {
                    return null;
                }

                dynamic rule = firewallPolicy.Rules.Item(ruleName);
                if (rule == null)
                    return null;

                // 验证规则是合法的 COM 对象（使用 CLSID 验证，防止 ProgID 劫持）
                if (!ComHelper.ValidateComObjectType(rule, Config.FIREWALL_RULE_CLSID, Config.FIREWALL_RULE_IID))
                {
                    LogManager.Warning(LangManager.GetText("logMessages.firewallRuleTypeValidationFailed"));
                    return null;
                }

                return new RuleDetailsInfo
                {
                    Name = ComHelper.SafeGetProperty<string>(rule, "Name", string.Empty),
                    Description = ComHelper.SafeGetProperty<string>(rule, "Description", string.Empty),
                    ApplicationName = ComHelper.SafeGetProperty<string>(rule, "ApplicationName", string.Empty),
                    Enabled = ComHelper.SafeGetProperty<bool>(rule, "Enabled", false),
                    Direction = ComHelper.SafeGetProperty<int>(rule, "Direction", 2),
                    Action = ComHelper.SafeGetProperty<int>(rule, "Action", 0)
                };
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.getRuleDetailsFailed", ruleName), ex);
                return null;
            }
        }

        public bool UpdateRule(string ruleName, string description, bool enabled, int direction, int action)
        {
            try
            {
                // 验证规则名称，防止注入攻击（与 GetRuleDetails 保持一致）
                if (!IsValidRuleName(ruleName))
                {
                    return false;
                }

                dynamic rule = firewallPolicy.Rules.Item(ruleName);
                if (rule == null)
                    return false;

                SafeSetProperty(rule, "Description", description);
                SafeSetProperty(rule, "Enabled", enabled);
                SafeSetProperty(rule, "Direction", direction);
                SafeSetProperty(rule, "Action", action);

                LogManager.Info(LangManager.GetText("logMessages.updateRule", ruleName));
                return true;
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.saveRuleFailed", ex.Message), ex);
                return false;
            }
        }

    }
}