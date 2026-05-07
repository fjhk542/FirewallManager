using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
        /// 防火墙策略对象
        /// </summary>
        private dynamic firewallPolicy;

        /// <summary>
        /// 已添加的规则列表
        /// </summary>
        private List<string> addedRules;

        /// <summary>
        /// 用于确保线程安全的锁对象
        /// </summary>
        private object addedRulesLock;

        /// <summary>
        /// 构造函数
        /// </summary>
        public FirewallService()
        {
            addedRules = new List<string>();
            addedRulesLock = new object();
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
            if (disposing)
            {
                // 释放托管资源
                if (addedRules != null)
                {
                    addedRules.Clear();
                }
            }

            // 释放非托管资源
            if (firewallPolicy != null)
            {
                try
                {
                    System.Runtime.InteropServices.Marshal.ReleaseComObject(firewallPolicy);
                    firewallPolicy = null;
                    LogManager.Info(LangManager.GetText("logMessages.firewallPolicyCOMObjectReleased"));
                }
                catch (Exception ex)
                {
                    LogManager.Error(LangManager.GetText("logMessages.releaseFirewallPolicyCOMObjectFailed"), ex);
                }
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

                Type firewallPolicyType = Type.GetTypeFromProgID(Config.FIREWALL_POLICY_PROGID);
                if (firewallPolicyType == null)
                {
                    LogManager.Error(LangManager.GetText("logMessages.firewallPolicyTypeNotFound"));
                    throw new Exception(LangManager.GetText("logMessages.firewallPolicyTypeNotFound"));
                }

                LogManager.Info(LangManager.GetText("logMessages.foundType", firewallPolicyType.FullName));

                // 使用动态类型避免接口转换问题
                firewallPolicy = Activator.CreateInstance(firewallPolicyType);
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
                    catch { }
                }

                // 更新本地规则列表
                lock (addedRulesLock)
                {
                    addedRules.Clear();
                    addedRules.AddRange(currentRules);
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
        /// 检查指定名称的规则是否存在于已添加的规则列表中
        /// </summary>
        /// <param name="ruleName">规则名称</param>
        /// <returns>是否存在</returns>
        public bool CheckRuleExists(string ruleName)
        {
            try
            {
                lock (addedRulesLock)
                {
                    return addedRules.Contains(ruleName);
                }
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.checkRuleExistsFailed", ruleName), ex);
                return false;
            }
        }

        /// <summary>
        /// 生成文件路径的哈希值，确保规则名称唯一性
        /// 使用MD5算法生成路径的哈希值，取前4个字节作为规则名称的一部分
        /// </summary>
        /// <param name="path">文件路径</param>
        /// <returns>路径的哈希值</returns>
        public string GetPathHash(string path)
        {
            using (var md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] hashBytes = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(path));
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 4; i++) // 只取前4个字节，避免规则名称过长
                {
                    sb.Append(hashBytes[i].ToString("x2"));
                }
                return sb.ToString();
            }
        }

        /// <summary>
        /// 清理规则名称中的不安全字符
        /// 将规则名称中的特殊字符替换为下划线，确保规则名称符合防火墙要求
        /// </summary>
        /// <param name="input">输入字符串</param>
        /// <returns>清理后的安全字符串</returns>
        public string SanitizeRuleName(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return input;
            }

            // 移除或替换规则名称中可能的不安全字符
            char[] unsafeChars = new char[] { '"', '\'', '\\', '/', ':', '*', '?', '<', '>', '|' };
            string sanitized = input;

            foreach (char c in unsafeChars)
            {
                sanitized = sanitized.Replace(c, '_');
            }

            return sanitized;
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
                if (Config.CRITICAL_PROGRAMS.Any(c => fullFileName.Equals(c, StringComparison.OrdinalIgnoreCase)))
                {
                    LogManager.Warning(LangManager.GetText("logMessages.skipCriticalProgram", exePath));
                    return false;
                }

                // 生成规则名称
                string fileName = System.IO.Path.GetFileNameWithoutExtension(exePath);
                string sanitizedFileName = SanitizeRuleName(fileName);
                string pathHash = GetPathHash(exePath);
                string ruleName = $"{Config.RULE_NAME_PREFIX}{sanitizedFileName}_{pathHash}";

                // 检查规则是否已存在
                if (!CheckRuleExists(ruleName))
                {
                    // 创建新规则
                    Type ruleType = Type.GetTypeFromProgID(Config.FIREWALL_RULE_PROGID);
                    dynamic newRule = Activator.CreateInstance(ruleType);

                    newRule.Name = ruleName;
                    newRule.Description = LangManager.GetText("firewall.ruleDescriptionAuto") + ": " + exePath;
                    newRule.ApplicationName = exePath;
                    newRule.Direction = (int)FirewallDirection.Outbound;
                    newRule.Action = (int)FirewallAction.Block;
                    newRule.Enabled = true;
                    newRule.Profiles = Config.ALL_FIREWALL_PROFILES;

                    firewallPolicy.Rules.Add(newRule);

                    // 添加到本地列表
                    lock (addedRulesLock)
                    {
                        if (!addedRules.Contains(ruleName))
                        {
                            addedRules.Add(ruleName);
                        }
                    }

                    LogManager.Info(LangManager.GetText("logMessages.autoCreateFirewallRule", ruleName, exePath));
                    return true;
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
        /// </summary>
        /// <returns>删除的规则数量</returns>
        public int ClearAllRules()
        {
            int deletedCount = 0;
            var rulesToDelete = new List<string>();

            try
            {
                LogManager.Info(LangManager.GetText("logMessages.clearingAllRules"));

                // 1. 首先删除本地列表中的规则
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

                // 2. 然后扫描防火墙中的所有规则，删除由本程序创建的规则
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
                        catch { }
                    }

                    // 删除由本程序创建的规则（以Block_开头）
                    foreach (var ruleName in allRuleNames)
                    {
                        if (ruleName.StartsWith(Config.RULE_NAME_PREFIX) && !rulesToDelete.Contains(ruleName))
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
        /// 删除防火墙规则
        /// </summary>
        /// <param name="ruleName">规则名称</param>
        /// <returns>是否删除成功</returns>
        public bool DeleteRule(string ruleName)
        {
            try
            {
                firewallPolicy.Rules.Remove(ruleName);
                
                lock (addedRulesLock)
                {
                    addedRules.Remove(ruleName);
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
                            var files = Directory.GetFiles(target.Path, Config.EXE_SEARCH_PATTERN, SearchOption.AllDirectories);
                            LogManager.Info(LangManager.GetText("logMessages.scanCompleted", target.Path, files.Length));
                            return files.ToList();
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
                
                // 合并结果
                foreach (var task in scanTasks)
                {
                    exeFiles.AddRange(task.Result);
                }

                // 去重，避免重复处理
                exeFiles = exeFiles.Distinct().ToList();

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
                        // 生成包含文件路径哈希值的规则名称，确保唯一性
                        string fileName = System.IO.Path.GetFileNameWithoutExtension(exeFile);
                        string sanitizedFileName = SanitizeRuleName(fileName);
                        string pathHash = GetPathHash(exeFile);
                        string ruleName = $"{Config.RULE_NAME_PREFIX}{sanitizedFileName}_{pathHash}";

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
                        if (Config.CRITICAL_PROGRAMS.Any(c => fullFileName.Equals(c, StringComparison.OrdinalIgnoreCase)))
                        {
                            LogManager.Warning(LangManager.GetText("logMessages.skipCriticalProgram", exeFile));
                            skippedCount++;
                            continue;
                        }

                        // 检查规则是否已存在
                        if (!CheckRuleExists(ruleName))
                        {
                            // 创建新规则
                            Type ruleType = Type.GetTypeFromProgID(Config.FIREWALL_RULE_PROGID);
                            dynamic newRule = Activator.CreateInstance(ruleType);

                            newRule.Name = ruleName;
                            newRule.Description = LangManager.GetText("firewall.ruleDescription") + ": " + exeFile;
                            newRule.ApplicationName = exeFile;
                            newRule.Direction = (int)FirewallDirection.Outbound;
                            newRule.Action = (int)FirewallAction.Block;
                            newRule.Enabled = true;
                            newRule.Profiles = Config.ALL_FIREWALL_PROFILES;

                            firewallPolicy.Rules.Add(newRule);

                            // 添加到本地列表
                            lock (addedRulesLock)
                            {
                                addedRules.Add(ruleName);
                            }

                            addedCount++;
                            LogManager.Info(LangManager.GetText("logMessages.createFirewallRule", ruleName, exeFile));
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
                        exeFiles = Directory.GetFiles(folderPath, Config.EXE_SEARCH_PATTERN, SearchOption.AllDirectories).ToList();
                    }
                    catch (Exception ex)
                    {
                        LogManager.Error(LangManager.GetText("logMessages.scanFolderFailed", folderPath, ""), ex);
                        return 0;
                    }
                }

                LogManager.Info(LangManager.GetText("logMessages.removingFolderRules", folderPath, exeFiles.Count));

                // 为每个可执行文件生成规则名称并删除
                foreach (var exeFile in exeFiles)
                {
                    try
                    {
                        string fileName = System.IO.Path.GetFileNameWithoutExtension(exeFile);
                        string sanitizedFileName = SanitizeRuleName(fileName);
                        string pathHash = GetPathHash(exeFile);
                        string ruleName = $"{Config.RULE_NAME_PREFIX}{sanitizedFileName}_{pathHash}";

                        // 检查规则是否存在
                        if (CheckRuleExists(ruleName))
                        {
                            try
                            {
                                firewallPolicy.Rules.Remove(ruleName);
                                lock (addedRulesLock)
                                {
                                    addedRules.Remove(ruleName);
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
        public dynamic GetRuleDetails(string ruleName)
        {
            try
            {
                return firewallPolicy.Rules.Item(ruleName);
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.getRuleDetailsFailed", ruleName), ex);
                return null;
            }
        }
    }
}