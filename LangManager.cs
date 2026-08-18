using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace FirewallManager
{
    /// <summary>
    /// 国际化管理类
    /// 负责加载和管理语言文件，提供翻译文本的获取方法
    /// </summary>
    public class LangManager
    {
        // 语言文件目录和默认语言已移至 Config 类

        /// <summary>
        /// 当前语言
        /// 存储当前使用的语言代码（如 "en", "zh"）
        /// </summary>
        private static string currentLanguage = Config.DEFAULT_LANGUAGE;

        /// <summary>
        /// 语言资源字典
        /// 存储所有语言的翻译文本，键为语言代码，值为翻译字典
        /// </summary>
        private static readonly Dictionary<string, Dictionary<string, string>> languageResources = new Dictionary<string, Dictionary<string, string>>();
        
        /// <summary>
        /// 翻译缓存
        /// 使用 ConcurrentDictionary 实现线程安全的热点翻译缓存
        /// </summary>
        private static readonly ConcurrentDictionary<string, string> translationCache = new ConcurrentDictionary<string, string>();
        
        /// <summary>
        /// 用于线程安全访问的锁对象
        /// </summary>
        private static readonly object resourceLock = new object();

        /// <summary>
        /// 预编译的正则表达式：匹配 {0}、{1} 等格式化占位符
        /// 使用静态编译避免每次调用 GetText 时重新编译正则
        /// </summary>
        private static readonly System.Text.RegularExpressions.Regex _placeholderRegex =
            new System.Text.RegularExpressions.Regex(
                @"\{\d+\}",
                System.Text.RegularExpressions.RegexOptions.Compiled);

        /// <summary>
        /// 初始化国际化管理器
        /// </summary>
        static LangManager()
        {
            LoadLanguageFiles();
            // 尝试根据系统语言设置当前语言
            TrySetSystemLanguage();
        }

        /// <summary>
        /// 加载所有语言文件
        /// </summary>
        private static void LoadLanguageFiles()
        {
            try
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                string languageDir = Path.Combine(baseDir, Config.LANGUAGE_DIR);
                
                if (!Directory.Exists(languageDir))
                {
                    string errorMsg = $"Language directory not found: {languageDir}. " +
                                     $"Base directory: {baseDir}. " +
                                     $"Expected language files: {Config.DEFAULT_LANGUAGE}.json";
                    LogManager.Error(errorMsg);
                    return;
                }
                
                var files = Directory.GetFiles(languageDir, "*.json");
                if (files.Length == 0)
                {
                    string errorMsg = $"No language files found in directory: {languageDir}. " +
                                     $"Expected at least: {Config.DEFAULT_LANGUAGE}.json";
                    LogManager.Error(errorMsg);
                    return;
                }
                
                int successCount = 0;
                int failCount = 0;
                
                foreach (var file in files)
                    {
                        try
                        {
                            string fileName = Path.GetFileNameWithoutExtension(file);
                            string languageCode = fileName.Contains('-') ? fileName.Split('-')[0].ToLower() : fileName.ToLower();
                            
                            if (!System.Text.RegularExpressions.Regex.IsMatch(languageCode, "^[a-z]{2}$"))
                            {
                                string errorMsg = $"Invalid language code format: {languageCode} from file: {file}. Expected 2-letter code (e.g., 'en', 'zh')";
                                LogManager.Warning(errorMsg);
                                failCount++;
                                continue;
                            }
                            
                            string jsonContent = File.ReadAllText(file, System.Text.Encoding.UTF8);
                            
                            if (string.IsNullOrWhiteSpace(jsonContent))
                            {
                                string errorMsg = $"Language file is empty: {file}";
                                LogManager.Warning(errorMsg);
                                failCount++;
                                continue;
                            }
                        
                        var jsonDoc = JsonDocument.Parse(jsonContent);
                        var translations = new Dictionary<string, string>();
                        
                        ProcessJsonNode(jsonDoc.RootElement, "", translations);
                        
                        if (translations.Count == 0)
                        {
                            string errorMsg = $"No translations found in language file: {file}";
                            LogManager.Warning(errorMsg);
                            failCount++;
                            continue;
                        }
                        
                        lock (resourceLock)
                        {
                            if (languageResources.ContainsKey(languageCode))
                                languageResources[languageCode] = translations;
                            else
                                languageResources.Add(languageCode, translations);
                        }
                        
                        successCount++;
                    }
                    catch (JsonException ex)
                    {
                        string errorMsg = $"Failed to parse JSON in language file: {file}. Error: {ex.Message}";
                        LogManager.Error(errorMsg, ex);
                        failCount++;
                    }
                    catch (Exception ex)
                    {
                        string errorMsg = $"Failed to load language file: {file}. Error: {ex.Message}";
                        LogManager.Error(errorMsg, ex);
                        failCount++;
                    }
                }
                
                string summaryMsg = $"Language files loading completed. Success: {successCount}, Failed: {failCount}";
                
                if (successCount == 0)
                {
                    LogManager.Error($"No language files loaded successfully. Application may not display text correctly.");
                    LogManager.Info(LangManager.GetText("logMessages.langManager.loadFailedNoFallback"));
                }
                else if (failCount > 0)
                {
                    LogManager.Warning(summaryMsg);
                }
                else
                {
                    LogManager.Info(summaryMsg);
                }
            }
            catch (Exception ex)
            {
                string errorMsg = $"Failed to initialize language manager: {ex.Message}";
                LogManager.Error(errorMsg, ex);
            }
        }
        
        private const int _maxJsonDepth = 10;

        /// <summary>
        /// 递归处理 JSON 节点（带深度限制）
        /// </summary>
        /// <param name="element">JSON 元素</param>
        /// <param name="prefix">当前路径前缀</param>
        /// <param name="translations">翻译字典</param>
        private static void ProcessJsonNode(JsonElement element, string prefix, Dictionary<string, string> translations)
        {
            ProcessJsonNode(element, prefix, translations, 0);
        }

        private static void ProcessJsonNode(JsonElement element, string prefix, Dictionary<string, string> translations, int depth)
        {
            if (depth >= _maxJsonDepth)
            {
                // 直接使用硬编码消息，避免递归调用 GetText
                LogManager.Warning("JSON parsing depth exceeded maximum limit");
                return;
            }

            switch (element.ValueKind)
            {
                case JsonValueKind.Object:
                    foreach (var property in element.EnumerateObject())
                    {
                        string newPrefix = string.IsNullOrEmpty(prefix) ? property.Name : $"{prefix}.{property.Name}";
                        ProcessJsonNode(property.Value, newPrefix, translations, depth + 1);
                    }
                    break;
                case JsonValueKind.String:
                    if (!string.IsNullOrEmpty(prefix))
                    {
                        translations[prefix] = element.GetString();
                    }
                    break;
                // 忽略其他类型
                default:
                    break;
            }
        }

        /// <summary>
        /// 尝试根据系统语言设置当前语言
        /// </summary>
        private static void TrySetSystemLanguage()
        {
            try
            {
                string systemLanguage = System.Globalization.CultureInfo.CurrentUICulture.TwoLetterISOLanguageName.ToLower();
                lock (resourceLock)
                {
                    if (languageResources.ContainsKey(systemLanguage))
                    {
                        currentLanguage = systemLanguage;
                    }
                }
            }
            catch { }
        }

        /// <summary>
        /// 设置当前语言
        /// 切换应用程序的显示语言
        /// </summary>
        /// <param name="languageCode">语言代码（如 "en", "zh"）</param>
        public static void SetLanguage(string languageCode)
        {
            lock (resourceLock)
            {
                if (languageResources.ContainsKey(languageCode))
                {
                    currentLanguage = languageCode;
                }
                else
                {
                    currentLanguage = Config.DEFAULT_LANGUAGE;
                }
            }
            // 语言切换时清空缓存，确保获取最新翻译
            translationCache.Clear();
        }

        /// <summary>
        /// 获取当前语言
        /// </summary>
        /// <returns>当前语言代码</returns>
        public static string GetCurrentLanguage()
        {
            return currentLanguage;
        }

        /// <summary>
        /// 检查语言资源是否已加载
        /// </summary>
        /// <returns>是否已加载语言资源</returns>
        public static bool IsLanguageLoaded()
        {
            lock (resourceLock)
            {
                return languageResources.Count > 0;
            }
        }

        /// <summary>
        /// 重新加载语言文件
        /// </summary>
        public static void ReloadLanguageFiles()
        {
            LoadLanguageFiles();
        }

        /// <summary>
        /// 获取翻译文本
        /// </summary>
        /// <param name="key">文本键值，格式为 "section.key"</param>
        /// <param name="key">Text key in format "section.key"</param>
        /// <param name="args">格式化参数</param>
        /// <param name="args">Formatting parameters</param>
        /// <returns>翻译后的文本</returns>
        /// <returns>Translated text</returns>
        public static string GetText(string key, params object[] args)
        {
            try
            {
                string text = GetTextInternal(key);
                if (!string.IsNullOrEmpty(text) && args != null && args.Length > 0)
                {
                    int placeholderCount = _placeholderRegex.Matches(text).Count;
                    if (placeholderCount > 0)
                    {
                        if (placeholderCount <= args.Length)
                        {
                            return string.Format(text, args);
                        }
                        else
                        {
                            object[] extendedArgs = new object[placeholderCount];
                            Array.Copy(args, extendedArgs, args.Length);
                            for (int i = args.Length; i < placeholderCount; i++)
                            {
                                extendedArgs[i] = string.Empty;
                            }
                            return string.Format(text, extendedArgs);
                        }
                    }
                }
                return text;
            }
            catch (Exception)
            {
                return key;
            }
        }

        /// <summary>
        /// 内置回退翻译字典（语言文件加载失败时使用）
        /// </summary>
        private static readonly Dictionary<string, string> FallbackTranslations = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "messages.errorTitle", "Error" },
            { "messages.warningTitle", "Warning" },
            { "messages.infoTitle", "Information" },
            { "messages.confirmTitle", "Confirm" },
            { "messages.yes", "Yes" },
            { "messages.no", "No" },
            { "messages.ok", "OK" },
            { "messages.cancel", "Cancel" },
            { "messages.close", "Close" },
            { "firewall.ruleDescription", "Block outbound traffic" },
            { "status.idle", "Idle" },
            { "status.running", "Running" },
            { "status.rulesCount", "Rules: {0}" },
            { "status.scanningTargets", "Scanning targets..." },
            { "status.creatingRules", "Creating rules ({0} files found)..." },
            { "status.processingFile", "Processing {0}/{1}: {2}" },
            { "status.firewallNotInitialized", "Firewall not initialized" },
            { "logMessages.startup", "Application started" },
            { "logMessages.shutdown", "Application shutting down" },
            { "logMessages.fileNotFound", "File not found: {0}" },
            { "logMessages.nullOrEmptyPath", "Path is null or empty" },
            { "logMessages.newFileDetected", "New file detected: {0}" },
            { "logMessages.createRuleForExeFailed", "Failed to create rule for {0}: {1}" },
            { "logMessages.firewallPolicyNotInitialized", "Firewall policy not initialized" },
            { "logMessages.startInitializeFirewallComponents", "Starting firewall component initialization" },
            { "logMessages.updateCompleted", "Update completed. Added: {0}, Skipped: {1}" },
            { "logMessages.updateCanceled", "Update was canceled" },
            { "logMessages.updateError", "Update error: {0}" },
            { "logMessages.langManager.paramMismatch", "Parameter count mismatch for key: {0}" },
            { "logMessages.langManager.getTranslationFailed", "Failed to get translation: {0}" },
            { "logMessages.langManager.loadFailedNoFallback", "No language files loaded. Using built-in fallback translations." },
            { "logMessages.invalidCallerDetected", "Invalid caller detected for path: {0}" },
            { "logMessages.fileNotReadyAfterRetries", "File not ready after retries: {0}" },
            { "logMessages.fileDisappearedBeforeProcessing", "File disappeared before processing: {0}" },
            { "logMessages.fileChanged", "File changed: {0}" },
            { "logMessages.processFileChangedEventFailed", "Failed to process file changed event" },
            { "logMessages.rejectSymbolicLinkFile", "Rejected symbolic link file: {0}" },
            { "logMessages.rejectExtendedLengthPath", "Rejected extended-length path: {0}" },
            { "logMessages.pathTooLong", "Path too long, skipping: {0}..." },
            { "logMessages.jsonDepthExceeded", "JSON parsing depth exceeded maximum limit" },
            { "logMessages.processFileCreatedEventFailed", "Failed to process file created event" },
            { "logMessages.logWriteFailed", "Failed to write log: {0}" },
            { "logMessages.stackTrace", "Stack trace: {0}" },
            { "logMessages.readLogFailed", "Failed to read log file: {0}" },
            { "logMessages.clearLogFailed", "Failed to clear logs: {0}" },
            { "logMessages.clearLogEmptyFailed", "Failed to clear log file: {0}" },
            { "logMessages.whitelistCacheRefreshed", "Whitelist cache refreshed: {0} entries" },
            { "logMessages.whitelistInvalidPath", "Invalid whitelist path: {0}" },
            { "logMessages.whitelistCacheRefreshedManual", "Whitelist cache manually refreshed: {0} entries" },
            { "logMessages.refreshWhitelistCacheFailed", "Failed to refresh whitelist cache" },
            { "logMessages.whitelistFileChangedCacheRefreshed", "Whitelist file changed, cache refreshed" },
            { "logMessages.loadWhitelistItems", "Loaded {0} whitelist items" },
            { "logMessages.loadWhitelistFailed", "Failed to load whitelist: {0}" },
            { "logMessages.loadRuleDetailsFailed", "Failed to load rule details: {0}" },
            { "logMessages.clearingAllRules", "Clearing all firewall rules" },
            { "logMessages.deleteFirewallRule", "Deleted rule: {0}" },
            { "logMessages.deleteRuleFailed", "Failed to delete rule {0}: {1}" },
            { "logMessages.scanFirewallRulesFailed", "Failed to scan firewall rules" },
            { "logMessages.clearRulesSuccess", "Successfully cleared {0} rules" },
            { "logMessages.clearFirewallRulesFailed", "Failed to clear firewall rules" },
            { "logMessages.createFirewallRule", "Created rule: {0} for {1}" },
            { "logMessages.ruleExistsSkip", "Rule already exists, skipping: {0}" },
            { "logMessages.processExeFailed", "Failed to process {0}: {1}" },
            { "logMessages.autoCreateFirewallRule", "Auto-created rule: {0} for {1}" },
            { "logMessages.syncRulesStart", "Starting rule synchronization..." },
            { "logMessages.syncRulesCompleted", "Completed rule synchronization" },
            { "logMessages.syncRulesFailed", "Failed to synchronize rules" },
            { "logMessages.appInWhitelistSkipped", "Application in whitelist, skipped: {0}" },
            { "logMessages.skipCriticalProgram", "Skipping critical program: {0}" },
            { "logMessages.firewallRuleTypeNotFound", "Firewall rule COM type not found" },
            { "logMessages.createFirewallRuleInstanceFailed", "Failed to create firewall rule instance" },
            { "logMessages.foundExeFiles", "Found {0} executable files" },
            { "logMessages.startScanningFolder", "Scanning folder: {0}" },
            { "logMessages.scanCompleted", "Scan completed: {0} found {1} files" },
            { "logMessages.scanFolderFailed", "Failed to scan folder {0}: {1}" },
            { "logMessages.removingFolderRules", "Removing rules for folder: {0} ({1} files)" },
            { "logMessages.removingFolderRulesCompleted", "Completed removing rules for folder: {0}" },
            { "logMessages.removedFolderRules", "Removed {1} rules for folder: {0}" },
            { "logMessages.removingFolderRulesFailed", "Failed to remove folder rules: {0}" },
            { "logMessages.processFileFailed", "Failed to process file: {0}" },
            { "logMessages.getRuleDetailsFailed", "Failed to get rule details: {0}" },
            { "logMessages.checkRuleExistsFailed", "Failed to check rule existence: {0}" },
            { "logMessages.firewallPolicyTypeNotFound", "Firewall policy COM type not found" },
            { "logMessages.foundType", "Found type: {0}" },
            { "logMessages.firewallPolicyInstanceCreated", "Firewall policy instance created" },
            { "logMessages.firewallPolicyTypeValidationFailed", "Firewall policy COM object type validation failed" },
            { "logMessages.firewallRuleTypeValidationFailed", "Firewall rule COM object type validation failed" },
            { "logMessages.configIntegrityVerificationFailed", "Configuration file integrity verification failed" },
            { "logMessages.configIntegrityHashSaved", "Configuration file integrity hash saved" },
            { "logMessages.configIntegrityHashSaveFailed", "Failed to save configuration file integrity hash" },
            { "logMessages.hmacKeyGenerated", "HMAC key generated and saved with DPAPI protection" },
            { "logMessages.hmacKeySaveFailed", "Failed to save HMAC key: {0}" },
            { "messages.configIntegrityVerificationFailed", "Configuration file may have been tampered. Loading aborted for security." },
            { "messages.configLoadFailed", "Failed to load configuration file. The file may be corrupted." },
            { "messages.securityWarningTitle", "Security Warning" },
            { "messages.ruleActionAllowWarning", "WARNING: Changing rule action to Allow will permit the application to make network connections." },
            { "messages.ruleDirectionInboundWarning", "WARNING: Changing rule direction to Inbound will allow incoming connections to this application." },
            { "messages.ruleChangeConfirm", "Are you sure you want to make this change?" },
            { "messages.ruleNotFound", "Rule not found." },
            { "messages.selectExeToViewDetails", "Please select an EXE file to view rule details." },
            { "messages.informationTitle", "Information" },
            { "menu.viewRuleDetails", "View Rule Details" },
            { "messages.languageChangeFailed", "Failed to change language." },
            { "messages.logContentTruncated", "[Log content truncated]" },
            { "logMessages.tryCreateFirewallPolicyObject", "Attempting to create firewall policy object: {0}" },
            { "logMessages.deleteWhitelistAppRule", "Deleted whitelist app rule: {0}" },
            { "logMessages.deleteWhitelistAppRuleFailed", "Failed to delete whitelist app rule {0}: {1}" },
            { "logMessages.stopTaskTimeout", "Stop operation timed out after 5 seconds" },
            { "logMessages.stopTaskFailed", "Failed to stop task: {0}" },
            { "logMessages.safeSetPropertyFailed", "Failed to set COM property '{0}': {1}" },
            { "logMessages.releaseComObjectFailed", "Failed to release COM object: {0}" },
            { "logMessages.readRuleNameFailed", "Failed to read rule name: {0}" },
            { "logMessages.safeGetPropertyFailed", "Failed to get COM property '{0}': {1}" },
            { "logMessages.invalidGuidForComObject", "Invalid GUID for COM object: {0}" },
            { "logMessages.clsidTypeNotFound", "CLSID type not found: {0}" },
            { "logMessages.createComObjectFailed", "Failed to create COM object: {0}" },
            { "logMessages.comObjectValidationFailed", "COM object validation failed: {0}" },
            { "logMessages.createComObjectException", "Exception creating COM object {0}: {1}" },
            { "logMessages.comObjectClsidMismatch", "COM object CLSID mismatch: got {0}, expected {1}" },
            { "logMessages.comObjectIidMismatch", "COM object IID mismatch for {0}" },
            { "logMessages.comObjectQueryInterfaceFailed", "COM object QueryInterface failed: {0}" },
            { "logMessages.comObjectValidationException", "COM object validation exception: {0}" },
            { "logMessages.configIntegrityFileMissing", "Config integrity file missing for {0}, refusing to load" },
            { "logMessages.updatingRules", "Updating firewall rules..." },
            { "logMessages.whitelistFileChanged", "Whitelist file changed" },
            { "logMessages.pathNormalizationFailed", "Failed to normalize path '{0}': {1}" },
            { "logMessages.setFilePermissionsFailed", "Failed to set secure file permissions: {0}" },
        };

        /// <summary>
        /// 内部方法：获取翻译文本
        /// </summary>
        /// <param name="key">文本键值，格式为 "section.key"</param>
        /// <returns>翻译后的文本</returns>
        private static string GetTextInternal(string key)
        {
            if (string.IsNullOrEmpty(key))
            {
                return string.Empty;
            }

            // 构建缓存键，包含当前语言
            // Build cache key including current language
            string cacheKey = $"{currentLanguage}:{key}";
            
            // 尝试从缓存获取
            // Try to get from cache first
            if (translationCache.TryGetValue(cacheKey, out string cachedText))
            {
                return cachedText;
            }

            // 尝试从当前语言获取
            string text = GetTextFromLanguage(key, currentLanguage);
            if (!string.IsNullOrEmpty(text))
            {
                translationCache.TryAdd(cacheKey, text);
                return text;
            }

            // 如果当前语言没有找到，尝试从默认语言获取
            text = GetTextFromLanguage(key, Config.DEFAULT_LANGUAGE);
            if (!string.IsNullOrEmpty(text))
            {
                translationCache.TryAdd(cacheKey, text);
                return text;
            }

            // 如果语言文件加载失败，尝试从内置回退字典获取
            if (FallbackTranslations.TryGetValue(key, out string fallbackText))
            {
                translationCache.TryAdd(cacheKey, fallbackText);
                return fallbackText;
            }

            // 如果都没有找到，返回原始键值并缓存
            translationCache.TryAdd(cacheKey, key);
            return key;
        }

        /// <summary>
        /// 从指定语言获取文本
        /// </summary>
        /// <param name="key">文本键值，格式为 "section.key"</param>
        /// <param name="languageCode">语言代码</param>
        /// <returns>翻译后的文本</returns>
        private static string GetTextFromLanguage(string key, string languageCode)
        {
            lock (resourceLock)
            {
                if (languageResources.TryGetValue(languageCode, out var translations))
                {
                    if (translations.TryGetValue(key, out string text))
                    {
                        return text;
                    }
                }
                return string.Empty;
            }
        }
    }
}