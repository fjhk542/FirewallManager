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
        /// <summary>
        /// 条件编译的调试输出方法
        /// 仅在 DEBUG 模式下输出，Release 模式下被移除
        /// </summary>
        [System.Diagnostics.Conditional("DEBUG")]
        private static void DebugLog(string message)
        {
            System.Diagnostics.Debug.WriteLine(message);
        }
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
                
                DebugLog($"[LangManager] Base directory: {baseDir}");
                DebugLog($"[LangManager] Language directory: {languageDir}");
                
                if (!Directory.Exists(languageDir))
                {
                    string errorMsg = $"Language directory not found: {languageDir}. " +
                                     $"Base directory: {baseDir}. " +
                                     $"Expected language files: {Config.DEFAULT_LANGUAGE}.json";
                    DebugLog($"[LangManager] ERROR: {errorMsg}");
                    LogManager.Error(errorMsg);
                    return;
                }
                
                DebugLog($"[LangManager] Language directory exists");
                
                var files = Directory.GetFiles(languageDir, "*.json");
                if (files.Length == 0)
                {
                    string errorMsg = $"No language files found in directory: {languageDir}. " +
                                     $"Expected at least: {Config.DEFAULT_LANGUAGE}.json";
                    DebugLog($"[LangManager] ERROR: {errorMsg}");
                    LogManager.Error(errorMsg);
                    return;
                }
                
                DebugLog($"[LangManager] Found {files.Length} language file(s)");
                
                int successCount = 0;
                int failCount = 0;
                
                foreach (var file in files)
                {
                    DebugLog($"[LangManager] Processing file: {file}");
                    try
                    {
                        string fileName = Path.GetFileNameWithoutExtension(file);
                        string languageCode = fileName.Contains('-') ? fileName.Split('-')[0].ToLower() : fileName.ToLower();
                        DebugLog($"[LangManager] Extracted language code: {languageCode}");
                        
                        if (!System.Text.RegularExpressions.Regex.IsMatch(languageCode, "^[a-z]{2}$"))
                        {
                            string errorMsg = $"Invalid language code format: {languageCode} from file: {file}. Expected 2-letter code (e.g., 'en', 'zh')";
                            DebugLog($"[LangManager] ERROR: {errorMsg}");
                            LogManager.Warning(errorMsg);
                            failCount++;
                            continue;
                        }
                        
                        string jsonContent = File.ReadAllText(file, System.Text.Encoding.UTF8);
                        
                        if (string.IsNullOrWhiteSpace(jsonContent))
                        {
                            string errorMsg = $"Language file is empty: {file}";
                            DebugLog($"[LangManager] ERROR: {errorMsg}");
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
                            DebugLog($"[LangManager] WARNING: {errorMsg}");
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
                        
                        DebugLog($"[LangManager] Successfully loaded language: {languageCode} with {translations.Count} translations");
                        successCount++;
                    }
                    catch (JsonException ex)
                    {
                        string errorMsg = $"Failed to parse JSON in language file: {file}. Error: {ex.Message}";
                        DebugLog($"[LangManager] ERROR: {errorMsg}");
                        LogManager.Error(errorMsg, ex);
                        failCount++;
                    }
                    catch (Exception ex)
                    {
                        string errorMsg = $"Failed to load language file: {file}. Error: {ex.Message}";
                        DebugLog($"[LangManager] ERROR: {errorMsg}");
                        LogManager.Error(errorMsg, ex);
                        failCount++;
                    }
                }
                
                string summaryMsg = $"Language files loading completed. Success: {successCount}, Failed: {failCount}";
                DebugLog($"[LangManager] {summaryMsg}");
                
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
                DebugLog($"[LangManager] FATAL ERROR: {errorMsg}");
                LogManager.Error(errorMsg, ex);
            }
        }
        
        /// <summary>
        /// 递归处理 JSON 节点
        /// </summary>
        /// <param name="element">JSON 元素</param>
        /// <param name="prefix">当前路径前缀</param>
        /// <param name="translations">翻译字典</param>
        private static void ProcessJsonNode(JsonElement element, string prefix, Dictionary<string, string> translations)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.Object:
                    foreach (var property in element.EnumerateObject())
                    {
                        string newPrefix = string.IsNullOrEmpty(prefix) ? property.Name : $"{prefix}.{property.Name}";
                        ProcessJsonNode(property.Value, newPrefix, translations);
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
        /// 测试语言文件加载
        /// </summary>
        /// <returns>加载结果</returns>
        public static string TestLanguageLoading()
        {
            try
            {
                string result = $"{LangManager.GetText("logMessages.langManager.testLoad")}\n";
                
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                string languageDir = Path.Combine(baseDir, Config.LANGUAGE_DIR);
                
                result += $"{LangManager.GetText("logMessages.langManager.baseDir", baseDir)}\n";
                result += $"{LangManager.GetText("logMessages.langManager.languageDir", languageDir)}\n";
                
                if (Directory.Exists(languageDir))
                {
                    result += $"{LangManager.GetText("logMessages.langManager.dirExists")}\n";
                    
                    var files = Directory.GetFiles(languageDir, "*.json");
                    result += $"{LangManager.GetText("logMessages.langManager.foundFiles", files.Length)}\n";
                    
                    foreach (var file in files)
                    {
                        result += $"{LangManager.GetText("logMessages.langManager.file", file)}\n";
                    }
                }
                else
                {
                    result += $"{LangManager.GetText("logMessages.langManager.dirNotExists")}\n";
                }
                
                // Check loaded language resources
                lock (resourceLock)
                {
                    result += $"\n{LangManager.GetText("logMessages.langManager.loadedResources", languageResources.Count)}\n";
                    foreach (var lang in languageResources.Keys)
                    {
                        result += $"- {lang}\n";
                    }
                }
                
                return result;
            }
            catch (Exception ex)
            {
                return LangManager.GetText("logMessages.langManager.testFailed", ex.Message);
            }
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
                    // 检查文本是否包含格式化占位符，防止格式化字符串攻击
                    // Check if text contains format placeholders to prevent format string attacks
                    int placeholderCount = System.Text.RegularExpressions.Regex.Matches(text, @"\{\d+\}").Count;
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
                        DebugLog(LangManager.GetText("logMessages.langManager.paramMismatch", key));
                        return text;
                    }
                }
                return text;
            }
            catch (Exception ex)
            {
                DebugLog(LangManager.GetText("logMessages.langManager.getTranslationFailed", ex.Message));
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
            { "logMessages.rejectSymbolicLinkFile", "Rejected symbolic link file: {0}" },
            { "logMessages.rejectExtendedLengthPath", "Rejected extended-length path: {0}" },
            { "logMessages.processFileCreatedEventFailed", "Failed to process file created event" },
            { "logMessages.logWriteFailed", "Failed to write log: {0}" },
            { "logMessages.stackTrace", "Stack trace: {0}" },
            { "logMessages.readLogFailed", "Failed to read log file: {0}" },
            { "logMessages.clearLogFailed", "Failed to clear logs: {0}" },
            { "logMessages.clearLogEmptyFailed", "Failed to clear log file: {0}" },
            { "logMessages.whitelistCacheRefreshed", "Whitelist cache refreshed: {0} entries" },
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
            { "logMessages.removingFolderRulesFailed", "Failed to remove folder rules: {0}" },
            { "logMessages.processFileFailed", "Failed to process file: {0}" },
            { "logMessages.getRuleDetailsFailed", "Failed to get rule details: {0}" },
            { "logMessages.checkRuleExistsFailed", "Failed to check rule existence: {0}" },
            { "logMessages.firewallPolicyTypeNotFound", "Firewall policy COM type not found" },
            { "logMessages.foundType", "Found type: {0}" },
            { "logMessages.firewallPolicyInstanceCreated", "Firewall policy instance created" },
            { "logMessages.tryCreateFirewallPolicyObject", "Attempting to create firewall policy object: {0}" },
            { "logMessages.deleteWhitelistAppRule", "Deleted whitelist app rule: {0}" },
            { "logMessages.deleteWhitelistAppRuleFailed", "Failed to delete whitelist app rule {0}: {1}" },
            { "logMessages.updatingRules", "Updating firewall rules..." },
            { "logMessages.whitelistFileChanged", "Whitelist file changed" },
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