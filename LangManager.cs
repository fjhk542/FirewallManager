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
                
                // 使用调试输出代替文件日志
                System.Diagnostics.Debug.WriteLine($"[LangManager] {LangManager.GetText("logMessages.langManager.baseDir", baseDir)}");
                System.Diagnostics.Debug.WriteLine($"[LangManager] {LangManager.GetText("logMessages.langManager.languageDir", languageDir)}");
                
                if (Directory.Exists(languageDir))
                {
                    System.Diagnostics.Debug.WriteLine($"[LangManager] {LangManager.GetText("logMessages.langManager.dirExists")}");
                    
                    var files = Directory.GetFiles(languageDir, "*.json");
                    System.Diagnostics.Debug.WriteLine($"[LangManager] {LangManager.GetText("logMessages.langManager.foundFiles", files.Length)}");
                    
                    foreach (var file in files)
                    {
                        System.Diagnostics.Debug.WriteLine($"[LangManager] {LangManager.GetText("logMessages.langManager.processingFile", file)}");
                        try
                        {
                            string fileName = Path.GetFileNameWithoutExtension(file);
                            string languageCode = fileName.Contains('-') ? fileName.Split('-')[0].ToLower() : fileName.ToLower();
                            System.Diagnostics.Debug.WriteLine($"[LangManager] {LangManager.GetText("logMessages.langManager.extractCode", languageCode)}");
                            
                            if (!System.Text.RegularExpressions.Regex.IsMatch(languageCode, "^[a-z]{2}$"))
                            {
                                System.Diagnostics.Debug.WriteLine($"[LangManager] {LangManager.GetText("logMessages.langManager.invalidCode", languageCode)}");
                                continue;
                            }
                            
                            string jsonContent = File.ReadAllText(file, System.Text.Encoding.UTF8);
                            // 尝试解析为动态对象
                            var jsonDoc = JsonDocument.Parse(jsonContent);
                            var translations = new Dictionary<string, string>();
                            
                            // 递归处理所有嵌套节点
                            ProcessJsonNode(jsonDoc.RootElement, "", translations);
                            
                            lock (resourceLock)
                            {
                                if (languageResources.ContainsKey(languageCode))
                                    languageResources[languageCode] = translations;
                                else
                                    languageResources.Add(languageCode, translations);
                            }
                            System.Diagnostics.Debug.WriteLine($"[LangManager] {LangManager.GetText("logMessages.langManager.loadSuccess", languageCode, translations.Count)}");
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine($"[LangManager] {LangManager.GetText("logMessages.langManager.loadFileFailed", file, ex.Message)}");
                        }
                    }
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine($"[LangManager] {LangManager.GetText("logMessages.langManager.dirNotExists")}");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[LangManager] {LangManager.GetText("logMessages.langManager.loadFailed", ex.Message)}");
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
                        // 没有占位符，直接返回文本
                        // No placeholders, return text directly
                        return text;
                    }
                    else
                    {
                        // Placeholder count doesn't match parameter count, log warning and return original text
                        System.Diagnostics.Debug.WriteLine(LangManager.GetText("logMessages.langManager.paramMismatch", key));
                        return text;
                    }
                }
                return text;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(LangManager.GetText("logMessages.langManager.getTranslationFailed", ex.Message));
                return key; // Return original key if failed to get translation
            }
        }

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