using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace FirewallManager
{
    /// <summary>
    /// 国际化管理类
    /// Internationalization Manager Class
    /// 负责加载和管理语言文件，提供翻译文本的获取方法
    /// Responsible for loading and managing language files, providing methods to get translated text
    /// </summary>
    public class LangManager
    {
        // 语言文件目录和默认语言已移至 Config 类
        // Language directory and default language moved to Config class

        /// <summary>
        /// 当前语言
        /// Current language
        /// </summary>
        private static string currentLanguage = Config.DEFAULT_LANGUAGE;

        /// <summary>
        /// 语言资源字典
        /// Language resource dictionary
        /// </summary>
        private static readonly Dictionary<string, Dictionary<string, string>> languageResources = new Dictionary<string, Dictionary<string, string>>();
        
        /// <summary>
        /// 用于线程安全访问的锁对象
        /// Lock object for thread-safe access
        /// </summary>
        private static readonly object resourceLock = new object();

        /// <summary>
        /// 初始化国际化管理器
        /// Initialize internationalization manager
        /// </summary>
        static LangManager()
        {
            LoadLanguageFiles();
            // 尝试根据系统语言设置当前语言
            // Try to set current language based on system language
            TrySetSystemLanguage();
        }

        /// <summary>
        /// 加载所有语言文件
        /// Load all language files
        /// </summary>
        private static void LoadLanguageFiles()
        {
            try
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                string languageDir = Path.Combine(baseDir, Config.LANGUAGE_DIR);
                
                // 写入调试日志到文件
                File.AppendAllText(Path.Combine(baseDir, "LangDebug.log"), $"[{DateTime.Now}] 基础目录: {baseDir}\n");
                File.AppendAllText(Path.Combine(baseDir, "LangDebug.log"), $"[{DateTime.Now}] 语言文件目录: {languageDir}\n");
                
                if (Directory.Exists(languageDir))
                {
                    File.AppendAllText(Path.Combine(baseDir, "LangDebug.log"), $"[{DateTime.Now}] 语言目录存在\n");
                    
                    var files = Directory.GetFiles(languageDir, "*.json");
                    File.AppendAllText(Path.Combine(baseDir, "LangDebug.log"), $"[{DateTime.Now}] 找到 {files.Length} 个语言文件\n");
                    
                    foreach (var file in files)
                    {
                        File.AppendAllText(Path.Combine(baseDir, "LangDebug.log"), $"[{DateTime.Now}] 处理文件: {file}\n");
                        try
                        {
                            string fileName = Path.GetFileNameWithoutExtension(file);
                            string languageCode = fileName.Contains('-') ? fileName.Split('-')[0].ToLower() : fileName.ToLower();
                            File.AppendAllText(Path.Combine(baseDir, "LangDebug.log"), $"[{DateTime.Now}] 提取语言代码: {languageCode}\n");
                            
                            if (!System.Text.RegularExpressions.Regex.IsMatch(languageCode, "^[a-z]{2}$"))
                            {
                                File.AppendAllText(Path.Combine(baseDir, "LangDebug.log"), $"[{DateTime.Now}] 无效的语言代码: {languageCode}\n");
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
                            File.AppendAllText(Path.Combine(baseDir, "LangDebug.log"), $"[{DateTime.Now}] 成功加载语言: {languageCode}, 条目数: {translations.Count}\n");
                        }
                        catch (Exception ex)
                        {
                            File.AppendAllText(Path.Combine(baseDir, "LangDebug.log"), $"[{DateTime.Now}] 加载语言文件 {file} 失败: {ex.Message}\n");
                        }
                    }
                }
                else
                {
                    File.AppendAllText(Path.Combine(baseDir, "LangDebug.log"), $"[{DateTime.Now}] 语言目录不存在\n");
                }
            }
            catch (Exception ex)
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                File.AppendAllText(Path.Combine(baseDir, "LangDebug.log"), $"[{DateTime.Now}] 加载语言文件失败: {ex.Message}\n");
            }
        }
        
        /// <summary>
        /// 递归处理 JSON 节点
        /// Process JSON node recursively
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
        /// Try to set current language based on system language
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
        /// Set current language
        /// </summary>
        /// <param name="languageCode">语言代码（如 "en", "zh"）</param>
        /// <param name="languageCode">Language code (e.g., "en", "zh")</param>
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
        }

        /// <summary>
        /// 获取当前语言
        /// Get current language
        /// </summary>
        /// <returns>当前语言代码</returns>
        /// <returns>Current language code</returns>
        public static string GetCurrentLanguage()
        {
            return currentLanguage;
        }

        /// <summary>
        /// 测试语言文件加载
        /// Test language file loading
        /// </summary>
        /// <returns>加载结果</returns>
        /// <returns>Loading result</returns>
        public static string TestLanguageLoading()
        {
            try
            {
                string result = "测试语言文件加载:\n";
                
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                string languageDir = Path.Combine(baseDir, Config.LANGUAGE_DIR);
                
                result += $"基础目录: {baseDir}\n";
                result += $"语言文件目录: {languageDir}\n";
                
                if (Directory.Exists(languageDir))
                {
                    result += "语言目录存在\n";
                    
                    var files = Directory.GetFiles(languageDir, "*.json");
                    result += $"找到 {files.Length} 个语言文件\n";
                    
                    foreach (var file in files)
                    {
                        result += $"文件: {file}\n";
                    }
                }
                else
                {
                    result += "语言目录不存在\n";
                }
                
                // 检查已加载的语言资源
                lock (resourceLock)
                {
                    result += $"\n已加载的语言资源: {languageResources.Count} 种语言\n";
                    foreach (var lang in languageResources.Keys)
                    {
                        result += $"- {lang}\n";
                    }
                }
                
                return result;
            }
            catch (Exception ex)
            {
                return $"测试失败: {ex.Message}";
            }
        }

        /// <summary>
        /// 检查语言资源是否已加载
        /// Check if language resources are loaded
        /// </summary>
        /// <returns>是否已加载语言资源</returns>
        /// <returns>Whether language resources are loaded</returns>
        public static bool IsLanguageLoaded()
        {
            lock (resourceLock)
            {
                return languageResources.Count > 0;
            }
        }

        /// <summary>
        /// 重新加载语言文件
        /// Reload language files
        /// </summary>
        public static void ReloadLanguageFiles()
        {
            LoadLanguageFiles();
        }

        /// <summary>
        /// 获取翻译文本
        /// Get translated text
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
                        // 占位符数量与参数数量不匹配，记录警告并返回原始文本
                        // Placeholder count doesn't match parameter count, log warning and return original text
                        System.Diagnostics.Debug.WriteLine($"格式化参数数量与占位符数量不匹配: {key}");
                        return text;
                    }
                }
                return text;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"获取翻译文本失败: {ex.Message}");
                return key; // 如果获取失败，返回原始键值
            }
        }

        /// <summary>
        /// 内部方法：获取翻译文本
        /// Internal method: Get translated text
        /// </summary>
        /// <param name="key">文本键值，格式为 "section.key"</param>
        /// <param name="key">Text key in format "section.key"</param>
        /// <returns>翻译后的文本</returns>
        /// <returns>Translated text</returns>
        private static string GetTextInternal(string key)
        {
            if (string.IsNullOrEmpty(key))
            {
                return string.Empty;
            }

            // 尝试从当前语言获取
            string text = GetTextFromLanguage(key, currentLanguage);
            if (!string.IsNullOrEmpty(text))
            {
                return text;
            }

            // 如果当前语言没有找到，尝试从默认语言获取
            text = GetTextFromLanguage(key, Config.DEFAULT_LANGUAGE);
            if (!string.IsNullOrEmpty(text))
            {
                return text;
            }

            // 如果都没有找到，返回原始键值
            return key;
        }

        /// <summary>
        /// 从指定语言获取文本
        /// Get text from specified language
        /// </summary>
        /// <param name="key">文本键值，格式为 "section.key"
        /// Text key in format "section.key"
        /// </param>
        /// <param name="languageCode">语言代码
        /// Language code
        /// </param>
        /// <returns>翻译后的文本
        /// Translated text
        /// </returns>
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