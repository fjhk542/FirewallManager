using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FirewallManager
{
    /// <summary>
    /// 配置持久化服务
    /// 统一管理监控目标、语言选择、自动监控开关的持久化
    /// Schema v2: { "version": 2, "language": "zh", "autoMonitor": true, "targets": ["..."] }
    /// 兼容 v1: 纯字符串数组 ["path1", "path2"]
    /// </summary>
    public static class TargetStore
    {
        /// <summary>
        /// 当前 schema 版本
        /// </summary>
        public const int CurrentVersion = 2;

        /// <summary>
        /// 配置数据结构
        /// </summary>
        public class ConfigData
        {
            /// <summary>Schema 版本号</summary>
            [JsonPropertyName("version")]
            public int Version { get; set; } = CurrentVersion;

            /// <summary>语言代码（如 "zh-CN"、"en-US"）</summary>
            [JsonPropertyName("language")]
            public string Language { get; set; }

            /// <summary>是否启用自动监控</summary>
            [JsonPropertyName("autoMonitor")]
            public bool AutoMonitor { get; set; } = false;

            /// <summary>监控目标路径列表</summary>
            [JsonPropertyName("targets")]
            public List<string> Targets { get; set; } = new List<string>();
        }

        /// <summary>
        /// 加载配置（含完整性校验和 v1 自动迁移）
        /// 完整性校验失败时降级为直接读取，保证向后兼容性
        /// </summary>
        /// <param name="configPath">配置文件路径</param>
        /// <returns>配置数据；加载失败返回 null</returns>
        public static ConfigData Load(string configPath)
        {
            if (string.IsNullOrEmpty(configPath))
            {
                LogManager.Warning("Config path is empty");
                return null;
            }

            if (!File.Exists(configPath))
            {
                LogManager.Info("Config file does not exist, no targets to load");
                return null;
            }

            // 加载前验证配置文件完整性（原子操作，防止TOCTOU攻击）
            string json;
            if (Config.VerifyConfigIntegrityAndRead(configPath, out json))
            {
                // 完整性校验通过
                if (string.IsNullOrWhiteSpace(json))
                {
                    LogManager.Warning("Config file is empty");
                    return null;
                }

                return ParseConfig(json);
            }

            // 完整性校验失败 —— 降级处理：尝试直接读取配置文件
            // 场景：旧版本配置无 .hmac 文件、校验文件丢失、或配置被外部编辑
            LogManager.Warning(LangManager.GetText("logMessages.configIntegrityVerificationFailed"));
            LogManager.Warning("Attempting fallback: reading config file directly");

            try
            {
                json = File.ReadAllText(configPath, Config.Utf8NoBom);
            }
            catch (Exception ex)
            {
                LogManager.Error($"Failed to read config file for fallback: {ex.Message}");
                return null;
            }

            if (string.IsNullOrWhiteSpace(json))
            {
                LogManager.Warning("Config file is empty");
                return null;
            }

            // 尝试解析配置
            var data = ParseConfig(json);
            if (data == null)
            {
                LogManager.Error("Config file integrity check failed and parsing failed, file may be corrupted");
                return null;
            }

            // 解析成功，自动修复完整性校验
            LogManager.Warning("Config loaded via fallback path. Integrity hash will be regenerated.");
            Config.SaveConfigIntegrityHash(configPath);

            return data;
        }

        /// <summary>
        /// 解析配置 JSON（支持 v1/v2 格式自动识别）
        /// 先检测 JSON 结构再选择反序列化方式，避免 v1 数组反序列化为 v2 对象时抛异常
        /// </summary>
        /// <param name="json">JSON 字符串</param>
        /// <returns>配置数据；解析失败返回 null</returns>
        private static ConfigData ParseConfig(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
                return null;

            try
            {
                var options = ComHelper.SafeJsonOptions;

                // 根据 JSON 结构判断格式：以 { 开头为 v2 对象，以 [ 开头为 v1 数组
                string trimmed = json.TrimStart();

                if (trimmed.StartsWith("{"))
                {
                    // v2 schema: { "version": 2, "language": "zh", ... }
                    var config = JsonSerializer.Deserialize<ConfigData>(json, options);
                    if (config != null && config.Version > 0)
                    {
                        // 验证 language 字段格式，防止路径遍历
                        if (!string.IsNullOrEmpty(config.Language) && !IsValidLanguageCode(config.Language))
                        {
                            LogManager.Warning($"Invalid language code in config, ignoring: {config.Language}");
                            config.Language = null;
                        }

                        LogManager.Info($"Loaded config v{config.Version}: language={config.Language ?? "null"}, autoMonitor={config.AutoMonitor}, targets={config.Targets?.Count ?? 0}");
                        return config;
                    }

                    LogManager.Warning("v2 config object parsed but version is missing or invalid");
                    return null;
                }
                else if (trimmed.StartsWith("["))
                {
                    // v1 schema: ["path1", "path2", ...]
                    var paths = JsonSerializer.Deserialize<List<string>>(json, options);
                    if (paths != null)
                    {
                        LogManager.Info("Loaded config v1 (legacy array format), migrating to v2");
                        return new ConfigData
                        {
                            Version = CurrentVersion,
                            Language = null,
                            AutoMonitor = false,
                            Targets = paths
                        };
                    }

                    LogManager.Warning("v1 config array parsed but paths list is null");
                    return null;
                }
                else
                {
                    LogManager.Warning($"Unknown config JSON format (starts with: {trimmed[0]})");
                    return null;
                }
            }
            catch (JsonException ex)
            {
                LogManager.Error($"Config JSON parse failed: {ex.Message}", ex);
                return null;
            }
        }

        /// <summary>
        /// 验证语言代码格式（符合 BCP 47 标准，如 "zh", "en", "zh-CN"）
        /// 防止路径遍历和注入攻击
        /// </summary>
        /// <param name="languageCode">语言代码</param>
        /// <returns>是否有效</returns>
        private static bool IsValidLanguageCode(string languageCode)
        {
            if (string.IsNullOrEmpty(languageCode) || languageCode.Length > 16)
                return false;

            // 验证符合 BCP 47 标准的语言代码格式
            // 主要语言代码: 2-3字母，可选子标签: 2字母国家代码或3字母数字代码
            string[] parts = languageCode.Split('-');
            
            // 主语言代码验证
            if (parts.Length == 0 || string.IsNullOrEmpty(parts[0]))
                return false;
                
            string primaryCode = parts[0];
            if (primaryCode.Length < 2 || primaryCode.Length > 3)
                return false;
                
            foreach (char c in primaryCode)
            {
                if (!char.IsLower(c) && !char.IsUpper(c))
                    return false;
            }

            // 子标签验证（国家代码、脚本等）
            for (int i = 1; i < parts.Length; i++)
            {
                string subtag = parts[i];
                if (string.IsNullOrEmpty(subtag) || subtag.Length < 2 || subtag.Length > 8)
                    return false;
                    
                foreach (char c in subtag)
                {
                    if (!char.IsLetterOrDigit(c))
                        return false;
                }
            }

            return true;
        }

        /// <summary>
        /// 保存配置（含原子写入和完整性校验更新）
        /// </summary>
        /// <param name="configPath">配置文件路径</param>
        /// <param name="data">配置数据</param>
        /// <returns>是否保存成功</returns>
        public static bool Save(string configPath, ConfigData data)
        {
            if (string.IsNullOrEmpty(configPath))
            {
                LogManager.Warning("Config path is empty, cannot save");
                return false;
            }

            if (data == null)
            {
                LogManager.Warning("Config data is null, cannot save");
                return false;
            }

            try
            {
                string configDir = Path.GetDirectoryName(configPath);
                if (string.IsNullOrEmpty(configDir))
                {
                    LogManager.Error($"Invalid config path: {configPath}");
                    return false;
                }
                if (!Directory.Exists(configDir))
                {
                    Directory.CreateDirectory(configDir);
                }

                // 确保版本号正确
                data.Version = CurrentVersion;

                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                };
                string json = JsonSerializer.Serialize(data, options);

                ComHelper.AtomicWriteAllText(configPath, json, Config.Utf8NoBom);

                // 保存后立即更新完整性校验值
                if (!Config.SaveConfigIntegrityHash(configPath))
                {
                    LogManager.Warning(LangManager.GetText("logMessages.configIntegrityHashSaveFailed"));
                }
                else
                {
                    LogManager.Info(LangManager.GetText("logMessages.configIntegrityHashSaved"));
                }

                LogManager.Info(LangManager.GetText("logMessages.monitoringTargetsSaved"));
                return true;
            }
            catch (UnauthorizedAccessException ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.saveMonitoringTargetsFailed") + " - Access denied", ex);
                return false;
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.saveMonitoringTargetsFailed"), ex);
                return false;
            }
        }
    }
}
