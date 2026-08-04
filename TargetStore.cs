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
            if (!Config.VerifyConfigIntegrityAndRead(configPath, out json))
            {
                LogManager.Error(LangManager.GetText("logMessages.configIntegrityVerificationFailed"));
                return null;
            }

            if (string.IsNullOrWhiteSpace(json))
            {
                LogManager.Warning("Config file is empty");
                return null;
            }

            return ParseConfig(json);
        }

        /// <summary>
        /// 解析配置 JSON（支持 v1/v2 格式自动识别）
        /// </summary>
        /// <param name="json">JSON 字符串</param>
        /// <returns>配置数据；解析失败返回 null</returns>
        private static ConfigData ParseConfig(string json)
        {
            try
            {
                // 使用统一的 SafeJsonOptions（MaxDepth=10），防止 DoS 攻击
                var options = ComHelper.SafeJsonOptions;

                // 尝试解析为 v2 schema（对象）
                var config = JsonSerializer.Deserialize<ConfigData>(json, options);
                if (config != null && config.Version > 0)
                {
                    // 深入防御：验证 language 字段格式（只允许字母数字和连字符，防止路径遍历）
                    if (!string.IsNullOrEmpty(config.Language) && !IsValidLanguageCode(config.Language))
                    {
                        LogManager.Warning($"Invalid language code in config, ignoring: {config.Language}");
                        config.Language = null;
                    }

                    LogManager.Info($"Loaded config v{config.Version}: language={config.Language ?? "null"}, autoMonitor={config.AutoMonitor}, targets={config.Targets?.Count ?? 0}");
                    return config;
                }

                // 回退到 v1 schema（纯字符串数组）
                var paths = JsonSerializer.Deserialize<List<string>>(json, options);
                if (paths != null)
                {
                    LogManager.Info("Loaded config v1 (legacy array format), migrating to v2");
                    return new ConfigData
                    {
                        Version = CurrentVersion,
                        Language = null, // v1 不含语言设置
                        AutoMonitor = false, // v1 不含自动监控设置
                        Targets = paths
                    };
                }

                LogManager.Warning("Failed to deserialize config");
                return null;
            }
            catch (JsonException ex)
            {
                LogManager.Error($"Config JSON parse failed: {ex.Message}", ex);
                return null;
            }
        }

        /// <summary>
        /// 验证语言代码格式（只允许字母、数字和连字符，最大长度 16）
        /// 防止路径遍历和注入攻击
        /// </summary>
        /// <param name="languageCode">语言代码</param>
        /// <returns>是否有效</returns>
        private static bool IsValidLanguageCode(string languageCode)
        {
            if (string.IsNullOrEmpty(languageCode) || languageCode.Length > 16)
                return false;

            foreach (char c in languageCode)
            {
                if (!char.IsLetterOrDigit(c) && c != '-' && c != '_')
                    return false;
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
