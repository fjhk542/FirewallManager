using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FirewallManager
{
    /// <summary>
    /// Configuration persistence service
    /// Uniformly manages persistence of monitoring targets, language selection, and the auto-monitor toggle.
    /// Schema v2: { "version": 2, "language": "zh", "autoMonitor": true, "targets": ["..."] }
    /// Backward compatible with v1: plain string array ["path1", "path2"]
    /// </summary>
    public static class TargetStore
    {
        /// <summary>
        /// Current schema version
        /// </summary>
        public const int CurrentVersion = 2;

        /// <summary>
        /// Configuration data structure
        /// </summary>
        public class ConfigData
        {
            /// <summary>Schema version number</summary>
            [JsonPropertyName("version")]
            public int Version { get; set; } = CurrentVersion;

            /// <summary>Language code (e.g., "zh-CN", "en-US")</summary>
            [JsonPropertyName("language")]
            public string Language { get; set; }

            /// <summary>Whether auto-monitor is enabled</summary>
            [JsonPropertyName("autoMonitor")]
            public bool AutoMonitor { get; set; } = false;

            /// <summary>List of monitoring target paths</summary>
            [JsonPropertyName("targets")]
            public List<string> Targets { get; set; } = new List<string>();
        }

        /// <summary>
        /// Loads configuration (includes integrity verification and automatic v1 migration)
        /// When integrity verification fails, falls back to direct reading to preserve backward compatibility.
        /// </summary>
        /// <param name="configPath">Configuration file path</param>
        /// <returns>Configuration data; null when loading fails</returns>
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

            // Verify configuration file integrity before loading (atomic operation to prevent TOCTOU attacks).
            string json;
            if (Config.VerifyConfigIntegrityAndRead(configPath, out json))
            {
                // Integrity verification passed.
                if (string.IsNullOrWhiteSpace(json))
                {
                    LogManager.Warning("Config file is empty");
                    return null;
                }

                return ParseConfig(json);
            }

            // Integrity verification failed.
            // Fail-closed by default: a config that fails verification is not loaded and is NOT
            // re-signed. Re-signing would turn the integrity mechanism into a no-op, because whoever
            // can write the file could then have their content blessed on the next start.
            LogManager.Warning(LangManager.GetText("logMessages.configIntegrityVerificationFailed"));

            // The single permitted exception is a first-run migration of a legacy v1 array.
            // It requires that (a) no integrity file exists yet, (b) the HMAC key has never been
            // created, and (c) the application data directory is actually protected. Without (c) a
            // same-user process could plant a crafted v1 array, which would then be signed by this
            // elevated process.
            if (Config.IntegrityFileExists(configPath) || Config.HmacKeyFileExists())
            {
                LogManager.Error("Config integrity verification failed. Refusing to load tampered or unverifiable config.");
                return null;
            }

            if (!Config.IsAppDataDirectorySecured)
            {
                LogManager.Error("Config integrity cannot be trusted: the application data directory is not protected. Refusing legacy migration.");
                return null;
            }

            try
            {
                json = File.ReadAllText(configPath, Config.Utf8NoBom);
            }
            catch (Exception ex)
            {
                LogManager.Error($"Failed to read config file for v1 migration: {ex.Message}");
                return null;
            }

            if (string.IsNullOrWhiteSpace(json))
            {
                LogManager.Warning("Config file is empty");
                return null;
            }

            // Only a v1 legacy array may be migrated; any other shape is rejected.
            if (!json.TrimStart().StartsWith("["))
            {
                LogManager.Error("Integrity verification failed and the file is not a legacy v1 array. Refusing to load.");
                return null;
            }

            var data = ParseConfig(json);
            if (data == null)
            {
                LogManager.Error("Legacy config parsing failed, file may be corrupted");
                return null;
            }

            LogManager.Info("Legacy v1 config migrated to v2 and signed");
            Config.SaveConfigIntegrityHash(configPath);

            return data;
        }

        /// <summary>
        /// Parses configuration JSON (supports automatic detection of v1 / v2 format)
        /// Detects the JSON structure first, then chooses how to deserialize — avoids exceptions when a v1 array is deserialized as a v2 object.
        /// </summary>
        /// <param name="json">JSON string</param>
        /// <returns>Configuration data; null when parsing fails</returns>
        private static ConfigData ParseConfig(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
                return null;

            try
            {
                var options = ComHelper.SafeJsonOptions;

                // Determine the format from the JSON structure: starts with { → v2 object, starts with [ → v1 array.
                string trimmed = json.TrimStart();

                if (trimmed.StartsWith("{"))
                {
                    // v2 schema: { "version": 2, "language": "zh", ... }
                    var config = JsonSerializer.Deserialize<ConfigData>(json, options);
                    if (config != null && config.Version > 0)
                    {
                        // Validate the language field format to prevent path-traversal.
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
        /// Validates the language code format (compliant with BCP 47, e.g., "zh", "en", "zh-CN")
        /// Prevents path-traversal and injection attacks.
        /// </summary>
        /// <param name="languageCode">Language code</param>
        /// <returns>True if valid</returns>
        private static bool IsValidLanguageCode(string languageCode)
        {
            if (string.IsNullOrEmpty(languageCode) || languageCode.Length > 16)
                return false;

            // Validate language code format per BCP 47.
            // Primary subtag: 2–3 letters; optional subtags: 2-letter country code or 3-letter numeric code.
            string[] parts = languageCode.Split('-');
            
            // Primary subtag validation.
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

            // Subtag validation (country codes, scripts, etc.).
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
        /// Saves configuration (includes atomic write and integrity-check update).
        /// </summary>
        /// <param name="configPath">Configuration file path</param>
        /// <param name="data">Configuration data</param>
        /// <returns>True if save succeeded</returns>
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

                // Ensure the version number is correct.
                data.Version = CurrentVersion;

                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                };
                string json = JsonSerializer.Serialize(data, options);

                ComHelper.AtomicWriteAllText(configPath, json, Config.Utf8NoBom);

                // Update the integrity hash immediately after saving.
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
