using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace FirewallManager
{
    public static class Config
    {
        /// <summary>
        /// 不带 BOM 的 UTF-8 编码，用于 JSON 文件读写
        /// 避免 BOM 导致 JSON 解析错误
        /// </summary>
        public static readonly Encoding Utf8NoBom = new UTF8Encoding(false);

        /// <summary>
        /// 规则名称前缀
        /// </summary>
        public const string RULE_NAME_PREFIX = "Block_";

        /// <summary>
        /// 默认语言
        /// </summary>
        public const string DEFAULT_LANGUAGE = "zh";

        /// <summary>
        /// 白名单文件名
        /// </summary>
        public const string WHITELIST_FILE = "whitelist.json";

        /// <summary>
        /// 语言文件目录
        /// </summary>
        public const string LANGUAGE_DIR = "Lang";

        /// <summary>
        /// 配置文件名
        /// </summary>
        public const string CONFIG_FILE = "config.json";

        /// <summary>
        /// EXE文件搜索模式
        /// </summary>
        public const string EXE_SEARCH_PATTERN = "*.exe";

        /// <summary>
        /// 防火墙策略ProgID
        /// </summary>
        public const string FIREWALL_POLICY_PROGID = "HNetCfg.FwPolicy2";

        /// <summary>
        /// 防火墙规则ProgID
        /// </summary>
        public const string FIREWALL_RULE_PROGID = "HNetCfg.FWRule";

        /// <summary>
        /// 防火墙策略CLSID (NetFwPolicy2) - 从注册表验证
        /// </summary>
        public const string FIREWALL_POLICY_CLSID = "E2B3C97F-6AE1-41AC-817A-F6F92166D7DD";

        /// <summary>
        /// 防火墙规则CLSID (NetFwRule) - 从注册表验证
        /// </summary>
        public const string FIREWALL_RULE_CLSID = "2C5BC43E-3369-4C33-AB0C-BE9469677AF4";

        /// <summary>
        /// 防火墙策略接口IID (INetFwPolicy2)
        /// </summary>
        public const string FIREWALL_POLICY_IID = "98325047-C371-474C-B5E4-70474F6D89BA";

        /// <summary>
        /// 防火墙规则接口IID (INetFwRule)
        /// </summary>
        public const string FIREWALL_RULE_IID = "9C4C6277-5027-441E-AFAE-CA1F542DA009";

        /// <summary>
        /// 所有防火墙配置文件
        /// Domain(1) | Private(2) | Public(4) = 7
        /// </summary>
        public const int ALL_FIREWALL_PROFILES = 7;

        /// <summary>
        /// 应用程序数据目录名称
        /// </summary>
        public const string APP_DATA_DIR = "FirewallManager";

        /// <summary>
        /// 日志文件名
        /// </summary>
        public const string LOG_FILE_NAME = "firewall_manager.log";

        /// <summary>
        /// 完整性校验文件扩展名
        /// </summary>
        private const string INTEGRITY_FILE_EXT = ".hmac";

        /// <summary>
        /// HMAC 密钥文件名（DPAPI 加密存储）
        /// </summary>
        private const string HMAC_KEY_FILE = "hmac.key";

        /// <summary>
        /// 用于派生 HMAC 密钥的固定标记
        /// </summary>
        private const string HMAC_KEY_TAG = "FirewallManager_Config_Integrity_v1";

        /// <summary>
        /// 缓存的 HMAC 密钥（延迟初始化）
        /// </summary>
        private static byte[] _cachedHmacKey;

        /// <summary>
        /// HMAC 密钥缓存锁
        /// </summary>
        private static readonly object _hmacKeyLock = new object();

        /// <summary>
        /// 关键程序集合（HashSet实现O(1)查找）
        /// 这些程序不应被阻止，否则可能导致系统不稳定
        /// </summary>
        public static readonly HashSet<string> CRITICAL_PROGRAMS = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "explorer.exe", "svchost.exe", "lsass.exe", "csrss.exe",
            "wininit.exe", "services.exe", "spoolsv.exe", "winlogon.exe",
            "msdtc.exe", "smss.exe", "system.exe", "idle.exe",
            "conhost.exe", "taskhostw.exe", "dwm.exe", "winmgmt.exe",
            "ntoskrnl.exe", "userinit.exe", "runtimebroker.exe", "taskmgr.exe"
        };

        /// <summary>
        /// 获取应用程序数据目录中的文件路径
        /// 使用 LocalApplicationData 目录，避免DLL劫持风险
        /// </summary>
        /// <param name="fileName">文件名</param>
        /// <returns>完整的文件路径</returns>
        public static string GetAppDataFilePath(string fileName)
        {
            // 使用 LocalApplicationData 目录，避免DLL劫持风险
            string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string appFolderPath = Path.Combine(appDataPath, APP_DATA_DIR);
            
            // 确保目录存在
            Directory.CreateDirectory(appFolderPath);
            
            return Path.Combine(appFolderPath, fileName);
        }

        /// <summary>
        /// 生成机器特定的 HMAC 密钥
        /// 使用 DPAPI 加密存储密钥，防止本地攻击者重建密钥
        /// </summary>
        /// <returns>HMAC 密钥字节数组</returns>
        private static byte[] GenerateHmacKey()
        {
            lock (_hmacKeyLock)
            {
                if (_cachedHmacKey != null)
                {
                    return (byte[])_cachedHmacKey.Clone();
                }

                string keyFilePath = GetAppDataFilePath(HMAC_KEY_FILE);

                try
                {
                    if (File.Exists(keyFilePath))
                    {
                        using (var fs = File.Open(keyFilePath, FileMode.Open, FileAccess.Read, FileShare.None))
                        {
                            byte[] encryptedKey = new byte[fs.Length];
                            int totalRead = 0;
                            while (totalRead < encryptedKey.Length)
                            {
                                int bytesRead = fs.Read(encryptedKey, totalRead, encryptedKey.Length - totalRead);
                                if (bytesRead == 0)
                                    throw new EndOfStreamException("Unexpected end of file while reading HMAC key");
                                totalRead += bytesRead;
                            }
                            byte[] decryptedKey = ProtectedData.Unprotect(encryptedKey, null, DataProtectionScope.CurrentUser);
                            if (decryptedKey != null && decryptedKey.Length >= 32)
                            {
                                _cachedHmacKey = decryptedKey;
                                return (byte[])_cachedHmacKey.Clone();
                            }
                        }
                    }
                }
                catch
                {
                    // 密钥文件读取或解密失败，生成新密钥
                }

                byte[] newKey = GenerateNewHmacKey();

                try
                {
                    byte[] encryptedKey = ProtectedData.Protect(newKey, null, DataProtectionScope.CurrentUser);
                    ComHelper.AtomicWriteAllBytes(keyFilePath, encryptedKey);
                    ComHelper.SetSecureFilePermissionsInternal(keyFilePath);
                    LogManager.Info(LangManager.GetText("logMessages.hmacKeyGenerated"));
                }
                catch (Exception ex)
                {
                    LogManager.Warning(LangManager.GetText("logMessages.hmacKeySaveFailed", ex.Message));
                }

                _cachedHmacKey = newKey;
                return (byte[])_cachedHmacKey.Clone();
            }
        }

        /// <summary>
        /// 生成新的 HMAC 密钥
        /// 使用 MachineGuid + 随机熵 + 硬编码标记 通过 SHA256 派生
        /// </summary>
        /// <returns>HMAC 密钥字节数组</returns>
        private static byte[] GenerateNewHmacKey()
        {
            try
            {
                string machineKey = HMAC_KEY_TAG;
                try
                {
                    string machineGuid = Microsoft.Win32.Registry.GetValue(
                        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography", "MachineGuid", null) as string;
                    if (!string.IsNullOrEmpty(machineGuid) && IsValidGuidFormat(machineGuid))
                    {
                        machineKey = machineGuid + HMAC_KEY_TAG;
                    }
                    else
                    {
                        // 如果 MachineGuid 不可用或格式无效，使用回退机制
                        LogManager.Info("MachineGuid not available or invalid, using fallback key generation");
                        machineKey = GenerateFallbackMachineKey();
                    }
                }
                catch (Exception ex)
                {
                    // 无法读取 MachineGuid 时使用回退机制
                    LogManager.Warning($"Failed to read MachineGuid: {ex.Message}, using fallback key generation");
                    machineKey = GenerateFallbackMachineKey();
                }

                byte[] randomEntropy = new byte[32];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(randomEntropy);
                }

                using (var sha256 = SHA256.Create())
                {
                    byte[] keyMaterial = new byte[Encoding.UTF8.GetByteCount(machineKey) + randomEntropy.Length];
                    Buffer.BlockCopy(Encoding.UTF8.GetBytes(machineKey), 0, keyMaterial, 0, Encoding.UTF8.GetByteCount(machineKey));
                    Buffer.BlockCopy(randomEntropy, 0, keyMaterial, Encoding.UTF8.GetByteCount(machineKey), randomEntropy.Length);
                    return sha256.ComputeHash(keyMaterial);
                }
            }
            catch
            {
                using (var rng = RandomNumberGenerator.Create())
                {
                    byte[] fallbackKey = new byte[32];
                    rng.GetBytes(fallbackKey);
                    return fallbackKey;
                }
            }
        }

        /// <summary>
        /// 验证 GUID 格式是否有效
        /// </summary>
        private static bool IsValidGuidFormat(string guidString)
        {
            if (string.IsNullOrEmpty(guidString))
                return false;
                
            return Guid.TryParse(guidString, out _);
        }

        /// <summary>
        /// 生成回退机器密钥（当 MachineGuid 不可用时）
        /// 使用计算机名称和用户信息生成机器唯一标识
        /// </summary>
        private static string GenerateFallbackMachineKey()
        {
            try
            {
                string machineName = Environment.MachineName ?? "unknown";
                string userName = Environment.UserName ?? "unknown";
                string osVersion = Environment.OSVersion.VersionString ?? "unknown";
                
                return $"{HMAC_KEY_TAG}_{machineName}_{userName}_{osVersion}";
            }
            catch
            {
                // 最终回退到完全随机的密钥
                return HMAC_KEY_TAG + "_" + Guid.NewGuid().ToString();
            }
        }

        /// <summary>
        /// 计算字节数组的 HMAC-SHA256 完整性校验值
        /// 使用 Convert.ToHexString 替代手动 StringBuilder 拼接，与 RuleNamingService 保持一致
        /// </summary>
        /// <param name="data">待计算的字节数据</param>
        /// <param name="key">HMAC 密钥</param>
        /// <returns>小写十六进制字符串</returns>
        private static string ComputeHmacHex(byte[] data, byte[] key)
        {
            using (var hmac = new HMACSHA256(key))
            {
                byte[] hashBytes = hmac.ComputeHash(data);
                return Convert.ToHexString(hashBytes).ToLowerInvariant();
            }
        }

        /// <summary>
        /// 计算文件的 HMAC-SHA256 完整性校验值
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <returns>完整性校验值的十六进制字符串，失败返回 null</returns>
        private static string ComputeFileIntegrityHash(string filePath)
        {
            try
            {
                if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                {
                    return null;
                }

                byte[] fileBytes = File.ReadAllBytes(filePath);
                byte[] key = GenerateHmacKey();
                return ComputeHmacHex(fileBytes, key);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// 获取与配置文件关联的完整性校验文件路径
        /// </summary>
        /// <param name="configFilePath">配置文件路径</param>
        /// <returns>完整性校验文件路径</returns>
        private static string GetIntegrityFilePath(string configFilePath)
        {
            return configFilePath + INTEGRITY_FILE_EXT;
        }

        /// <summary>
        /// 保存配置文件的完整性校验值
        /// </summary>
        /// <param name="configFilePath">配置文件路径</param>
        /// <returns>是否保存成功</returns>
        public static bool SaveConfigIntegrityHash(string configFilePath)
        {
            try
            {
                string hash = ComputeFileIntegrityHash(configFilePath);
                if (hash == null)
                {
                    return false;
                }

                string integrityFilePath = GetIntegrityFilePath(configFilePath);
                ComHelper.AtomicWriteAllText(integrityFilePath, hash, Encoding.UTF8);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 验证配置文件的完整性
        /// 通过比对文件内容的 HMAC-SHA256 校验值与之前保存的校验值来确认文件未被篡改
        /// </summary>
        /// <param name="configFilePath">配置文件路径</param>
        /// <returns>
        /// true: 完整性验证通过
        /// false: 完整性验证失败或校验文件缺失（出于安全考虑）
        /// </returns>
        public static bool VerifyConfigIntegrity(string configFilePath)
        {
            string content;
            return VerifyConfigIntegrityAndRead(configFilePath, out content);
        }

        /// <summary>
        /// 验证配置文件的完整性并读取内容（原子操作，防止TOCTOU攻击）
        /// 在锁定状态下完成验证和读取，确保验证的内容与读取的内容一致
        /// </summary>
        /// <param name="configFilePath">配置文件路径</param>
        /// <param name="content">输出参数：验证通过后的文件内容</param>
        /// <returns>
        /// true: 完整性验证通过，content包含文件内容
        /// false: 完整性验证失败或校验文件缺失（出于安全考虑）
        /// </returns>
        public static bool VerifyConfigIntegrityAndRead(string configFilePath, out string content)
        {
            content = null;
            try
            {
                if (!File.Exists(configFilePath))
                {
                    return false;
                }

                string integrityFilePath = GetIntegrityFilePath(configFilePath);

                // 如果校验文件不存在，拒绝加载（防止攻击者删除校验文件绕过验证）
                if (!File.Exists(integrityFilePath))
                {
                    LogManager.Error(LangManager.GetText("logMessages.configIntegrityFileMissing", configFilePath));
                    return false;
                }

                // 使用文件锁定防止TOCTOU攻击
                using (var fs = File.Open(integrityFilePath, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    using (var reader = new StreamReader(fs, Encoding.UTF8))
                    {
                        string savedHash = reader.ReadToEnd()?.Trim();
                        if (string.IsNullOrEmpty(savedHash))
                        {
                            return false;
                        }

                        // 使用文件锁定读取配置文件
                        using (var configFs = File.Open(configFilePath, FileMode.Open, FileAccess.Read, FileShare.None))
                        {
                            byte[] configBytes = new byte[configFs.Length];
                            int totalRead = 0;
                            while (totalRead < configBytes.Length)
                            {
                                int bytesRead = configFs.Read(configBytes, totalRead, configBytes.Length - totalRead);
                                if (bytesRead == 0)
                                    throw new EndOfStreamException("Unexpected end of file while reading config");
                                totalRead += bytesRead;
                            }

                            byte[] key = GenerateHmacKey();
                            string computedHash = ComputeHmacHex(configBytes, key);

                            if (!string.Equals(savedHash, computedHash, StringComparison.OrdinalIgnoreCase))
                            {
                                return false;
                            }

                            // 验证通过后才返回内容，确保没有TOCTOU窗口
                            // 使用 StreamReader 读取内容以自动处理 BOM
                            using (var streamReader = new StreamReader(new MemoryStream(configBytes), Encoding.UTF8, true))
                            {
                                content = streamReader.ReadToEnd();
                            }
                            return true;
                        }
                    }
                }
            }
            catch
            {
                // 验证失败时出于安全考虑返回 false
                return false;
            }
        }

        /// <summary>
        /// 为敏感配置文件设置受限ACL权限（仅管理员和SYSTEM可访问）
        /// 防止低权限用户篡改白名单、配置等关键文件
        /// 实际实现委托到 ComHelper.SetSecureFilePermissionsInternal，消除重复代码
        /// </summary>
        /// <param name="filePath">要保护的文件路径</param>
        public static void SetSecureFilePermissionsPublic(string filePath)
        {
            ComHelper.SetSecureFilePermissionsInternal(filePath);
        }
    }
}