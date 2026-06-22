using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace FirewallManager
{
    /// <summary>
    /// 配置类
    /// 包含应用程序的所有配置常量和配置相关方法
    /// </summary>
    public static class Config
    {
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
        /// 所有防火墙配置文件
        /// </summary>
        public const int ALL_FIREWALL_PROFILES = 2;

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
        /// 用于派生 HMAC 密钥的固定标记
        /// </summary>
        private const string HMAC_KEY_TAG = "FirewallManager_Config_Integrity_v1";

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
        /// 使用 MachineGuid 作为密钥基础，确保密钥在不同机器上不同
        /// </summary>
        /// <returns>HMAC 密钥字节数组</returns>
        private static byte[] GenerateHmacKey()
        {
            try
            {
                string machineKey = HMAC_KEY_TAG;
                try
                {
                    string machineGuid = Microsoft.Win32.Registry.GetValue(
                        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography", "MachineGuid", null) as string;
                    if (!string.IsNullOrEmpty(machineGuid))
                    {
                        machineKey = machineGuid + HMAC_KEY_TAG;
                    }
                }
                catch
                {
                    // 无法读取 MachineGuid 时使用默认标记
                }

                using (var sha256 = SHA256.Create())
                {
                    return sha256.ComputeHash(Encoding.UTF8.GetBytes(machineKey));
                }
            }
            catch
            {
                // 密钥生成失败时使用回退密钥
                using (var sha256 = SHA256.Create())
                {
                    return sha256.ComputeHash(Encoding.UTF8.GetBytes(HMAC_KEY_TAG));
                }
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

                byte[] key = GenerateHmacKey();
                using (var hmac = new HMACSHA256(key))
                {
                    byte[] fileBytes = File.ReadAllBytes(filePath);
                    byte[] hashBytes = hmac.ComputeHash(fileBytes);
                    StringBuilder sb = new StringBuilder(hashBytes.Length * 2);
                    foreach (byte b in hashBytes)
                    {
                        sb.Append(b.ToString("x2"));
                    }
                    return sb.ToString();
                }
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
        /// true: 完整性验证通过或无法验证（无校验文件时视为通过）
        /// false: 完整性验证失败
        /// </returns>
        public static bool VerifyConfigIntegrity(string configFilePath)
        {
            try
            {
                string integrityFilePath = GetIntegrityFilePath(configFilePath);

                // 如果校验文件不存在，视为首次运行或升级场景，创建校验文件后返回通过
                if (!File.Exists(integrityFilePath))
                {
                    SaveConfigIntegrityHash(configFilePath);
                    return true;
                }

                string savedHash = File.ReadAllText(integrityFilePath, Encoding.UTF8)?.Trim();
                if (string.IsNullOrEmpty(savedHash))
                {
                    return false;
                }

                string computedHash = ComputeFileIntegrityHash(configFilePath);
                if (computedHash == null)
                {
                    return false;
                }

                return string.Equals(savedHash, computedHash, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                // 验证失败时出于安全考虑返回 false
                return false;
            }
        }
    }
}