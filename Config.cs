using System;

namespace FirewallManager
{
    /// <summary>
    /// 应用程序配置常量类
    /// Application Configuration Constants Class
    /// 集中管理所有硬编码的配置常量，便于维护和修改
    /// Centralized management of all hardcoded configuration constants for easy maintenance and modification
    /// </summary>
    public static class Config
    {
        #region Windows Firewall COM接口配置

        /// <summary>
        /// Windows防火墙策略COM类ProgID
        /// Windows Firewall Policy COM Class ProgID
        /// </summary>
        public const string FIREWALL_POLICY_PROGID = "HNetCfg.FwPolicy2";

        /// <summary>
        /// Windows防火墙规则COM类ProgID
        /// Windows Firewall Rule COM Class ProgID
        /// </summary>
        public const string FIREWALL_RULE_PROGID = "HNetCfg.FwRule";

        /// <summary>
        /// INetFwPolicy2接口GUID
        /// INetFwPolicy2 Interface GUID
        /// </summary>
        public static readonly Guid INetFwPolicy2Guid = new Guid("743b5f60-8191-11d1-b944-00aa006b32a4");

        /// <summary>
        /// INetFwRules接口GUID
        /// INetFwRules Interface GUID
        /// </summary>
        public static readonly Guid INetFwRulesGuid = new Guid("2c5bc43e-6559-4762-9011-98d5cbb1c1bc");

        /// <summary>
        /// INetFwRule接口GUID
        /// INetFwRule Interface GUID
        /// </summary>
        public static readonly Guid INetFwRuleGuid = new Guid("af230c27-4f5f-11d1-b2e4-08002b10409f");

        #endregion

        #region 配置文件名配置

        /// <summary>
        /// 监控文件夹配置文件名
        /// Monitored Folders Configuration File Name
        /// </summary>
        public const string MONITORED_FOLDERS_FILE = "folders.txt";

        /// <summary>
        /// 防火墙规则配置文件名
        /// Firewall Rules Configuration File Name
        /// </summary>
        public const string RULES_FILE = "rules.txt";

        /// <summary>
        /// 白名单配置文件名
        /// Whitelist Configuration File Name
        /// </summary>
        public const string WHITELIST_FILE = "whitelist.txt";

        /// <summary>
        /// HMAC密钥文件名
        /// HMAC Key File Name
        /// </summary>
        public const string HMAC_KEY_FILE = "hmac.key";

        /// <summary>
        /// 日志文件名
        /// Log File Name
        /// </summary>
        public const string LOG_FILE_NAME = "FirewallManager.log";

        /// <summary>
        /// 配置文件签名文件扩展名
        /// Configuration File Signature File Extension
        /// </summary>
        public const string SIGNATURE_FILE_EXT = ".sig";

        #endregion

        #region 语言配置

        /// <summary>
        /// 语言文件目录
        /// Language Files Directory
        /// </summary>
        public const string LANGUAGE_DIR = "Lang";

        /// <summary>
        /// 默认语言代码
        /// Default Language Code
        /// </summary>
        public const string DEFAULT_LANGUAGE = "en";

        #endregion

        #region 系统关键程序配置

        /// <summary>
        /// 系统关键程序列表
        /// System Critical Programs List
        /// 这些程序不应被防火墙规则阻止
        /// These programs should not be blocked by firewall rules
        /// </summary>
        public static readonly string[] CRITICAL_PROGRAMS = new[]
        {
            "svchost.exe", "explorer.exe", "services.exe", "winlogon.exe", "lsass.exe",
            "csrss.exe", "smss.exe", "wininit.exe", "fontdrvhost.exe", "dwm.exe",
            "taskhostw.exe", "conhost.exe", "system", "system32", "syswow64"
        };

        #endregion

        #region 日志导出配置

        /// <summary>
        /// 日志导出文件名格式
        /// Log Export File Name Format
        /// </summary>
        public const string LOG_EXPORT_FILE_PREFIX = "FirewallManager_Logs_";
        public const string LOG_EXPORT_FILE_EXT = ".txt";

        #endregion
    }
}