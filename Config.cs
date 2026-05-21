using System;
using System.IO;

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
        /// 关键程序列表
        /// 这些程序不应被阻止，否则可能导致系统不稳定
        /// </summary>
        public static readonly string[] CRITICAL_PROGRAMS = new[]
        {
            "explorer.exe",
            "svchost.exe",
            "lsass.exe",
            "csrss.exe",
            "wininit.exe",
            "services.exe",
            "spoolsv.exe",
            "winlogon.exe",
            "msdtc.exe",
            "smss.exe",
            "system.exe",
            "idle.exe",
            "conhost.exe",
            "taskhostw.exe",
            "dwm.exe",
            "winmgmt.exe",
            "ntoskrnl.exe",
            "userinit.exe",
            "runtimebroker.exe",
            "taskmgr.exe"
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
    }
}