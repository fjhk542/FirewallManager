using System;
using System.Text;
using System.Security.Cryptography;

namespace FirewallManager
{
    /// <summary>
    /// 规则命名服务
    /// 统一规则名构建逻辑的唯一来源，消除 5 处重复代码
    /// 规则名格式: Block_{sanitizedFileName}_{32位hash}
    /// </summary>
    public static class RuleNamingService
    {
        /// <summary>
        /// 规则名最大长度（文件名部分）
        /// </summary>
        private const int MaxRuleNameLength = 60;

        /// <summary>
        /// 根据可执行文件路径构建防火墙规则名
        /// </summary>
        /// <param name="exePath">可执行文件路径</param>
        /// <returns>规则名称（格式: Block_{sanitizedFileName}_{32位hash}）</returns>
        public static string BuildRuleName(string exePath)
        {
            if (string.IsNullOrEmpty(exePath))
            {
                throw new ArgumentException("可执行文件路径不能为空", nameof(exePath));
            }

            string fileName = System.IO.Path.GetFileNameWithoutExtension(exePath);
            string sanitizedFileName = SanitizeRuleName(fileName);
            string pathHash = GetPathHash(exePath);
            return $"{Config.RULE_NAME_PREFIX}{sanitizedFileName}_{pathHash}";
        }

        /// <summary>
        /// 清理规则名称中的不安全字符
        /// 过滤控制字符和文件系统保留字符，防止规则名称注入
        /// </summary>
        /// <param name="input">输入字符串</param>
        /// <returns>清理后的安全字符串</returns>
        public static string SanitizeRuleName(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return input;
            }

            // 过滤控制字符（0x00-0x1F, 0x7F）和文件系统保留字符，防止规则名称注入
            char[] buffer = new char[input.Length];
            int pos = 0;
            foreach (char c in input)
            {
                if (c >= 32 && c != 127 && c != '"' && c != '\'' && c != '\\' && c != '/' && c != ':' && c != '*' && c != '?' && c != '<' && c != '>' && c != '|')
                {
                    buffer[pos++] = c;
                }
                else if (pos > 0 && buffer[pos - 1] != '_')
                {
                    buffer[pos++] = '_';
                }
            }
            string sanitized = new string(buffer, 0, pos);

            // 限制规则名称长度（防火墙规则名称通常限制在 64-128 字符）
            if (sanitized.Length > MaxRuleNameLength)
            {
                sanitized = sanitized.Substring(0, MaxRuleNameLength);
            }

            return sanitized;
        }

        /// <summary>
        /// 计算文件路径的哈希值
        /// 使用 SHA256 取前 16 字节（32 个十六进制字符），降低哈希碰撞概率
        /// </summary>
        /// <param name="path">文件路径</param>
        /// <returns>32 字符的十六进制哈希字符串</returns>
        public static string GetPathHash(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentException("路径不能为空", nameof(path));
            }

            using (var sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(path));
                StringBuilder sb = new StringBuilder(32);
                for (int i = 0; i < 16; i++) // 取前16个字节（32个十六进制字符）
                {
                    sb.Append(hashBytes[i].ToString("x2"));
                }
                return sb.ToString();
            }
        }

        /// <summary>
        /// 验证规则名是否由本程序创建
        /// 规则名格式: Block_{sanitizedFileName}_{32位hex hash}
        /// </summary>
        /// <param name="ruleName">规则名称</param>
        /// <returns>是否由本程序创建</returns>
        public static bool IsRuleCreatedByUs(string ruleName)
        {
            if (string.IsNullOrEmpty(ruleName))
                return false;

            // 必须以 Block_ 开头
            if (!ruleName.StartsWith(Config.RULE_NAME_PREFIX))
                return false;

            // 去除前缀后的部分必须包含下划线分隔符
            string rest = ruleName.Substring(Config.RULE_NAME_PREFIX.Length);
            int lastUnderscoreIndex = rest.LastIndexOf('_');
            if (lastUnderscoreIndex <= 0)
                return false;

            // 文件名部分不为空
            string fileNamePart = rest.Substring(0, lastUnderscoreIndex);
            if (string.IsNullOrEmpty(fileNamePart))
                return false;

            // 哈希值部分必须是 32 字符的十六进制字符串
            string hashPart = rest.Substring(lastUnderscoreIndex + 1);
            if (string.IsNullOrEmpty(hashPart) || hashPart.Length != 32)
                return false;

            // 验证 hashPart 只包含十六进制字符
            foreach (char c in hashPart)
            {
                if (!IsHexChar(c))
                    return false;
            }

            return true;
        }

        /// <summary>
        /// 判断字符是否为十六进制字符
        /// </summary>
        private static bool IsHexChar(char c)
        {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        }
    }
}
