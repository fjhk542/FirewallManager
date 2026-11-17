using System;
using System.Text;
using System.Security.Cryptography;

namespace FirewallManager
{
    /// <summary>
    /// Rule naming service
    /// Single source of truth for rule name construction logic, eliminates 5 duplicate code locations
    /// Rule name format: Block_{sanitizedFileName}_{32-char hash}
    /// </summary>
    public static class RuleNamingService
    {
        /// <summary>
        /// Max rule name length (file name portion)
        /// </summary>
        private const int MaxRuleNameLength = 60;

        /// <summary>
        /// Build firewall rule name from executable file path
        /// </summary>
        /// <param name="exePath">Executable file path</param>
        /// <returns>Rule name (format: Block_{sanitizedFileName}_{32-char hash})</returns>
        public static string BuildRuleName(string exePath)
        {
            if (string.IsNullOrEmpty(exePath))
            {
                throw new ArgumentException("可执行文件路径不能为空", nameof(exePath));
            }

            return BuildRuleNameWithHash(exePath, GetPathHash(NormalizePath(exePath)));
        }

        /// <summary>
        /// Canonical form used for hashing: full path, backslash separators, invariant lowercase.
        /// Windows path comparison is case-insensitive, so hashing the raw string would produce two
        /// different rule names for the same file depending on how the caller spelled the path
        /// (the FileSystemWatcher reports the on-disk casing while a directory scan reuses the
        /// user's spelling of the root). That mismatch defeats de-duplication and creates duplicates.
        /// </summary>
        /// <param name="path">Raw path</param>
        /// <returns>Canonical path used as hash input</returns>
        private static string NormalizePath(string path)
        {
            return System.IO.Path.GetFullPath(path).Replace('/', '\\').ToLowerInvariant();
        }

        private static string BuildRuleNameWithHash(string exePath, string pathHash)
        {
            string fileName = System.IO.Path.GetFileNameWithoutExtension(exePath);
            string sanitizedFileName = SanitizeRuleName(fileName);
            return $"{Config.RULE_NAME_PREFIX}{sanitizedFileName}_{pathHash}";
        }

        /// <summary>
        /// Sanitize unsafe characters in rule name
        /// Filter control characters and file system reserved characters to prevent rule name injection
        /// </summary>
        /// <param name="input">Input string</param>
        /// <returns>Sanitized safe string</returns>
        public static string SanitizeRuleName(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return input;
            }

            // Filter control characters (0x00-0x1F, 0x7F) and file system reserved characters to prevent rule name injection
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

            // Limit rule name length (firewall rule names are typically limited to 64-128 characters)
            if (sanitized.Length > MaxRuleNameLength)
            {
                sanitized = sanitized.Substring(0, MaxRuleNameLength);
            }

            return sanitized;
        }

        /// <summary>
        /// Compute file path hash
        /// Use SHA256 and take first 16 bytes (32 hex chars) to reduce hash collision probability
        /// </summary>
        /// <param name="path">File path</param>
        /// <returns>32-character hex hash string</returns>
        public static string GetPathHash(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentException("路径不能为空", nameof(path));
            }

            using (var sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(path));
                // Take first 16 bytes and convert to lowercase hex string (32 chars)
                // Use Convert.ToHexString instead of manual StringBuilder concatenation for better performance
                return Convert.ToHexString(hashBytes, 0, 16).ToLowerInvariant();
            }
        }

        /// <summary>
        /// Verify if rule name was created by this program.
        /// Rule name format: Block_{sanitizedFileName}_{32-char hex hash}
        /// WARNING: this only checks the shape of the name. It cannot tell whether this program really
        /// created the rule. Use <see cref="IsRuleOwnedByUs"/> before deleting anything.
        /// </summary>
        /// <param name="ruleName">Rule name</param>
        /// <returns>Whether the name matches this program's naming scheme</returns>
        public static bool IsRuleCreatedByUs(string ruleName)
        {
            if (string.IsNullOrEmpty(ruleName))
                return false;

            // Must start with Block_
            if (!ruleName.StartsWith(Config.RULE_NAME_PREFIX))
                return false;

            // The portion after prefix must contain underscore separator
            string rest = ruleName.Substring(Config.RULE_NAME_PREFIX.Length);
            int lastUnderscoreIndex = rest.LastIndexOf('_');
            if (lastUnderscoreIndex <= 0)
                return false;

            // File name portion must not be empty
            string fileNamePart = rest.Substring(0, lastUnderscoreIndex);
            if (string.IsNullOrEmpty(fileNamePart))
                return false;

            // Hash portion must be a 32-character hex string
            string hashPart = rest.Substring(lastUnderscoreIndex + 1);
            if (string.IsNullOrEmpty(hashPart) || hashPart.Length != 32)
                return false;

            // Verify hashPart contains only hex characters
            foreach (char c in hashPart)
            {
                if (!IsHexChar(c))
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Verifies that a rule was really created by this program for the given executable path.
        /// The path hash embedded in the name must equal the hash recomputed from the rule's
        /// ApplicationName, which binds the name to a concrete path instead of trusting its shape.
        /// </summary>
        /// <param name="ruleName">Rule name as reported by the firewall API</param>
        /// <param name="applicationPath">Rule's ApplicationName property</param>
        /// <returns>true only when the name is the one this program would have generated for that path</returns>
        public static bool IsRuleOwnedByUs(string ruleName, string applicationPath)
        {
            if (!IsRuleCreatedByUs(ruleName) || string.IsNullOrEmpty(applicationPath))
                return false;

            try
            {
                string expectedName = BuildRuleName(applicationPath);
                if (string.Equals(ruleName, expectedName, StringComparison.OrdinalIgnoreCase))
                    return true;

                // Rules written before path normalization hashed the raw path string. Accept that
                // legacy form as well, otherwise those rules could never be recognized, deleted or
                // cleaned up after an upgrade.
                string legacyName = BuildRuleNameWithHash(applicationPath, GetPathHash(applicationPath));
                return string.Equals(ruleName, legacyName, StringComparison.OrdinalIgnoreCase);
            }
            catch (Exception)
            {
                // ApplicationName values written by other products are not guaranteed to be valid
                // paths; anything that cannot be normalized is simply not ours.
                return false;
            }
        }

        /// <summary>
        /// Determine if character is a hex character
        /// </summary>
        private static bool IsHexChar(char c)
        {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        }
    }
}
