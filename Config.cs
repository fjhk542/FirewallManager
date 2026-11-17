using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;

namespace FirewallManager
{
    public static class Config
    {
        /// <summary>
        /// UTF-8 encoding without BOM, used for JSON file read/write
        /// Prevents BOM from causing JSON parsing errors
        /// </summary>
        public static readonly Encoding Utf8NoBom = new UTF8Encoding(false);

        /// <summary>
        /// JSON serialization options for export/readable configs.
        /// </summary>
        public static readonly JsonSerializerOptions ExportJsonOptions = new JsonSerializerOptions { WriteIndented = true };

        /// <summary>
        /// Rule name prefix
        /// </summary>
        public const string RULE_NAME_PREFIX = "Block_";

        /// <summary>
        /// Default language
        /// </summary>
        public const string DEFAULT_LANGUAGE = "zh";

        /// <summary>
        /// Whitelist file name
        /// </summary>
        public const string WHITELIST_FILE = "whitelist.json";

        /// <summary>
        /// Language file directory
        /// </summary>
        public const string LANGUAGE_DIR = "Lang";

        /// <summary>
        /// Config file name
        /// </summary>
        public const string CONFIG_FILE = "config.json";

        /// <summary>
        /// EXE file search pattern
        /// </summary>
        public const string EXE_SEARCH_PATTERN = "*.exe";

        /// <summary>
        /// Firewall policy ProgID
        /// </summary>
        public const string FIREWALL_POLICY_PROGID = "HNetCfg.FwPolicy2";

        /// <summary>
        /// Firewall rule ProgID
        /// </summary>
        public const string FIREWALL_RULE_PROGID = "HNetCfg.FWRule";

        /// <summary>
        /// Firewall policy CLSID (NetFwPolicy2) - verified from registry
        /// </summary>
        public const string FIREWALL_POLICY_CLSID = "E2B3C97F-6AE1-41AC-817A-F6F92166D7DD";

        /// <summary>
        /// Firewall rule CLSID (NetFwRule) - verified from registry
        /// </summary>
        public const string FIREWALL_RULE_CLSID = "2C5BC43E-3369-4C33-AB0C-BE9469677AF4";

        /// <summary>
        /// Firewall policy interface IID (INetFwPolicy2)
        /// </summary>
        public const string FIREWALL_POLICY_IID = "98325047-C371-474C-B5E4-70474F6D89BA";

        /// <summary>
        /// Firewall rule interface IID (INetFwRule)
        /// </summary>
        public const string FIREWALL_RULE_IID = "9C4C6277-5027-441E-AFAE-CA1F542DA009";

        /// <summary>
        /// All firewall profiles
        /// Domain(1) | Private(2) | Public(4) = 7
        /// </summary>
        public const int ALL_FIREWALL_PROFILES = 7;

        /// <summary>
        /// Application data directory name
        /// </summary>
        public const string APP_DATA_DIR = "FirewallManager";

        /// <summary>
        /// Log file name
        /// </summary>
        public const string LOG_FILE_NAME = "firewall_manager.log";

        /// <summary>
        /// Integrity check file extension
        /// </summary>
        private const string INTEGRITY_FILE_EXT = ".hmac";

        /// <summary>
        /// HMAC key file name (stored encrypted with DPAPI)
        /// </summary>
        private const string HMAC_KEY_FILE = "hmac.key";

        /// <summary>
        /// Fixed tag used to derive the HMAC key
        /// </summary>
        private const string HMAC_KEY_TAG = "FirewallManager_Config_Integrity_v1";

        /// <summary>
        /// Cached HMAC key (lazy initialization)
        /// </summary>
        private static byte[] _cachedHmacKey;

        /// <summary>
        /// HMAC key cache lock
        /// </summary>
        private static readonly object _hmacKeyLock = new object();

        /// <summary>
        /// Critical programs collection (HashSet for O(1) lookup)
        /// These programs should not be blocked, otherwise system instability may result
        /// </summary>
        public static readonly HashSet<string> CRITICAL_PROGRAMS = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "explorer.exe", "svchost.exe", "lsass.exe", "csrss.exe",
            "wininit.exe", "services.exe", "spoolsv.exe", "winlogon.exe",
            "msdtc.exe", "smss.exe", "system.exe", "idle.exe",
            "conhost.exe", "taskhostw.exe", "dwm.exe", "winmgmt.exe",
            "ntoskrnl.exe", "userinit.exe", "runtimebroker.exe", "taskmgr.exe"
        };

        private static readonly object _appDataDirLock = new object();

        /// <summary>
        /// 0 = not attempted, 1 = secured, 2 = failed.
        /// The pessimistic value is written before the ACL call so that a nested call triggered by
        /// logging inside the ACL helper cannot re-enter the hardening block.
        /// </summary>
        private static int _appDataDirState;

        /// <summary>
        /// True when the application data directory is protected by a restrictive ACL (only
        /// Administrators and SYSTEM can write). Trust-sensitive operations (such as accepting a
        /// legacy unverified config) must fail closed when this is false.
        /// </summary>
        public static bool IsAppDataDirectorySecured
        {
            get { return _appDataDirState == 1; }
        }

        /// <summary>
        /// Gets a file path within the application data directory.
        /// The directory ACL is tightened once per process (Administrators/SYSTEM full control,
        /// current user read-only) so that files stored here cannot be deleted or replaced by a
        /// non-elevated process running as the same user.
        /// </summary>
        /// <param name="fileName">File name</param>
        /// <returns>Full file path</returns>
        public static string GetAppDataFilePath(string fileName)
        {
            string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string appFolderPath = Path.Combine(appDataPath, APP_DATA_DIR);

            // Ensure directory exists
            Directory.CreateDirectory(appFolderPath);

            if (_appDataDirState == 0)
            {
                lock (_appDataDirLock)
                {
                    if (_appDataDirState == 0)
                    {
                        // Pessimistic first: logging inside the helper must not re-enter this block.
                        _appDataDirState = 2;
                        if (ComHelper.SetSecureDirectoryPermissionsInternal(appFolderPath))
                        {
                            _appDataDirState = 1;
                        }
                        else
                        {
                            LogManager.Error($"Failed to protect the application data directory: {appFolderPath}. " +
                                             "Integrity-sensitive features will run in a restricted mode.");
                        }
                    }
                }
            }

            return Path.Combine(appFolderPath, fileName);
        }

        /// <summary>
        /// Returns true when the HMAC key file already exists, i.e. the integrity mechanism has been
        /// initialized by a previous run.
        /// </summary>
        public static bool HmacKeyFileExists()
        {
            try
            {
                return File.Exists(GetAppDataFilePath(HMAC_KEY_FILE));
            }
            catch
            {
                return true;
            }
        }

        /// <summary>
        /// Returns true when an integrity (.hmac) file exists for the given config file.
        /// </summary>
        /// <param name="configFilePath">Config file path</param>
        public static bool IntegrityFileExists(string configFilePath)
        {
            try
            {
                return !string.IsNullOrEmpty(configFilePath)
                    && File.Exists(GetIntegrityFilePath(configFilePath));
            }
            catch
            {
                return true;
            }
        }

        /// <summary>
        /// Generates a machine-specific HMAC key
        /// Uses DPAPI to encrypt and store the key, preventing local attackers from reconstructing it
        /// </summary>
        /// <returns>HMAC key byte array</returns>
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
                    // Key file read or decryption failed; generate a new key
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
        /// Generates a new HMAC key
        /// Derived via SHA256 using MachineGuid + random entropy + hardcoded tag
        /// </summary>
        /// <returns>HMAC key byte array</returns>
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
                        // Fallback if MachineGuid is unavailable or has an invalid format
                        LogManager.Info("MachineGuid not available or invalid, using fallback key generation");
                        machineKey = GenerateFallbackMachineKey();
                    }
                }
                catch (Exception ex)
                {
                    // Use fallback when MachineGuid cannot be read
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
        /// Validates whether a GUID format is valid
        /// </summary>
        private static bool IsValidGuidFormat(string guidString)
        {
            if (string.IsNullOrEmpty(guidString))
                return false;
                
            return Guid.TryParse(guidString, out _);
        }

        /// <summary>
        /// Generates a fallback machine key (when MachineGuid is unavailable)
        /// Produces a machine-unique identifier using machine name and user info
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
                // Final fallback to a completely random key
                return HMAC_KEY_TAG + "_" + Guid.NewGuid().ToString();
            }
        }

        /// <summary>
        /// Computes the HMAC-SHA256 integrity check value of a byte array
        /// Uses Convert.ToHexString instead of manual StringBuilder concatenation for consistency with RuleNamingService
        /// </summary>
        /// <param name="data">Byte data to compute</param>
        /// <param name="key">HMAC key</param>
        /// <returns>Lowercase hexadecimal string</returns>
        private static string ComputeHmacHex(byte[] data, byte[] key)
        {
            using (var hmac = new HMACSHA256(key))
            {
                byte[] hashBytes = hmac.ComputeHash(data);
                return Convert.ToHexString(hashBytes).ToLowerInvariant();
            }
        }

        /// <summary>
        /// Computes the HMAC-SHA256 integrity check value of a file
        /// </summary>
        /// <param name="filePath">File path</param>
        /// <returns>Hexadecimal string of the integrity check value, null on failure</returns>
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
        /// Gets the path of the integrity check file associated with a config file
        /// </summary>
        /// <param name="configFilePath">Config file path</param>
        /// <returns>Integrity check file path</returns>
        private static string GetIntegrityFilePath(string configFilePath)
        {
            return configFilePath + INTEGRITY_FILE_EXT;
        }

        /// <summary>
        /// Saves the integrity check value for a config file
        /// </summary>
        /// <param name="configFilePath">Config file path</param>
        /// <returns>Whether the save was successful</returns>
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
        /// Verifies the integrity of a config file
        /// Confirms the file has not been tampered with by comparing the HMAC-SHA256 checksum of the file content against a previously saved checksum
        /// </summary>
        /// <param name="configFilePath">Config file path</param>
        /// <returns>
        /// true: Integrity verification passed
        /// false: Integrity verification failed or checksum file is missing (for security reasons)
        /// </returns>
        public static bool VerifyConfigIntegrity(string configFilePath)
        {
            string content;
            return VerifyConfigIntegrityAndRead(configFilePath, out content);
        }

        /// <summary>
        /// Verifies config file integrity and reads its content (atomic operation to prevent TOCTOU attacks)
        /// Verification and reading are completed under a lock to ensure the verified content matches the read content
        /// </summary>
        /// <param name="configFilePath">Config file path</param>
        /// <param name="content">Output parameter: file content after successful verification</param>
        /// <returns>
        /// true: Integrity verification passed, content contains the file content
        /// false: Integrity verification failed or checksum file is missing (for security reasons)
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

                // Reject loading if the checksum file is missing (prevents attackers from deleting it to bypass verification)
                if (!File.Exists(integrityFilePath))
                {
                    LogManager.Error(LangManager.GetText("logMessages.configIntegrityFileMissing", configFilePath));
                    return false;
                }

                // Use file locking to prevent TOCTOU attacks
                using (var fs = File.Open(integrityFilePath, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    using (var reader = new StreamReader(fs, Encoding.UTF8))
                    {
                        string savedHash = reader.ReadToEnd()?.Trim();
                        if (string.IsNullOrEmpty(savedHash))
                        {
                            return false;
                        }

                        // Use file locking to read the config file
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

                            // Return content only after verification passes, ensuring no TOCTOU window
                            // Use StreamReader to read content so that BOM is handled automatically
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
                // Return false on verification failure for security reasons
                return false;
            }
        }

        /// <summary>
        /// Sets restricted ACL permissions for sensitive config files (only Administrators and SYSTEM can access)
        /// Prevents low-privilege users from tampering with critical files such as the whitelist and config
        /// Actual implementation is delegated to ComHelper.SetSecureFilePermissionsInternal to eliminate duplicate code
        /// </summary>
        /// <param name="filePath">Path of the file to protect</param>
        public static void SetSecureFilePermissionsPublic(string filePath)
        {
            ComHelper.SetSecureFilePermissionsInternal(filePath);
        }
    }
}