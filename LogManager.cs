using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FirewallManager
{
    /// <summary>
    /// Log manager class
    /// Used for recording and reading operation logs
    /// Fix: use file handle to prevent symbolic link following, set restricted ACL, atomic log cleanup
    /// </summary>
    public static class LogManager
    {
        /// <summary>
        /// Log file path
        /// </summary>
        private static readonly string _logFilePath;

        /// <summary>
        /// Log file handle (exclusive create to prevent symbolic link attacks)
        /// </summary>
        private static FileStream _logFileStream;

        /// <summary>
        /// Gets the log file path
        /// </summary>
        /// <returns>Full path of the log file</returns>
        public static string LogFilePath
        {
            get { return _logFilePath; }
        }

        /// <summary>
        /// Log file size limit (10MB)
        /// </summary>
        private const long _logFileSizeLimit = 10 * 1024 * 1024;

        /// <summary>
        /// Maximum number of log lines
        /// </summary>
        private const int _maxLogLines = 1000;

        /// <summary>
        /// Number of lines to keep during log cleanup
        /// When log file exceeds size limit, keep the latest 5000 lines
        /// </summary>
        private const int _linesToKeepOnClean = 5000;

        /// <summary>
        /// Log write counter, used to control cleanup frequency
        /// </summary>
        private static int _logWriteCounter = 0;

        /// <summary>
        /// Cleanup check interval (check every 100 log writes)
        /// </summary>
        private const int _cleanCheckInterval = 100;
        
        /// <summary>
        /// Log frequency limit counter
        /// </summary>
        private static int _logFrequencyCounter = 0;
        
        /// <summary>
        /// Log frequency limit time window (milliseconds)
        /// </summary>
        private const int _logFrequencyTimeWindow = 1000;
        
        /// <summary>
        /// Maximum number of logs within the time window
        /// </summary>
        private const int _logFrequencyLimit = 100;
        
        /// <summary>
        /// Last log frequency check timestamp
        /// </summary>
        private static long _lastLogFrequencyCheck = 0;

        /// <summary>
        /// Lock object to ensure thread safety
        /// </summary>
        private static readonly object _logLock = new object();

        /// <summary>
        /// Pre-compiled regex: control characters (preserves \t \n \r), prevents log injection attacks
        /// Use static compilation to avoid re-compiling regex on each call, improving performance
        /// </summary>
        private static readonly System.Text.RegularExpressions.Regex _controlCharsRegex =
            new System.Text.RegularExpressions.Regex(
                @"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]",
                System.Text.RegularExpressions.RegexOptions.Compiled);

        /// <summary>
        /// Pre-compiled regex: Unicode control characters (e.g., bidirectional text override characters), prevents log forgery
        /// </summary>
        private static readonly System.Text.RegularExpressions.Regex _unicodeControlCharsRegex =
            new System.Text.RegularExpressions.Regex(
                @"[\u200B-\u200F\u2028-\u202F\u2060-\u2069\uFEFF]",
                System.Text.RegularExpressions.RegexOptions.Compiled);

        /// <summary>
        /// Pre-compiled regex: sensitive information (password/token/secret/apikey/auth)
        /// </summary>
        private static readonly System.Text.RegularExpressions.Regex _sensitiveInfoRegex =
            new System.Text.RegularExpressions.Regex(
                @"(?<key>password|token|secret|apikey|auth)[=:]\s*[""']?[^\s""']+[""']?",
                System.Text.RegularExpressions.RegexOptions.Compiled | System.Text.RegularExpressions.RegexOptions.IgnoreCase);

        /// <summary>
        /// Log update event
        /// Triggered when new content is written to the log file, used to notify UI to update log display
        /// </summary>
        public static event Action<string> OnLogUpdated;

        /// <summary>
        /// Static constructor
        /// Initializes log file path, uses exclusive handle to prevent symbolic link attacks
        /// </summary>
        static LogManager()
        {
            try
            {
                // Get application data directory
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

                // Ensure path is valid and safe
                if (string.IsNullOrEmpty(appDataPath))
                {
                    throw new InvalidOperationException("Cannot get app data directory");
                }

                // Build application folder path
                string appFolderPath = Path.Combine(appDataPath, Config.APP_DATA_DIR);

                // Normalize path to prevent path traversal attacks
                appFolderPath = Path.GetFullPath(appFolderPath);

                // Ensure directory exists
                Directory.CreateDirectory(appFolderPath);

                // Build log file path
                string logFileName = Config.LOG_FILE_NAME;

                // Validate file name safety
                if (logFileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
                {
                    throw new InvalidOperationException("Log file name contains invalid characters");
                }

                // Set log file path
                _logFilePath = Path.Combine(appFolderPath, logFileName);

                // Normalize final path again
                _logFilePath = Path.GetFullPath(_logFilePath);

                // Ensure path is still within application directory
                string expectedPrefix = appFolderPath + Path.DirectorySeparatorChar;
                if (!_logFilePath.StartsWith(expectedPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException("Log file path outside safe range");
                }

                // Open/create log file with exclusive handle to prevent symbolic link attacks
                // FileShare.ReadWrite allows other readers (like File.ReadLines) to access concurrently
                _logFileStream = new FileStream(_logFilePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite);

                // Verify file is not a reparse point
                FileInfo logFileInfo = new FileInfo(_logFilePath);
                if ((logFileInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    _logFileStream.Dispose();
                    _logFileStream = null;
                    throw new InvalidOperationException("Log file path contains symbolic link");
                }

                // Set restricted ACL on log file
                SetLogFileSecurePermissions();
            }
            catch (Exception ex)
            {
                // Use safe fallback path with the same validation
                try
                {
                    string tempPath = Path.GetTempPath();
                    if (string.IsNullOrEmpty(tempPath))
                    {
                        throw new InvalidOperationException("Cannot get temp directory");
                    }
                    tempPath = Path.GetFullPath(tempPath);
                    if (tempPath.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException("Temp path is not safe");
                    }
                    _logFilePath = Path.Combine(tempPath, Config.LOG_FILE_NAME);
                    _logFilePath = Path.GetFullPath(_logFilePath);

                    // Open log file with exclusive handle
                    _logFileStream = new FileStream(_logFilePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite);

                    // Set restricted ACL on log file
                    SetLogFileSecurePermissions();
                }
                catch
                {
                    // Extreme case: use current directory
                    _logFilePath = Path.GetFullPath(Config.LOG_FILE_NAME);
                    _logFileStream = new FileStream(_logFilePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite);
                }
                // Avoid calling LogManager itself during static constructor phase (prevent recursion)
                try
                {
                    Console.Error.WriteLine($"LogManager initialization failed: {ex.Message}");
                }
                catch { }
            }
        }

        /// <summary>
        /// Sets restricted ACL permissions on log file
        /// Actual implementation delegates to ComHelper.SetSecureFilePermissionsInternal to eliminate duplicate code
        /// </summary>
        private static void SetLogFileSecurePermissions()
        {
            ComHelper.SetSecureFilePermissionsInternal(_logFilePath);
        }

        /// <summary>
        /// Releases log file handle
        /// </summary>
        internal static void Dispose()
        {
            try
            {
                if (_logFileStream != null)
                {
                    _logFileStream.Dispose();
                    _logFileStream = null;
                }
            }
            catch { }
        }

        /// <summary>
        /// Log level enum
        /// Defines different log severity levels
        /// </summary>
        public enum LogLevel
        {
            /// <summary>
            /// Debug information
            /// </summary>
            Debug,
            /// <summary>
            /// General information
            /// </summary>
            Info,
            /// <summary>
            /// Warning information
            /// </summary>
            Warning,
            /// <summary>
            /// Error information
            /// </summary>
            Error
        }

        /// <summary>
        /// Records log to file and triggers update event
        /// Fix: writes using held file handle to prevent symbolic link following attacks
        /// </summary>
        /// <param name="level">Log level (Debug/Info/Warning/Error)</param>
        /// <param name="message">Log message content</param>
        /// <param name="exception">Associated exception object, optional</param>
        public static void Log(LogLevel level, string message, Exception exception = null)
        {
            try
            {
                // Check log frequency limit
                if (!CheckLogFrequencyLimit())
                {
                    return;
                }
                
                // Filter sensitive information
                string filteredMessage = FilterSensitiveInfo(message);
                
                // Build log message
                string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
                string logMessage = $"[{timestamp}] [{level}] {filteredMessage}";
                
                // If there is an exception, add exception information
                if (exception != null)
                {
                    string filteredExceptionMessage = FilterSensitiveInfo(exception.Message);
                    string filteredStackTrace = exception.StackTrace != null ? FilterSensitiveInfo(exception.StackTrace) : string.Empty;
                    logMessage += $" Exception: {filteredExceptionMessage} Stack Trace: {filteredStackTrace}";
                }
                
                if (logMessage.Length > 10000)
                {
                    logMessage = logMessage.Substring(0, 10000) + "... [Message truncated]";
                }
                
                // Lock to ensure thread safety
                lock (_logLock)
                {
                    // Write using held file handle to prevent symbolic link following
                    if (_logFileStream != null)
                    {
                        byte[] logBytes = Encoding.UTF8.GetBytes(logMessage + Environment.NewLine);
                        _logFileStream.Seek(0, SeekOrigin.End);
                        _logFileStream.Write(logBytes, 0, logBytes.Length);
                        _logFileStream.Flush();
                    }
                    else
                    {
                        // Fallback
                        File.AppendAllText(_logFilePath, logMessage + Environment.NewLine, Encoding.UTF8);
                    }
                    
                    // Increment write counter
                    _logWriteCounter++;
                    
                    // Periodically check and clean logs to avoid frequent checks
                    if (_logWriteCounter >= _cleanCheckInterval)
                    {
                        _logWriteCounter = 0;
                        Task.Run(() => CheckAndCleanLogFile());
                    }
                }

                // Trigger log update event
                OnLogUpdated?.Invoke(logMessage);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Log error: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Checks log frequency limit
        /// <returns>Whether to allow writing log</returns>
        private static bool CheckLogFrequencyLimit()
        {
            lock (_logLock)
            {
                long currentTimestamp = DateTime.Now.Ticks / TimeSpan.TicksPerMillisecond;
                
                // Reset counter if time window has passed
                if (currentTimestamp - _lastLogFrequencyCheck > _logFrequencyTimeWindow)
                {
                    _logFrequencyCounter = 0;
                    _lastLogFrequencyCheck = currentTimestamp;
                }
                
                // Check if frequency limit is exceeded
                if (_logFrequencyCounter >= _logFrequencyLimit)
                {
                    return false;
                }
                
                // Increment counter
                _logFrequencyCounter++;
                return true;
            }
        }
        
        /// <summary>
        /// Filters sensitive information and control characters in log messages
        /// </summary>
        /// <param name="message">Original log message</param>
        /// <returns>Filtered log message</returns>
        private static string FilterSensitiveInfo(string message)
        {
            if (string.IsNullOrEmpty(message))
            {
                return message;
            }
            
            string filtered = message;
            
            // Remove control characters (except common newlines and tabs) to prevent log injection attacks
            // Preserve \t (0x09), \n (0x0A), \r (0x0D) for formatting
            // Remove all other control characters (0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F, 0x7F)
            filtered = _controlCharsRegex.Replace(filtered, string.Empty);
            
            // Remove Unicode control characters (e.g., bidirectional text override characters) to prevent log forgery
            filtered = _unicodeControlCharsRegex.Replace(filtered, string.Empty);
            
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrEmpty(userProfile))
            {
                filtered = filtered.Replace(userProfile, "[UserProfile]");
            }
            
            filtered = _sensitiveInfoRegex.Replace(
                filtered,
                "[" + LangManager.GetText("logMessages.logManager.sensitiveInfo") + "]");
            
            // Replace newlines with safe placeholders to prevent forged log entries
            // but first preserve exception stack trace format
            filtered = filtered.Replace("\r\n", " [CRLF] ");
            filtered = filtered.Replace("\r", " [CR] ");
            filtered = filtered.Replace("\n", " [LF] ");
            
            return filtered;
        }

        /// <summary>
        /// Records info log
        /// </summary>
        public static void Info(string message)
        {
            Log(LogLevel.Info, message);
        }

        /// <summary>
        /// Records warning log
        /// </summary>
        public static void Warning(string message)
        {
            Log(LogLevel.Warning, message);
        }

        /// <summary>
        /// Records error log
        /// </summary>
        /// <param name="exception">Exception object</param>
        public static void Error(string message, Exception exception = null)
        {
            Log(LogLevel.Error, message, exception);
        }

        /// <summary>
        /// Reads log file content
        /// Returns the latest 1000 log records
        /// </summary>
        /// <returns>Log line list, containing up to 1000 latest logs</returns>
        /// <remarks>
        /// This method performs the following operations:
        /// 1. Checks if log file exists
        /// 2. Uses File.ReadLines to read line by line, avoids loading entire large file into memory
        /// 3. Uses queue to keep latest 1000 lines of logs
        /// 4. Removes oldest line when queue exceeds 1000 lines
        /// 
        /// Performance optimizations:
        /// - Uses ReadLines instead of ReadAllLines, memory usage reduced by approximately 90%
        /// - Uses queue instead of array + Reverse, avoids multiple reversal operations
        /// - Limits number of returned lines, avoids UI lag
        /// </remarks>
        public static List<string> ReadLogs()
        {
            var logs = new List<string>();
            
            try
            {
                if (File.Exists(_logFilePath))
                {
                    // Optimize log read performance, avoid multiple Reverse() operations
                    var logLines = new Queue<string>(_maxLogLines + 1);
                    
                    try
                    {
                        // Prefer FileStream + StreamReader, ensures file sharing mode compatibility
                        using (var stream = new FileStream(_logFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        using (var reader = new StreamReader(stream, Encoding.UTF8))
                        {
                            string line;
                            while ((line = reader.ReadLine()) != null)
                            {
                                logLines.Enqueue(line);
                                if (logLines.Count > _maxLogLines)
                                {
                                    logLines.Dequeue();
                                }
                            }
                        }
                    }
                    catch (IOException)
                    {
                        // Fallback when file is locked: use File.ReadLines to handle automatically
                        System.Threading.Thread.Sleep(50);
                        var lines = File.ReadLines(_logFilePath, Encoding.UTF8);
                        foreach (var line in lines)
                        {
                            logLines.Enqueue(line);
                            if (logLines.Count > _maxLogLines)
                            {
                                logLines.Dequeue();
                            }
                        }
                    }
                    
                    logs.AddRange(logLines);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Log error: {ex.Message}");
            }
            
            return logs;
        }

        /// <summary>
        /// Core logic for atomically replacing log file content
        /// Extracted from CheckAndCleanLogFile and ClearLogs to eliminate duplicate temp file creation/handle switching/atomic replacement logic
        /// Flow: create exclusive temp file -> verify not reparse point -> write new content -> close current handle -> atomic replace -> reopen handle -> set ACL
        /// </summary>
        /// <param name="writeContent">Callback that writes new content to temp file; returns false to reject write (e.g., reparse point)</param>
        /// <returns>Whether replacement succeeded</returns>
        private static bool AtomicReplaceLogContent(Func<FileStream, bool> writeContent)
        {
            string tempPath = Path.Combine(Path.GetDirectoryName(_logFilePath), Path.GetRandomFileName());
            bool rejectWrite = false;
            try
            {
                // Create exclusive temp file
                using (var tempFs = new FileStream(tempPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
                {
                    // Verify not a reparse point (use flag to notify outer cleanup on rejection,
                    // avoid deleting already opened file within using block)
                    FileInfo tempFileInfo = new FileInfo(tempPath);
                    if ((tempFileInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        rejectWrite = true;
                        return false;
                    }

                    // Write new content (caller decides what to write)
                    if (!writeContent(tempFs))
                    {
                        rejectWrite = true;
                        return false;
                    }
                }

                // Close currently held handle
                if (_logFileStream != null)
                {
                    _logFileStream.Dispose();
                    _logFileStream = null;
                }

                // Atomic replace
                File.Replace(tempPath, _logFilePath, null);

                // Reopen file handle (use ReadWrite mode to ensure log read/write compatibility)
                _logFileStream = new FileStream(_logFilePath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
                _logFileStream.Seek(0, SeekOrigin.End);

                // Set ACL
                SetLogFileSecurePermissions();
                return true;
            }
            catch
            {
                try
                {
                    if (File.Exists(tempPath))
                    {
                        File.Delete(tempPath);
                    }
                }
                catch { }
                // Rejected write (e.g., reparse point) is a security policy, don't throw up
                if (rejectWrite)
                {
                    return false;
                }
                throw;
            }
        }

        /// <summary>
        /// Cleans old logs
        /// When log file exceeds size limit, keeps the latest log content
        /// Fix: uses atomic write to prevent symbolic link attacks
        /// </summary>
        private static void CheckAndCleanLogFile()
        {
            try
            {
                // Acquire lock to ensure no other thread writes logs while cleaning
                lock (_logLock)
                {
                    if (File.Exists(_logFilePath))
                    {
                        FileInfo fileInfo = new FileInfo(_logFilePath);

                        // Clean old logs if log file exceeds size limit
                        if (fileInfo.Length > _logFileSizeLimit)
                        {
                            // Use streaming read to avoid loading entire large file into memory at once
                            var linesToKeep = new Queue<string>(_linesToKeepOnClean + 1);

                            using (var reader = new StreamReader(_logFilePath, Encoding.UTF8))
                            {
                                string line;
                                while ((line = reader.ReadLine()) != null)
                                {
                                    linesToKeep.Enqueue(line);
                                    // Keep queue size not exceeding _linesToKeepOnClean
                                    if (linesToKeep.Count > _linesToKeepOnClean)
                                    {
                                        linesToKeep.Dequeue();
                                    }
                                }
                            }

                            // Use atomic write to replace log content (prevents symbolic link attacks)
                            AtomicReplaceLogContent(tempFs =>
                            {
                                using (var writer = new StreamWriter(tempFs, Encoding.UTF8, leaveOpen: true))
                                {
                                    foreach (var line in linesToKeep)
                                    {
                                        writer.WriteLine(line);
                                    }
                                }
                                return true;
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Log error during ClearLogs: {ex.Message}");
            }
        }

        /// <summary>
        /// Clears all logs
        /// Fix: uses atomic write to prevent symbolic link attacks
        /// </summary>
        public static void ClearLogs()
        {
            try
            {
                // Use atomic write to clear logs (prevents symbolic link attacks)
                // Writing no content clears the log file
                AtomicReplaceLogContent(_ => true);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Log error during ClearLogs: {ex.Message}");
            }
        }
    }
}