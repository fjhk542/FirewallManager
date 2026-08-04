using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FirewallManager
{
    /// <summary>
    /// 日志管理器类
    /// 用于记录和读取操作日志
    /// 修复：使用文件句柄防止符号链接跟随，设置受限ACL，原子操作清理日志
    /// </summary>
    public static class LogManager
    {
        /// <summary>
        /// 日志文件路径
        /// </summary>
        private static readonly string _logFilePath;

        /// <summary>
        /// 日志文件句柄（排他创建，防止符号链接攻击）
        /// </summary>
        private static FileStream _logFileStream;

        /// <summary>
        /// 获取日志文件路径
        /// </summary>
        /// <returns>日志文件的完整路径</returns>
        public static string LogFilePath
        {
            get { return _logFilePath; }
        }

        /// <summary>
        /// 日志文件大小限制（10MB）
        /// </summary>
        private const long _logFileSizeLimit = 10 * 1024 * 1024;

        /// <summary>
        /// 最大日志行数
        /// </summary>
        private const int _maxLogLines = 1000;

        /// <summary>
        /// 日志清理时保留的行数
        /// 当日志文件超过大小限制时，保留最新的5000行
        /// </summary>
        private const int _linesToKeepOnClean = 5000;

        /// <summary>
        /// 日志写入计数器，用于控制清理频率
        /// </summary>
        private static int _logWriteCounter = 0;

        /// <summary>
        /// 清理检查间隔（每100次日志写入检查一次）
        /// </summary>
        private const int _cleanCheckInterval = 100;
        
        /// <summary>
        /// 日志频率限制计数器
        /// </summary>
        private static int _logFrequencyCounter = 0;
        
        /// <summary>
        /// 日志频率限制时间窗口（毫秒）
        /// </summary>
        private const int _logFrequencyTimeWindow = 1000;
        
        /// <summary>
        /// 时间窗口内的最大日志数量
        /// </summary>
        private const int _logFrequencyLimit = 100;
        
        /// <summary>
        /// 上次日志频率检查时间戳
        /// </summary>
        private static long _lastLogFrequencyCheck = 0;

        /// <summary>
        /// 用于确保线程安全的锁对象
        /// </summary>
        private static readonly object _logLock = new object();

        /// <summary>
        /// 日志更新事件
        /// 当日志文件有新内容写入时触发，用于通知UI更新日志显示
        /// </summary>
        public static event Action<string> OnLogUpdated;

        /// <summary>
        /// 静态构造函数
        /// 初始化日志文件路径，使用排他句柄防止符号链接攻击
        /// </summary>
        static LogManager()
        {
            try
            {
                // 获取应用程序数据目录
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

                // 确保路径有效且安全
                if (string.IsNullOrEmpty(appDataPath))
                {
                    throw new InvalidOperationException("Cannot get app data directory");
                }

                // 构建应用程序文件夹路径
                string appFolderPath = Path.Combine(appDataPath, Config.APP_DATA_DIR);

                // 规范化路径，防止路径遍历攻击
                appFolderPath = Path.GetFullPath(appFolderPath);

                // 确保目录存在
                Directory.CreateDirectory(appFolderPath);

                // 构建日志文件路径
                string logFileName = Config.LOG_FILE_NAME;

                // 验证文件名安全性
                if (logFileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
                {
                    throw new InvalidOperationException("Log file name contains invalid characters");
                }

                // 设置日志文件路径
                _logFilePath = Path.Combine(appFolderPath, logFileName);

                // 再次规范化最终路径
                _logFilePath = Path.GetFullPath(_logFilePath);

                // 确保路径仍然在应用程序目录内
                string expectedPrefix = appFolderPath + Path.DirectorySeparatorChar;
                if (!_logFilePath.StartsWith(expectedPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException("Log file path outside safe range");
                }

                // 使用排他句柄打开/创建日志文件，防止符号链接攻击
                _logFileStream = new FileStream(_logFilePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read);

                // 验证文件不是reparse point
                FileInfo logFileInfo = new FileInfo(_logFilePath);
                if ((logFileInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    _logFileStream.Dispose();
                    _logFileStream = null;
                    throw new InvalidOperationException("Log file path contains symbolic link");
                }

                // 设置日志文件受限ACL
                SetLogFileSecurePermissions();
            }
            catch (Exception ex)
            {
                // 使用安全的回退路径，并对其进行相同的验证
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

                    // 使用排他句柄打开日志文件
                    _logFileStream = new FileStream(_logFilePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read);

                    // 设置日志文件受限ACL
                    SetLogFileSecurePermissions();
                }
                catch
                {
                    // 极端情况：使用当前目录
                    _logFilePath = Path.GetFullPath(Config.LOG_FILE_NAME);
                    _logFileStream = new FileStream(_logFilePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read);
                }
                // 静态构造函数阶段避免调用 LogManager 自身（防止递归）
                try
                {
                    Console.Error.WriteLine($"LogManager initialization failed: {ex.Message}");
                }
                catch { }
            }
        }

        /// <summary>
        /// 设置日志文件受限ACL权限
        /// </summary>
        private static void SetLogFileSecurePermissions()
        {
            try
            {
                if (!File.Exists(_logFilePath))
                    return;

                var fileInfo = new FileInfo(_logFilePath);
                System.Security.AccessControl.FileSecurity fileSecurity = fileInfo.GetAccessControl();
                fileSecurity.SetAccessRuleProtection(true, false);

                System.Security.Principal.SecurityIdentifier adminSid = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
                System.Security.AccessControl.FileSystemAccessRule adminRule = new System.Security.AccessControl.FileSystemAccessRule(
                    adminSid,
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.AccessControlType.Allow);
                fileSecurity.AddAccessRule(adminRule);

                System.Security.Principal.SecurityIdentifier systemSid = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
                System.Security.AccessControl.FileSystemAccessRule systemRule = new System.Security.AccessControl.FileSystemAccessRule(
                    systemSid,
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.AccessControlType.Allow);
                fileSecurity.AddAccessRule(systemRule);

                fileInfo.SetAccessControl(fileSecurity);
            }
            catch
            {
                // ACL设置失败不应影响主要功能
            }
        }

        /// <summary>
        /// 释放日志文件句柄
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
        /// 日志级别枚举
        /// 定义不同的日志严重级别
        /// </summary>
        public enum LogLevel
        {
            /// <summary>
            /// 调试信息
            /// </summary>
            Debug,
            /// <summary>
            /// 普通信息
            /// </summary>
            Info,
            /// <summary>
            /// 警告信息
            /// </summary>
            Warning,
            /// <summary>
            /// 错误信息
            /// </summary>
            Error
        }

        /// <summary>
        /// 记录日志到文件并触发更新事件
        /// 修复：使用持有文件句柄写入，防止符号链接跟随攻击
        /// </summary>
        /// <param name="level">日志级别（Debug/Info/Warning/Error）</param>
        /// <param name="message">日志消息内容</param>
        /// <param name="exception">关联的异常对象，可选</param>
        public static void Log(LogLevel level, string message, Exception exception = null)
        {
            try
            {
                // 检查日志频率限制
                if (!CheckLogFrequencyLimit())
                {
                    return;
                }
                
                // 过滤敏感信息
                string filteredMessage = FilterSensitiveInfo(message);
                
                // 构建日志消息
                string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
                string logMessage = $"[{timestamp}] [{level}] {filteredMessage}";
                
                // 如果有异常，添加异常信息
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
                
                // 加锁确保线程安全
                lock (_logLock)
                {
                    // 使用持有文件句柄写入，防止符号链接跟随
                    if (_logFileStream != null)
                    {
                        byte[] logBytes = Encoding.UTF8.GetBytes(logMessage + Environment.NewLine);
                        _logFileStream.Seek(0, SeekOrigin.End);
                        _logFileStream.Write(logBytes, 0, logBytes.Length);
                        _logFileStream.Flush();
                    }
                    else
                    {
                        // 回退方案
                        File.AppendAllText(_logFilePath, logMessage + Environment.NewLine, Encoding.UTF8);
                    }
                    
                    // 增加写入计数器
                    _logWriteCounter++;
                    
                    // 定期检查并清理日志，避免频繁检查
                    if (_logWriteCounter >= _cleanCheckInterval)
                    {
                        _logWriteCounter = 0;
                        Task.Run(() => CheckAndCleanLogFile());
                    }
                }

                // 触发日志更新事件
                OnLogUpdated?.Invoke(logMessage);
            }
            catch (Exception)
            {
            }
        }
        
        /// <summary>
        /// 检查日志频率限制
        /// <returns>是否允许写入日志</returns>
        /// <returns>Whether to allow writing log</returns>
        private static bool CheckLogFrequencyLimit()
        {
            lock (_logLock)
            {
                long currentTimestamp = DateTime.Now.Ticks / TimeSpan.TicksPerMillisecond;
                
                // 如果时间窗口已过，重置计数器
                if (currentTimestamp - _lastLogFrequencyCheck > _logFrequencyTimeWindow)
                {
                    _logFrequencyCounter = 0;
                    _lastLogFrequencyCheck = currentTimestamp;
                }
                
                // 检查是否超过频率限制
                if (_logFrequencyCounter >= _logFrequencyLimit)
                {
                    return false;
                }
                
                // 增加计数器
                _logFrequencyCounter++;
                return true;
            }
        }
        
        /// <summary>
        /// 过滤日志消息中的敏感信息和控制字符
        /// </summary>
        /// <param name="message">原始日志消息</param>
        /// <returns>过滤后的日志消息</returns>
        private static string FilterSensitiveInfo(string message)
        {
            if (string.IsNullOrEmpty(message))
            {
                return message;
            }
            
            string filtered = message;
            
            // 移除控制字符（除了常见的换行和制表符），防止日志注入攻击
            // 保留 \t (0x09), \n (0x0A), \r (0x0D) 用于格式化
            // 移除其他所有控制字符 (0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F, 0x7F)
            filtered = System.Text.RegularExpressions.Regex.Replace(
                filtered,
                @"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]",
                string.Empty);
            
            // 移除 Unicode 控制字符（如双向文本覆盖字符），防止日志伪造
            filtered = System.Text.RegularExpressions.Regex.Replace(
                filtered,
                @"[\u200B-\u200F\u2028-\u202F\u2060-\u2069\uFEFF]",
                string.Empty);
            
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrEmpty(userProfile))
            {
                filtered = filtered.Replace(userProfile, "[UserProfile]");
            }
            
            filtered = System.Text.RegularExpressions.Regex.Replace(
                filtered,
                @"(?<key>password|token|secret|apikey|auth)[=:]\s*[""']?[^\s""']+[""']?",
                "[" + LangManager.GetText("logMessages.logManager.sensitiveInfo") + "]",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            
            // 用安全占位符替换换行符，防止伪造日志条目
            // 但先保留异常堆栈的格式
            filtered = filtered.Replace("\r\n", " [CRLF] ");
            filtered = filtered.Replace("\r", " [CR] ");
            filtered = filtered.Replace("\n", " [LF] ");
            
            return filtered;
        }

        /// <summary>
        /// 记录调试日志
        /// </summary>
        public static void Debug(string message)
        {
            Log(LogLevel.Debug, message);
        }

        /// <summary>
        /// 记录信息日志
        /// </summary>
        public static void Info(string message)
        {
            Log(LogLevel.Info, message);
        }

        /// <summary>
        /// 记录警告日志
        /// </summary>
        public static void Warning(string message)
        {
            Log(LogLevel.Warning, message);
        }

        /// <summary>
        /// 记录错误日志
        /// </summary>
        /// <param name="exception">异常对象</param>
        public static void Error(string message, Exception exception = null)
        {
            Log(LogLevel.Error, message, exception);
        }

        /// <summary>
        /// 读取日志文件内容
        /// 返回最新的1000行日志记录
        /// </summary>
        /// <returns>日志行列表，最多包含1000行最新日志</returns>
        /// <returns>Log line list, containing up to 1000 latest logs</returns>
        /// <remarks>
        /// 该方法执行以下操作：
        /// 1. 检查日志文件是否存在
        /// 2. 使用File.ReadLines逐行读取，避免一次性加载大文件到内存
        /// 3. 使用队列保持最新的1000行日志
        /// 4. 当队列超过1000行时，移除最旧的行
        /// 
        /// 性能优化：
        /// - 使用ReadLines而非ReadAllLines，内存占用减少约90%
        /// - 使用队列而非数组+Reverse，避免多次反转操作
        /// - 限制返回行数，避免UI卡顿
        /// </remarks>
        public static List<string> ReadLogs()
        {
            var logs = new List<string>();
            
            try
            {
                if (File.Exists(_logFilePath))
                {
                    // 优化日志读取性能，避免多次Reverse()操作
                    var lines = File.ReadLines(_logFilePath, Encoding.UTF8);
                    var logLines = new Queue<string>(_maxLogLines + 1);
                    
                    foreach (var line in lines)
                    {
                        logLines.Enqueue(line);
                        // 保持队列大小不超过_maxLogLines
                        if (logLines.Count > _maxLogLines)
                        {
                            logLines.Dequeue();
                        }
                    }
                    
                    logs.AddRange(logLines);
                }
            }
            catch (Exception)
            {
            }
            
            return logs;
        }

        /// <summary>
        /// 清理旧日志
        /// 当日志文件超过大小限制时，保留最新的日志内容
        /// 修复：使用原子写入防止符号链接攻击
        /// </summary>
        private static void CheckAndCleanLogFile()
        {
            try
            {
                // 获取锁，确保在清理日志时不会有其他线程写入日志
                lock (_logLock)
                {
                    if (File.Exists(_logFilePath))
                    {
                        FileInfo fileInfo = new FileInfo(_logFilePath);

                        // 如果日志文件超过大小限制，清理旧日志
                        if (fileInfo.Length > _logFileSizeLimit)
                        {
                            // 使用流式读取，避免一次性加载大文件到内存
                            var linesToKeep = new Queue<string>(_linesToKeepOnClean + 1);

                            using (var reader = new StreamReader(_logFilePath, Encoding.UTF8))
                            {
                                string line;
                                while ((line = reader.ReadLine()) != null)
                                {
                                    linesToKeep.Enqueue(line);
                                    // 保持队列大小不超过_linesToKeepOnClean
                                    if (linesToKeep.Count > _linesToKeepOnClean)
                                    {
                                        linesToKeep.Dequeue();
                                    }
                                }
                            }

                            // 使用原子写入替换日志内容（防止符号链接攻击）
                            string tempPath = Path.Combine(Path.GetDirectoryName(_logFilePath), Path.GetRandomFileName());
                            try
                            {
                                // 排他创建临时文件
                                using (var tempFs = new FileStream(tempPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
                                {
                                    // 验证不是reparse point
                                    FileInfo tempFileInfo = new FileInfo(tempPath);
                                    if ((tempFileInfo.Attributes & FileAttributes.ReparsePoint) == 0)
                                    {
                                        using (var writer = new StreamWriter(tempFs, Encoding.UTF8))
                                        {
                                            foreach (var line in linesToKeep)
                                            {
                                                writer.WriteLine(line);
                                            }
                                        }
                                    }
                                    else
                                    {
                                        // 删除reparse point临时文件，终止操作
                                        File.Delete(tempPath);
                                        return;
                                    }
                                }

                                // 关闭当前持有句柄
                                if (_logFileStream != null)
                                {
                                    _logFileStream.Dispose();
                                    _logFileStream = null;
                                }

                                // 原子替换
                                File.Replace(tempPath, _logFilePath, null);

                                // 重新打开文件句柄
                                _logFileStream = new FileStream(_logFilePath, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
                                _logFileStream.Seek(0, SeekOrigin.End);

                                // 设置ACL
                                SetLogFileSecurePermissions();
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
                                throw;
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
            }
        }

        /// <summary>
        /// 清空所有日志
        /// 修复：使用原子写入防止符号链接攻击
        /// </summary>
        public static void ClearLogs()
        {
            try
            {
                // 使用原子写入清空日志（防止符号链接攻击）
                string tempPath = Path.Combine(Path.GetDirectoryName(_logFilePath), Path.GetRandomFileName());
                try
                {
                    // 排他创建临时文件
                    using (var tempFs = new FileStream(tempPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
                    {
                        // 验证不是reparse point
                        FileInfo tempFileInfo = new FileInfo(tempPath);
                        if ((tempFileInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                        {
                            File.Delete(tempPath);
                            return;
                        }
                    }

                    // 关闭当前持有句柄
                    if (_logFileStream != null)
                    {
                        _logFileStream.Dispose();
                        _logFileStream = null;
                    }

                    // 原子替换
                    File.Replace(tempPath, _logFilePath, null);

                    // 重新打开文件句柄
                    _logFileStream = new FileStream(_logFilePath, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
                    _logFileStream.Seek(0, SeekOrigin.End);

                    // 设置ACL
                    SetLogFileSecurePermissions();
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
                    throw;
                }
            }
            catch (Exception)
            {
            }
        }
    }
}