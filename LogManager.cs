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
    /// Log Manager Class
    /// 用于记录和读取操作日志
    /// Used for recording and reading operation logs
    /// </summary>
    public static class LogManager
    {
        /// <summary>
        /// 日志文件路径
        /// Log file path
        /// </summary>
        private static readonly string _logFilePath;
        
        /// <summary>
        /// 获取日志文件路径
        /// Get log file path
        /// </summary>
        public static string LogFilePath
        {
            get { return _logFilePath; }
        }

        /// <summary>
        /// 日志文件大小限制（10MB）
        /// Log file size limit (10MB)
        /// </summary>
        private const long _logFileSizeLimit = 10 * 1024 * 1024;

        /// <summary>
        /// 最大日志行数
        /// Maximum number of log lines
        /// </summary>
        private const int _maxLogLines = 1000;

        /// <summary>
        /// 日志清理时保留的行数
        /// Number of lines to keep during log cleanup
        /// 当日志文件超过大小限制时，保留最新的5000行
        /// Keep the latest 5000 lines when log file exceeds size limit
        /// </summary>
        private const int _linesToKeepOnClean = 5000;

        /// <summary>
        /// 日志写入计数器，用于控制清理频率
        /// Log write counter, used to control cleanup frequency
        /// </summary>
        private static int _logWriteCounter = 0;

        /// <summary>
        /// 清理检查间隔（每100次日志写入检查一次）
        /// Cleanup check interval (check every 100 log writes)
        /// </summary>
        private const int _cleanCheckInterval = 100;
        
        /// <summary>
        /// 日志频率限制计数器
        /// Log frequency limit counter
        /// </summary>
        private static int _logFrequencyCounter = 0;
        
        /// <summary>
        /// 日志频率限制时间窗口（毫秒）
        /// Log frequency limit time window (milliseconds)
        /// </summary>
        private const int _logFrequencyTimeWindow = 1000; // 1秒
        
        /// <summary>
        /// 时间窗口内的最大日志数量
        /// Maximum number of logs in time window
        /// </summary>
        private const int _logFrequencyLimit = 100; // 1秒内最多100条日志
        
        /// <summary>
        /// 上次日志频率检查时间戳
        /// Last log frequency check timestamp
        /// </summary>
        private static long _lastLogFrequencyCheck = 0;

        /// <summary>
        /// 用于确保线程安全的锁对象
        /// Lock object for ensuring thread safety
        /// </summary>
        private static readonly object _logLock = new object();

        /// <summary>
        /// 日志更新事件
        /// Log update event
        /// 当日志文件有新内容写入时触发
        /// Triggered when new content is written to the log file
        /// </summary>
        public static event Action<string> OnLogUpdated;

        /// <summary>
        /// 静态构造函数
        /// Static constructor
        /// 初始化日志文件路径
        /// Initialize log file path
        /// </summary>
        static LogManager()
        {
            try
            {
                System.Diagnostics.Debug.WriteLine("开始初始化日志文件路径");
                
                // 获取应用程序数据目录
                // Get application data directory
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                System.Diagnostics.Debug.WriteLine($"应用程序数据目录: {appDataPath}");
                
                // 确保路径有效且安全
                // Ensure path is valid and safe
                if (string.IsNullOrEmpty(appDataPath))
                {
                    throw new InvalidOperationException("无法获取应用程序数据目录");
                }
                
                // 构建应用程序文件夹路径
                // Build application folder path
                string appFolderPath = Path.Combine(appDataPath, "FirewallManager");
                System.Diagnostics.Debug.WriteLine($"应用程序文件夹路径: {appFolderPath}");
                
                // 规范化路径，防止路径遍历攻击
                // Normalize path to prevent path traversal attacks
                appFolderPath = Path.GetFullPath(appFolderPath);
                System.Diagnostics.Debug.WriteLine($"规范化后的应用程序文件夹路径: {appFolderPath}");
                
                // 确保目录存在
                // Ensure directory exists
                System.Diagnostics.Debug.WriteLine("确保目录存在");
                Directory.CreateDirectory(appFolderPath);
                System.Diagnostics.Debug.WriteLine("目录创建成功");
                
                // 构建日志文件路径
                // Build log file path
                string logFileName = Config.LOG_FILE_NAME;
                System.Diagnostics.Debug.WriteLine($"日志文件名: {logFileName}");
                
                // 验证文件名安全性
                // Validate file name safety
                if (logFileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
                {
                    throw new InvalidOperationException("日志文件名包含非法字符");
                }
                
                // 设置日志文件路径
                // Set log file path
                _logFilePath = Path.Combine(appFolderPath, logFileName);
                System.Diagnostics.Debug.WriteLine($"日志文件路径: {_logFilePath}");
                
                // 再次规范化最终路径
                // Normalize final path again
                _logFilePath = Path.GetFullPath(_logFilePath);
                System.Diagnostics.Debug.WriteLine($"规范化后的日志文件路径: {_logFilePath}");
                
                // 确保路径仍然在LocalApplicationData目录内
                // Ensure path is still within LocalApplicationData directory
                if (!_logFilePath.StartsWith(appDataPath + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException("日志文件路径超出安全范围");
                }
                
                // 检测并禁止符号链接
                // Detect and block symbolic links
                if (IsSymbolicLink(_logFilePath))
                {
                    throw new InvalidOperationException("日志文件路径包含符号链接");
                }
                
                System.Diagnostics.Debug.WriteLine("日志文件路径初始化成功");
            }
            catch (Exception ex)
            {
                // 日志初始化失败，使用临时目录作为 fallback
                // Log initialization failed, use temporary directory as fallback
                string tempPath = Path.GetTempPath();
                _logFilePath = Path.Combine(tempPath, Config.LOG_FILE_NAME);
                System.Diagnostics.Debug.WriteLine($"日志路径初始化失败: {ex.Message}，使用临时目录: {_logFilePath}");
            }
        }

        /// <summary>
        /// 日志级别枚举
        /// Log level enumeration
        /// </summary>
        public enum LogLevel
        {
            /// <summary>
            /// 调试信息
            /// Debug information
            /// </summary>
            Debug,
            /// <summary>
            /// 普通信息
            /// General information
            /// </summary>
            Info,
            /// <summary>
            /// 警告信息
            /// Warning information
            /// </summary>
            Warning,
            /// <summary>
            /// 错误信息
            /// Error information
            /// </summary>
            Error
        }

        /// <summary>
        /// 记录日志到文件并触发更新事件
        /// Log to file and trigger update event
        /// </summary>
        /// <param name="level">日志级别（Debug/Info/Warning/Error）</param>
        /// <param name="level">Log level (Debug/Info/Warning/Error)</param>
        /// <param name="message">日志消息内容</param>
        /// <param name="message">Log message content</param>
        /// <param name="exception">关联的异常对象，可选</param>
        /// <param name="exception">Associated exception object, optional</param>
        /// <remarks>
        /// 该方法执行以下操作：
        /// This method performs the following operations:
        /// 1. 构建带时间戳和日志级别的日志消息
        /// 1. Build log message with timestamp and log level
        /// 2. 如果提供了异常对象，追加异常信息和堆栈跟踪
        /// 2. If exception object is provided, append exception information and stack trace
        /// 3. 使用锁确保多线程安全地写入日志文件
        /// 3. Use lock to ensure thread-safe writing to log file
        /// 4. 每100次写入检查一次日志文件大小，超过10MB时清理
        /// 4. Check log file size every 100 writes, clean up if over 10MB
        /// 5. 触发OnLogUpdated事件，通知订阅者有新日志
        /// 5. Trigger OnLogUpdated event to notify subscribers of new logs
        /// 
        /// 性能优化：
        /// Performance optimizations:
        /// - 使用锁而非Monitor，减少上下文切换
        /// - Use lock instead of Monitor to reduce context switching
        /// - 定期检查文件大小而非每次检查，减少99%的文件系统调用
        /// - Check file size periodically instead of every time, reducing 99% of file system calls
        /// - 异步清理日志，避免阻塞日志写入
        /// - Asynchronously clean up logs to avoid blocking log writing
        /// 
        /// 安全措施：
        /// Security measures:
        /// - 过滤敏感信息，防止泄露
        /// - Filter sensitive information to prevent leakage
        /// - 限制日志长度，防止DoS攻击
        /// - Limit log length to prevent DoS attacks
        /// </remarks>
        public static void Log(LogLevel level, string message, Exception exception = null)
        {
            try
            {
                // 检查日志频率限制
                // Check log frequency limit
                if (!CheckLogFrequencyLimit())
                {
                    return;
                }
                
                // 过滤敏感信息
                // Filter sensitive information
                string filteredMessage = FilterSensitiveInfo(message);
                
                // 构建日志消息
                // Build log message
                string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
                string logMessage = $"[{timestamp}] [{level}] {filteredMessage}";
                
                // 如果有异常，添加异常信息
                // If there is an exception, add exception information
                if (exception != null)
                {
                    // 过滤异常消息中的敏感信息
                    // Filter sensitive information in exception message
                    string filteredExceptionMessage = FilterSensitiveInfo(exception.Message);
                    logMessage += $"\nException: {filteredExceptionMessage}\nStack Trace: {exception.StackTrace}";
                }
                
                // 限制日志消息长度，防止DoS攻击
                // Limit log message length to prevent DoS attacks
                if (logMessage.Length > 10000)
                {
                    logMessage = logMessage.Substring(0, 10000) + "... [消息被截断]";
                }
                
                // 加锁确保线程安全
                // Lock to ensure thread safety
                lock (_logLock)
                {
                    // 写入日志文件
                    // Write to log file
                    File.AppendAllText(_logFilePath, logMessage + Environment.NewLine, Encoding.UTF8);
                    
                    // 增加写入计数器
                    // Increment write counter
                    _logWriteCounter++;
                    
                    // 定期检查并清理日志，避免频繁检查
                    // Check and clean logs periodically to avoid frequent checks
                    if (_logWriteCounter >= _cleanCheckInterval)
                    {
                        _logWriteCounter = 0;
                        Task.Run(() => CheckAndCleanLogFile());
                    }
                }

                // 触发日志更新事件
                // Trigger log update event
                OnLogUpdated?.Invoke(logMessage);
            }
            catch (Exception ex)
            {
                // 日志写入失败，记录到调试输出以便排查问题
                System.Diagnostics.Debug.WriteLine($"日志写入失败: {ex.Message}");
                System.Diagnostics.Debug.WriteLine($"异常堆栈: {ex.StackTrace}");
            }
        }
        
        /// <summary>
        /// 检查日志频率限制
        /// Check log frequency limit
        /// </summary>
        /// <returns>是否允许写入日志</returns>
        /// <returns>Whether to allow writing log</returns>
        private static bool CheckLogFrequencyLimit()
        {
            lock (_logLock)
            {
                long currentTimestamp = DateTime.Now.Ticks / TimeSpan.TicksPerMillisecond;
                
                // 如果时间窗口已过，重置计数器
                // Reset counter if time window has passed
                if (currentTimestamp - _lastLogFrequencyCheck > _logFrequencyTimeWindow)
                {
                    _logFrequencyCounter = 0;
                    _lastLogFrequencyCheck = currentTimestamp;
                }
                
                // 检查是否超过频率限制
                // Check if frequency limit is exceeded
                if (_logFrequencyCounter >= _logFrequencyLimit)
                {
                    return false;
                }
                
                // 增加计数器
                // Increment counter
                _logFrequencyCounter++;
                return true;
            }
        }
        
        /// <summary>
        /// 过滤日志消息中的敏感信息
        /// Filter sensitive information in log messages
        /// </summary>
        /// <param name="message">原始日志消息</param>
        /// <param name="message">Original log message</param>
        /// <returns>过滤后的日志消息</returns>
        /// <returns>Filtered log message</returns>
        private static string FilterSensitiveInfo(string message)
        {
            if (string.IsNullOrEmpty(message))
            {
                return message;
            }
            
            string filtered = message;
            
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrEmpty(userProfile))
            {
                filtered = filtered.Replace(userProfile, "[UserProfile]");
            }
            
            filtered = System.Text.RegularExpressions.Regex.Replace(
                filtered,
                @"(?<key>password|token|secret|apikey|auth)[=:]\s*[""']?[^\s""']+[""']?",
                "[敏感信息]",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            
            filtered = filtered.Replace("\r", "").Replace("\n", "");
            
            if (filtered.Length > 8000)
            {
                filtered = filtered.Substring(0, 8000) + "... [消息被截断]";
            }
            
            return filtered;
        }

        /// <summary>
        /// 记录调试日志
        /// Log debug message
        /// </summary>
        /// <param name="message">日志消息</param>
        /// <param name="message">Log message</param>
        public static void Debug(string message)
        {
            Log(LogLevel.Debug, message);
        }

        /// <summary>
        /// 记录信息日志
        /// Log information message
        /// </summary>
        /// <param name="message">日志消息</param>
        /// <param name="message">Log message</param>
        public static void Info(string message)
        {
            Log(LogLevel.Info, message);
        }

        /// <summary>
        /// 记录警告日志
        /// Log warning message
        /// </summary>
        /// <param name="message">日志消息</param>
        /// <param name="message">Log message</param>
        public static void Warning(string message)
        {
            Log(LogLevel.Warning, message);
        }

        /// <summary>
        /// 记录错误日志
        /// Log error message
        /// </summary>
        /// <param name="message">日志消息</param>
        /// <param name="message">Log message</param>
        /// <param name="exception">异常对象</param>
        /// <param name="exception">Exception object</param>
        public static void Error(string message, Exception exception = null)
        {
            Log(LogLevel.Error, message, exception);
        }

        /// <summary>
        /// 读取日志文件内容
        /// Read log file content
        /// 返回最新的1000行日志记录
        /// Return the latest 1000 log records
        /// </summary>
        /// <returns>日志行列表，最多包含1000行最新日志</returns>
        /// <returns>Log line list, containing up to 1000 latest logs</returns>
        /// <remarks>
        /// 该方法执行以下操作：
        /// This method performs the following operations:
        /// 1. 检查日志文件是否存在
        /// 1. Check if log file exists
        /// 2. 使用File.ReadLines逐行读取，避免一次性加载大文件到内存
        /// 2. Use File.ReadLines to read line by line, avoiding loading large files into memory at once
        /// 3. 使用队列保持最新的1000行日志
        /// 3. Use queue to keep the latest 1000 log lines
        /// 4. 当队列超过1000行时，移除最旧的行
        /// 4. When queue exceeds 1000 lines, remove the oldest lines
        /// 
        /// 性能优化：
        /// Performance optimizations:
        /// - 使用ReadLines而非ReadAllLines，内存占用减少约90%
        /// - Use ReadLines instead of ReadAllLines, reducing memory usage by about 90%
        /// - 使用队列而非数组+Reverse，避免多次反转操作
        /// - Use queue instead of array+Reverse to avoid multiple reversal operations
        /// - 限制返回行数，避免UI卡顿
        /// - Limit returned lines to avoid UI lag
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
            catch (Exception ex)
            {
                // 读取日志失败，记录到调试输出
                System.Diagnostics.Debug.WriteLine($"读取日志失败: {ex.Message}");
            }
            
            return logs;
        }

        /// <summary>
        /// 清理旧日志
        /// Clean up old logs
        /// 当日志文件超过大小限制时，保留最新的日志内容
        /// Keep the latest log content when log file exceeds size limit
        /// </summary>
        private static void CheckAndCleanLogFile()
        {
            try
            {
                if (File.Exists(_logFilePath))
                {
                    FileInfo fileInfo = new FileInfo(_logFilePath);
                    
                    // 如果日志文件超过大小限制，清理旧日志
                    // If log file exceeds size limit, clean up old logs
                    if (fileInfo.Length > _logFileSizeLimit)
                    {
                        // 使用流式读取，避免一次性加载大文件到内存
                        // Use stream reading to avoid loading large files into memory at once
                        var linesToKeep = new Queue<string>(_linesToKeepOnClean + 1);
                        
                        using (var reader = new StreamReader(_logFilePath, Encoding.UTF8))
                        {
                            string line;
                            while ((line = reader.ReadLine()) != null)
                            {
                                linesToKeep.Enqueue(line);
                                // 保持队列大小不超过_linesToKeepOnClean
                                // Keep queue size within _linesToKeepOnClean
                                if (linesToKeep.Count > _linesToKeepOnClean)
                                {
                                    linesToKeep.Dequeue();
                                }
                            }
                        }
                        
                        // 写入新日志内容
                        // Write new log content
                        using (var writer = new StreamWriter(_logFilePath, false, Encoding.UTF8))
                        {
                            foreach (var line in linesToKeep)
                            {
                                writer.WriteLine(line);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // 清理日志失败，记录到调试输出
                // Log cleanup failed, record to debug output
                System.Diagnostics.Debug.WriteLine($"清理日志失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 清空所有日志
        /// Clear all logs
        /// </summary>
        public static void ClearLogs()
        {
            try
            {
                if (File.Exists(_logFilePath))
                {
                    File.WriteAllText(_logFilePath, string.Empty, Encoding.UTF8);
                }
            }
            catch (Exception ex)
            {
                // 清空日志失败，记录到调试输出
                // Clear logs failed, record to debug output
                System.Diagnostics.Debug.WriteLine($"清空日志失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 检测路径是否为符号链接
        /// Detect if a path is a symbolic link
        /// </summary>
        /// <param name="path">要检测的路径</param>
        /// <param name="path">Path to detect</param>
        /// <returns>是否为符号链接</returns>
        /// <returns>Whether the path is a symbolic link</returns>
        private static bool IsSymbolicLink(string path)
        {
            try
            {
                if (Directory.Exists(path))
                {
                    var dirInfo = new DirectoryInfo(path);
                    return dirInfo.Attributes.HasFlag(FileAttributes.ReparsePoint);
                }
                else if (File.Exists(path))
                {
                    var fileInfo = new FileInfo(path);
                    return fileInfo.Attributes.HasFlag(FileAttributes.ReparsePoint);
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
    }
}