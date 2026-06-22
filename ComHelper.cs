using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace FirewallManager
{
    internal static class ComHelper
    {
        /// <summary>
        /// 安全的JSON反序列化选项 - 限制最大深度防止嵌套攻击
        /// </summary>
        internal static readonly JsonSerializerOptions SafeJsonOptions = new JsonSerializerOptions
        {
            MaxDepth = 10
        };

        internal static T SafeGetProperty<T>(dynamic obj, string propertyName, T defaultValue = default)
        {
            try
            {
                if (obj == null)
                    return defaultValue;
                object value = obj.GetType().InvokeMember(propertyName, BindingFlags.GetProperty, null, obj, null);
                return value == null ? defaultValue : (T)Convert.ChangeType(value, typeof(T));
            }
            catch
            {
                return defaultValue;
            }
        }

        internal static bool SafeSetProperty(dynamic obj, string propertyName, object value)
        {
            try
            {
                if (obj == null)
                    return false;
                obj.GetType().InvokeMember(propertyName, BindingFlags.SetProperty, null, obj, new[] { value });
                return true;
            }
            catch
            {
                return false;
            }
        }

        internal static bool IsSymbolicLink(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path))
                    return false;
                if (Directory.Exists(path))
                {
                    var dirInfo = new DirectoryInfo(path);
                    return !string.IsNullOrEmpty(dirInfo.LinkTarget);
                }
                if (File.Exists(path))
                {
                    var fileInfo = new FileInfo(path);
                    return !string.IsNullOrEmpty(fileInfo.LinkTarget);
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        internal static bool WaitForFileReady(string filePath, int maxRetries, int retryDelayMs)
        {
            long previousSize = -1;
            int stableCount = 0;
            const int requiredStableChecks = 2;

            for (int i = 0; i < maxRetries; i++)
            {
                try
                {
                    if (!File.Exists(filePath))
                    {
                        System.Threading.Thread.Sleep(retryDelayMs);
                        continue;
                    }

                    using (var fileStream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        long currentSize = fileStream.Length;
                        if (currentSize == previousSize && currentSize > 0)
                        {
                            stableCount++;
                            if (stableCount >= requiredStableChecks)
                                return true;
                        }
                        else
                        {
                            stableCount = 0;
                        }
                        previousSize = currentSize;
                    }
                }
                catch (IOException) { stableCount = 0; }
                catch (UnauthorizedAccessException) { stableCount = 0; }

                if (i < maxRetries - 1)
                    System.Threading.Thread.Sleep(retryDelayMs);
            }
            return false;
        }

        /// <summary>
        /// 原子写入文本文件 - 先写临时文件再替换，防止写入中断导致文件损坏
        /// </summary>
        internal static void AtomicWriteAllText(string filePath, string contents, System.Text.Encoding encoding)
        {
            string tempPath = filePath + ".tmp";
            File.WriteAllText(tempPath, contents, encoding);
            File.Replace(tempPath, filePath, null);
        }
    }
}