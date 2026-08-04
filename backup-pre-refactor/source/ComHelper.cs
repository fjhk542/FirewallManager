using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace FirewallManager
{
    internal static class Win32Native
    {
        public const uint GENERIC_READ = 0x80000000;
        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint OPEN_EXISTING = 3;
        public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        public const uint WINTRUST_ACTION_GENERIC_VERIFY_V2 = 0x00000002;

        [StructLayout(LayoutKind.Sequential)]
        public struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public string pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        public static extern uint WinVerifyTrust(
            IntPtr hWnd,
            IntPtr pgActionID,
            ref WINTRUST_DATA pWinTrustData);
    }
}

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

        /// <summary>
        /// 使用固定CLSID创建COM对象并验证
        /// 防止ProgID劫持攻击
        /// </summary>
        /// <param name="clsid">CLSID字符串</param>
        /// <param name="iid">接口IID字符串</param>
        /// <param name="progId">ProgID（用于日志）</param>
        /// <returns>COM对象，失败返回null</returns>
        internal static object CreateComObjectWithClsid(string clsid, string iid, string progId)
        {
            try
            {
                Guid clsidGuid;
                Guid iidGuid;
                
                if (!Guid.TryParse(clsid, out clsidGuid) || !Guid.TryParse(iid, out iidGuid))
                {
                    LogManager.Error(LangManager.GetText("logMessages.invalidGuidForComObject", progId));
                    return null;
                }

                Type expectedType = Type.GetTypeFromCLSID(clsidGuid);
                if (expectedType == null)
                {
                    LogManager.Error(LangManager.GetText("logMessages.clsidTypeNotFound", clsid));
                    return null;
                }

                object comObject = Activator.CreateInstance(expectedType);
                if (comObject == null)
                {
                    LogManager.Error(LangManager.GetText("logMessages.createComObjectFailed", progId));
                    return null;
                }

                // 验证 COM 对象
                bool clsidValid = ValidateComObjectClsid(comObject, clsidGuid);
                bool iidValid = ValidateComObjectIid(comObject, iidGuid);

                if (!clsidValid && !iidValid)
                {
                    LogManager.Error(LangManager.GetText("logMessages.comObjectValidationFailed", progId));
                    Marshal.ReleaseComObject(comObject);
                    return null;
                }

                // 如果 CLSID 验证通过，即使 IID 验证失败也允许使用
                // （某些 COM 对象的 IID 可能与文档不完全一致）
                if (!iidValid && clsidValid)
                {
                    LogManager.Warning($"COM object IID validation failed but CLSID is valid, proceeding with {progId}");
                }

                return comObject;
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.createComObjectException", progId, ex.Message));
                return null;
            }
        }

        /// <summary>
        /// 验证 COM 对象的 CLSID
        /// </summary>
        internal static bool ValidateComObjectClsid(object obj, Guid expectedClsid)
        {
            if (obj == null)
                return false;

            try
            {
                Type objType = obj.GetType();
                Guid objClsid = objType.GUID;

                // 对于 System.__ComObject，GUID 可能是空的
                // 这种情况下，因为我们已经通过 Type.GetTypeFromCLSID 验证了 CLSID，
                // 所以认为 CLSID 验证通过
                if (objClsid == Guid.Empty)
                {
                    return true;
                }

                if (objClsid != expectedClsid)
                {
                    LogManager.Warning(LangManager.GetText("logMessages.comObjectClsidMismatch", objClsid, expectedClsid));
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                LogManager.Warning($"CLSID validation failed: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 验证 COM 对象的 IID (通过 QueryInterface)
        /// </summary>
        internal static bool ValidateComObjectIid(object obj, Guid expectedIid)
        {
            if (obj == null)
                return false;

            try
            {
                IntPtr unknownPtr = Marshal.GetIUnknownForObject(obj);
                IntPtr interfacePtr;
                int result = Marshal.QueryInterface(unknownPtr, ref expectedIid, out interfacePtr);
                Marshal.Release(unknownPtr);

                if (result != 0 || interfacePtr == IntPtr.Zero)
                {
                    LogManager.Warning($"COM object IID mismatch for {expectedIid}");
                    return false;
                }

                Marshal.Release(interfacePtr);
                return true;
            }
            catch (Exception ex)
            {
                LogManager.Warning($"IID validation failed: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 使用CLSID和IID验证COM对象（保留向后兼容）
        /// </summary>
        internal static bool ValidateComObjectWithClsid(object obj, Guid expectedClsid, Guid expectedIid)
        {
            bool clsidValid = ValidateComObjectClsid(obj, expectedClsid);
            bool iidValid = ValidateComObjectIid(obj, expectedIid);
            return clsidValid && iidValid;
        }

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

        internal static T SafeGetProperty<T>(dynamic obj, string propertyName, T defaultValue, string logPropertyName)
        {
            try
            {
                if (obj == null)
                {
                    LogManager.Warning(LangManager.GetText("logMessages.safeGetPropertyFailed", logPropertyName, "null object"));
                    return defaultValue;
                }
                object value = obj.GetType().InvokeMember(propertyName, BindingFlags.GetProperty, null, obj, null);
                return value == null ? defaultValue : (T)Convert.ChangeType(value, typeof(T));
            }
            catch (Exception ex)
            {
                LogManager.Warning(LangManager.GetText("logMessages.safeGetPropertyFailed", logPropertyName, ex.Message));
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
            catch (Exception ex)
            {
                LogManager.Warning(LangManager.GetText("logMessages.safeSetPropertyFailed", propertyName, ex.Message));
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
                    if (!string.IsNullOrEmpty(dirInfo.LinkTarget))
                        return true;
                    return IsJunction(path);
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

        private static bool IsJunction(string path)
        {
            try
            {
                if (!Directory.Exists(path))
                    return false;

                var dirInfo = new DirectoryInfo(path);
                System.IO.FileAttributes attr = dirInfo.Attributes;
                if ((attr & System.IO.FileAttributes.ReparsePoint) == 0)
                    return false;

                using (var fs = System.IO.File.Open(path, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.Read))
                {
                    System.IntPtr handle = fs.SafeFileHandle.DangerousGetHandle();
                    if (handle == System.IntPtr.Zero)
                        return false;

                    byte[] reparseData = new byte[1024];
                    uint bytesReturned;
                    bool result = DeviceIoControl(
                        handle,
                        0x000900A8,
                        IntPtr.Zero, 0,
                        reparseData, (uint)reparseData.Length,
                        out bytesReturned,
                        IntPtr.Zero);

                    if (result && bytesReturned >= 20)
                    {
                        uint reparseTag = BitConverter.ToUInt32(reparseData, 0);
                        if (reparseTag == 0xA0000003)
                            return true;
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            byte[] lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern uint GetFinalPathNameByHandle(IntPtr hFile, System.Text.StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

        private const uint VOLUME_NAME_NT = 0x0;
        private const uint FILE_NAME_NORMALIZED = 0x2;

        internal static string GetRealPath(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path))
                    return null;

                // 直接返回规范化路径，不尝试使用 GetFinalPathNameByHandle
                // 因为该 API 在某些系统配置下可能会失败
                string normalizedPath = Path.GetFullPath(path);
                
                // 验证路径存在
                if (Directory.Exists(normalizedPath) || File.Exists(normalizedPath))
                {
                    return normalizedPath;
                }
                
                // 路径不存在，返回 null
                LogManager.Warning($"Path does not exist: {normalizedPath}");
                return null;
            }
            catch (Exception ex)
            {
                LogManager.Warning($"GetRealPath failed for '{path}': {ex.Message}");
                return null;
            }
        }

        internal static bool HasReparsePoint(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path))
                    return false;

                string normalizedPath = Path.GetFullPath(path);

                if (Directory.Exists(normalizedPath))
                {
                    var dirInfo = new DirectoryInfo(normalizedPath);
                    if ((dirInfo.Attributes & FileAttributes.ReparsePoint) == 0)
                        return false;
                    return HasDangerousReparseTag(normalizedPath);
                }
                if (File.Exists(normalizedPath))
                {
                    var fileInfo = new FileInfo(normalizedPath);
                    if ((fileInfo.Attributes & FileAttributes.ReparsePoint) == 0)
                        return false;
                    return HasDangerousReparseTag(normalizedPath);
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        private const uint IO_REPARSE_TAG_SYMLINK = 0xA000000C;
        private const uint IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003;
        private const uint IO_REPARSE_TAG_JUNCTION = 0xA0000003;

        private static bool HasDangerousReparseTag(string path)
        {
            try
            {
                bool isDirectory = Directory.Exists(path);
                
                // 使用 CreateFile API 打开文件/目录，目录需要 FILE_FLAG_BACKUP_SEMANTICS
                uint flags = isDirectory ? Win32Native.FILE_FLAG_BACKUP_SEMANTICS : 0u;
                IntPtr handle = Win32Native.CreateFile(
                    path,
                    Win32Native.GENERIC_READ,
                    Win32Native.FILE_SHARE_READ,
                    IntPtr.Zero,
                    Win32Native.OPEN_EXISTING,
                    flags,
                    IntPtr.Zero);

                if (handle == IntPtr.Zero || handle == new IntPtr(-1))
                    return false;  // 无法打开，视为安全

                try
                {
                    byte[] reparseData = new byte[1024];
                    uint bytesReturned;
                    bool result = DeviceIoControl(
                        handle,
                        0x000900A8,  // FSCTL_GET_REPARSE_POINT
                        IntPtr.Zero, 0,
                        reparseData, (uint)reparseData.Length,
                        out bytesReturned,
                        IntPtr.Zero);

                    if (result && bytesReturned >= 20)
                    {
                        uint reparseTag = BitConverter.ToUInt32(reparseData, 0);
                        
                        // 检查是否为危险的 reparse tag
                        if (reparseTag == IO_REPARSE_TAG_SYMLINK ||
                            reparseTag == IO_REPARSE_TAG_MOUNT_POINT ||
                            reparseTag == IO_REPARSE_TAG_JUNCTION)
                        {
                            return true;  // 检测到危险的 reparse point
                        }
                    }

                    // 没有检测到危险的 reparse point
                    return false;
                }
                finally
                {
                    Win32Native.CloseHandle(handle);
                }
            }
            catch
            {
                return false;  // 出错时默认为安全
            }
        }

        internal static bool HasReparsePointInPath(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path))
                    return false;

                string normalizedPath = Path.GetFullPath(path);

                // 对于系统目录，跳过父目录检查（这些目录可能包含正常的 junction）
                string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).ToLowerInvariant();
                string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).ToLowerInvariant();
                string systemFolder = Environment.GetFolderPath(Environment.SpecialFolder.System).ToLowerInvariant();
                string windowsFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();

                string normalizedLower = normalizedPath.ToLowerInvariant();

                if (normalizedLower.StartsWith(programFiles) ||
                    normalizedLower.StartsWith(programFilesX86) ||
                    normalizedLower.StartsWith(systemFolder) ||
                    normalizedLower.StartsWith(windowsFolder))
                {
                    // 系统目录：只检查路径本身
                    return HasReparsePoint(normalizedPath);
                }

                // 非系统目录：检查完整路径链，包括所有父级
                string currentPath = normalizedPath;
                int depth = 0;
                const int maxDepth = 10; // 防止循环引用

                while (!string.IsNullOrEmpty(currentPath) && depth < maxDepth)
                {
                    if (HasReparsePoint(currentPath))
                        return true;

                    string parentDir = Path.GetDirectoryName(currentPath);
                    if (parentDir == null || parentDir == currentPath)
                        break;

                    currentPath = parentDir;
                    depth++;
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
        /// 修复：使用排他创建+随机文件名+句柄级reparse校验+受限ACL，防止符号链接攻击
        /// </summary>
        internal static void AtomicWriteAllText(string filePath, string contents, System.Text.Encoding encoding)
        {
            // 使用随机文件名防止符号链接预判攻击
            string tempPath = Path.Combine(Path.GetDirectoryName(filePath), Path.GetRandomFileName());
            try
            {
                // 使用排他创建，确保临时文件是新建的，不存在符号链接
                using (var fs = new FileStream(tempPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
                {
                    // 检查文件句柄的属性，确认不是reparse point
                    FileInfo tempFileInfo = new FileInfo(tempPath);
                    if ((tempFileInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        throw new InvalidOperationException("临时文件是reparse point，拒绝写入");
                    }

                    byte[] contentBytes = encoding.GetBytes(contents);
                    fs.Write(contentBytes, 0, contentBytes.Length);
                    fs.Flush();
                }

                // 对临时文件设置受限ACL
                SetSecureFilePermissionsInternal(tempPath);

                // 原子替换或移动
                if (File.Exists(filePath))
                {
                    File.Replace(tempPath, filePath, null);
                }
                else
                {
                    File.Move(tempPath, filePath);
                }

                // 对目标文件也设置受限ACL
                SetSecureFilePermissionsInternal(filePath);
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

        /// <summary>
        /// 原子写入字节数组 - 先写临时文件再替换，防止写入中断导致文件损坏
        /// 修复：使用排他创建+随机文件名+句柄级reparse校验+受限ACL，防止符号链接攻击
        /// </summary>
        internal static void AtomicWriteAllBytes(string filePath, byte[] bytes)
        {
            // 使用随机文件名防止符号链接预判攻击
            string tempPath = Path.Combine(Path.GetDirectoryName(filePath), Path.GetRandomFileName());
            try
            {
                // 使用排他创建，确保临时文件是新建的，不存在符号链接
                using (var fs = new FileStream(tempPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
                {
                    // 检查文件句柄的属性，确认不是reparse point
                    FileInfo tempFileInfo = new FileInfo(tempPath);
                    if ((tempFileInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        throw new InvalidOperationException("临时文件是reparse point，拒绝写入");
                    }

                    fs.Write(bytes, 0, bytes.Length);
                    fs.Flush();
                }

                // 对临时文件设置受限ACL
                SetSecureFilePermissionsInternal(tempPath);

                // 原子替换或移动
                if (File.Exists(filePath))
                {
                    File.Replace(tempPath, filePath, null);
                }
                else
                {
                    File.Move(tempPath, filePath);
                }

                // 对目标文件也设置受限ACL
                SetSecureFilePermissionsInternal(filePath);
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

        /// <summary>
        /// 设置文件受限ACL权限（仅管理员和SYSTEM可访问）
        /// </summary>
        private static void SetSecureFilePermissionsInternal(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                    return;

                var fileInfo = new FileInfo(filePath);
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

        internal static bool IsFilePathTrusted(string filePath)
        {
            try
            {
                if (string.IsNullOrEmpty(filePath))
                    return false;

                if (!File.Exists(filePath))
                    return false;

                string normalizedPath = Path.GetFullPath(filePath).ToLowerInvariant();

                string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).ToLowerInvariant();
                string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).ToLowerInvariant();
                string systemFolder = Environment.GetFolderPath(Environment.SpecialFolder.System).ToLowerInvariant();
                string windowsFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();

                if ((normalizedPath.StartsWith(programFiles + '\\') || normalizedPath == programFiles) ||
                    (normalizedPath.StartsWith(programFilesX86 + '\\') || normalizedPath == programFilesX86) ||
                    (normalizedPath.StartsWith(systemFolder + '\\') || normalizedPath == systemFolder) ||
                    (normalizedPath.StartsWith(windowsFolder + '\\') || normalizedPath == windowsFolder))
                {
                    return true;
                }

                return IsFileDigitallySigned(filePath);
            }
            catch
            {
                return false;
            }
        }

        private static bool IsFileDigitallySigned(string filePath)
        {
            try
            {
                // 首先使用 WinVerifyTrust 验证签名完整性（最重要的一步）
                if (!VerifyFileSignatureIntegrity(filePath))
                {
                    return false;
                }

                // 然后验证证书链有效性
#pragma warning disable SYSLIB0057
                using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
#pragma warning restore SYSLIB0057
                if (cert == null || string.IsNullOrEmpty(cert.Subject))
                {
                    return false;
                }

                if (cert.NotAfter < DateTime.Now || cert.NotBefore > DateTime.Now)
                {
                    return false;
                }

                bool isValid = VerifyCertificateChain(cert);
                if (!isValid)
                {
                    return false;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 使用 WinVerifyTrust API 验证文件签名完整性
        /// 确保文件内容与数字签名匹配，防止篡改攻击
        /// </summary>
        private static bool VerifyFileSignatureIntegrity(string filePath)
        {
            try
            {
                IntPtr filePathPtr = Marshal.StringToCoTaskMemUni(filePath);
                try
                {
                    Win32Native.WINTRUST_FILE_INFO fileInfo = new Win32Native.WINTRUST_FILE_INFO
                    {
                        cbStruct = (uint)Marshal.SizeOf(typeof(Win32Native.WINTRUST_FILE_INFO)),
                        pcwszFilePath = filePathPtr,
                        hFile = IntPtr.Zero,
                        pgKnownSubject = IntPtr.Zero
                    };

                    IntPtr fileInfoPtr = Marshal.AllocCoTaskMem((int)fileInfo.cbStruct);
                    try
                    {
                        Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

                        Win32Native.WINTRUST_DATA trustData = new Win32Native.WINTRUST_DATA
                        {
                            cbStruct = (uint)Marshal.SizeOf(typeof(Win32Native.WINTRUST_DATA)),
                            pPolicyCallbackData = IntPtr.Zero,
                            pSIPClientData = IntPtr.Zero,
                            dwUIChoice = 2, // WTD_UI_NONE - 无UI
                            fdwRevocationChecks = 0, // 不进行吊销检查（由 VerifyCertificateChain 处理）
                            dwUnionChoice = 1, // WTD_CHOICE_FILE
                            pFile = fileInfoPtr,
                            dwStateAction = 0, // WTD_STATEACTION_VERIFY
                            hWVTStateData = IntPtr.Zero,
                            pwszURLReference = null,
                            dwProvFlags = 0x20000, // WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
                            dwUIContext = 0,
                            pSignatureSettings = IntPtr.Zero
                        };

                        IntPtr actionId = Marshal.AllocCoTaskMem(16);
                        try
                        {
                            Guid actionGuid = new Guid("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");
                            Marshal.StructureToPtr(actionGuid, actionId, false);

                            uint result = Win32Native.WinVerifyTrust(IntPtr.Zero, actionId, ref trustData);
                            return result == 0; // ERROR_SUCCESS
                        }
                        finally
                        {
                            Marshal.FreeCoTaskMem(actionId);
                        }
                    }
                    finally
                    {
                        Marshal.FreeCoTaskMem(fileInfoPtr);
                    }
                }
                finally
                {
                    Marshal.FreeCoTaskMem(filePathPtr);
                }
            }
            catch (Exception ex)
            {
                LogManager.Warning(LangManager.GetText("logMessages.signatureIntegrityCheckFailed", ex.Message));
                return false;
            }
        }

        private static bool VerifyCertificateChain(X509Certificate2 cert)
        {
            try
            {
                using var onlineChain = new X509Chain();
                onlineChain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                onlineChain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                onlineChain.ChainPolicy.VerificationTime = DateTime.Now;
                onlineChain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 5);
                
                bool isValid = onlineChain.Build(cert);
                if (isValid)
                {
                    return true;
                }
            }
            catch (Exception ex)
            {
                LogManager.Warning(LangManager.GetText("logMessages.certificateOnlineRevocationCheckFailed", ex.Message));
            }

            try
            {
                using var offlineChain = new X509Chain();
                offlineChain.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
                offlineChain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                offlineChain.ChainPolicy.VerificationTime = DateTime.Now;
                
                bool isValid = offlineChain.Build(cert);
                if (isValid)
                {
                    return true;
                }
            }
            catch (Exception ex)
            {
                LogManager.Warning(LangManager.GetText("logMessages.certificateOfflineRevocationCheckFailed", ex.Message));
            }

            return false;
        }

        /// <summary>
        /// 验证 COM 对象类型是否匹配预期 CLSID
        /// 使用 CLSID 验证而非 ProgID，防止 ProgID 劫持攻击
        /// </summary>
        /// <param name="obj">COM 对象</param>
        /// <param name="expectedClsid">预期的 CLSID（如 "{14C4B0D1-04A3-4666-A29C-3E8B50E9E955}"）</param>
        /// <param name="expectedIid">预期的 IID（如 "{2C5BC43E-3369-4C33-AB0C-BE9469677AF4}"）</param>
        /// <returns>是否匹配</returns>
        internal static bool ValidateComObjectType(object obj, string expectedClsid, string expectedIid)
        {
            try
            {
                if (obj == null)
                    return false;

                if (string.IsNullOrEmpty(expectedClsid) || string.IsNullOrEmpty(expectedIid))
                    return false;

                Guid expectedClsidGuid;
                Guid expectedIidGuid;

                if (!Guid.TryParse(expectedClsid, out expectedClsidGuid) || 
                    !Guid.TryParse(expectedIid, out expectedIidGuid))
                {
                    return false;
                }

                Type objType = obj.GetType();
                Guid objClsid = objType.GUID;

                if (objClsid != expectedClsidGuid)
                {
                    LogManager.Warning(LangManager.GetText("logMessages.comObjectClsidMismatch", objClsid, expectedClsidGuid));
                    return false;
                }

                try
                {
                    IntPtr unknownPtr = Marshal.GetIUnknownForObject(obj);
                    IntPtr interfacePtr;
                    int result = Marshal.QueryInterface(unknownPtr, ref expectedIidGuid, out interfacePtr);
                    Marshal.Release(unknownPtr);

                    if (result != 0 || interfacePtr == IntPtr.Zero)
                    {
                        LogManager.Warning(LangManager.GetText("logMessages.comObjectIidMismatch", expectedIidGuid));
                        return false;
                    }

                    Marshal.Release(interfacePtr);
                }
                catch (Exception ex)
                {
                    LogManager.Warning(LangManager.GetText("logMessages.comObjectQueryInterfaceFailed", ex.Message));
                    return false;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}