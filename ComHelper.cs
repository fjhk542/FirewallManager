using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace FirewallManager
{
    internal static class Win32Native
    {
        public const uint GENERIC_READ = 0x80000000;
        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint FILE_SHARE_WRITE = 0x00000002;
        public const uint FILE_SHARE_DELETE = 0x00000004;
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

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetFinalPathNameByHandle(
            IntPtr hFile,
            System.Text.StringBuilder lpszFilePath,
            uint cchFilePath,
            uint dwFlags);

    }
}

namespace FirewallManager
{
    internal static class ComHelper
    {
        /// <summary>
        /// Safe JSON deserialization options - limits max depth to prevent nesting attacks
        /// </summary>
        internal static readonly JsonSerializerOptions SafeJsonOptions = new JsonSerializerOptions
        {
            MaxDepth = 10
        };

        /// <summary>
        /// Create a COM object from a fixed CLSID.
        /// Before activation the server registration is verified (no per-user override and the server
        /// binary lives inside the Windows directory) — see <see cref="ValidateComServerRegistration"/>.
        /// Guessing a ProgID is not the threat here: HKCU\Software\Classes\CLSID takes precedence over
        /// HKLM and can redirect the CLSID to an arbitrary DLL, which would then be loaded into this
        /// elevated process. That is what the pre-activation check blocks.
        /// </summary>
        /// <param name="clsid">CLSID string</param>
        /// <param name="iid">Interface IID string</param>
        /// <param name="progId">ProgID (used for logging)</param>
        /// <returns>COM object, returns null on failure</returns>
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

                // Authoritative trust check: this must run BEFORE activation, because once
                // Activator.CreateInstance returns, the server has already been loaded into the
                // (elevated) process and post-activation property checks can no longer help.
                if (!ValidateComServerRegistration(clsidGuid, progId))
                {
                    LogManager.Error(LangManager.GetText("logMessages.comObjectValidationFailed", progId));
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

                // Validate the COM object
                bool clsidValid = ValidateComObjectClsid(comObject, clsidGuid);
                bool iidValid = ValidateComObjectIid(comObject, iidGuid);

                if (!clsidValid && !iidValid)
                {
                    LogManager.Error(LangManager.GetText("logMessages.comObjectValidationFailed", progId));
                    Marshal.ReleaseComObject(comObject);
                    return null;
                }

                // Post-activation checks are diagnostic only. A mismatching IID is tolerated because
                // the server binary itself was already verified before activation.
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
        /// Validates where the CLSID will actually be served from, before any code is loaded.
        /// Two checks are applied:
        ///   1. A per-user registration (HKCU\Software\Classes\CLSID\{...}) is rejected outright.
        ///      HKCU takes precedence over HKLM during COM activation, so a non-elevated process
        ///      running as the same user could otherwise redirect the CLSID to its own DLL and have
        ///      it loaded inside this elevated process.
        ///   2. The resolved InprocServer32 / LocalServer32 binary must live under the Windows
        ///      directory (System32 / SysWOW64 / WinSxS), so a machine-wide registration pointing at
        ///      an arbitrary path is refused as well.
        /// This is the authoritative identity check; the CLSID/IID checks performed after activation
        /// are diagnostic only and cannot detect a substituted server.
        /// </summary>
        /// <param name="clsid">CLSID to validate</param>
        /// <param name="progId">ProgID used for logging</param>
        /// <returns>true only when the registration is machine-wide and the server binary is a Windows component</returns>
        private static bool ValidateComServerRegistration(Guid clsid, string progId)
        {
            try
            {
                string clsidKeyPath = @"Software\Classes\CLSID\" + clsid.ToString("B");

                // 1. Reject any per-user registration of this CLSID. Both registry views are checked
                //    because a 32-bit and a 64-bit registration are stored in different places and
                //    either one can win during activation.
                foreach (var view in new[] { Microsoft.Win32.RegistryView.Registry64, Microsoft.Win32.RegistryView.Registry32 })
                {
                    using (var hkcu = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.CurrentUser, view))
                    using (var perUserKey = hkcu.OpenSubKey(clsidKeyPath))
                    {
                        if (perUserKey != null)
                        {
                            LogManager.Error($"Per-user COM registration detected for {progId} ({clsid:B}); refusing to activate");
                            return false;
                        }
                    }
                }

                // 2. Resolve the server binary from the machine-wide registration.
                string serverPath = null;
                foreach (var view in new[] { Microsoft.Win32.RegistryView.Registry64, Microsoft.Win32.RegistryView.Registry32 })
                {
                    using (var hklm = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, view))
                    using (var machineKey = hklm.OpenSubKey(clsidKeyPath))
                    {
                        if (machineKey == null)
                            continue;

                        serverPath = ReadServerBinaryPath(machineKey);

                        // Some in-process servers register the default value directly on the CLSID key.
                        if (string.IsNullOrEmpty(serverPath))
                        {
                            serverPath = machineKey.GetValue(null) as string;
                        }

                        if (!string.IsNullOrEmpty(serverPath))
                            break;
                    }
                }

                if (string.IsNullOrEmpty(serverPath))
                {
                    LogManager.Error($"No machine-wide server binary registered for {progId} ({clsid:B})");
                    return false;
                }

                serverPath = Environment.ExpandEnvironmentVariables(serverPath.Trim().Trim('"'));
                if (!Path.IsPathRooted(serverPath))
                {
                    LogManager.Error($"COM server path for {progId} is not rooted: {serverPath}");
                    return false;
                }

                string normalizedServerPath = Path.GetFullPath(serverPath);
                if (!IsUnderWindowsDirectory(normalizedServerPath))
                {
                    LogManager.Error($"COM server for {progId} resolves outside the Windows directory: {normalizedServerPath}");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                // Fail-closed: an unverifiable registration is treated as untrusted.
                LogManager.Error($"COM server registration validation failed for {progId}: {ex.Message}");
                return false;
            }
        }

        private static string ReadServerBinaryPath(Microsoft.Win32.RegistryKey clsidKey)
        {
            foreach (string subKeyName in new[] { "InprocServer32", "LocalServer32" })
            {
                using (var serverKey = clsidKey.OpenSubKey(subKeyName))
                {
                    if (serverKey == null)
                        continue;

                    string value = serverKey.GetValue(null) as string;
                    if (!string.IsNullOrEmpty(value))
                        return value;
                }
            }

            return null;
        }

        private static bool IsUnderWindowsDirectory(string normalizedPath)
        {
            string windowsFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (string.IsNullOrEmpty(windowsFolder))
                return false;

            string normalizedWindows = Path.GetFullPath(windowsFolder).TrimEnd('\\');
            return normalizedPath.StartsWith(normalizedWindows + '\\', StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Validate the CLSID of a COM object
        /// </summary>
        internal static bool ValidateComObjectClsid(object obj, Guid expectedClsid)
        {
            if (obj == null)
                return false;

            try
            {
                Type objType = obj.GetType();
                Guid objClsid = objType.GUID;

                // Diagnostic only. Activator.CreateInstance(Type.GetTypeFromCLSID(...)) returns a
                // transparent proxy (System.__ComObject) whose Type.GUID is Guid.Empty, so this
                // method can never distinguish the real server from a substituted one.
                // Server identity is established by ValidateComServerRegistration before activation.
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
        /// Validate the IID of a COM object (via QueryInterface)
        /// </summary>
        internal static bool ValidateComObjectIid(object obj, Guid expectedIid)
        {
            if (obj == null)
                return false;

            try
            {
                IntPtr unknownPtr = Marshal.GetIUnknownForObject(obj);
                IntPtr interfacePtr;
                int result = Marshal.QueryInterface(unknownPtr, in expectedIid, out interfacePtr);
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

        internal static T SafeGetProperty<T>(dynamic obj, string propertyName, T defaultValue = default, string logPropertyName = null)
        {
            try
            {
                if (obj == null)
                {
                    if (logPropertyName != null)
                        LogManager.Warning(LangManager.GetText("logMessages.safeGetPropertyFailed", logPropertyName, "null object"));
                    return defaultValue;
                }
                object value = obj.GetType().InvokeMember(propertyName, BindingFlags.GetProperty, null, obj, null);
                return value == null ? defaultValue : (T)Convert.ChangeType(value, typeof(T));
            }
            catch (Exception ex)
            {
                if (logPropertyName != null)
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

        /// <summary>
        /// Safely release a COM object. Exceptions are only logged, never thrown.
        /// Unified implementation, reused by modules such as FirewallService.
        /// </summary>
        internal static void ReleaseComObject(object obj)
        {
            if (obj == null)
                return;

            try
            {
                Marshal.ReleaseComObject(obj);
            }
            catch (Exception ex)
            {
                LogManager.Warning(LangManager.GetText("logMessages.releaseComObjectFailed", ex.Message));
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

        /// <summary>
        /// Returns the real (fully dereferenced) path of an existing file or directory.
        /// Uses GetFinalPathNameByHandle so that symbolic links, junctions and mount points are
        /// resolved to their target before any security decision is made. Returns null (fail-closed)
        /// when the path does not exist or the handle cannot be opened.
        /// </summary>
        /// <param name="path">Input path</param>
        /// <returns>Resolved path, or null when it cannot be verified</returns>
        internal static string GetRealPath(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path))
                    return null;

                string normalizedPath = Path.GetFullPath(path);

                if (!Directory.Exists(normalizedPath) && !File.Exists(normalizedPath))
                {
                    LogManager.Warning($"Path does not exist: {normalizedPath}");
                    return null;
                }

                string resolvedPath = ResolveFinalPathByHandle(normalizedPath);
                if (resolvedPath == null)
                {
                    LogManager.Warning($"Unable to resolve final path for '{normalizedPath}'");
                    return null;
                }

                return resolvedPath;
            }
            catch (Exception ex)
            {
                LogManager.Warning($"GetRealPath failed for '{path}': {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Resolves the final path of an existing item by opening a handle and querying
        /// GetFinalPathNameByHandle. Returns null on any failure (fail-closed).
        /// </summary>
        private static string ResolveFinalPathByHandle(string normalizedPath)
        {
            bool isDirectory = Directory.Exists(normalizedPath);
            uint flags = isDirectory ? Win32Native.FILE_FLAG_BACKUP_SEMANTICS : 0u;

            IntPtr handle = Win32Native.CreateFile(
                normalizedPath,
                Win32Native.GENERIC_READ,
                Win32Native.FILE_SHARE_READ | Win32Native.FILE_SHARE_WRITE | Win32Native.FILE_SHARE_DELETE,
                IntPtr.Zero,
                Win32Native.OPEN_EXISTING,
                flags,
                IntPtr.Zero);

            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
                return null;

            try
            {
                var buffer = new System.Text.StringBuilder(1024);
                uint length = Win32Native.GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
                if (length == 0)
                    return null;

                if (length >= buffer.Capacity)
                {
                    buffer = new System.Text.StringBuilder((int)length + 1);
                    length = Win32Native.GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
                    if (length == 0)
                        return null;
                }

                string result = buffer.ToString();

                // Strip the \\?\ prefix (and convert \\?\UNC\ back to a UNC path).
                if (result.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                {
                    result = @"\\" + result.Substring(8);
                }
                else if (result.StartsWith(@"\\?\Volume{", StringComparison.OrdinalIgnoreCase))
                {
                    // A volume mounted without a drive letter. Stripping the prefix would turn
                    // "\\?\Volume{GUID}\x.exe" into an invalid relative-looking path, so keep it.
                }
                else if (result.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
                {
                    result = result.Substring(4);
                }

                return result;
            }
            finally
            {
                Win32Native.CloseHandle(handle);
            }
        }

        /// <summary>
        /// Determines whether an existing file or directory is a reparse point.
        /// Any reparse point is treated as unsafe: symlinks, junctions and mount points redirect the
        /// path outside the monitored location, and other tags (cloud placeholders, AppExecLink, …)
        /// are not worth allow-listing in a security decision.
        /// Fails closed: if the attributes cannot be read, the item is reported as a reparse point.
        /// </summary>
        /// <param name="path">Path to inspect</param>
        /// <returns>true when the item is (or may be) a reparse point</returns>
        internal static bool HasReparsePoint(string path)
        {
            if (string.IsNullOrEmpty(path))
                return false;

            try
            {
                string normalizedPath = Path.GetFullPath(path);

                FileAttributes attributes;
                if (Directory.Exists(normalizedPath))
                {
                    attributes = new DirectoryInfo(normalizedPath).Attributes;
                }
                else if (File.Exists(normalizedPath))
                {
                    attributes = new FileInfo(normalizedPath).Attributes;
                }
                else
                {
                    // Nothing to inspect; the caller checks existence separately.
                    return false;
                }

                return (attributes & FileAttributes.ReparsePoint) != 0;
            }
            catch
            {
                // Fail-closed: an uninspectable path must not be treated as safe.
                return true;
            }
        }

        /// <summary>
        /// Rejects network (UNC) and device paths before any filesystem call is made.
        /// Directory.Exists / File.Exists / new FileInfo / File.Open all initiate an SMB connection
        /// when given a UNC path, which leaks the current user's NetNTLM credentials to an arbitrary
        /// host. The check therefore has to run at every entry point, before the path is probed —
        /// not only inside the path normalizer, where probing has already happened.
        /// Extended local drive syntax (\\?\C:\...) stays local and is allowed.
        /// </summary>
        /// <param name="path">User-supplied or imported path</param>
        /// <returns>true when the path cannot reach a remote host</returns>
        internal static bool IsLocalPathCandidate(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return false;

            string candidate = path.Trim();

            // Mixed separators are normalized by Windows: "\/server\share", "/\server\share" and
            // "\//server\share" all resolve to a UNC path, so each of the first two characters is
            // tested independently instead of comparing whole prefixes.
            bool startsWithSeparatorPair =
                (candidate[0] == '\\' || candidate[0] == '/') &&
                candidate.Length > 1 &&
                (candidate[1] == '\\' || candidate[1] == '/');

            if (!startsWithSeparatorPair)
            {
                return true;
            }

            return candidate.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase)
                   && candidate.Length > 5
                   && char.IsLetter(candidate[4])
                   && candidate[5] == ':';
        }

        internal static bool HasReparsePointInPath(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path))
                    return false;

                string normalizedPath = Path.GetFullPath(path);

                // For system directories, skip parent-directory checks (they may contain normal junctions)
                string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).ToLowerInvariant();
                string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).ToLowerInvariant();
                string systemFolder = Environment.GetFolderPath(Environment.SpecialFolder.System).ToLowerInvariant();
                string windowsFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();

                string normalizedLower = normalizedPath.ToLowerInvariant();

                // Compare with a trailing separator so that a sibling directory whose name merely
                // starts with the same characters (e.g. "C:\Program FilesEvil") is not whitelisted.
                if (IsUnderFolder(normalizedLower, programFiles) ||
                    IsUnderFolder(normalizedLower, programFilesX86) ||
                    IsUnderFolder(normalizedLower, systemFolder) ||
                    IsUnderFolder(normalizedLower, windowsFolder))
                {
                    // System directories: only check the path itself
                    return HasReparsePoint(normalizedPath);
                }

                // Non-system directories: check the full path chain, including all parents
                string currentPath = normalizedPath;
                int depth = 0;
                const int maxDepth = 10; // Prevent circular references

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
                // Fail-closed: if the chain cannot be inspected, treat the path as unsafe.
                return true;
            }
        }

        private static bool IsUnderFolder(string candidatePath, string folder)
        {
            if (string.IsNullOrEmpty(folder))
                return false;

            string normalizedFolder = folder.TrimEnd('\\');
            return candidatePath.Equals(normalizedFolder, StringComparison.OrdinalIgnoreCase)
                || candidatePath.StartsWith(normalizedFolder + '\\', StringComparison.OrdinalIgnoreCase);
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
        /// Core logic for atomic write — write to a temp file first, then replace,
        /// preventing file corruption caused by interrupted writes.
        /// Hardening: exclusive creation + random file name + handle-level reparse validation + restricted ACL,
        /// to defend against symlink attacks.
        /// AtomicWriteAllText and AtomicWriteAllBytes share this implementation, eliminating duplicated code.
        /// </summary>
        /// <param name="filePath">Target file path</param>
        /// <param name="writeBytes">Callback that writes a byte array to the temp file</param>
        private static void AtomicWriteCore(string filePath, Action<FileStream> writeBytes)
        {
            // Use a random file name to prevent symlink pre-judgement attacks
            string tempPath = Path.Combine(Path.GetDirectoryName(filePath), Path.GetRandomFileName());
            try
            {
                // Use exclusive creation to ensure the temp file is newly created, no symlink present
                using (var fs = new FileStream(tempPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
                {
                    // Check the file handle attributes, confirm it is not a reparse point
                    FileInfo tempFileInfo = new FileInfo(tempPath);
                    if ((tempFileInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        throw new InvalidOperationException("Temporary file is a reparse point, rejecting write");
                    }

                    writeBytes(fs);
                    fs.Flush();
                }

                // Apply a restricted ACL to the temp file
                SetSecureFilePermissionsInternal(tempPath);

                // Atomic replace or move
                if (File.Exists(filePath))
                {
                    File.Replace(tempPath, filePath, null);
                }
                else
                {
                    File.Move(tempPath, filePath);
                }

                // Also apply a restricted ACL to the target file
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
        /// Atomically write a text file — write to a temp file first, then replace,
        /// preventing file corruption caused by interrupted writes.
        /// Hardening: exclusive creation + random file name + handle-level reparse validation + restricted ACL,
        /// to defend against symlink attacks.
        /// </summary>
        internal static void AtomicWriteAllText(string filePath, string contents, System.Text.Encoding encoding)
        {
            byte[] contentBytes = encoding.GetBytes(contents);
            AtomicWriteCore(filePath, fs => fs.Write(contentBytes, 0, contentBytes.Length));
        }

        /// <summary>
        /// Atomically write a byte array — write to a temp file first, then replace,
        /// preventing file corruption caused by interrupted writes.
        /// Hardening: exclusive creation + random file name + handle-level reparse validation + restricted ACL,
        /// to defend against symlink attacks.
        /// </summary>
        internal static void AtomicWriteAllBytes(string filePath, byte[] bytes)
        {
            AtomicWriteCore(filePath, fs => fs.Write(bytes, 0, bytes.Length));
        }

        /// <summary>
        /// Removes every explicit (non-inherited) access rule from the security descriptor.
        /// Used before hardening a file or directory so that ACEs planted by an attacker before the
        /// protection was applied cannot survive alongside our own rules.
        /// </summary>
        private static void RemoveExplicitAccessRules(System.Security.AccessControl.FileSystemSecurity security)
        {
            foreach (System.Security.AccessControl.FileSystemAccessRule rule in
                     security.GetAccessRules(true, false, typeof(System.Security.Principal.SecurityIdentifier)))
            {
                security.RemoveAccessRule(rule);
            }
        }

        /// <summary>
        /// Apply a restricted ACL to a file (only Administrators and SYSTEM can access it).
        /// Unified implementation, reused by modules such as Config/LogManager, eliminating
        /// three duplicate code sites.
        /// </summary>
        internal static void SetSecureFilePermissionsInternal(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                    return;

                var fileInfo = new FileInfo(filePath);
                System.Security.AccessControl.FileSecurity fileSecurity = fileInfo.GetAccessControl();
                fileSecurity.SetAccessRuleProtection(true, false);

                // SetAccessRuleProtection(false) only drops inherited entries. Explicit entries that
                // an attacker planted before the file was created would survive, so clear them all.
                RemoveExplicitAccessRules(fileSecurity);

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

                // The owner of an object implicitly holds READ_CONTROL and WRITE_DAC regardless of the
                // DACL, so a file owned by the current user could be re-opened by any non-elevated
                // process of that user even after the ACL above. Reassign the owner to Administrators.
                try
                {
                    System.Security.AccessControl.FileSecurity ownerSecurity = fileInfo.GetAccessControl();
                    ownerSecurity.SetOwner(adminSid);
                    fileInfo.SetAccessControl(ownerSecurity);
                }
                catch (Exception ex)
                {
                    LogManager.Warning($"Failed to set owner of '{filePath}': {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                // ACL-setting failure should not break main functionality; just log it
                LogManager.Warning(LangManager.GetText("logMessages.setFilePermissionsFailed", ex.Message));
            }
        }

        /// <summary>
        /// Apply a restricted ACL to a directory (Administrators/SYSTEM full control, current user
        /// read-only). Protecting the containing directory is what makes the per-file ACLs effective:
        /// on Windows, a user holding FILE_DELETE_CHILD on the parent directory can delete a child file
        /// regardless of that file's own ACL, so hardening files alone does not prevent replacement.
        /// </summary>
        /// <param name="directoryPath">Directory to harden</param>
        internal static bool SetSecureDirectoryPermissionsInternal(string directoryPath)
        {
            try
            {
                if (string.IsNullOrEmpty(directoryPath) || !Directory.Exists(directoryPath))
                    return false;

                var dirInfo = new DirectoryInfo(directoryPath);
                System.Security.AccessControl.DirectorySecurity dirSecurity = dirInfo.GetAccessControl();
                dirSecurity.SetAccessRuleProtection(true, false);

                // Explicit ACEs planted before we hardened the directory would survive
                // SetAccessRuleProtection(false), so clear them before granting our own.
                RemoveExplicitAccessRules(dirSecurity);

                System.Security.Principal.SecurityIdentifier adminSid = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
                dirSecurity.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    adminSid,
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.AccessControlType.Allow));

                System.Security.Principal.SecurityIdentifier systemSid = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
                dirSecurity.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    systemSid,
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.AccessControlType.Allow));

                // Keep the current user able to read (log viewer, language files) but not to
                // write, delete or replace the protected files.
                System.Security.Principal.SecurityIdentifier currentUserSid = System.Security.Principal.WindowsIdentity.GetCurrent().User;
                if (currentUserSid != null)
                {
                    dirSecurity.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                        currentUserSid,
                        System.Security.AccessControl.FileSystemRights.ReadAndExecute,
                        System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                        System.Security.AccessControl.PropagationFlags.None,
                        System.Security.AccessControl.AccessControlType.Allow));
                }

                dirInfo.SetAccessControl(dirSecurity);

                // The owner of a directory implicitly holds READ_CONTROL and WRITE_DAC regardless of
                // the DACL. Because this directory lives under the user profile it is normally owned
                // by the current user, which would let a non-elevated process re-grant itself write
                // access. Reassign the owner to Administrators.
                try
                {
                    System.Security.AccessControl.DirectorySecurity ownerSecurity = dirInfo.GetAccessControl();
                    ownerSecurity.SetOwner(adminSid);
                    dirInfo.SetAccessControl(ownerSecurity);
                }
                catch (Exception ex)
                {
                    // The owner implicitly holds WRITE_DAC, so a directory that stays owned by the
                    // current user can be re-opened for writing by a non-elevated process, which
                    // would defeat every integrity gate that depends on this directory.
                    LogManager.Error($"Failed to reassign owner of '{directoryPath}' to Administrators: {ex.Message}. Treating the directory as unprotected.");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                // A non-elevated start cannot change the directory ACL; log and report the failure so
                // that the caller can refuse trust-sensitive operations instead of degrading silently.
                LogManager.Warning($"Failed to apply directory ACL to '{directoryPath}': {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Returns true when the executable belongs to Windows itself, in which case blocking its
        /// outbound traffic would destabilize the operating system. Used to decide whether a newly
        /// detected executable should be skipped.
        /// </summary>
        /// <param name="filePath">Executable path</param>
        /// <returns>true when the file is a critical system executable</returns>
        internal static bool IsCriticalSystemExecutable(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                return false;

            try
            {
                string normalizedPath = Path.GetFullPath(filePath);

                string windowsFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                if (string.IsNullOrEmpty(windowsFolder))
                    return false;

                bool insideWindows = IsUnderFolder(normalizedPath, windowsFolder);

                // A name-only match is not a system executable. Any unprivileged user can drop a
                // binary called "svchost.exe" into a writable folder, so honouring the name list
                // outside the Windows directory would be a free pass out of the blocker.
                string fileName = Path.GetFileName(normalizedPath);
                if (!insideWindows && !string.IsNullOrEmpty(fileName) && Config.CRITICAL_PROGRAMS.Contains(fileName))
                {
                    LogManager.Warning($"Executable named like a system process outside the Windows directory: {normalizedPath}");
                }

                return insideWindows;
            }
            catch
            {
                // Fail-safe: an unverifiable path is skipped rather than blocked.
                return true;
            }
        }

        /// <summary>
        /// Validate that a COM object type matches the expected CLSID.
        /// Uses CLSID validation rather than ProgID to prevent ProgID hijacking attacks.
        /// </summary>
        /// <param name="obj">COM object</param>
        /// <param name="expectedClsid">Expected CLSID (e.g. "{14C4B0D1-04A3-4666-A29C-3E8B50E9E955}")</param>
        /// <param name="expectedIid">Expected IID (e.g. "{2C5BC43E-3369-4C33-AB0C-BE9469677AF4}")</param>
        /// <returns>Whether it matches</returns>
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

                // Late-bound COM objects returned by Rules.Item(name) are transparent proxies
                // (System.__ComObject) whose Type.GUID is Guid.Empty. Treat that as "unknown" and
                // rely on the QueryInterface check below instead of rejecting every rule.
                if (objClsid != Guid.Empty && objClsid != expectedClsidGuid)
                {
                    LogManager.Warning(LangManager.GetText("logMessages.comObjectClsidMismatch", objClsid, expectedClsidGuid));
                    return false;
                }

                try
                {
                    IntPtr unknownPtr = Marshal.GetIUnknownForObject(obj);
                    IntPtr interfacePtr;
                    int result = Marshal.QueryInterface(unknownPtr, in expectedIidGuid, out interfacePtr);
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