using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FirewallManager
{
    /// <summary>
    /// Whitelist Management Window
    /// Used to manage firewall whitelist
    /// </summary>
    public partial class WhitelistForm : Form
    {
        #region UI Controls
        // UI control definitions
        private System.Windows.Forms.Button btnAdd;
        private System.Windows.Forms.Button btnRemove;
        private System.Windows.Forms.Button btnClear;
        private System.Windows.Forms.Button btnSave;
        private System.Windows.Forms.Button btnClose;
        private System.Windows.Forms.ListBox whitelistListBox;
        #endregion

        /// <summary>
        /// Whitelist list
        /// List of whitelist items displayed in the current window
        /// </summary>
        private List<string> whitelist = new List<string>();

        /// <summary>
        /// Set when the on-disk whitelist could not be trusted. Saving is refused in that state,
        /// because the empty list box would otherwise overwrite the user's existing entries.
        /// </summary>
        private bool whitelistLoadFailed;

        /// <summary>
        /// Whitelist cache
        /// Uses HashSet for O(1) lookup
        /// Keys are normalized paths (all lowercase)
        /// Uses volatile to implement copy-on-write pattern, reducing lock contention
        /// </summary>
        private static volatile HashSet<string> whitelistCache = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        /// <summary>
        /// Whitelist cache loaded flag
        /// </summary>
        private static volatile bool whitelistCacheLoaded = false;

        /// <summary>
        /// Lock object for thread safety
        /// Lock object for ensuring thread safety
        /// </summary>
        private static readonly object whitelistLock = new object();
        
        /// <summary>
        /// Lock object for static resource access
        /// Lock object for static resource access
        /// </summary>
        private static readonly object staticResourceLock = new object();

        /// <summary>
        /// Whitelist file watcher
        /// Whitelist file watcher
        /// </summary>
        private static System.IO.FileSystemWatcher whitelistWatcher;

        /// <summary>
        /// Debounce cancellation token source
        /// Debounce cancellation token source
        /// </summary>
        private static CancellationTokenSource debounceCts;

        /// <summary>
        /// Static constructor
        /// Static constructor
        /// Initialize file system watcher
        /// Initialize file system watcher
        /// </summary>
        static WhitelistForm()
        {
            try
            {
                // Initialize whitelist file watcher
                string configPath = Config.GetAppDataFilePath(Config.WHITELIST_FILE);
                string configDir = Path.GetDirectoryName(configPath);
                
                // Ensure config directory exists
                if (!Directory.Exists(configDir))
                {
                    Directory.CreateDirectory(configDir);
                    LogManager.Info(LangManager.GetText("logMessages.configDirCreated", configDir));
                }
                
                // Initialize file watcher
                whitelistWatcher = new System.IO.FileSystemWatcher();
                whitelistWatcher.Path = configDir;
                whitelistWatcher.Filter = Config.WHITELIST_FILE;
                whitelistWatcher.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size;
                whitelistWatcher.Changed += WhitelistFileChanged;
                whitelistWatcher.EnableRaisingEvents = true;
                
                LogManager.Info(LangManager.GetText("logMessages.whitelistFileWatcherInitialized"));
            }
            catch
            {
                LogManager.Error(LangManager.GetText("logMessages.initializeWhitelistFileWatcherFailed"));
            }
        }

        /// <summary>
        /// Whitelist file changed event handler (using async debounce pattern)
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private static async void WhitelistFileChanged(object sender, System.IO.FileSystemEventArgs e)
        {
            CancellationTokenSource localCts;
            
            // Use lock to safely cancel and create new CancellationTokenSource
            lock (staticResourceLock)
            {
                // Cancel previous delayed task
                debounceCts?.Cancel();
                debounceCts = new CancellationTokenSource();
                localCts = debounceCts;
            }
            
            try
            {
                // Use async delay instead of Thread.Sleep to avoid blocking the event handler thread
                await Task.Delay(200, localCts.Token);
                
                // Re-check if cancelled (may have been released by ReleaseStaticResources during delay)
                if (localCts.IsCancellationRequested)
                {
                    return;
                }
                
                // Refresh cache on background thread to avoid blocking UI thread
                await Task.Run(() => RefreshWhitelistCache());
                
                LogManager.Info(LangManager.GetText("logMessages.whitelistFileChangedCacheRefreshed"));
            }
            catch (ObjectDisposedException)
            {
                // Resource has been released (ReleaseStaticResources), exit silently
            }
            catch (OperationCanceledException)
            {
                // Debounce cancellation is normal behavior, no need to log error
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.processWhitelistFileChangeEventFailed"), ex);
            }
        }

        /// <summary>
        /// Release static resources
        /// Release static resources
        /// Used to clean up resources like file watcher when application exits
        /// Used to clean up resources like file watcher when application exits
        /// </summary>
        public static void ReleaseStaticResources()
        {
            // Use lock to ensure thread-safe resource release
            lock (staticResourceLock)
            {
                try
                {
                    // Cancel debounce task
                    if (debounceCts != null)
                    {
                        try
                        {
                            debounceCts.Cancel();
                            debounceCts.Dispose();
                        }
                        catch (Exception ex)
                        {
                            LogManager.Error(LangManager.GetText("logMessages.disposeDebounceCtsFailed"), ex);
                        }
                        finally
                        {
                            debounceCts = null;
                        }
                    }
                    
                    // Release file watcher
                    if (whitelistWatcher != null)
                    {
                        try
                        {
                            whitelistWatcher.EnableRaisingEvents = false;
                            whitelistWatcher.Changed -= WhitelistFileChanged;
                            whitelistWatcher.Dispose();
                        }
                        catch (Exception ex)
                        {
                            LogManager.Error(LangManager.GetText("logMessages.disposeWhitelistWatcherFailed"), ex);
                        }
                        finally
                        {
                            whitelistWatcher = null;
                        }
                        
                        LogManager.Info(LangManager.GetText("logMessages.whitelistFileWatcherReleased"));
                    }
                }
                catch (Exception ex)
                {
                    LogManager.Error(LangManager.GetText("logMessages.releaseWhitelistFileWatcherFailed"), ex);
                }
            }
        }

        /// <summary>
        /// Constructor
        /// Initialize whitelist management window, including UI components and whitelist loading
        /// </summary>
        public WhitelistForm()
        {
            // Simple initialization
            this.Text = LangManager.GetText("forms.whitelistForm");
            this.Size = new Size(600, 400);
            
            // Create basic controls
            whitelistListBox = new ListBox();
            whitelistListBox.Dock = DockStyle.Fill;
            
            btnAdd = new Button();
            btnAdd.Text = LangManager.GetText("buttons.add");
            btnAdd.Size = new Size(100, 30);
            btnAdd.Click += btnAdd_Click;
            
            btnRemove = new Button();
            btnRemove.Text = LangManager.GetText("whitelist.delete");
            btnRemove.Size = new Size(100, 30);
            btnRemove.Click += btnRemove_Click;
            
            btnClear = new Button();
            btnClear.Text = LangManager.GetText("buttons.clearRules");
            btnClear.Size = new Size(100, 30);
            btnClear.Click += btnClear_Click;
            
            btnSave = new Button();
            btnSave.Text = LangManager.GetText("buttons.save");
            btnSave.Size = new Size(100, 30);
            btnSave.Click += btnSave_Click;
            
            btnClose = new Button();
            btnClose.Text = LangManager.GetText("buttons.close");
            btnClose.Size = new Size(100, 30);
            btnClose.Click += btnClose_Click;
            
            // Layout - Option 1: top button bar, bottom action button
            TableLayoutPanel panel = new TableLayoutPanel();
            panel.Dock = DockStyle.Fill;
            panel.ColumnCount = 4;
            panel.RowCount = 3;
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
            panel.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            panel.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            
            // Top button bar
            panel.Controls.Add(btnAdd, 0, 0);
            panel.SetColumnSpan(btnAdd, 1);
            panel.SetCellPosition(btnAdd, new TableLayoutPanelCellPosition(0, 0));
            
            panel.Controls.Add(btnRemove, 1, 0);
            panel.SetColumnSpan(btnRemove, 1);
            panel.SetCellPosition(btnRemove, new TableLayoutPanelCellPosition(1, 0));
            
            panel.Controls.Add(btnClear, 2, 0);
            panel.SetColumnSpan(btnClear, 1);
            panel.SetCellPosition(btnClear, new TableLayoutPanelCellPosition(2, 0));
            
            panel.Controls.Add(btnSave, 3, 0);
            panel.SetColumnSpan(btnSave, 1);
            panel.SetCellPosition(btnSave, new TableLayoutPanelCellPosition(3, 0));
            
            // Middle list
            panel.Controls.Add(whitelistListBox, 0, 1);
            panel.SetColumnSpan(whitelistListBox, 4);
            
            // Bottom close button
            panel.Controls.Add(btnClose, 0, 2);
            panel.SetColumnSpan(btnClose, 4);
            btnClose.Anchor = AnchorStyles.None;
            
            this.Controls.Add(panel);
            
            // Load whitelist
            LoadWhitelist();
        }

        /// <summary>
        /// Whitelists written before integrity signing existed have no .hmac sidecar. They may be
        /// migrated when no integrity file exists for this whitelist and the data directory is
        /// actually protected, so a non-elevated process could not have planted the content.
        /// The HMAC key itself is not part of the condition: it is created as soon as the main
        /// config is signed, so requiring its absence would lock out every legacy user.
        /// </summary>
        /// <param name="configPath">Whitelist file path</param>
        /// <param name="json">File content on success</param>
        /// <returns>true when a legacy unsigned whitelist was read</returns>
        private static bool TryReadLegacyUnsignedWhitelist(string configPath, out string json)
        {
            json = null;

            if (Config.IntegrityFileExists(configPath) || !Config.IsAppDataDirectorySecured)
            {
                return false;
            }

            try
            {
                json = File.ReadAllText(configPath, Config.Utf8NoBom);
                if (string.IsNullOrWhiteSpace(json))
                {
                    json = null;
                    return false;
                }

                if (!Config.SaveConfigIntegrityHash(configPath))
                {
                    LogManager.Warning("Legacy whitelist was read but could not be signed; it will be verified again next time");
                }

                LogManager.Info("Legacy unsigned whitelist migrated and signed");
                return true;
            }
            catch (Exception ex)
            {
                LogManager.Error($"Failed to read legacy whitelist: {ex.Message}");
                json = null;
                return false;
            }
        }

        /// <summary>
        /// Load whitelist
        /// </summary>
        private void LoadWhitelist()
        {
            try
            {
                whitelistLoadFailed = false;
                string configPath = Config.GetAppDataFilePath(Config.WHITELIST_FILE);
                
                if (File.Exists(configPath))
                {
                    // Verify the HMAC before trusting the content. Loading (and later re-signing) a
                    // tampered file would launder injected entries into a valid whitelist.
                    string json;
                    if (!Config.VerifyConfigIntegrityAndRead(configPath, out json) &&
                        !TryReadLegacyUnsignedWhitelist(configPath, out json))
                    {
                        whitelistLoadFailed = true;
                        LogManager.Error(LangManager.GetText("logMessages.whitelistIntegrityCheckFailed"));
                        MessageBox.Show(LangManager.GetText("logMessages.whitelistIntegrityCheckFailed"),
                            LangManager.GetText("messages.loadWhitelistFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }

                    whitelist = JsonSerializer.Deserialize<List<string>>(json, ComHelper.SafeJsonOptions) ?? new List<string>();
                    
                    foreach (var item in whitelist)
                    {
                        whitelistListBox.Items.Add(item);
                    }
                    
                    LogManager.Info(LangManager.GetText("logMessages.loadWhitelistItems", whitelist.Count));
                }
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.loadWhitelistFailed"), ex);
                MessageBox.Show(LangManager.GetText("messages.loadWhitelistFailed", ex.Message), LangManager.GetText("messages.loadWhitelistFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Whitelist saved event
        /// Triggered when whitelist is saved, notifies main form to update firewall rules
        /// </summary>
        public event EventHandler WhitelistSaved;
        
        /// <summary>
        /// Save whitelist
        /// </summary>
        private void SaveWhitelist()
        {
            try
            {
                if (whitelistLoadFailed)
                {
                    // The existing file failed verification, so it was never loaded. Writing the empty
                    // list box back would silently destroy the user's entries.
                    LogManager.Error("Refusing to save whitelist: the existing file failed the integrity check");
                    MessageBox.Show(LangManager.GetText("logMessages.whitelistIntegrityCheckFailed"),
                        LangManager.GetText("messages.saveWhitelistFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                string configPath = Config.GetAppDataFilePath(Config.WHITELIST_FILE);
                Directory.CreateDirectory(Path.GetDirectoryName(configPath));
                
                whitelist.Clear();
                foreach (var item in whitelistListBox.Items)
                {
                    whitelist.Add(item.ToString());
                }
                
                string json = JsonSerializer.Serialize(whitelist, new JsonSerializerOptions { WriteIndented = true });
                ComHelper.AtomicWriteAllText(configPath, json, Config.Utf8NoBom);

                // Update integrity check value after saving
                if (!Config.SaveConfigIntegrityHash(configPath))
                {
                    LogManager.Error(LangManager.GetText("logMessages.configIntegrityHashSaveFailed"));
                    MessageBox.Show(
                        LangManager.GetText("messages.saveWhitelistFailed", LangManager.GetText("logMessages.configIntegrityHashSaveFailed")),
                        LangManager.GetText("messages.saveWhitelistFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                // Set secure file permissions, restrict modification to Administrators and SYSTEM accounts only
                Config.SetSecureFilePermissionsPublic(configPath);

                LogManager.Info(LangManager.GetText("logMessages.saveWhitelistItems", whitelist.Count));
                MessageBox.Show(LangManager.GetText("messages.whitelistSaved"), LangManager.GetText("messages.successTitle"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                
                // Trigger whitelist saved event
                WhitelistSaved?.Invoke(this, EventArgs.Empty);
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.saveWhitelistFailed"), ex);
                MessageBox.Show(LangManager.GetText("messages.saveWhitelistFailed", ex.Message), LangManager.GetText("messages.saveWhitelistFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Add button click event
        /// </summary>
        private void btnAdd_Click(object sender, EventArgs e)
        {
            using (var openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Filter = LangManager.GetText("messages.exeFileFilter");
                openFileDialog.Title = LangManager.GetText("messages.selectExeFile");
                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    string selectedPath = openFileDialog.FileName;
                    try
                    {
                        // A UNC path typed into the dialog would make the symbolic-link probe below
                        // contact the remote host and leak NTLM credentials.
                        if (!ComHelper.IsLocalPathCandidate(selectedPath))
                        {
                            LogManager.Warning(LangManager.GetText("logMessages.whitelistRejectUncPath", selectedPath));
                            return;
                        }

                        string normalizedPath = Path.GetFullPath(selectedPath);
                        if (ComHelper.IsSymbolicLink(normalizedPath))
                        {
                            LogManager.Warning(LangManager.GetText("logMessages.rejectSymbolicLink", normalizedPath));
                            return;
                        }
                        if (!whitelistListBox.Items.Contains(normalizedPath))
                        {
                            whitelistListBox.Items.Add(normalizedPath);
                            LogManager.Info(LangManager.GetText("logMessages.addToWhitelist", normalizedPath));
                        }
                    }
                    catch
                    {
                        LogManager.Warning(LangManager.GetText("logMessages.whitelistInvalidPath", selectedPath));
                    }
                }
            }
        }

        /// <summary>
        /// Remove button click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void btnRemove_Click(object sender, EventArgs e)
        {
            if (whitelistListBox.SelectedItem != null)
            {
                string selectedItem = whitelistListBox.SelectedItem.ToString();
                whitelistListBox.Items.Remove(whitelistListBox.SelectedItem);
                LogManager.Info(LangManager.GetText("logMessages.removeFromWhitelist", selectedItem));
            }
        }

        /// <summary>
        /// Clear button click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void btnClear_Click(object sender, EventArgs e)
        {
            if (MessageBox.Show(LangManager.GetText("messages.clearWhitelistConfirm"), LangManager.GetText("messages.confirmTitle"), MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes)
            {
                try
                {
                    whitelistListBox.Items.Clear();
                    LogManager.Info(LangManager.GetText("logMessages.whitelistCleared"));
                }
                catch (Exception ex)
                {
                    LogManager.Error(LangManager.GetText("logMessages.clearWhitelistFailed"), ex);
                    MessageBox.Show(LangManager.GetText("messages.clearWhitelistFailed", ex.Message), LangManager.GetText("messages.clearWhitelistFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        /// <summary>
        /// Save button click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void btnSave_Click(object sender, EventArgs e)
        {
            SaveWhitelist();
        }

        /// <summary>
        /// Close button click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void btnClose_Click(object sender, EventArgs e)
        {
            this.Close();
        }
        
        /// <summary>
        /// Check if application is in whitelist
        /// Uses cached normalized paths for efficient O(1) hash lookup
        /// </summary>
        /// <param name="appPath">Application path</param>
        /// <returns>Whether it is in whitelist</returns>
        public static bool IsInWhitelist(string appPath)
        {
            try
            {
                if (string.IsNullOrEmpty(appPath))
                {
                    return false;
                }

                // Ensure cache is loaded (thread-safe double-checked locking)
                if (!whitelistCacheLoaded)
                {
                    lock (whitelistLock)
                    {
                        if (!whitelistCacheLoaded)
                        {
                            RefreshWhitelistCache();
                        }
                    }
                }

                string normalizedAppPath;
                try
                {
                    normalizedAppPath = Path.GetFullPath(appPath);
                }
                catch (Exception ex)
                {
                    LogManager.Warning(LangManager.GetText("logMessages.pathNormalizationFailed", appPath, ex.Message));
                    return false;
                }

                // Use copy-on-write pattern: read without lock, directly access volatile reference
                // Refresh replaces the entire collection atomically to keep reads lock-free and thread-safe
                var cacheSnapshot = whitelistCache;
                return cacheSnapshot.Contains(normalizedAppPath);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Refresh whitelist cache
        /// </summary>
        public static void RefreshWhitelistCache()
        {
            try
            {
                string configPath = Config.GetAppDataFilePath(Config.WHITELIST_FILE);

                HashSet<string> newCache;

                if (!File.Exists(configPath))
                {
                    newCache = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                }
                else
                {
                    // Validate file size to prevent memory exhaustion from malicious large files (check before read)
                    var fileInfo = new FileInfo(configPath);
                    if (fileInfo.Length > 10 * 1024 * 1024)
                    {
                        LogManager.Error(LangManager.GetText("logMessages.whitelistFileTooLarge"));
                        return;
                    }

                    // Verify config integrity and read content (atomic operation, prevents TOCTOU attacks)
                    string json;
                    if (!Config.VerifyConfigIntegrityAndRead(configPath, out json) &&
                        !TryReadLegacyUnsignedWhitelist(configPath, out json))
                    {
                        LogManager.Error(LangManager.GetText("logMessages.whitelistIntegrityCheckFailed"));
                        newCache = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    }
                    else
                    {
                        var paths = JsonSerializer.Deserialize<List<string>>(json, ComHelper.SafeJsonOptions);

                        newCache = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        if (paths != null)
                        {
                            // Validate entry count to prevent DoS from malicious large number of entries
                            if (paths.Count > 100000)
                            {
                                LogManager.Error(LangManager.GetText("logMessages.whitelistTooManyEntries", paths.Count));
                                return;
                            }
                            
                            foreach (var path in paths)
                            {
                                if (string.IsNullOrEmpty(path)) continue;
                                try
                                {
                                    string normalized = Path.GetFullPath(path);
                                    
                                    // Reject extended-length path prefix to prevent path traversal bypass
                                    if (normalized.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
                                    {
                                        LogManager.Warning(LangManager.GetText("logMessages.whitelistRejectExtendedPath", normalized));
                                        continue;
                                    }
                                    
                                    // Reject UNC paths to prevent network share path injection
                                    if (normalized.StartsWith(@"\\", StringComparison.OrdinalIgnoreCase))
                                    {
                                        LogManager.Warning(LangManager.GetText("logMessages.whitelistRejectUncPath", normalized));
                                        continue;
                                    }
                                    
                                    newCache.Add(normalized);
                                }
                                catch
                                {
                                    // Paths that cannot be normalized are not added to cache
                                    LogManager.Warning(LangManager.GetText("logMessages.whitelistInvalidPath", path));
                                }
                            }
                        }
                    }
                }

                // Use copy-on-write pattern: build new cache first, then atomically replace reference
                // Lock only protects replacement, not reads, reducing lock contention
                lock (whitelistLock)
                {
                    whitelistCache = newCache;
                    whitelistCacheLoaded = true;
                }

                LogManager.Info(LangManager.GetText("logMessages.whitelistCacheRefreshedManual", newCache.Count));
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.refreshWhitelistCacheFailed"), ex);
            }
        }
    }
}