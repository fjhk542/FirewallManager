using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace FirewallManager
{


    /// <summary>
    /// Firewall Manager main form
    /// Responsible for monitoring executable files in specified directories and automatically creating firewall rules to block their outbound connections
    /// </summary>
    public partial class Form1 : Form
    {
        #region Class Definitions

        /// <summary>
        /// Scan target class
        /// Represents a folder or a single executable file to be monitored
        /// </summary>
        public class ScanTarget : IScanTarget
        {
            /// <summary>
            /// Path of the scan target
            /// </summary>
            public string Path { get; set; }

            /// <summary>
            /// Whether it is a single executable file
            /// True: a single executable file
            /// False: a folder
            /// </summary>
            public bool IsExe { get; set; }

            /// <summary>
            /// Display name, used for ListBox display
            /// </summary>
            public string DisplayName => Path;

            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="path">Path of the scan target</param>
            public ScanTarget(string path)
            {
                Path = path;
                IsExe = File.Exists(path) && System.IO.Path.GetExtension(path).Equals(".exe", StringComparison.OrdinalIgnoreCase);
            }

            /// <summary>
            /// Override ToString method, used for ListBox display
            /// </summary>
            /// <returns>Display name</returns>
            public override string ToString()
            {
                return DisplayName;
            }
        }

        #endregion

        #region Field Definitions

        /// <summary>
        /// Firewall service
        /// </summary>
        private IFirewallService firewallService;

        /// <summary>
        /// List of monitored targets
        /// </summary>
        private readonly List<ScanTarget> monitoredTargets = new List<ScanTarget>();

        /// <summary>
        /// Pending auto-monitor setting to be applied (loaded from config file, applied after UI initialization completes)
        /// </summary>
        private bool? pendingAutoMonitorSetting = null;

        /// <summary>
        /// Current work state
        /// </summary>
        private volatile WorkState currentState = WorkState.Idle;

        /// <summary>
        /// Cancellation token source
        /// </summary>
        private volatile CancellationTokenSource cancellationTokenSource;

        /// <summary>
        /// Work task
        /// </summary>
        private volatile Task workTask;

        /// <summary>
        /// Pause event
        /// </summary>
        private readonly ManualResetEvent pauseEvent = new ManualResetEvent(true);

        /// <summary>
        /// Log manager
        /// </summary>
        // LogManager is a static class; no instance creation needed



        /// <summary>
        /// Release resources
        /// Releases all managed and unmanaged resources, including cancellation token source, event objects, firewall service, and file watchers
        /// </summary>
        /// <summary>
        /// Whether resources have been released
        /// </summary>
        private volatile bool resourcesReleased = false;

        /// <summary>
        /// Release all resources
        /// Including firewall service, file watchers, event objects, etc.
        /// </summary>
        private void ReleaseResources()
        {
            // Use double-check locking to ensure thread-safety and only release once
            if (resourcesReleased)
            {
                return;
            }

            lock (this)
            {
                if (resourcesReleased)
                {
                    return;
                }

                try
                {
                    // Safely release CancellationTokenSource
                    if (cancellationTokenSource != null)
                    {
                        try
                        {
                            // Cancel first to ensure all tasks using this token receive the cancellation signal
                            if (!cancellationTokenSource.IsCancellationRequested)
                            {
                                cancellationTokenSource.Cancel();
                            }
                            cancellationTokenSource.Dispose();
                        }
                        catch (Exception ex)
                        {
                            LogManager.Error(LangManager.GetText("logMessages.disposeCancellationTokenSourceFailed"), ex);
                        }
                        finally
                        {
                            cancellationTokenSource = null;
                        }
                    }
                    
                    // Release the manual reset event
                    pauseEvent?.Dispose();
                    
                    // Release the firewall service
                    firewallService?.Dispose();
                    
                    // Release file watchers
                    foreach (var watcher in watchers)
                    {
                        watcher.Dispose();
                    }
                    watchers.Clear();
                    
                    // Release whitelist static resources
                    WhitelistForm.ReleaseStaticResources();
                    
                    LogManager.Info(LangManager.GetText("logMessages.resourcesReleased"));
                    
                    resourcesReleased = true;
                }
                catch (Exception ex)
                {
                    LogManager.Error(LangManager.GetText("logMessages.releaseResourcesFailed"), ex);
                }
            }
        }

        /// <summary>
        /// Override Dispose method to ensure proper resource release
        /// </summary>
        /// <param name="disposing">Whether to release managed resources</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                // Release managed resources
                ReleaseResources();
            }
            base.Dispose(disposing);
        }

        

        /// <summary>
        /// Normalize and validate path
        /// </summary>
        /// <param name="path">Input path</param>
        /// <param name="isDirectory">Whether it is a directory</param>
        /// <returns>Normalized path, or null if the path is invalid</returns>
        private string NormalizeAndValidatePath(string path, bool isDirectory)
        {
            try
            {
                if (string.IsNullOrEmpty(path))
                {
                    LogManager.Warning("Path validation failed: empty path");
                    return null;
                }

                LogManager.Info($"Validating path: '{path}', isDirectory={isDirectory}");

                // Reject network (UNC) and device paths before any filesystem call. Directory.Exists on
                // a UNC path transmits the current user's NTLM credentials to the remote host, and the
                // resulting rules would target a UNC path that the firewall cannot match.
                string candidatePath = path.Trim();
                if (!ComHelper.IsLocalPathCandidate(candidatePath))
                {
                    LogManager.Warning($"Path validation failed: network or device path rejected '{path}'");
                    return null;
                }

                // Strip special prefixes (e.g., \\?\) to prevent bypassing path validation
                string sanitizedPath = candidatePath;
                if (sanitizedPath.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
                {
                    sanitizedPath = sanitizedPath.Substring(4);
                }
                if (sanitizedPath.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
                {
                    sanitizedPath = sanitizedPath.Substring(4);
                }
                if (sanitizedPath.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                {
                    sanitizedPath = @"\\" + sanitizedPath.Substring(8);
                }

                // Get the normalized path
                string realPath = Path.GetFullPath(sanitizedPath);
                LogManager.Info($"Normalized path: '{realPath}'");

                // A relative path resolved against a UNC working directory only becomes UNC after
                // GetFullPath, so the network/device check has to be repeated on the result.
                if (!ComHelper.IsLocalPathCandidate(realPath))
                {
                    LogManager.Warning($"Path validation failed: network or device path rejected '{realPath}'");
                    return null;
                }

                // Check whether the path exists
                if (isDirectory && !Directory.Exists(realPath))
                {
                    LogManager.Warning($"Path validation failed: directory does not exist '{realPath}'");
                    return null;
                }
                if (!isDirectory && !File.Exists(realPath))
                {
                    LogManager.Warning($"Path validation failed: file does not exist '{realPath}'");
                    return null;
                }

                // Check if it is a system root directory (e.g., C:\) to avoid scanning the entire system
                string rootPath = Path.GetPathRoot(realPath);
                if (!string.IsNullOrEmpty(rootPath) && realPath.Equals(rootPath, StringComparison.OrdinalIgnoreCase))
                {
                    LogManager.Warning(LangManager.GetText("logMessages.rejectSystemRoot", realPath));
                    return null;
                }

                // Verify that the path root is a local drive
                if (!Path.IsPathRooted(realPath))
                {
                    LogManager.Warning($"Path validation failed: not rooted '{realPath}'");
                    return null;
                }

                // A junction or symlink used as a monitored target would silently redirect scans and
                // watchers to an unrelated tree: EnumerationOptions filters children, not the root,
                // and FileSystemWatcher follows reparse points on its own.
                if (ComHelper.HasReparsePointInPath(realPath))
                {
                    LogManager.Warning($"Path validation failed: reparse point in path '{realPath}'");
                    return null;
                }

                LogManager.Info($"Path validated successfully: '{realPath}'");
                return realPath;
            }
            catch (Exception ex)
            {
                LogManager.Error($"Path validation exception for '{path}': {ex.Message}", ex);
                return null;
            }
        }

        /// <summary>
        /// Attempt to add a normalized path to the monitoring list (deduplication)
        /// Only responsible for the core add logic (deduplication check + add to monitoredTargets and folderListBox)
        /// Side effects (SaveMonitoredTargets, CreateFileWatcher, counters, UI feedback) are handled by the caller
        /// </summary>
        /// <param name="normalizedPath">Normalized path</param>
        /// <returns>The newly created ScanTarget; null if the path is invalid or already exists</returns>
        private ScanTarget TryAddPathToMonitoring(string normalizedPath)
        {
            if (string.IsNullOrEmpty(normalizedPath))
                return null;

            if (monitoredTargets.Any(t => t.Path.Equals(normalizedPath, StringComparison.OrdinalIgnoreCase)))
                return null;

            var target = new ScanTarget(normalizedPath);
            monitoredTargets.Add(target);
            folderListBox.Items.Add(target);
            return target;
        }

        private List<System.IO.FileSystemWatcher> watchers = new List<System.IO.FileSystemWatcher>();
        #endregion

        #region Constructors

        /// <summary>
        /// Default constructor (for designer use)
        /// </summary>
        public Form1() : this(new FirewallService())
        {
        }

        /// <summary>
        /// Constructor with dependency injection
        /// </summary>
        /// <param name="firewallService">Firewall service</param>
        public Form1(IFirewallService firewallService)
        {
            this.firewallService = firewallService ?? throw new ArgumentNullException(nameof(firewallService));
            
            try
            {
                InitializeComponent();

                // Bind the event for viewing rule details
                folderListBox.DoubleClick += folderListBox_DoubleClick;
                var viewRuleDetailsMenuItem = new ToolStripMenuItem(
                    LangManager.GetText("menu.viewRuleDetails"),
                    null,
                    viewRuleDetailsMenuItem_Click);
                contextMenuStrip.Items.Add(new ToolStripSeparator());
                contextMenuStrip.Items.Add(viewRuleDetailsMenuItem);

                // Check whether language resources have been loaded; if not, try reloading
                if (!LangManager.IsLanguageLoaded())
                {
                    LangManager.ReloadLanguageFiles();
                }
                
                // Set UI control text
                SetUIControlsText();
                
                // Log program startup
                LogManager.Info(LangManager.GetText("logMessages.startup"));

                // Check administrator privileges
                if (!IsRunningAsAdministrator())
                {
                    HandleNotAdmin();
                    return;
                }

                // Initialize the privilege separation architecture
                InitializePermissionArchitecture();

                // Ensure tray icon is displayed right after InitializeComponent
                InitializeTrayIcon();
                
                // Initialize firewall components (including loading monitored targets)
                InitializeFirewallComponents();
                
                // Ensure all controls are laid out correctly
                this.PerformLayout();
            }
            catch (Exception ex)
            {
                // Catch all unhandled exceptions
                HandleStartupError(ex);
            }
        }

        #endregion

        #region Initialization Methods

        /// <summary>
        /// Initialize the privilege separation architecture
        /// Designed to separate administrator privileges from normal user privileges
        /// </summary>
        private void InitializePermissionArchitecture()
        {
            // Log the privilege status
            bool isAdmin = IsRunningAsAdministrator();
            LogManager.Info(LangManager.GetText("logMessages.permissionStatus", isAdmin ? LangManager.GetText("messages.admin") : LangManager.GetText("messages.user")));
            
            // Configure functionality based on privilege level
            if (isAdmin)
            {
                // Administrator privileges: enable all firewall management features
                LogManager.Info(LangManager.GetText("logMessages.adminModeEnabled"));

                // Enable all management feature buttons (these will be set again in InitializeFirewallComponents based on firewall initialization status)
                SafeInvoke(() => SetManagementButtonsEnabled(true));
            }
            else
            {
                // Normal user privileges: disable features that require administrator privileges
                LogManager.Warning(LangManager.GetText("logMessages.userModeLimited"));

                // Disable features that require administrator privileges
                SafeInvoke(() =>
                {
                    SetManagementButtonsEnabled(false);

                    // Update the status label
                    statusLabel.Text = LangManager.GetText("status.adminRequired");
                });
            }
        }

        /// <summary>
        /// Initialize tray icon
        /// </summary>
        private void InitializeTrayIcon()
        {
            try
            {
                // In the constructor we are already on the UI thread, so initialize the tray icon directly
                // No need to use SafeInvoke because InvokeRequired will return false
                trayIcon.Icon = this.Icon; // Use the application icon as the tray icon
                trayIcon.Text = LangManager.GetText("app.trayText");
                trayIcon.Visible = true;
                LogManager.Info(LangManager.GetText("logMessages.trayInitialized"));
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.initializeTrayFailed"), ex);
                MessageBox.Show(LangManager.GetText("messages.initializeTrayFailed"), LangManager.GetText("messages.initializeTrayFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Initialize firewall components
        /// </summary>
        private void InitializeFirewallComponents()
        {
            try
            {
                // Load monitored targets first (needed regardless of whether firewall initialization succeeds)
                LoadMonitoredTargets();
                
                // Initialize firewall components (firewallService has been injected via the constructor)
                bool initialized = firewallService.InitializeFirewallComponents();
                
                if (initialized)
                {
                    LoadMonitoredFolders();
                    
                    LogManager.Info(LangManager.GetText("logMessages.firewallInitialized"));
                    
                    UpdateUI(WorkState.Idle, LangManager.GetText("status.readyWait"));
                }
                else
                {
                    throw new Exception(LangManager.GetText("messages.firewallInitializationFailed"));
                }
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.initializeFirewallFailed") + $": {ex.GetType().Name}: {ex.Message}");
                LogManager.Error(LangManager.GetText("logMessages.stackTrace", ex.StackTrace));
                MessageBox.Show(LangManager.GetText("messages.initializeFirewallFailed"), LangManager.GetText("messages.initializeFirewallFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                
                // Disable all firewall-related function buttons
                SafeInvoke(() =>
                {
                    SetManagementButtonsEnabled(false);
                    statusLabel.Text = LangManager.GetText("status.firewallError");
                });
            }

            // Apply the auto-monitor setting restored from the config file (after UI initialization completes)
            if (pendingAutoMonitorSetting.HasValue)
            {
                bool autoMonitor = pendingAutoMonitorSetting.Value;
                pendingAutoMonitorSetting = null;
                if (autoMonitor && autoMonitorCheckBox.Checked != autoMonitor)
                {
                    // Trigger the event by setting Checked instead of calling the logic directly
                    autoMonitorCheckBox.Checked = true;
                }
                else
                {
                    autoMonitorCheckBox.Checked = autoMonitor;
                }
            }
        }
        
        /// <summary>
        /// Initialize file system watchers
        /// </summary>
        private void InitializeFileWatchers()
        {
            try
            {
                // Stop existing watchers
                StopFileWatchers();
                
                // Create a watcher for each monitored target
                foreach (var target in monitoredTargets)
                {
                    if (!target.IsExe && Directory.Exists(target.Path))
                    {
                        CreateFileWatcher(target.Path);
                    }
                }
                
                LogManager.Info(LangManager.GetText("logMessages.fileSystemWatchersInitialized", watchers.Count));
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.initializeFileWatcherFailed"), ex);
            }
        }
        
        /// <summary>
        /// Create a file system watcher
        /// </summary>
        /// <param name="path">Path to monitor</param>
        private void CreateFileWatcher(string path)
        {
            try
            {
                var watcher = new System.IO.FileSystemWatcher();
                watcher.Path = path;
                watcher.Filter = "*.exe";
                watcher.IncludeSubdirectories = true;
                
                // Subscribe to events
                watcher.Created += FileSystemWatcher_Created;
                watcher.Renamed += FileSystemWatcher_Renamed;
                watcher.Changed += FileSystemWatcher_Changed;
                
                // Start monitoring
                watcher.EnableRaisingEvents = true;
                
                watchers.Add(watcher);
                LogManager.Info(LangManager.GetText("logMessages.fileSystemWatcherCreated", path));
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.createFileSystemWatcherFailed", path), ex);
            }
        }
        
        /// <summary>
        /// Stop file system watchers
        /// </summary>
        private void StopFileWatchers()
        {
            foreach (var watcher in watchers)
            {
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                }
                catch (Exception ex)
                {
                    LogManager.Error(LangManager.GetText("logMessages.stopFileWatcherFailed"), ex);
                }
            }
            watchers.Clear();
        }
        
        /// <summary>
        /// File created event handler
        /// Uses a retry mechanism to ensure the file is fully written before processing, preventing TOCTOU race conditions
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void FileSystemWatcher_Created(object sender, System.IO.FileSystemEventArgs e)
        {
            try
            {
                LogManager.Info(LangManager.GetText("logMessages.newFileDetected", e.FullPath));
                ValidateAndCreateRuleForExe(e.FullPath, waitForReady: true);
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.processFileCreatedEventFailed"), ex);
            }
        }

        /// <summary>
        /// File renamed event handler
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void FileSystemWatcher_Renamed(object sender, System.IO.RenamedEventArgs e)
        {
            try
            {
                LogManager.Info(LangManager.GetText("logMessages.fileRenamed", e.OldFullPath, e.FullPath));
                ValidateAndCreateRuleForExe(e.FullPath, waitForReady: false);
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.processFileRenamedEventFailed"), ex);
            }
        }

        /// <summary>
        /// File changed event handler
        /// Re-validate and update rules when a file is modified
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void FileSystemWatcher_Changed(object sender, System.IO.FileSystemEventArgs e)
        {
            try
            {
                LogManager.Info(LangManager.GetText("logMessages.fileChanged", e.FullPath));
                ValidateAndCreateRuleForExe(e.FullPath, waitForReady: true);
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.processFileChangedEventFailed"), ex);
            }
        }

        /// <summary>
        /// Unified EXE file validation and rule creation logic
        /// Extracted from FileSystemWatcher_Created/Renamed/Changed event handlers to eliminate duplicate code
        /// Validation flow: extension -> wait for file ready -> real path -> reparse point -> trust check -> create rule
        /// </summary>
        /// <param name="rawPath">Raw file path</param>
        /// <param name="waitForReady">Whether to wait for file write to complete (required for Created/Changed events, not needed for Renamed)</param>
        private void ValidateAndCreateRuleForExe(string rawPath, bool waitForReady)
        {
            // Explicitly verify .exe extension to prevent Filter from matching short file names on some Windows versions
            string fileName = Path.GetFileName(rawPath);
            if (!fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            // Use retry mechanism to wait for file write to complete (prevent TOCTOU)
            if (waitForReady && !ComHelper.WaitForFileReady(rawPath, maxRetries: 10, retryDelayMs: 500))
            {
                LogManager.Warning(LangManager.GetText("logMessages.fileNotReadyAfterRetries", rawPath));
                return;
            }

            // Re-verify file exists and has not been replaced before creating rule (prevent TOCTOU)
            if (!File.Exists(rawPath))
            {
                LogManager.Warning(LangManager.GetText("logMessages.fileDisappearedBeforeProcessing", rawPath));
                return;
            }

            // Check the ORIGINAL path for reparse points before resolving it. GetRealPath replaces the
            // link with its target, so checking afterwards can never detect the link itself.
            if (ComHelper.HasReparsePointInPath(rawPath))
            {
                LogManager.Warning(LangManager.GetText("logMessages.rejectSymbolicLinkFile", rawPath));
                return;
            }

            // Use GetRealPath to obtain real path (resolve symbolic links and mount points)
            string fullPath = ComHelper.GetRealPath(rawPath);
            if (fullPath == null)
            {
                LogManager.Warning(LangManager.GetText("logMessages.pathNormalizationFailed", rawPath, "GetRealPath failed"));
                return;
            }

            // Skip only Windows' own executables; blocking them would destabilize the system.
            // Unsigned binaries must NOT be skipped: containing them is the whole point of this tool.
            if (ComHelper.IsCriticalSystemExecutable(fullPath))
            {
                LogManager.Warning($"Skipping critical system executable: {fullPath}");
                return;
            }

            // Create firewall rule for newly created EXE file
            firewallService.CreateRuleForExe(fullPath);
        }
        
        #endregion

        #region UI-related methods

        /// <summary>
        /// Safely recreate CancellationTokenSource
        /// </summary>
        /// <returns>Newly created CancellationTokenSource</returns>
        private CancellationTokenSource SafeRecreateCancellationTokenSource()
        {
            // Safely dispose the old CancellationTokenSource
            if (cancellationTokenSource != null)
            {
                try
                {
                    // Cancel first to ensure all tasks using this token receive the cancellation signal
                    if (!cancellationTokenSource.IsCancellationRequested)
                    {
                        cancellationTokenSource.Cancel();
                    }
                    cancellationTokenSource.Dispose();
                }
                catch (Exception ex)
                {
                    LogManager.Error(LangManager.GetText("logMessages.disposeCancellationTokenSourceFailed"), ex);
                }
                finally
                {
                    cancellationTokenSource = null;
                }
            }
            
            // Create a new CancellationTokenSource
            cancellationTokenSource = new CancellationTokenSource();
            return cancellationTokenSource;
        }

        /// <summary>
        /// Set UI control text
        /// </summary>
        private void SetUIControlsText()
        {
            // Set window title
            this.Text = LangManager.GetText("app.title");

            // Set button text
            addButton.Text = LangManager.GetText("buttons.add");
            updateRulesButton.Text = LangManager.GetText("buttons.updateRules");
            clearRulesButton.Text = LangManager.GetText("buttons.clearRules");
            removeFolderButton.Text = LangManager.GetText("buttons.removeFolder");
            pauseButton.Text = LangManager.GetText("buttons.pause");
            resumeButton.Text = LangManager.GetText("buttons.resume");
            stopButton.Text = LangManager.GetText("buttons.stop");
            viewLogsButton.Text = LangManager.GetText("buttons.viewLogs");
            whitelistButton.Text = LangManager.GetText("buttons.whitelist");
            exportConfigButton.Text = LangManager.GetText("buttons.exportConfig");
            importConfigButton.Text = LangManager.GetText("buttons.importConfig");

            // Set context menu item text
            pasteMenuItem.Text = LangManager.GetText("menu.paste");
            addFolderToolStripMenuItem.Text = LangManager.GetText("menu.addFolder");
            addExeToolStripMenuItem.Text = LangManager.GetText("menu.addFile");

            // Set tray menu item text
            showMainFormToolStripMenuItem.Text = LangManager.GetText("menu.showMainForm");
            updateRulesTrayToolStripMenuItem.Text = LangManager.GetText("menu.updateRules");
            exitToolStripMenuItem.Text = LangManager.GetText("menu.exit");

            // Set auto-monitor checkbox text
            autoMonitorCheckBox.Text = LangManager.GetText("menu.autoMonitor");

            // Set language combo box
            if (languageComboBox.Items.Count == 0)
            {
                languageComboBox.Items.Add(LangManager.GetText("language.chinese"));
                languageComboBox.Items.Add(LangManager.GetText("language.english"));
            }
            // Set current language as selected item
            string currentLang = LangManager.GetCurrentLanguage();
            languageComboBox.SelectedIndex = currentLang == "zh" ? 0 : 1;

            // Set file dialog text
            openFileDialog.Title = LangManager.GetText("messages.selectExeFile");
            openFileDialog.Filter = LangManager.GetText("messages.exeFileFilter");
        }

        /// <summary>
        /// Thread-safe UI update method
        /// Checks whether cross-thread invoke is needed and ensures UI operations are executed on the main thread
        /// </summary>
        /// <param name="action">Action to be executed on UI thread</param>
        private void SafeInvoke(Action action)
        {
            if (this.InvokeRequired)
            {
                this.Invoke(action);
            }
            else
            {
                action();
            }
        }

        /// <summary>
        /// Uniformly set the enabled/disabled state of management function buttons
        /// Extracted from InitializePermissionArchitecture and InitializeFirewallComponents to eliminate 3 duplicates
        /// Runtime control buttons (pause/resume/stop) are always set to false, controlled individually by UpdateUI based on work state
        /// </summary>
        /// <param name="enabled">Whether management buttons are enabled</param>
        private void SetManagementButtonsEnabled(bool enabled)
        {
            addButton.Enabled = enabled;
            updateRulesButton.Enabled = enabled;
            clearRulesButton.Enabled = enabled;
            removeFolderButton.Enabled = enabled;
            whitelistButton.Enabled = enabled;
            exportConfigButton.Enabled = enabled;
            importConfigButton.Enabled = enabled;
            pauseButton.Enabled = false;
            resumeButton.Enabled = false;
            stopButton.Enabled = false;
        }

        /// <summary>
        /// Update UI state
        /// </summary>
        /// <param name="state">Work state</param>
        /// <param name="statusText">Status text</param>
        private void UpdateUI(WorkState state, string statusText)
        {
            SafeInvoke(() =>
            {
                currentState = state;
                statusLabel.Text = statusText;
                
                // Enable/disable buttons based on state
                bool isIdle = (state == WorkState.Idle);
                bool isRunning = (state == WorkState.Running);
                bool isPaused = (state == WorkState.Paused);
                bool isStopping = (state == WorkState.Stopping);
                
                // Primary operation buttons
                addButton.Enabled = isIdle;
                updateRulesButton.Enabled = isIdle;
                clearRulesButton.Enabled = isIdle;
                removeFolderButton.Enabled = isIdle;
                whitelistButton.Enabled = isIdle;
                exportConfigButton.Enabled = isIdle;
                importConfigButton.Enabled = isIdle;
                
                // Runtime control buttons
                pauseButton.Enabled = isRunning;
                resumeButton.Enabled = isPaused;
                stopButton.Enabled = isRunning || isPaused;
                
                // Update progress bar visibility
                progressBar.Style = isRunning ? ProgressBarStyle.Marquee : ProgressBarStyle.Blocks;
                progressBar.MarqueeAnimationSpeed = isRunning ? 30 : 0;
            });
        }

        #endregion

        #region Permission-related methods

        /// <summary>
        /// Check if running as administrator
        /// Determined by checking if the current user belongs to the administrator role
        /// </summary>
        /// <returns>Whether running as administrator</returns>
        private bool IsRunningAsAdministrator()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        /// <summary>
        /// Handle non-admin permission case
        /// Logs error and prompts user that administrator privileges are required, then exits the application
        /// </summary>
        private void HandleNotAdmin()
        {
            LogManager.Error(LangManager.GetText("logMessages.notAdmin"));
            MessageBox.Show(LangManager.GetText("messages.notAdmin"), LangManager.GetText("messages.notAdminTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            Application.Exit();
        }

        #endregion

        #region Firewall-related methods

        /// <summary>
        /// Load monitored folders and sync firewall rules
        /// </summary>
        private void LoadMonitoredFolders()
        {
            try
            {
                LogManager.Info(LangManager.GetText("logMessages.loadingMonitoredFolders"));
                
                // Sync firewall rules list (load existing rules from actual firewall)
                firewallService.SyncRulesList();
                
                // Get rule count
                var ruleNames = firewallService.GetAllRuleNames();
                LogManager.Info(LangManager.GetText("logMessages.loadedFirewallRules", ruleNames.Count));
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.loadingFoldersFailed", ex.Message), ex);
                // Report error to user
                this.Invoke((MethodInvoker)delegate
                {
                    MessageBox.Show(LangManager.GetText("logMessages.loadingFoldersFailed", ex.Message), LangManager.GetText("messages.pathErrorTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                });
            }
        }

        /// <summary>
        /// Save monitored targets to config file
        /// Uses TargetStore v2 schema, persists language and autoMonitor
        /// </summary>
        private void SaveMonitoredTargets()
        {
            try
            {
                string configPath = Config.GetAppDataFilePath(Config.CONFIG_FILE);

                // Collect current state
                var data = new TargetStore.ConfigData
                {
                    Language = LangManager.GetCurrentLanguage(),
                    AutoMonitor = autoMonitorCheckBox.Checked,
                    Targets = monitoredTargets.Select(t => t.Path).ToList()
                };

                if (!TargetStore.Save(configPath, data))
                {
                    // Prompt user when save fails
                    MessageBox.Show(
                        LangManager.GetText("messages.saveMonitoringTargetsFailed", "Save failed"),
                        LangManager.GetText("messages.errorTitle"),
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                }
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.saveMonitoringTargetsFailed"), ex);
                MessageBox.Show(LangManager.GetText("messages.saveMonitoringTargetsFailed", ex.Message), LangManager.GetText("messages.errorTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Load monitored targets from config file
        /// Uses TargetStore v2 schema, restores language and autoMonitor
        /// </summary>
        private void LoadMonitoredTargets()
        {
            try
            {
                string configPath = Config.GetAppDataFilePath(Config.CONFIG_FILE);
                LogManager.Info($"Loading monitored targets from: {configPath}");

                if (!File.Exists(configPath))
                {
                    LogManager.Info("Config file does not exist, no targets to load");
                    return;
                }

                // Load using TargetStore (includes integrity validation, graceful degradation, and automatic v1 migration)
                var data = TargetStore.Load(configPath);
                if (data == null)
                {
                    // Config file cannot be read or parsed (may be corrupted)
                    MessageBox.Show(
                        LangManager.GetText("messages.configLoadFailed"),
                        LangManager.GetText("messages.errorTitle"),
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                    return;
                }

                // Restore language setting (v2 schema only)
                if (!string.IsNullOrEmpty(data.Language))
                {
                    string currentLang = LangManager.GetCurrentLanguage();
                    if (!string.Equals(currentLang, data.Language, StringComparison.OrdinalIgnoreCase))
                    {
                        LogManager.Info($"Restoring language setting: {data.Language}");
                        LangManager.SetLanguage(data.Language);
                    }
                }

                // Restore auto-monitor toggle (v2 schema only)
                // Note: Only set the state here, do not start monitoring immediately (to avoid triggering before UI initialization)
                pendingAutoMonitorSetting = data.AutoMonitor;

                // Load monitored target paths
                if (data.Targets == null || data.Targets.Count == 0)
                {
                    LogManager.Info("No targets in config file");
                    return;
                }

                int addedCount = 0;
                int skippedCount = 0;
                foreach (var path in data.Targets)
                {
                    if (string.IsNullOrEmpty(path))
                    {
                        LogManager.Warning("Config file contains null/empty entry, skipping");
                        skippedCount++;
                        continue;
                    }

                    // Validate each path using NormalizeAndValidatePath
                    // Prevent bypass attacks such as symlinks, junctions, UNC paths and
                    // extended-length paths in config file. Validation runs before any existence
                    // check, because Directory.Exists on a UNC path contacts the remote host.
                    string normalizedPath = NormalizeAndValidatePath(path, true) ??
                                            NormalizeAndValidatePath(path, false);
                    if (normalizedPath == null)
                    {
                        LogManager.Warning($"Path failed validation, skipping: {path}");
                        skippedCount++;
                        continue;
                    }

                    if (TryAddPathToMonitoring(normalizedPath) != null)
                    {
                        addedCount++;
                    }
                    else
                    {
                        skippedCount++;
                        LogManager.Warning($"Path already added, skipping: {normalizedPath}");
                    }
                }
                LogManager.Info(LangManager.GetText("logMessages.loadedMonitorTargetsFromConfig", addedCount, skippedCount));
            }
            catch (JsonException ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.loadMonitoringTargetsFailed") + " - Invalid JSON format", ex);
                MessageBox.Show(LangManager.GetText("messages.loadMonitoringTargetsFailedJson", ex.Message), LangManager.GetText("messages.errorTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.loadMonitoringTargetsFailed"), ex);
                MessageBox.Show(LangManager.GetText("messages.loadMonitoringTargetsFailed", ex.Message), LangManager.GetText("messages.errorTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// View rule details
        /// </summary>
        /// <param name="ruleName">Rule name</param>
        private void ViewRuleDetails(string ruleName)
        {
            try
            {
                RuleDetailsInfo rule = firewallService.GetRuleDetails(ruleName);
                if (rule != null)
                    {
                        var detailsForm = new RuleDetailsForm(rule, ruleName, firewallService);
                        detailsForm.ShowDialog();
                    }
                else
                {
                    MessageBox.Show(
                        LangManager.GetText("messages.ruleNotFound"),
                        LangManager.GetText("messages.errorTitle"),
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.viewRuleDetailsFailed", ex.Message));
                MessageBox.Show(LangManager.GetText("messages.viewRulesDetailsFailed", ex.Message), LangManager.GetText("messages.viewRulesDetailsFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Folder list double-click event - view rule details of selected target
        /// </summary>
        private void folderListBox_DoubleClick(object sender, EventArgs e)
        {
            if (folderListBox.SelectedItem is ScanTarget selectedTarget)
            {
                if (selectedTarget.IsExe)
                {
                    string ruleName = RuleNamingService.BuildRuleName(selectedTarget.Path);
                    ViewRuleDetails(ruleName);
                }
                else
                {
                    MessageBox.Show(
                        LangManager.GetText("messages.selectExeToViewDetails"),
                        LangManager.GetText("messages.informationTitle"),
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                }
            }
        }

        /// <summary>
        /// Context menu opening event - select the clicked list item before the context menu is displayed
        /// </summary>
        private void contextMenuStrip_Opening(object sender, System.ComponentModel.CancelEventArgs e)
        {
            var contextMenu = sender as ContextMenuStrip;
            if (contextMenu != null && folderListBox != null)
            {
                System.Drawing.Point mousePos = folderListBox.PointToClient(System.Windows.Forms.Cursor.Position);
                int index = folderListBox.IndexFromPoint(mousePos);
                if (index >= 0 && index < folderListBox.Items.Count)
                {
                    folderListBox.SelectedIndex = index;
                }
            }
        }

        /// <summary>
        /// Context menu "view rule details" item click event
        /// </summary>
        private void viewRuleDetailsMenuItem_Click(object sender, EventArgs e)
        {
            if (folderListBox.SelectedItem is ScanTarget selectedTarget)
            {
                folderListBox_DoubleClick(sender, e);
            }
            else
            {
                MessageBox.Show(
                    LangManager.GetText("messages.selectExeToViewDetails"),
                    LangManager.GetText("messages.informationTitle"),
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
        }

        #endregion

        #region Error Handling

        /// <summary>
        /// Handle startup error
        /// </summary>
        /// <param name="ex">Exception object</param>
        private void HandleStartupError(Exception ex)
        {
            LogManager.Error(LangManager.GetText("logMessages.startupFailed"), ex);
            MessageBox.Show(LangManager.GetText("messages.startupFailed"), LangManager.GetText("messages.startupFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            Application.Exit();
        }

        #endregion

        #region Event Handling

        /// <summary>
        /// Add button click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void addButton_Click(object sender, EventArgs e)
        {
            addContextMenu.Show(addButton, new System.Drawing.Point(0, addButton.Height));
        }
        
        /// <summary>
        /// Add folder menu item click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void addFolderToolStripMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                // Use FolderBrowserDialog to select folder
                using (var folderDialog = new FolderBrowserDialog())
                {
                    folderDialog.Description = LangManager.GetText("buttons.addFolder");
                    folderDialog.UseDescriptionForTitle = true;
                    
                    LogManager.Info("Opening folder browser dialog...");
                    
                    if (folderDialog.ShowDialog() == DialogResult.OK)
                    {
                        string selectedPath = folderDialog.SelectedPath;
                        LogManager.Info($"Selected folder: '{selectedPath}'");
                        
                        // Normalize and validate path
                        string normalizedPath = NormalizeAndValidatePath(selectedPath, true);
                        if (normalizedPath == null)
                        {
                            LogManager.Warning($"Path validation failed for: '{selectedPath}'");
                            MessageBox.Show(LangManager.GetText("messages.invalidPath"), LangManager.GetText("messages.errorTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }
                        
                        LogManager.Info($"Path validated: '{normalizedPath}'");
                        
                        var target = TryAddPathToMonitoring(normalizedPath);
                        if (target != null)
                        {
                            SaveMonitoredTargets();
                            LogManager.Info(LangManager.GetText("logMessages.addFolderToMonitor", normalizedPath));

                            if (autoMonitorCheckBox.Checked && !target.IsExe)
                            {
                                CreateFileWatcher(normalizedPath);
                            }
                        }
                        else
                        {
                            LogManager.Info($"Path already monitored: '{normalizedPath}'");
                        }
                    }
                    else
                    {
                        LogManager.Info("Folder browser dialog cancelled");
                    }
                }
            }
            catch (Exception ex)
            {
                LogManager.Error($"Error adding folder: {ex.Message}", ex);
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Update rules button click event
        /// </summary>
        private void updateRulesButton_Click(object sender, EventArgs e)
        {
            StartUpdateRulesTask();
        }

        /// <summary>
        /// Clear rules button click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void clearRulesButton_Click(object sender, EventArgs e)
        {
            // Clear all firewall rules
            try
            {
                LogManager.Info(LangManager.GetText("logMessages.clearingAllRules"));
                
                // Confirm operation
                if (MessageBox.Show(LangManager.GetText("messages.clearRulesConfirm"), LangManager.GetText("messages.clearRulesConfirmTitle"), MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                {
                    return;
                }
                
                // Use firewall service to clear rules
                int deletedCount = firewallService.ClearAllRules();
                
                LogManager.Info(LangManager.GetText("logMessages.clearingRulesCompleted", deletedCount));
                MessageBox.Show(LangManager.GetText("status.rulesCleared", deletedCount), LangManager.GetText("app.title"), MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.clearingRulesFailed", ex.Message), ex);
                MessageBox.Show(LangManager.GetText("messages.clearFailed"), LangManager.GetText("app.title"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Remove folder button click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void removeFolderButton_Click(object sender, EventArgs e)
        {
            if (folderListBox.SelectedItem is ScanTarget selectedTarget)
            {
                monitoredTargets.Remove(selectedTarget);
                folderListBox.Items.Remove(selectedTarget);
                SaveMonitoredTargets(); // Save monitored targets

                // Remove firewall rules corresponding to this folder
                try
                {
                    if (!selectedTarget.IsExe)
                    {
                        int removedCount = firewallService.RemoveFolderRules(selectedTarget.Path);
                        LogManager.Info(LangManager.GetText("logMessages.removedFolderRules", selectedTarget.Path, removedCount));
                    }
                    else
                    {
                        string ruleName = RuleNamingService.BuildRuleName(selectedTarget.Path);
                        if (firewallService.CheckRuleExists(ruleName))
                        {
                            firewallService.DeleteRule(ruleName);
                            LogManager.Info(LangManager.GetText("logMessages.deleteFirewallRule", ruleName));
                        }
                    }
                }
                catch (Exception ex)
                {
                    LogManager.Error(LangManager.GetText("logMessages.removeFolderRulesFailed", selectedTarget.Path), ex);
                }

                // Reinitialize file system watchers if auto-monitor is enabled
                if (autoMonitorCheckBox.Checked)
                {
                    InitializeFileWatchers();
                }
            }
        }

        /// <summary>
        /// View logs button click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void viewLogsButton_Click(object sender, EventArgs e)
        {
            // Open logs window
            try
            {
                var logsForm = new LogsForm();
                logsForm.Show();
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.openLogsFailed"), ex);
                MessageBox.Show(LangManager.GetText("messages.openLogsFailed"), LangManager.GetText("messages.openLogsFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        
        /// <summary>
        /// Whitelist management button click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void whitelistButton_Click(object sender, EventArgs e)
        {
            // Open whitelist management window
            try
            {
                var whitelistForm = new WhitelistForm();
                whitelistForm.WhitelistSaved += WhitelistForm_WhitelistSaved;
                whitelistForm.Show();
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.openWhitelistFormFailed"), ex);
                MessageBox.Show(LangManager.GetText("logMessages.openWhitelistFormFailed") + ": " + ex.Message, LangManager.GetText("messages.errorTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        
        /// <summary>
        /// Whitelist saved event handler
        /// </summary>
        private void WhitelistForm_WhitelistSaved(object sender, EventArgs e)
        {
            StartUpdateRulesTask();
        }
        
        /// <summary>
        /// Auto monitor checkbox click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void autoMonitorCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            try
            {
                if (autoMonitorCheckBox.Checked)
                {
                    // Enable auto-monitor
                    InitializeFileWatchers();
                    LogManager.Info(LangManager.GetText("logMessages.autoMonitorEnabled"));
                    trayIcon.ShowBalloonTip(1000, LangManager.GetText("app.trayTitle"), LangManager.GetText("logMessages.autoMonitorEnabled"), ToolTipIcon.Info);
                }
                else
                {
                    // Disable auto-monitor
                    StopFileWatchers();
                    LogManager.Info(LangManager.GetText("logMessages.autoMonitorDisabled"));
                    trayIcon.ShowBalloonTip(1000, LangManager.GetText("app.trayTitle"), LangManager.GetText("logMessages.autoMonitorDisabled"), ToolTipIcon.Info);
                }
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.toggleAutoMonitorFailed"), ex);
                autoMonitorCheckBox.Checked = false; // Restore to unchecked state
                MessageBox.Show(LangManager.GetText("logMessages.toggleAutoMonitorFailed") + ": " + ex.Message, LangManager.GetText("messages.errorTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Language combo box selection changed event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void languageComboBox_SelectedIndexChanged(object sender, EventArgs e)
        {
            try
            {
                string newLanguage = languageComboBox.SelectedIndex == 0 ? "zh" : "en";
                string currentLang = LangManager.GetCurrentLanguage();
                
                if (newLanguage != currentLang)
                {
                    // Switch language
                    LangManager.SetLanguage(newLanguage);
                    
                    // Reset UI text
                    SetUIControlsText();
                    
                    // Update tray icon text
                    trayIcon.Text = LangManager.GetText("app.trayText");
                    
                    // Show notification
                    trayIcon.ShowBalloonTip(2000, LangManager.GetText("app.trayTitle"), LangManager.GetText("messages.languageChanged"), ToolTipIcon.Info);
                    
                    LogManager.Info($"Language changed to {newLanguage}");

                    // Persist language setting to config file
                    SaveMonitoredTargets();
                }
            }
            catch (Exception ex)
            {
                LogManager.Error("Failed to change language", ex);
                MessageBox.Show(
                    LangManager.GetText("messages.languageChangeFailed"),
                    LangManager.GetText("messages.errorTitle"),
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Pause button click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void pauseButton_Click(object sender, EventArgs e)
        {
            if (currentState == WorkState.Running)
            {
                pauseEvent.Reset();
                UpdateUI(WorkState.Paused, LangManager.GetText("status.paused"));
                LogManager.Info(LangManager.GetText("logMessages.taskPaused"));
            }
        }

        /// <summary>
        /// Resume button click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void resumeButton_Click(object sender, EventArgs e)
        {
            if (currentState == WorkState.Paused)
            {
                pauseEvent.Set();
                UpdateUI(WorkState.Running, LangManager.GetText("status.running"));
                LogManager.Info(LangManager.GetText("logMessages.taskResumed"));
            }
        }

        /// <summary>
        /// Stop button click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private async void stopButton_Click(object sender, EventArgs e)
        {
            if (currentState == WorkState.Running || currentState == WorkState.Paused)
            {
                // If paused, resume first so the task can respond to cancellation
                if (currentState == WorkState.Paused)
                {
                    pauseEvent.Set();
                }

                // Cancel task
                cancellationTokenSource?.Cancel();
                UpdateUI(WorkState.Stopping, LangManager.GetText("status.stopping"));

                // Wait for task completion asynchronously to avoid blocking UI thread
                if (workTask != null)
                {
                    try
                    {
                        var timeoutTask = Task.Delay(5000);
                        var completedTask = await Task.WhenAny(workTask, timeoutTask);
                        if (completedTask == timeoutTask)
                        {
                            LogManager.Warning(LangManager.GetText("logMessages.stopTaskTimeout"));
                        }
                    }
                    catch (Exception ex)
                    {
                        LogManager.Error(LangManager.GetText("logMessages.stopTaskFailed", ex.Message));
                    }
                }

                // Reset pause event
                pauseEvent.Set();

                UpdateUI(WorkState.Idle, LangManager.GetText("status.ready"));
                LogManager.Info(LangManager.GetText("logMessages.taskStopped"));
            }
        }

        #endregion

        #region Firewall Rule Updates

        /// <summary>
        /// Start update rules task
        /// </summary>
        private void StartUpdateRulesTask()
        {
            if (currentState != WorkState.Idle) return;

            SafeRecreateCancellationTokenSource();

            workTask = Task.Run(async () =>
            {
                await UpdateFirewallRules(cancellationTokenSource.Token);
            }, cancellationTokenSource.Token);

            UpdateUI(WorkState.Running, LangManager.GetText("status.running"));
        }

        /// <summary>
        /// Update firewall rules
        /// </summary>
        private async Task UpdateFirewallRules(CancellationToken cancellationToken)
        {
            try
            {
                // Wait for pause to be lifted
                pauseEvent.WaitOne();
                
                // Check cancellation request again (may have been cancelled during pause)
                cancellationToken.ThrowIfCancellationRequested();
                
                // Use firewall service to update rules
                var result = await firewallService.UpdateFirewallRules(monitoredTargets, cancellationToken, (state, text) => UpdateUI(WorkState.Running, text));
                
                UpdateUI(WorkState.Idle, LangManager.GetText("status.updateCompleted", result.addedCount, result.skippedCount));
                LogManager.Info(LangManager.GetText("logMessages.updateCompleted", result.addedCount, result.skippedCount));
            }
            catch (OperationCanceledException)
            {
                UpdateUI(WorkState.Idle, LangManager.GetText("status.operationCanceled"));
                LogManager.Info(LangManager.GetText("logMessages.updateCanceled"));
            }
            catch (Exception ex)
            {
                UpdateUI(WorkState.Idle, LangManager.GetText("status.error", ex.Message));
                LogManager.Error(LangManager.GetText("logMessages.updateError", ex.Message), ex);
            }
        }

        #endregion

        #region Import/Export Functions

        /// <summary>
        /// Export config button click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void exportConfigButton_Click(object sender, EventArgs e)
        {
            try
            {
                if (monitoredTargets.Count == 0)
                {
                    MessageBox.Show(LangManager.GetText("messages.noValidPath"), LangManager.GetText("messages.noValidPathTitle"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                saveFileDialog.Title = LangManager.GetText("messages.selectConfigFile");
                saveFileDialog.Filter = LangManager.GetText("messages.configFileFilter");
                saveFileDialog.FileName = $"FirewallManager_Config_{DateTime.Now:yyyyMMdd_HHmmss}.json";

                if (saveFileDialog.ShowDialog() == DialogResult.OK)
                {
                    string exportPath = saveFileDialog.FileName;

                    // Create export config object
                    var exportConfig = new
                    {
                        Version = "1.0",
                        ExportDate = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                        Targets = monitoredTargets.Select(t => new
                        {
                            Path = t.Path,
                            IsExe = t.IsExe
                        }).ToList()
                    };

                    string json = JsonSerializer.Serialize(exportConfig, Config.ExportJsonOptions);
                    ComHelper.AtomicWriteAllText(exportPath, json, Config.Utf8NoBom);

                    LogManager.Info($"Config exported to: {exportPath}");
                    MessageBox.Show(LangManager.GetText("messages.exportConfigSuccess"), LangManager.GetText("messages.exportConfigSuccessTitle"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.exportConfigFailed", ex.Message), ex);
                MessageBox.Show(LangManager.GetText("messages.saveFailedAccessDenied"), LangManager.GetText("messages.exportConfigFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.exportConfigFailed", ex.Message), ex);
                MessageBox.Show(LangManager.GetText("messages.exportConfigFailed", ex.Message), LangManager.GetText("messages.exportConfigFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Import config button click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void importConfigButton_Click(object sender, EventArgs e)
        {
            try
            {
                openFileDialog.Title = LangManager.GetText("messages.selectConfigFile");
                openFileDialog.Filter = LangManager.GetText("messages.configFileFilter");

                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    string importPath = openFileDialog.FileName;

                    // The dialog accepts typed UNC paths; probing one would leak NTLM credentials.
                    if (!ComHelper.IsLocalPathCandidate(importPath))
                    {
                        LogManager.Warning($"Config import rejected (network or device path): '{importPath}'");
                        MessageBox.Show(LangManager.GetText("messages.importConfigInvalid"), LangManager.GetText("messages.importConfigInvalidTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }

                    // Confirm import operation
                    if (MessageBox.Show(LangManager.GetText("messages.importConfigConfirm"), LangManager.GetText("messages.importConfigConfirmTitle"), MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                    {
                        return;
                    }

                    // Validate file size to prevent DoS attacks (max 5MB)
                    const long maxConfigFileSize = 5 * 1024 * 1024;
                    FileInfo fileInfo = new FileInfo(importPath);
                    if (fileInfo.Length > maxConfigFileSize)
                    {
                        LogManager.Warning($"Config file too large: {fileInfo.Length} bytes (max {maxConfigFileSize / 1024 / 1024}MB)");
                        MessageBox.Show(
                            LangManager.GetText("messages.importConfigFileTooLarge", maxConfigFileSize / 1024 / 1024),
                            LangManager.GetText("messages.errorTitle"),
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Warning);
                        return;
                    }

                    // Read config file
                    string json;
                    try
                    {
                        using (var fs = File.Open(importPath, FileMode.Open, FileAccess.Read, FileShare.None))
                        {
                            // Re-verify length (prevent TOCTOU)
                            if (fs.Length > maxConfigFileSize)
                            {
                                throw new Exception("Config file size exceeded limit");
                            }

                            byte[] configBytes = new byte[fs.Length];
                            int bytesRead = fs.Read(configBytes, 0, configBytes.Length);
                            if (bytesRead != configBytes.Length)
                            {
                                throw new Exception(LangManager.GetText("messages.importConfigInvalid"));
                            }
                            json = Encoding.UTF8.GetString(configBytes);
                        }
                    }
                    catch (Exception ex)
                    {
                        LogManager.Error(LangManager.GetText("logMessages.importConfigFailed", ex.Message), ex);
                        MessageBox.Show(LangManager.GetText("messages.importConfigInvalid"), LangManager.GetText("messages.importConfigInvalidTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }

                    // Parse config file
                    try
                    {
                        var importConfig = JsonSerializer.Deserialize<ImportConfig>(json, ComHelper.SafeJsonOptions);

                        if (importConfig == null || importConfig.Targets == null)
                        {
                            MessageBox.Show(LangManager.GetText("messages.importConfigInvalid"), LangManager.GetText("messages.importConfigInvalidTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }

                        // Check version compatibility
                        if (!string.Equals(importConfig.Version, "1.0", StringComparison.OrdinalIgnoreCase))
                        {
                            MessageBox.Show(LangManager.GetText("messages.importConfigVersionMismatch"), LangManager.GetText("messages.importConfigVersionMismatchTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }

                        // Clear current monitored targets
                        monitoredTargets.Clear();
                        folderListBox.Items.Clear();

                        // Import new monitored targets
                        int addedCount = 0;
                        int skippedCount = 0;

                        foreach (var target in importConfig.Targets)
                        {
                            if (target == null || string.IsNullOrWhiteSpace(target.Path))
                            {
                                skippedCount++;
                                continue;
                            }

                            // Validate path
                            bool isDirectory = !target.IsExe;
                            string normalizedPath = NormalizeAndValidatePath(target.Path, isDirectory);
                            if (normalizedPath == null)
                            {
                                skippedCount++;
                                LogManager.Warning($"Path validation failed during import: {target.Path}");
                                continue;
                            }

                            bool exists = Directory.Exists(normalizedPath) ||
                                          (File.Exists(normalizedPath) &&
                                           normalizedPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));

                            if (exists && TryAddPathToMonitoring(normalizedPath) != null)
                            {
                                addedCount++;
                            }
                            else
                            {
                                skippedCount++;
                                LogManager.Warning($"Path does not exist during import: {normalizedPath}");
                            }
                        }

                        // Save config
                        SaveMonitoredTargets();

                        // Rebuild watchers: without this the watchers of removed directories keep
                        // creating rules in the background and imported directories are not monitored.
                        if (autoMonitorCheckBox.Checked)
                        {
                            InitializeFileWatchers();
                        }

                        LogManager.Info($"Config imported: {addedCount} targets added, {skippedCount} skipped");
                        MessageBox.Show(
                            $"{LangManager.GetText("messages.importConfigSuccess")}\n{LangManager.GetText("logMessages.loadedMonitorTargetsFromConfig", addedCount, skippedCount)}",
                            LangManager.GetText("messages.importConfigSuccessTitle"),
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Information);
                    }
                    catch (JsonException ex)
                    {
                        LogManager.Error(LangManager.GetText("logMessages.importConfigFailed", ex.Message), ex);
                        MessageBox.Show(LangManager.GetText("messages.importConfigInvalid"), LangManager.GetText("messages.importConfigInvalidTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.importConfigFailed", ex.Message), ex);
                MessageBox.Show(LangManager.GetText("messages.importConfigFailed", ex.Message), LangManager.GetText("messages.importConfigFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Import config data structure
        /// </summary>
        private class ImportConfig
        {
            public string Version { get; set; }
            public string ExportDate { get; set; }
            public List<ImportTarget> Targets { get; set; }
        }

        /// <summary>
        /// Import target data structure
        /// </summary>
        private class ImportTarget
        {
            public string Path { get; set; }
            public bool IsExe { get; set; }
        }

        #endregion

        #region Form Events

        /// <summary>
        /// Form closing event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (e.CloseReason == CloseReason.UserClosing)
            {
                // User clicked close button, minimize to tray
                e.Cancel = true;
                this.Hide();
                trayIcon.ShowBalloonTip(1000, LangManager.GetText("app.trayTitle"), LangManager.GetText("messages.trayMinimized"), ToolTipIcon.Info);
            }
            else
            {
                // Non-user close (e.g., Task Manager, system shutdown), release resources
                ReleaseResources();
            }
        }

        #endregion

        #region Event Handler Methods

        /// <summary>
        /// Paste menu item click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void pasteMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                // Use retry mechanism to access clipboard
                string clipboardText = null;
                int retryCount = 5; // Increase retry count
                for (int i = 0; i < retryCount; i++)
                {
                    try
                    {
                        if (Clipboard.ContainsText())
                        {
                            clipboardText = Clipboard.GetText();
                            if (!string.IsNullOrEmpty(clipboardText))
                            {
                                break; // Successfully retrieved text, exit loop
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        // Increase retry interval, doubling each time
                        System.Diagnostics.Debug.WriteLine($"Clipboard retry {i + 1} failed: {ex.Message}");
                        System.Threading.Thread.Sleep(100 * (i + 1));
                    }
                }

                if (string.IsNullOrWhiteSpace(clipboardText))
                {
                    MessageBox.Show(LangManager.GetText("messages.clipboardEmpty"), LangManager.GetText("messages.clipboardEmptyTitle"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                
                // Limit clipboard content size
                if (clipboardText.Length > 1024 * 1024)
                {
                    LogManager.Warning(LangManager.GetText("logMessages.clipboardContentTooLarge"));
                    MessageBox.Show(LangManager.GetText("messages.clipboardTooLarge"), LangManager.GetText("messages.clipboardTooLargeTitle"), MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                // Parse paths (supports multiple separators: \r\n, \n, \r)
                string[] paths = clipboardText.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                if (paths.Length > 1000)
                {
                    LogManager.Warning(LangManager.GetText("logMessages.tooManyPastedPaths", paths.Length));
                    MessageBox.Show(LangManager.GetText("messages.tooManyPaths", paths.Length.ToString()), LangManager.GetText("messages.tooManyPathsTitle"), MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                
                int addedCount = 0;
                int invalidCount = 0;
                
                LogManager.Info($"Processing {paths.Length} pasted paths...");

                foreach (string path in paths)
                {
                    string trimmedPath = path.Trim();
                    if (string.IsNullOrWhiteSpace(trimmedPath))
                        continue;

                    // Filter control characters
                    trimmedPath = System.Text.RegularExpressions.Regex.Replace(
                        trimmedPath, @"[\x00-\x1F\x7F]", string.Empty);
                    if (string.IsNullOrWhiteSpace(trimmedPath))
                        continue;

                    LogManager.Info($"Processing path: '{trimmedPath}'");

                    // Probe the path only after confirming it cannot reach a remote host: Directory.Exists
                    // on a UNC path would send the current user's NTLM credentials to that host.
                    if (!ComHelper.IsLocalPathCandidate(trimmedPath))
                    {
                        LogManager.Warning($"Path rejected (network or device path): '{trimmedPath}'");
                        invalidCount++;
                        continue;
                    }

                    // First try to validate as directory, then as file
                    string normalizedPath = null;
                    if (Directory.Exists(trimmedPath))
                    {
                        normalizedPath = NormalizeAndValidatePath(trimmedPath, true);
                    }
                    else if (File.Exists(trimmedPath))
                    {
                        normalizedPath = NormalizeAndValidatePath(trimmedPath, false);
                    }
                    else
                    {
                        LogManager.Warning($"Path does not exist: '{trimmedPath}'");
                        invalidCount++;
                        continue;
                    }
                    
                    if (normalizedPath == null)
                    {
                        LogManager.Warning($"Path validation failed: '{trimmedPath}'");
                        invalidCount++;
                        continue;
                    }
                    
                    bool isDirectory = Directory.Exists(normalizedPath);
                    bool isExeFile = File.Exists(normalizedPath) && normalizedPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
                    
                    if ((isDirectory || isExeFile) && TryAddPathToMonitoring(normalizedPath) != null)
                    {
                        addedCount++;
                        LogManager.Info($"Added: '{normalizedPath}'");
                    }
                    else
                    {
                        invalidCount++;
                    }
                }
                
                if (addedCount > 0)
                {
                    LogManager.Info($"Pasted {addedCount} paths successfully");
                    SaveMonitoredTargets();
                    
                    if (invalidCount > 0)
                    {
                        MessageBox.Show(
                            string.Format(LangManager.GetText("messages.pastePartialSuccess"), addedCount, invalidCount),
                            LangManager.GetText("messages.pastePartialSuccessTitle"),
                            MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
                else
                {
                    MessageBox.Show(LangManager.GetText("messages.noValidPath"), LangManager.GetText("messages.noValidPathTitle"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("messages.pasteFailed"), ex);
                MessageBox.Show(LangManager.GetText("messages.pasteFailedMessage", ex.Message), LangManager.GetText("messages.pasteFailedMessageTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Add executable file menu item click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void addExeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            // Open file selection dialog
            using (var openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Title = LangManager.GetText("messages.selectExeFile");
                openFileDialog.Filter = LangManager.GetText("messages.exeFileFilter");
                openFileDialog.Multiselect = false;
                
                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    string selectedPath = openFileDialog.FileName;
                    
                    // Normalize and validate path
                    string normalizedPath = NormalizeAndValidatePath(selectedPath, false);
                    if (normalizedPath == null)
                    {
                        MessageBox.Show(LangManager.GetText("messages.invalidPath"), LangManager.GetText("messages.errorTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                    
                    if (normalizedPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    {
                        if (TryAddPathToMonitoring(normalizedPath) != null)
                        {
                            SaveMonitoredTargets(); // Save monitored targets
                            LogManager.Info(LangManager.GetText("logMessages.addExeToMonitor", normalizedPath));
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Show main form menu item click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void showMainFormToolStripMenuItem_Click(object sender, EventArgs e)
        {
            this.Show();
            this.WindowState = FormWindowState.Normal;
        }

        /// <summary>
        /// Update rules menu item click event
        /// </summary>
        private void updateRulesTrayToolStripMenuItem_Click(object sender, EventArgs e)
        {
            StartUpdateRulesTask();
            trayIcon.ShowBalloonTip(1000, LangManager.GetText("app.trayTitle"), LangManager.GetText("status.updatingRules"), ToolTipIcon.Info);
        }

        /// <summary>
        /// Exit menu item click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void exitToolStripMenuItem_Click(object sender, EventArgs e)
        {
            // Release resources
            ReleaseResources();
            Application.Exit();
        }

        /// <summary>
        /// Tray icon double click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void trayIcon_MouseDoubleClick(object sender, MouseEventArgs e)
        {
            this.Show();
            this.WindowState = FormWindowState.Normal;
        }

        /// <summary>
        /// Form resize event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void Form1_Resize(object sender, EventArgs e)
        {
            if (this.WindowState == FormWindowState.Minimized)
            {
                this.Hide();
            }
        }

        #endregion
    }
}