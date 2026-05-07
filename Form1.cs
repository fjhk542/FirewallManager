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
    /// 防火墙管理器主窗体
    /// 负责监控指定目录中的可执行文件，并自动创建防火墙规则拦截其出站连接
    /// </summary>
    public partial class Form1 : Form
    {
        #region 类定义

        /// <summary>
        /// 扫描目标类
        /// 用于表示需要监控的文件夹或单个可执行文件
        /// </summary>
        public class ScanTarget
        {
            /// <summary>
            /// 扫描目标的路径
            /// </summary>
            public string Path { get; set; }

            /// <summary>
            /// 是否为单个可执行文件
            /// True: 单个可执行文件
            /// False: 文件夹
            /// </summary>
            public bool IsExe { get; set; }

            /// <summary>
            /// 显示名称，用于ListBox显示
            /// </summary>
            public string DisplayName => Path;

            /// <summary>
            /// 构造函数
            /// </summary>
            /// <param name="path">扫描目标的路径</param>
            public ScanTarget(string path)
            {
                Path = path;
                IsExe = File.Exists(path) && System.IO.Path.GetExtension(path).Equals(".exe", StringComparison.OrdinalIgnoreCase);
            }

            /// <summary>
            /// 重写ToString方法，用于ListBox显示
            /// </summary>
            /// <returns>显示名称</returns>
            public override string ToString()
            {
                return DisplayName;
            }
        }

        #endregion

        #region 字段定义

        /// <summary>
        /// 防火墙服务
        /// </summary>
        private IFirewallService firewallService;

        /// <summary>
        /// 监控目标列表
        /// </summary>
        private readonly List<ScanTarget> monitoredTargets = new List<ScanTarget>();

        /// <summary>
        /// 当前工作状态
        /// </summary>
        private WorkState currentState = WorkState.Idle;

        /// <summary>
        /// 取消令牌源
        /// </summary>
        private CancellationTokenSource cancellationTokenSource;

        /// <summary>
        /// 工作线程
        /// </summary>
        private Task workTask;

        /// <summary>
        /// 任务完成事件
        /// </summary>
        private readonly ManualResetEvent taskCompletedEvent = new ManualResetEvent(true);
        
        /// <summary>
        /// 暂停事件
        /// </summary>
        private readonly ManualResetEvent pauseEvent = new ManualResetEvent(true);

        /// <summary>
        /// 日志管理器
        /// </summary>
        // LogManager 是静态类，不需要创建实例



        /// <summary>
        /// 释放资源
        /// 释放所有托管和非托管资源，包括取消令牌源、事件对象、防火墙服务和文件监控器
        /// </summary>
        private void ReleaseResources()
        {
            try
            {
                // 释放 CancellationTokenSource
                cancellationTokenSource?.Dispose();
                
                // 释放手动重置事件
                taskCompletedEvent?.Dispose();
                pauseEvent?.Dispose();
                
                // 释放防火墙服务
                firewallService?.Dispose();
                
                // 释放文件监控器
                foreach (var watcher in watchers)
                {
                    watcher.Dispose();
                }
                watchers.Clear();
                
                // 释放白名单静态资源
                WhitelistForm.ReleaseStaticResources();
                
                LogManager.Info(LangManager.GetText("logMessages.resourcesReleased"));
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.releaseResourcesFailed"), ex);
            }
        }

        /// <summary>
        /// 重写 Dispose 方法，确保资源正确释放
        /// </summary>
        /// <param name="disposing">是否释放托管资源</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                // 释放托管资源
                ReleaseResources();
            }
            base.Dispose(disposing);
        }

        

        /// <summary>
        /// 规范化和验证路径
        /// </summary>
        /// <param name="path">输入路径</param>
        /// <param name="isDirectory">是否为目录</param>
        /// <returns>规范化后的路径，如果路径无效则返回 null</returns>
        private string NormalizeAndValidatePath(string path, bool isDirectory)
        {
            try
            {
                if (string.IsNullOrEmpty(path))
                {
                    return null;
                }

                // 规范化路径
                string normalizedPath = Path.GetFullPath(path);

                // 检查路径是否存在
                if (isDirectory && !Directory.Exists(normalizedPath))
                {
                    return null;
                }
                if (!isDirectory && !File.Exists(normalizedPath))
                {
                    return null;
                }

                // 检查是否为系统根目录（如 C:\），避免扫描整个系统
                string rootPath = Path.GetPathRoot(normalizedPath);
                if (normalizedPath.Equals(rootPath, StringComparison.OrdinalIgnoreCase))
                {
                    LogManager.Warning(LangManager.GetText("logMessages.rejectSystemRoot", normalizedPath));
                    return null;
                }

                return normalizedPath;
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.pathValidationFailed", path), ex);
                return null;
            }
        }

        private List<System.IO.FileSystemWatcher> watchers = new List<System.IO.FileSystemWatcher>();
        #endregion

        #region 构造函数

        /// <summary>
        /// 默认构造函数（供设计器使用）
        /// </summary>
        public Form1() : this(new FirewallService())
        {
        }

        /// <summary>
        /// 带依赖注入的构造函数
        /// </summary>
        /// <param name="firewallService">防火墙服务</param>
        public Form1(IFirewallService firewallService)
        {
            this.firewallService = firewallService ?? throw new ArgumentNullException(nameof(firewallService));
            
            try
            {
                InitializeComponent();
                
                // 检查语言资源是否已加载，如果没有加载则尝试重新加载
                if (!LangManager.IsLanguageLoaded())
                {
                    System.Diagnostics.Debug.WriteLine("语言资源未加载，尝试重新加载...");
                    LangManager.ReloadLanguageFiles();
                }
                
                // 设置UI控件文本
                SetUIControlsText();
                
                // 记录程序启动
                LogManager.Info(LangManager.GetText("logMessages.startup"));

                // 检查管理员权限
                if (!IsRunningAsAdministrator())
                {
                    HandleNotAdmin();
                    return;
                }

                // 初始化权限拆分架构
                InitializePermissionArchitecture();

                // 确保托盘图标在InitializeComponent后就显示
                InitializeTrayIcon();
                
                // 加载监控目标（无论防火墙是否初始化成功都需要加载）
                LoadMonitoredTargets();
            }
            catch (Exception ex)
            {
                // 捕获所有未处理的异常
                HandleStartupError(ex);
            }
        }

        #endregion

        #region 初始化方法

        /// <summary>
        /// 初始化权限拆分架构
        /// 设计用于分离管理员权限和普通用户权限
        /// </summary>
        private void InitializePermissionArchitecture()
        {
            // 记录权限状态
            bool isAdmin = IsRunningAsAdministrator();
            LogManager.Info(LangManager.GetText("logMessages.permissionStatus", isAdmin ? LangManager.GetText("messages.admin") : LangManager.GetText("messages.user")));
        }

        /// <summary>
        /// 初始化托盘图标
        /// </summary>
        private void InitializeTrayIcon()
        {
            try
            {
                // 在构造函数中，我们已经在UI线程上，直接初始化托盘图标
                // 无需使用SafeInvoke，因为InvokeRequired会返回false
                trayIcon.Icon = this.Icon; // 使用应用程序图标作为托盘图标
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
        /// 初始化防火墙组件
        /// </summary>
        private void InitializeFirewallComponents()
        {
            try
            {
                // 先加载监控目标（无论防火墙是否初始化成功都需要加载）
                LoadMonitoredTargets();
                
                // 初始化防火墙组件（firewallService已通过构造函数注入）
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
                
                // 禁用所有与防火墙相关的功能按钮
                SafeInvoke(() =>
                {
                    addButton.Enabled = false;
                    updateRulesButton.Enabled = false;
                    clearRulesButton.Enabled = false;
                    removeFolderButton.Enabled = false;
                    whitelistButton.Enabled = false;
                    pauseButton.Enabled = false;
                    resumeButton.Enabled = false;
                    stopButton.Enabled = false;
                    statusLabel.Text = LangManager.GetText("status.firewallError");
                });
            }
        }
        
        /// <summary>
        /// 初始化文件系统监控器
        /// </summary>
        private void InitializeFileWatchers()
        {
            try
            {
                // 停止现有的监控器
                StopFileWatchers();
                
                // 为每个监控目标创建监控器
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
        /// 创建文件系统监控器
        /// </summary>
        /// <param name="path">监控路径</param>
        private void CreateFileWatcher(string path)
        {
            try
            {
                var watcher = new System.IO.FileSystemWatcher();
                watcher.Path = path;
                watcher.Filter = "*.exe";
                watcher.IncludeSubdirectories = true;
                
                // 订阅事件
                watcher.Created += FileSystemWatcher_Created;
                watcher.Renamed += FileSystemWatcher_Renamed;
                
                // 启动监控
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
        /// 停止文件系统监控器
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
        /// 文件创建事件处理
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void FileSystemWatcher_Created(object sender, System.IO.FileSystemEventArgs e)
        {
            try
            {
                LogManager.Info(LangManager.GetText("logMessages.newFileDetected", e.FullPath));
                // 为新创建的EXE文件创建防火墙规则
                firewallService.CreateRuleForExe(e.FullPath);
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.processFileCreatedEventFailed"), ex);
            }
        }
        
        /// <summary>
        /// 文件重命名事件处理
        /// File renamed event handler
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void FileSystemWatcher_Renamed(object sender, System.IO.RenamedEventArgs e)
        {
            try
            {
                LogManager.Info(LangManager.GetText("logMessages.fileRenamed", e.OldFullPath, e.FullPath));
                // 为新名称创建规则，删除旧规则
                firewallService.CreateRuleForExe(e.FullPath);
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.processFileRenamedEventFailed"), ex);
            }
        }
        
        #endregion

        #region UI相关方法

        /// <summary>
        /// 设置UI控件文本
        /// Set UI control text
        /// </summary>
        private void SetUIControlsText()
        {
            // 设置窗口标题
            this.Text = LangManager.GetText("app.title");

            // 设置按钮文本
            addButton.Text = LangManager.GetText("buttons.add");
            updateRulesButton.Text = LangManager.GetText("buttons.updateRules");
            clearRulesButton.Text = LangManager.GetText("buttons.clearRules");
            removeFolderButton.Text = LangManager.GetText("buttons.removeFolder");
            pauseButton.Text = LangManager.GetText("buttons.pause");
            resumeButton.Text = LangManager.GetText("buttons.resume");
            stopButton.Text = LangManager.GetText("buttons.stop");
            viewLogsButton.Text = LangManager.GetText("buttons.viewLogs");
            whitelistButton.Text = LangManager.GetText("buttons.whitelist");

            // 设置上下文菜单项文本
            pasteMenuItem.Text = LangManager.GetText("menu.paste");
            addFolderToolStripMenuItem.Text = LangManager.GetText("menu.addFolder");
            addExeToolStripMenuItem.Text = LangManager.GetText("menu.addFile");

            // 设置托盘菜单项文本
            showMainFormToolStripMenuItem.Text = LangManager.GetText("menu.showMainForm");
            updateRulesTrayToolStripMenuItem.Text = LangManager.GetText("menu.updateRules");
            exitToolStripMenuItem.Text = LangManager.GetText("menu.exit");

            // 设置自动监控复选框文本
            autoMonitorCheckBox.Text = LangManager.GetText("menu.autoMonitor");

            // 设置语言下拉框
            if (languageComboBox.Items.Count == 0)
            {
                languageComboBox.Items.Add(LangManager.GetText("language.chinese"));
                languageComboBox.Items.Add(LangManager.GetText("language.english"));
            }
            // 设置当前语言为选中项
            string currentLang = LangManager.GetCurrentLanguage();
            languageComboBox.SelectedIndex = currentLang == "zh" ? 0 : 1;

            // 设置文件对话框文本
            openFileDialog.Title = LangManager.GetText("messages.selectExeFile");
            openFileDialog.Filter = LangManager.GetText("messages.exeFileFilter");
        }

        /// <summary>
        /// 线程安全的UI更新方法
        /// Thread-safe UI update method
        /// 检查是否需要跨线程调用，确保UI操作在主线程上执行
        /// Check if cross-thread invoke is needed and ensure UI operations are executed on main thread
        /// </summary>
        /// <param name="action">要在UI线程上执行的操作</param>
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
        /// 更新UI状态
        /// Update UI state
        /// </summary>
        /// <param name="state">工作状态</param>
        /// <param name="statusText">状态文本</param>
        private void UpdateUI(WorkState state, string statusText)
        {
            SafeInvoke(() =>
            {
                currentState = state;
                statusLabel.Text = statusText;
                
                // 根据状态启用/禁用按钮
                bool isIdle = (state == WorkState.Idle);
                bool isRunning = (state == WorkState.Running);
                bool isPaused = (state == WorkState.Paused);
                bool isStopping = (state == WorkState.Stopping);
                
                // 主要操作按钮
                addButton.Enabled = isIdle;
                updateRulesButton.Enabled = isIdle;
                clearRulesButton.Enabled = isIdle;
                removeFolderButton.Enabled = isIdle;
                whitelistButton.Enabled = isIdle;
                
                // 运行控制按钮
                pauseButton.Enabled = isRunning;
                resumeButton.Enabled = isPaused;
                stopButton.Enabled = isRunning || isPaused;
                
                // 更新进度条可见性
                progressBar.Style = isRunning ? ProgressBarStyle.Marquee : ProgressBarStyle.Blocks;
                progressBar.MarqueeAnimationSpeed = isRunning ? 30 : 0;
            });
        }

        #endregion

        #region 权限相关方法

        /// <summary>
        /// 检查是否以管理员身份运行
        /// Check if running as administrator
        /// 通过检查当前用户是否属于管理员角色来判断
        /// Determine by checking if current user is in administrator role
        /// </summary>
        /// <returns>是否以管理员身份运行</returns>
        /// <returns>true if running as administrator; false otherwise</returns>
        private bool IsRunningAsAdministrator()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        /// <summary>
        /// 处理非管理员权限情况
        /// Handle non-admin permission case
        /// 记录错误日志并提示用户需要以管理员身份运行，然后退出应用程序
        /// Log error and prompt user that administrator privileges are required, then exit application
        /// </summary>
        private void HandleNotAdmin()
        {
            LogManager.Error(LangManager.GetText("logMessages.notAdmin"));
            MessageBox.Show(LangManager.GetText("messages.notAdmin"), LangManager.GetText("messages.notAdminTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            Application.Exit();
        }

        #endregion

        #region 防火墙相关方法

        /// <summary>
        /// 缓存防火墙规则
        /// Cache firewall rules
        /// </summary>
        private void CacheFirewallRules()
        {
            try
            {
                LogManager.Info(LangManager.GetText("logMessages.refreshCache"));
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.refreshCacheFailed"), ex);
            }
        }

        /// <summary>
        /// 加载监控文件夹
        /// Load monitored folders
        /// </summary>
        private void LoadMonitoredFolders()
        {
            try
            {
                // 这里可以从配置文件加载监控文件夹
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.loadingFoldersFailed", ex.Message), ex);
                // 向用户反馈错误
                this.Invoke((MethodInvoker)delegate
                {
                    MessageBox.Show(LangManager.GetText("logMessages.loadingFoldersFailed", ex.Message), LangManager.GetText("messages.pathErrorTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                });
            }
        }

        /// <summary>
        /// 加载已添加的规则
        /// Load added rules
        /// </summary>
        private void LoadAddedRules()
        {
            try
            {
                // 这里可以从配置文件加载已添加的规则
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.loadingRulesFailed"), ex);
                // 向用户反馈错误
                this.Invoke((MethodInvoker)delegate
                {
                    MessageBox.Show(LangManager.GetText("logMessages.loadingRulesFailed"), LangManager.GetText("messages.pathErrorTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                });
            }
        }

        /// <summary>
        /// 保存监控目标到配置文件
        /// Save monitored targets to config file
        /// </summary>
        private void SaveMonitoredTargets()
        {
            try
            {
                string configPath = Config.GetAppDataFilePath(Config.CONFIG_FILE);
                string configDir = Path.GetDirectoryName(configPath);
                if (string.IsNullOrEmpty(configDir) || configDir.Equals(Path.GetFileName(configPath), StringComparison.OrdinalIgnoreCase))
                {
                    LogManager.Error($"Invalid config path: {configPath}");
                    return;
                }
                if (!Directory.Exists(configDir))
                {
                    Directory.CreateDirectory(configDir);
                }

                var targets = monitoredTargets.Select(t => t.Path).ToList();
                string json = JsonSerializer.Serialize(targets, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(configPath, json, Encoding.UTF8);

                LogManager.Info(LangManager.GetText("logMessages.monitoringTargetsSaved"));
            }
            catch (UnauthorizedAccessException ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.saveMonitoringTargetsFailed") + " - Access denied", ex);
                MessageBox.Show(LangManager.GetText("messages.saveFailedAccessDenied"), LangManager.GetText("messages.errorTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.saveMonitoringTargetsFailed"), ex);
                MessageBox.Show(LangManager.GetText("messages.saveMonitoringTargetsFailed", ex.Message), LangManager.GetText("messages.errorTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// 加载监控目标从配置文件
        /// Load monitored targets from config file
        /// </summary>
        private void LoadMonitoredTargets()
        {
            try
            {
                string configPath = Config.GetAppDataFilePath(Config.CONFIG_FILE);
                LogManager.Info($"Loading monitored targets from: {configPath}");

                if (File.Exists(configPath))
                {
                    string json = File.ReadAllText(configPath, Encoding.UTF8);
                    LogManager.Info($"Config file content length: {json.Length} characters");

                    if (string.IsNullOrWhiteSpace(json))
                    {
                        LogManager.Warning("Config file is empty");
                        return;
                    }

                    var paths = JsonSerializer.Deserialize<List<string>>(json);

                    if (paths == null)
                    {
                        LogManager.Warning("Failed to deserialize paths from config file");
                        return;
                    }

                    int addedCount = 0;
                    int skippedCount = 0;
                    foreach (var path in paths)
                    {
                        bool exists = Directory.Exists(path) || (File.Exists(path) && path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));
                        bool alreadyAdded = monitoredTargets.Any(t => t.Path.Equals(path, StringComparison.OrdinalIgnoreCase));

                        if (exists && !alreadyAdded)
                        {
                            var target = new ScanTarget(path);
                            monitoredTargets.Add(target);
                            folderListBox.Items.Add(target);
                            addedCount++;
                        }
                        else
                        {
                            skippedCount++;
                            if (!exists)
                            {
                                LogManager.Warning($"Path no longer exists, skipping: {path}");
                            }
                            else if (alreadyAdded)
                            {
                                LogManager.Warning($"Path already added, skipping: {path}");
                            }
                        }
                    }
                    LogManager.Info(LangManager.GetText("logMessages.loadedMonitorTargetsFromConfig", addedCount, skippedCount));
                }
                else
                {
                    LogManager.Info("Config file does not exist, no targets to load");
                }
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
        /// 查看规则详情
        /// View rule details
        /// </summary>
        /// <param name="ruleName">规则名称</param>
        private void ViewRuleDetails(string ruleName)
        {
            try
            {
                dynamic rule = firewallService.GetRuleDetails(ruleName);
                if (rule != null)
                {
                    var detailsForm = new RuleDetailsForm(rule, ruleName);
                    detailsForm.ShowDialog();
                }
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.viewRuleDetailsFailed", ex.Message));
                MessageBox.Show(LangManager.GetText("messages.viewRulesDetailsFailed", ex.Message), LangManager.GetText("messages.viewRulesDetailsFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        #endregion

        #region 错误处理

        /// <summary>
        /// 处理启动错误
        /// Handle startup error
        /// </summary>
        /// <param name="ex">异常对象</param>
        private void HandleStartupError(Exception ex)
        {
            LogManager.Error(LangManager.GetText("logMessages.startupFailed"), ex);
            MessageBox.Show(LangManager.GetText("messages.startupFailed"), LangManager.GetText("messages.startupFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            Application.Exit();
        }

        #endregion

        #region 事件处理

        /// <summary>
        /// 添加按钮点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void addButton_Click(object sender, EventArgs e)
        {
            addContextMenu.Show(addButton, new System.Drawing.Point(0, addButton.Height));
        }
        
        /// <summary>
        /// 添加文件夹菜单项点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void addFolderToolStripMenuItem_Click(object sender, EventArgs e)
        {
            // 打开文件夹选择对话框
            using (var folderDialog = new FolderBrowserDialog())
            {
                folderDialog.Description = LangManager.GetText("buttons.addFolder");
                if (folderDialog.ShowDialog() == DialogResult.OK)
                {
                    string selectedPath = folderDialog.SelectedPath;
                    
                    // 规范化和验证路径
                    string normalizedPath = NormalizeAndValidatePath(selectedPath, true);
                    if (normalizedPath == null)
                    {
                        MessageBox.Show(LangManager.GetText("messages.invalidPath"), LangManager.GetText("messages.errorTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                    
                    if (!monitoredTargets.Any(t => t.Path.Equals(normalizedPath, StringComparison.OrdinalIgnoreCase)))
                    {
                        var target = new ScanTarget(normalizedPath);
                        monitoredTargets.Add(target);
                        folderListBox.Items.Add(target);
                        SaveMonitoredTargets(); // 保存监控目标
                        LogManager.Info(LangManager.GetText("logMessages.addFolderToMonitor", normalizedPath));
                        
                        // 如果自动监控已启用，为新添加的文件夹创建监控器
                        if (autoMonitorCheckBox.Checked && !target.IsExe)
                        {
                            CreateFileWatcher(normalizedPath);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// 更新规则按钮点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void updateRulesButton_Click(object sender, EventArgs e)
        {
            // 启动更新规则任务
            if (currentState == WorkState.Idle)
            {
                // 释放旧的 CancellationTokenSource
                cancellationTokenSource?.Dispose();
                cancellationTokenSource = new CancellationTokenSource();
                taskCompletedEvent.Reset();
                
                workTask = Task.Run(async () =>
                {
                    try
                    {
                        await UpdateFirewallRules(cancellationTokenSource.Token);
                    }
                    finally
                    {
                        taskCompletedEvent.Set();
                    }
                }, cancellationTokenSource.Token);
                
                UpdateUI(WorkState.Running, LangManager.GetText("status.running"));
            }
        }

        /// <summary>
        /// 清空规则按钮点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void clearRulesButton_Click(object sender, EventArgs e)
        {
            // 清空所有防火墙规则
            try
            {
                LogManager.Info(LangManager.GetText("logMessages.clearingAllRules"));
                
                // 确认操作
                if (MessageBox.Show(LangManager.GetText("messages.clearRulesConfirm"), LangManager.GetText("messages.clearRulesConfirmTitle"), MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                {
                    return;
                }
                
                // 使用防火墙服务清空规则
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
        /// 移除文件夹按钮点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void removeFolderButton_Click(object sender, EventArgs e)
        {
            if (folderListBox.SelectedItem is ScanTarget selectedTarget)
            {
                monitoredTargets.Remove(selectedTarget);
                folderListBox.Items.Remove(selectedTarget);
                SaveMonitoredTargets(); // 保存监控目标
                
                // 如果自动监控已启用，重新初始化文件系统监控器
                if (autoMonitorCheckBox.Checked)
                {
                    InitializeFileWatchers();
                }
            }
        }

        /// <summary>
        /// 查看日志按钮点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void viewLogsButton_Click(object sender, EventArgs e)
        {
            // 打开日志窗口
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
        /// 白名单管理按钮点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void whitelistButton_Click(object sender, EventArgs e)
        {
            // 打开白名单管理窗口
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
        /// 白名单保存事件处理
        /// Whitelist saved event handler
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void WhitelistForm_WhitelistSaved(object sender, EventArgs e)
        {
            // 白名单保存后，更新防火墙规则
            if (currentState == WorkState.Idle)
            {
                // 释放旧的 CancellationTokenSource
                cancellationTokenSource?.Dispose();
                cancellationTokenSource = new CancellationTokenSource();
                taskCompletedEvent.Reset();
                
                workTask = Task.Run(async () =>
                {
                    try
                    {
                        await UpdateFirewallRules(cancellationTokenSource.Token);
                    }
                    finally
                    {
                        taskCompletedEvent.Set();
                    }
                }, cancellationTokenSource.Token);
                
                UpdateUI(WorkState.Running, LangManager.GetText("status.running"));
            }
        }
        
        /// <summary>
        /// 自动监控复选框点击事件
        /// Auto monitor checkbox click event
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void autoMonitorCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            try
            {
                if (autoMonitorCheckBox.Checked)
                {
                    // 启用自动监控
                    InitializeFileWatchers();
                    LogManager.Info(LangManager.GetText("logMessages.autoMonitorEnabled"));
                    trayIcon.ShowBalloonTip(1000, LangManager.GetText("app.trayTitle"), LangManager.GetText("logMessages.autoMonitorEnabled"), ToolTipIcon.Info);
                }
                else
                {
                    // 禁用自动监控
                    StopFileWatchers();
                    LogManager.Info(LangManager.GetText("logMessages.autoMonitorDisabled"));
                    trayIcon.ShowBalloonTip(1000, LangManager.GetText("app.trayTitle"), LangManager.GetText("logMessages.autoMonitorDisabled"), ToolTipIcon.Info);
                }
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.toggleAutoMonitorFailed"), ex);
                autoMonitorCheckBox.Checked = false; // 恢复到未勾选状态
                MessageBox.Show(LangManager.GetText("logMessages.toggleAutoMonitorFailed") + ": " + ex.Message, LangManager.GetText("messages.errorTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// 语言切换下拉框选择改变事件
        /// Language combo box selection changed event
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void languageComboBox_SelectedIndexChanged(object sender, EventArgs e)
        {
            try
            {
                string newLanguage = languageComboBox.SelectedIndex == 0 ? "zh" : "en";
                string currentLang = LangManager.GetCurrentLanguage();
                
                if (newLanguage != currentLang)
                {
                    // 切换语言
                    LangManager.SetLanguage(newLanguage);
                    
                    // 重新设置UI文本
                    SetUIControlsText();
                    
                    // 更新托盘图标文本
                    trayIcon.Text = LangManager.GetText("app.trayText");
                    
                    // 显示提示
                    trayIcon.ShowBalloonTip(2000, LangManager.GetText("app.trayTitle"), LangManager.GetText("messages.languageChanged"), ToolTipIcon.Info);
                    
                    LogManager.Info($"Language changed to {newLanguage}");
                }
            }
            catch (Exception ex)
            {
                LogManager.Error("Failed to change language", ex);
                MessageBox.Show(LangManager.GetText("messages.errorTitle"), LangManager.GetText("messages.errorTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// 暂停按钮点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
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
        /// 继续按钮点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
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
        /// 停止按钮点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void stopButton_Click(object sender, EventArgs e)
        {
            if (currentState == WorkState.Running || currentState == WorkState.Paused)
            {
                // 如果处于暂停状态，先解除暂停以便任务能够响应取消
                if (currentState == WorkState.Paused)
                {
                    pauseEvent.Set();
                }
                
                // 取消任务
                cancellationTokenSource?.Cancel();
                UpdateUI(WorkState.Stopping, LangManager.GetText("status.stopping"));
                
                // 等待任务完成
                taskCompletedEvent.WaitOne(5000);
                
                // 重置暂停事件
                pauseEvent.Set();
                
                UpdateUI(WorkState.Idle, LangManager.GetText("status.ready"));
                LogManager.Info(LangManager.GetText("logMessages.taskStopped"));
            }
        }

        #endregion

        #region 防火墙规则更新

        /// <summary>
        /// 更新防火墙规则
        /// Update firewall rules
        /// </summary>
        /// <param name="cancellationToken">取消令牌</param>
        private async Task UpdateFirewallRules(CancellationToken cancellationToken)
        {
            try
            {
                // 等待暂停解除
                pauseEvent.WaitOne();
                
                // 再次检查取消请求（在暂停期间可能被取消）
                cancellationToken.ThrowIfCancellationRequested();
                
                // 使用防火墙服务更新规则
                var result = await firewallService.UpdateFirewallRules(monitoredTargets.Cast<dynamic>().ToList(), cancellationToken, (state, text) => UpdateUI(WorkState.Running, text));
                
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

        #region 托盘图标事件

        /// <summary>
        /// 托盘图标双击事件
        /// Tray icon double click event
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void trayIcon_DoubleClick(object sender, EventArgs e)
        {
            this.Show();
            this.WindowState = FormWindowState.Normal;
        }

        #endregion

        #region 窗体事件

        /// <summary>
        /// 窗体关闭事件
        /// Form closing event
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (e.CloseReason == CloseReason.UserClosing)
            {
                // 用户点击关闭按钮，最小化到托盘
                // User clicked close button, minimize to tray
                e.Cancel = true;
                this.Hide();
                trayIcon.ShowBalloonTip(1000, LangManager.GetText("app.trayTitle"), LangManager.GetText("messages.trayMinimized"), ToolTipIcon.Info);
            }
            else
            {
                // 非用户关闭（如任务管理器、系统关机等），释放资源
                // Non-user closing (e.g., Task Manager, system shutdown), release resources
                ReleaseResources();
            }
        }

        #endregion

        #region 事件处理方法

        /// <summary>
        /// 粘贴菜单项点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void pasteMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                string clipboardText = Clipboard.GetText();
                if (string.IsNullOrWhiteSpace(clipboardText))
                {
                    MessageBox.Show(LangManager.GetText("messages.clipboardEmpty"), LangManager.GetText("messages.clipboardEmptyTitle"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                
                string[] paths = clipboardText.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                int addedCount = 0;
                
                foreach (string path in paths)
                {
                    string trimmedPath = path.Trim();
                    if (string.IsNullOrWhiteSpace(trimmedPath))
                        continue;
                    
                    bool isDirectory = Directory.Exists(trimmedPath);
                    bool isFile = File.Exists(trimmedPath) && trimmedPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
                    
                    if (isDirectory || isFile)
                    {
                        // 规范化和验证路径
                        string normalizedPath = NormalizeAndValidatePath(trimmedPath, isDirectory);
                        if (normalizedPath == null)
                        {
                            LogManager.Warning(LangManager.GetText("logMessages.skipInvalidPath", trimmedPath));
                            continue;
                        }
                        
                        if (!monitoredTargets.Any(t => t.Path.Equals(normalizedPath, StringComparison.OrdinalIgnoreCase)))
                        {
                            var target = new ScanTarget(normalizedPath);
                            monitoredTargets.Add(target);
                            folderListBox.Items.Add(target);
                            addedCount++;
                        }
                    }
                }
                
                if (addedCount > 0)
                {
                    LogManager.Info(LangManager.GetText("logMessages.pastePathsSuccess", addedCount));
                    SaveMonitoredTargets(); // 保存监控目标
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
        /// 添加可执行文件菜单项点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void addExeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            // 打开文件选择对话框
            using (var openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Title = LangManager.GetText("messages.selectExeFile");
                openFileDialog.Filter = LangManager.GetText("messages.exeFileFilter");
                openFileDialog.Multiselect = false;
                
                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    string selectedPath = openFileDialog.FileName;
                    
                    // 规范化和验证路径
                    string normalizedPath = NormalizeAndValidatePath(selectedPath, false);
                    if (normalizedPath == null)
                    {
                        MessageBox.Show(LangManager.GetText("messages.invalidPath"), LangManager.GetText("messages.errorTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                    
                    if (normalizedPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    {
                        if (!monitoredTargets.Any(t => t.Path.Equals(normalizedPath, StringComparison.OrdinalIgnoreCase)))
                        {
                            var target = new ScanTarget(normalizedPath);
                            monitoredTargets.Add(target);
                            folderListBox.Items.Add(target);
                            SaveMonitoredTargets(); // 保存监控目标
                            LogManager.Info(LangManager.GetText("logMessages.addExeToMonitor", normalizedPath));
                        }
                    }
                }
            }
        }

        /// <summary>
        /// 显示主窗体菜单项点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void showMainFormToolStripMenuItem_Click(object sender, EventArgs e)
        {
            this.Show();
            this.WindowState = FormWindowState.Normal;
        }

        /// <summary>
        /// 更新规则菜单项点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void updateRulesTrayToolStripMenuItem_Click(object sender, EventArgs e)
        {
            // 启动更新规则任务
            if (currentState == WorkState.Idle)
            {
                // 释放旧的 CancellationTokenSource
                cancellationTokenSource?.Dispose();
                cancellationTokenSource = new CancellationTokenSource();
                taskCompletedEvent.Reset();
                
                workTask = Task.Run(async () =>
                {
                    try
                    {
                        await UpdateFirewallRules(cancellationTokenSource.Token);
                    }
                    finally
                    {
                        taskCompletedEvent.Set();
                    }
                }, cancellationTokenSource.Token);
                
                UpdateUI(WorkState.Running, LangManager.GetText("status.running"));
                
                // 显示系统托盘通知
                trayIcon.ShowBalloonTip(1000, LangManager.GetText("app.trayTitle"), LangManager.GetText("status.updatingRules"), ToolTipIcon.Info);
            }
        }

        /// <summary>
        /// 退出菜单项点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void exitToolStripMenuItem_Click(object sender, EventArgs e)
        {
            // 释放资源
            ReleaseResources();
            Application.Exit();
        }

        /// <summary>
        /// 托盘图标双击事件
        /// Tray icon double click event
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void trayIcon_MouseDoubleClick(object sender, MouseEventArgs e)
        {
            this.Show();
            this.WindowState = FormWindowState.Normal;
        }

        /// <summary>
        /// 窗体调整大小事件
        /// Form resize event
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
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