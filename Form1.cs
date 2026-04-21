﻿﻿﻿using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace FirewallManager
{
    #region COM Interop Interfaces

    [ComImport]
    [Guid("743B5F60-8191-11D1-B944-00AA006B32A4")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface INetFwPolicy2
    {
        int CurrentProfileTypes { get; set; }
        INetFwRules Rules { get; }
        // Add other properties and methods as needed
    }

    [ComImport]
    [Guid("2C5BC43E-6559-4762-9011-98D5CBB1C1BC")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface INetFwRules
    {
        int Count { get; }
        void Add([MarshalAs(UnmanagedType.Interface)] INetFwRule rule);
        void Remove(string name);
        INetFwRule Item(string name);
        System.Collections.IEnumerator GetEnumerator();
    }

    [ComImport]
    [Guid("AF230C27-4F5F-11D1-B2E4-08002B10409F")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface INetFwRule
    {
        string Name { get; set; }
        string Description { get; set; }
        string ApplicationName { get; set; }
        string ServiceName { get; set; }
        int Protocol { get; set; }
        string LocalPorts { get; set; }
        string RemotePorts { get; set; }
        string LocalAddresses { get; set; }
        string RemoteAddresses { get; set; }
        int ICMPTypeAndCode { get; set; }
        int Direction { get; set; }
        int Action { get; set; }
        int Profiles { get; set; }
        bool Enabled { get; set; }
        string EdgeTraversal { get; set; }
    }

    public enum NET_FW_DIRECTION_
    {
        NET_FW_DIRECTION_IN = 1,
        NET_FW_DIRECTION_OUT = 2,
    }

    public enum NET_FW_ACTION_
    {
        NET_FW_ACTION_BLOCK = 0,
        NET_FW_ACTION_ALLOW = 1,
    }

    public enum NET_FW_IP_PROTOCOL_
    {
        NET_FW_IP_PROTOCOL_ANY = 256,
        NET_FW_IP_PROTOCOL_TCP = 6,
        NET_FW_IP_PROTOCOL_UDP = 17,
    }

    #endregion

    /// <summary>
    /// 防火墙管理器主窗体
    /// Firewall Manager Main Form
    /// 负责监控指定目录中的可执行文件，并自动创建防火墙规则拦截其出站连接
    /// Responsible for monitoring executable files in specified directories and automatically creating firewall rules to block their outbound connections
    /// </summary>
    public partial class Form1 : Form
    {
        #region 类定义

        /// <summary>
        /// 扫描目标类
        /// Scan Target Class
        /// 用于表示需要监控的文件夹或单个可执行文件
        /// Used to represent folders or individual executable files that need to be monitored
        /// </summary>
        public class ScanTarget
        {
            /// <summary>
            /// 扫描目标的路径
            /// Path of the scan target
            /// </summary>
            public string Path { get; set; }

            /// <summary>
            /// 是否为单个可执行文件
            /// Whether it is a single executable file
            /// True: 单个可执行文件
            /// True: Single executable file
            /// False: 文件夹
            /// False: Folder
            /// </summary>
            public bool IsExe { get; set; }

            /// <summary>
            /// 显示名称，用于ListBox显示
            /// Display name, used for ListBox display
            /// </summary>
            public string DisplayName => Path;

            /// <summary>
            /// 构造函数
            /// Constructor
            /// </summary>
            /// <param name="path">扫描目标的路径</param>
            /// <param name="path">Path of the scan target</param>
            public ScanTarget(string path)
            {
                Path = path;
                IsExe = File.Exists(path) && System.IO.Path.GetExtension(path).Equals(".exe", StringComparison.OrdinalIgnoreCase);
            }

            /// <summary>
            /// 重写ToString方法，用于ListBox显示
            /// Override ToString method for ListBox display
            /// </summary>
            /// <returns>显示名称</returns>
            /// <returns>Display name</returns>
            public override string ToString()
            {
                return DisplayName;
            }
        }

        #endregion

        #region 字段定义

        /// <summary>
        /// 防火墙策略对象
        /// Firewall policy object
        /// </summary>
        private dynamic firewallPolicy;

        /// <summary>
        /// 监控目标列表
        /// Monitored targets list
        /// </summary>
        private readonly List<ScanTarget> monitoredTargets = new List<ScanTarget>();

        /// <summary>
        /// 已添加的规则列表
        /// Added rules list
        /// </summary>
        private readonly List<string> addedRules = new List<string>();

        /// <summary>
        /// 工作状态
        /// Work state
        /// </summary>
        private enum WorkState { Idle, Running, Paused, Stopping }

        /// <summary>
        /// 当前工作状态
        /// Current work state
        /// </summary>
        private WorkState currentState = WorkState.Idle;

        /// <summary>
        /// 取消令牌源
        /// Cancellation token source
        /// </summary>
        private CancellationTokenSource cancellationTokenSource;

        /// <summary>
        /// 工作线程
        /// Work thread
        /// </summary>
        private Task workTask;

        /// <summary>
        /// 任务完成事件
        /// Task completion event
        /// </summary>
        private readonly ManualResetEvent taskCompletedEvent = new ManualResetEvent(true);
        
        /// <summary>
        /// 暂停事件
        /// Pause event
        /// </summary>
        private readonly ManualResetEvent pauseEvent = new ManualResetEvent(true);

        /// <summary>
        /// 日志管理器
        /// Log manager
        /// </summary>
        // LogManager 是静态类，不需要创建实例
        // LogManager is a static class, no need to create an instance

        /// <summary>
        /// 生成文件路径的哈希值，确保规则名称唯一性
        /// Generate hash for file path to ensure unique rule names
        /// </summary>
        /// <param name="path">文件路径</param>
        /// <returns>路径的哈希值</returns>
        private string GetPathHash(string path)
        {
            using (var md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] hashBytes = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(path));
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 4; i++) // 只取前4个字节，避免规则名称过长
                {
                    sb.Append(hashBytes[i].ToString("x2"));
                }
                return sb.ToString();
            }
        }

        #region UI Controls
        // UI 控件定义
        private System.Windows.Forms.ListBox folderListBox;
        private System.Windows.Forms.Button addButton;
        private System.Windows.Forms.Button updateRulesButton;
        private System.Windows.Forms.Button clearRulesButton;
        private System.Windows.Forms.Button removeFolderButton;
        private System.Windows.Forms.Button pauseButton;
        private System.Windows.Forms.Button resumeButton;
        private System.Windows.Forms.Button stopButton;
        private System.Windows.Forms.Button viewLogsButton;
        private System.Windows.Forms.ProgressBar progressBar;
        private System.Windows.Forms.Label statusLabel;
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanel;
        private System.Windows.Forms.NotifyIcon trayIcon;
        private System.Windows.Forms.FolderBrowserDialog folderBrowserDialog;
        private System.Windows.Forms.OpenFileDialog openFileDialog;
        private System.Windows.Forms.ContextMenuStrip contextMenuStrip;
        private System.Windows.Forms.ToolStripMenuItem pasteMenuItem;
        private System.Windows.Forms.ContextMenuStrip addContextMenu;
        private System.Windows.Forms.ToolStripMenuItem addFolderToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem addExeToolStripMenuItem;
        private System.Windows.Forms.ContextMenuStrip trayMenu;
        private System.Windows.Forms.ToolStripMenuItem showMainFormToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem updateRulesTrayToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem exitToolStripMenuItem;
        #endregion

        #endregion

        #region 构造函数

        /// <summary>
        /// 构造函数
        /// Constructor
        /// 初始化主窗体，包括UI组件、权限检查、托盘图标和防火墙组件
        /// Initialize main form, including UI components, permission check, tray icon, and firewall components
        /// </summary>
        public Form1()
        {
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

                // 初始化防火墙相关功能
                InitializeFirewallComponents();
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
        /// Initialize permission architecture
        /// 设计用于分离管理员权限和普通用户权限
        /// Designed to separate administrator permissions and regular user permissions
        /// </summary>
        private void InitializePermissionArchitecture()
        {
            // 记录权限状态
            bool isAdmin = IsRunningAsAdministrator();
            LogManager.Info(LangManager.GetText("logMessages.permissionStatus", isAdmin ? "管理员" : "普通用户"));
        }

        /// <summary>
        /// 初始化托盘图标
        /// Initialize tray icon
        /// </summary>
        private void InitializeTrayIcon()
        {
            try
            {
                // 在构造函数中，我们已经在UI线程上，直接初始化托盘图标
                // In the constructor, we are already on the UI thread, directly initialize the tray icon
                // 无需使用SafeInvoke，因为InvokeRequired会返回false
                // No need to use SafeInvoke because InvokeRequired will return false
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
        /// Initialize firewall components
        /// </summary>
        private void InitializeFirewallComponents()
        {
            try
            {
                LogManager.Info("开始初始化防火墙组件...");
                LogManager.Info($"尝试创建防火墙策略对象，ProgID: {Config.FIREWALL_POLICY_PROGID}");
                
                Type firewallPolicyType = Type.GetTypeFromProgID(Config.FIREWALL_POLICY_PROGID);
                if (firewallPolicyType == null)
                {
                    LogManager.Error("无法找到防火墙策略类型");
                    throw new Exception("无法找到防火墙策略类型");
                }
                
                LogManager.Info($"找到类型: {firewallPolicyType.FullName}");
                
                // 使用动态类型避免接口转换问题
                firewallPolicy = Activator.CreateInstance(firewallPolicyType);
                LogManager.Info("防火墙策略实例创建成功");
                
                // 测试获取 CurrentProfileTypes 属性
                try
                {
                    var currentProfileTypes = firewallPolicy.CurrentProfileTypes;
                    LogManager.Info($"CurrentProfileTypes: {currentProfileTypes}");
                }
                catch (Exception ex)
                {
                    LogManager.Error($"获取 CurrentProfileTypes 属性失败: {ex.Message}");
                }
                
                // 测试获取 Rules 属性
                try
                {
                    var rules = firewallPolicy.Rules;
                    LogManager.Info($"Rules 对象获取成功: {rules.GetType().FullName}");
                }
                catch (Exception ex)
                {
                    LogManager.Error($"获取 Rules 属性失败: {ex.Message}");
                }
                
                CacheFirewallRules();
                LoadMonitoredFolders();
                LoadAddedRules();
                
                LogManager.Info(LangManager.GetText("logMessages.firewallInitialized"));
                
                UpdateUI(WorkState.Idle, LangManager.GetText("status.readyWait"));
            }
            catch (Exception ex)
            {
                LogManager.Error($"初始化防火墙失败: {ex.GetType().Name}: {ex.Message}");
                LogManager.Error($"堆栈跟踪: {ex.StackTrace}");
                MessageBox.Show(LangManager.GetText("messages.initializeFirewallFailed"), LangManager.GetText("messages.initializeFirewallFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
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
        }

        /// <summary>
        /// 更新UI状态
        /// Update UI state
        /// </summary>
        /// <param name="state">工作状态</param>
        /// <param name="statusText">状态文本</param>
        private void UpdateUI(WorkState state, string statusText)
        {
            if (this.InvokeRequired)
            {
                this.Invoke(new Action(() => UpdateUI(state, statusText)));
                return;
            }
            
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
            
            // 运行控制按钮
            pauseButton.Enabled = isRunning;
            resumeButton.Enabled = isPaused;
            stopButton.Enabled = isRunning || isPaused;
            
            // 更新进度条可见性
            progressBar.Style = isRunning ? ProgressBarStyle.Marquee : ProgressBarStyle.Blocks;
            progressBar.MarqueeAnimationSpeed = isRunning ? 30 : 0;
        }

        #endregion

        #region 权限相关方法

        /// <summary>
        /// 检查是否以管理员身份运行
        /// Check if running as administrator
        /// </summary>
        /// <returns>是否以管理员身份运行</returns>
        /// <returns>Whether running as administrator</returns>
        private bool IsRunningAsAdministrator()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        /// <summary>
        /// 处理非管理员权限情况
        /// Handle non-admin permission case
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
            }
        }
        
        /// <summary>
        /// 同步本地规则列表与实际防火墙规则
        /// Sync local rules list with actual firewall rules
        /// </summary>
        private void SyncRulesList()
        {
            try
            {
                LogManager.Info("正在同步规则列表...");
                var rulesToRemove = new List<string>();
                
                // 检查本地列表中的规则是否仍然存在于防火墙中
                foreach (var ruleName in addedRules.ToList())
                {
                    bool ruleExists = false;
                    
                    // 方法1：尝试通过名称获取规则
                    try
                    {
                        var existingRule = firewallPolicy.Rules.Item(ruleName);
                        if (existingRule != null)
                        {
                            try
                            {
                                var name = existingRule.Name;
                                ruleExists = true;
                            }
                            catch
                            {
                                ruleExists = false;
                            }
                        }
                    }
                    catch
                    {
                        ruleExists = false;
                    }
                    
                    // 方法2：遍历所有规则确认
                    try
                    {
                        bool found = false;
                        foreach (var rule in firewallPolicy.Rules)
                        {
                            try
                            {
                                dynamic fwRule = rule;
                                string existingName = fwRule.Name;
                                if (existingName == ruleName)
                                {
                                    found = true;
                                    break;
                                }
                            }
                            catch { }
                        }
                        ruleExists = found;
                    }
                    catch { }
                    
                    // 方法3：再次尝试获取规则
                    try
                    {
                        var existingRule = firewallPolicy.Rules.Item(ruleName);
                        if (existingRule != null)
                        {
                            try
                            {
                                var name = existingRule.Name;
                                var desc = existingRule.Description;
                                ruleExists = true;
                            }
                            catch
                            {
                                ruleExists = false;
                            }
                        }
                        else
                        {
                            ruleExists = false;
                        }
                    }
                    catch
                    {
                        ruleExists = false;
                    }
                    
                    LogManager.Debug($"同步检查规则 {ruleName}: 存在={ruleExists}");
                    
                    if (!ruleExists)
                    {
                        rulesToRemove.Add(ruleName);
                    }
                }
                
                // 移除不存在的规则
                foreach (var ruleName in rulesToRemove)
                {
                    addedRules.Remove(ruleName);
                    LogManager.Info($"从本地列表移除不存在的规则: {ruleName}");
                }
                
                if (rulesToRemove.Count > 0)
                {
                    LogManager.Info($"同步完成，移除了 {rulesToRemove.Count} 个不存在的规则");
                }
            }
            catch (Exception ex)
            {
                LogManager.Error("同步规则列表失败", ex);
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
        /// Add button click event
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void addButton_Click(object sender, EventArgs e)
        {
            // 打开文件夹选择对话框
            using (var folderDialog = new FolderBrowserDialog())
            {
                folderDialog.Description = LangManager.GetText("buttons.addFolder");
                if (folderDialog.ShowDialog() == DialogResult.OK)
                {
                    string selectedPath = folderDialog.SelectedPath;
                    if (!monitoredTargets.Any(t => t.Path.Equals(selectedPath, StringComparison.OrdinalIgnoreCase)))
                    {
                        var target = new ScanTarget(selectedPath);
                        monitoredTargets.Add(target);
                        folderListBox.Items.Add(target);
                    }
                }
            }
        }

        /// <summary>
        /// 更新规则按钮点击事件
        /// Update rules button click event
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void updateRulesButton_Click(object sender, EventArgs e)
        {
            // 启动更新规则任务
            if (currentState == WorkState.Idle)
            {
                cancellationTokenSource = new CancellationTokenSource();
                taskCompletedEvent.Reset();
                
                workTask = Task.Run(() =>
                {
                    try
                    {
                        UpdateFirewallRules(cancellationTokenSource.Token);
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
        /// Clear rules button click event
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
                if (MessageBox.Show("确定要清空所有由本程序创建的防火墙规则吗？", "确认", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                {
                    return;
                }
                
                int deletedCount = 0;
                var rulesToDelete = new List<string>();
                
                // 1. 首先删除本地列表中的规则
                foreach (var ruleName in addedRules.ToList())
                {
                    try
                    {
                        firewallPolicy.Rules.Remove(ruleName);
                        rulesToDelete.Add(ruleName);
                        deletedCount++;
                        LogManager.Info($"删除防火墙规则: {ruleName}");
                    }
                    catch (Exception ex)
                    {
                        LogManager.Warning($"删除规则失败: {ruleName} - {ex.Message}");
                    }
                }
                
                // 2. 然后扫描防火墙中的所有规则，删除由本程序创建的规则
                try
                {
                    var rules = firewallPolicy.Rules;
                    var allRuleNames = new List<string>();
                    
                    // 收集所有规则名称
                    foreach (var rule in rules)
                    {
                        try
                        {
                            dynamic fwRule = rule;
                            string ruleName = fwRule.Name;
                            allRuleNames.Add(ruleName);
                        }
                        catch { }
                    }
                    
                    // 删除由本程序创建的规则（以Block_开头）
                    foreach (var ruleName in allRuleNames)
                    {
                        if (ruleName.StartsWith("Block_") && !rulesToDelete.Contains(ruleName))
                        {
                            try
                            {
                                firewallPolicy.Rules.Remove(ruleName);
                                rulesToDelete.Add(ruleName);
                                deletedCount++;
                                LogManager.Info($"删除防火墙规则: {ruleName}");
                            }
                            catch (Exception ex)
                            {
                                LogManager.Warning($"删除规则失败: {ruleName} - {ex.Message}");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    LogManager.Warning($"扫描防火墙规则失败: {ex.Message}");
                }
                
                // 从本地列表中移除已删除的规则
                foreach (var ruleName in rulesToDelete)
                {
                    addedRules.Remove(ruleName);
                }
                
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
        /// Remove folder button click event
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void removeFolderButton_Click(object sender, EventArgs e)
        {
            if (folderListBox.SelectedItem is ScanTarget selectedTarget)
            {
                monitoredTargets.Remove(selectedTarget);
                folderListBox.Items.Remove(selectedTarget);
            }
        }

        /// <summary>
        /// 查看日志按钮点击事件
        /// View logs button click event
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
        /// 暂停按钮点击事件
        /// Pause button click event
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void pauseButton_Click(object sender, EventArgs e)
        {
            if (currentState == WorkState.Running)
            {
                pauseEvent.Reset();
                UpdateUI(WorkState.Paused, LangManager.GetText("status.paused"));
                LogManager.Info("任务已暂停");
            }
        }

        /// <summary>
        /// 继续按钮点击事件
        /// Resume button click event
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void resumeButton_Click(object sender, EventArgs e)
        {
            if (currentState == WorkState.Paused)
            {
                pauseEvent.Set();
                UpdateUI(WorkState.Running, LangManager.GetText("status.running"));
                LogManager.Info("任务已继续");
            }
        }

        /// <summary>
        /// 停止按钮点击事件
        /// Stop button click event
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
                LogManager.Info("任务已停止");
            }
        }

        #endregion

        #region 防火墙规则更新

        /// <summary>
        /// 更新防火墙规则
        /// Update firewall rules
        /// </summary>
        /// <param name="cancellationToken">取消令牌</param>
        private void UpdateFirewallRules(CancellationToken cancellationToken)
        {
            int addedCount = 0;
            int skippedCount = 0;
            
            try
            {
                LogManager.Info(LangManager.GetText("logMessages.updatingRules"));
                UpdateUI(WorkState.Running, "正在扫描监控目标...");
                
                // 同步本地规则列表与实际防火墙规则
                SyncRulesList();
                
                // 收集所有需要处理的EXE文件
                List<string> exeFiles = new List<string>();
                
                foreach (var target in monitoredTargets.ToList())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    if (target.IsExe)
                    {
                        if (File.Exists(target.Path))
                        {
                            exeFiles.Add(target.Path);
                        }
                    }
                    else if (Directory.Exists(target.Path))
                    {
                        UpdateUI(WorkState.Running, $"正在扫描文件夹: {target.Path}");
                        
                        try
                        {
                            var files = Directory.GetFiles(target.Path, "*.exe", SearchOption.AllDirectories);
                            exeFiles.AddRange(files);
                        }
                        catch (Exception ex)
                        {
                            LogManager.Warning($"扫描文件夹失败: {target.Path} - {ex.Message}");
                        }
                    }
                }
                
                LogManager.Info($"找到 {exeFiles.Count} 个可执行文件");
                UpdateUI(WorkState.Running, $"找到 {exeFiles.Count} 个可执行文件，正在创建防火墙规则...");
                
                // 为每个EXE文件创建防火墙规则
                int processedCount = 0;
                foreach (var exeFile in exeFiles)
                {
                    // 检查取消请求
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    // 等待暂停解除
                    pauseEvent.WaitOne();
                    
                    // 再次检查取消请求（在暂停期间可能被取消）
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    processedCount++;
                    UpdateUI(WorkState.Running, $"正在处理 ({processedCount}/{exeFiles.Count}): {System.IO.Path.GetFileName(exeFile)}");
                    
                    try
                    {
                        // 生成包含文件路径哈希值的规则名称，确保唯一性
                        string fileName = System.IO.Path.GetFileNameWithoutExtension(exeFile);
                        string pathHash = GetPathHash(exeFile);
                        string ruleName = $"Block_{fileName}_{pathHash}";
                        
                        // 检查规则是否已存在
                        bool ruleExists = false;
                        
                        // 直接遍历所有规则，这是最可靠的方法
                        try
                        {
                            bool found = false;
                            int totalRules = 0;
                            int blockRulesCount = 0;
                            
                            LogManager.Debug($"开始检查规则: {ruleName}");
                            
                            foreach (var rule in firewallPolicy.Rules)
                            {
                                totalRules++;
                                try
                                {
                                    dynamic fwRule = rule;
                                    string existingName = fwRule.Name;
                                    
                                    // 统计以Block_开头的规则数量
                                    if (existingName.StartsWith("Block_"))
                                    {
                                        blockRulesCount++;
                                        LogManager.Debug($"发现Block规则: {existingName}");
                                    }
                                    
                                    // 检查是否是当前规则
                                    if (existingName == ruleName)
                                    {
                                        found = true;
                                        LogManager.Debug($"找到规则: {ruleName}");
                                        break;
                                    }
                                }
                                catch (Exception ex)
                                {
                                    LogManager.Debug($"遍历规则时出错: {ex.Message}");
                                }
                            }
                            
                            ruleExists = found;
                            LogManager.Info($"规则检查结果: {ruleName} - 存在={found}, 总规则数={totalRules}, Block规则数={blockRulesCount}");
                        }
                        catch (Exception ex)
                        {
                            LogManager.Error($"检查规则失败: {ex.Message}");
                            ruleExists = false;
                        }
                        
                        // 最终检查结果
                        LogManager.Debug($"最终检查规则 {ruleName}: 存在={ruleExists}");
                        
                        if (!ruleExists)
                        {
                            // 创建新规则
                            Type ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
                            dynamic newRule = Activator.CreateInstance(ruleType);
                            
                            newRule.Name = ruleName;
                            newRule.Description = $"Blocked by FirewallManager: {exeFile}";
                            newRule.ApplicationName = exeFile;
                            newRule.Direction = (int)NET_FW_DIRECTION_.NET_FW_DIRECTION_OUT;
                            newRule.Action = (int)NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                            newRule.Enabled = true;
                            newRule.Profiles = 0x7FFFFFFF; // 所有配置文件
                            
                            firewallPolicy.Rules.Add(newRule);
                            
                            // 确保添加到本地列表
                            if (!addedRules.Contains(ruleName))
                            {
                                addedRules.Add(ruleName);
                            }
                            
                            addedCount++;
                            LogManager.Info($"创建防火墙规则: {ruleName} -> {exeFile}");
                        }
                        else
                        {
                            // 确保本地列表与实际状态同步
                            if (!addedRules.Contains(ruleName))
                            {
                                addedRules.Add(ruleName);
                            }
                            skippedCount++;
                        }
                    }
                    catch (Exception ex)
                    {
                        LogManager.Warning($"创建规则失败: {exeFile} - {ex.Message}");
                    }
                }
                
                UpdateUI(WorkState.Idle, $"完成: 添加 {addedCount} 条规则，跳过 {skippedCount} 条已存在的规则");
                LogManager.Info(LangManager.GetText("logMessages.updateCompleted", addedCount, skippedCount));
            }
            catch (OperationCanceledException)
            {
                UpdateUI(WorkState.Idle, "操作已取消");
                LogManager.Info(LangManager.GetText("logMessages.updateCanceled"));
            }
            catch (Exception ex)
            {
                UpdateUI(WorkState.Idle, $"错误: {ex.Message}");
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
                e.Cancel = true;
                this.Hide();
                trayIcon.ShowBalloonTip(1000, LangManager.GetText("app.trayTitle"), LangManager.GetText("messages.trayMinimized"), ToolTipIcon.Info);
            }
        }

        #endregion

        #region 事件处理方法

        /// <summary>
        /// 粘贴菜单项点击事件
        /// Paste menu item click event
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
                    MessageBox.Show("剪贴板为空或内容无效", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                
                string[] paths = clipboardText.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                int addedCount = 0;
                
                foreach (string path in paths)
                {
                    string trimmedPath = path.Trim();
                    if (string.IsNullOrWhiteSpace(trimmedPath))
                        continue;
                    
                    if (Directory.Exists(trimmedPath) || (File.Exists(trimmedPath) && trimmedPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)))
                    {
                        if (!monitoredTargets.Any(t => t.Path.Equals(trimmedPath, StringComparison.OrdinalIgnoreCase)))
                        {
                            var target = new ScanTarget(trimmedPath);
                            monitoredTargets.Add(target);
                            folderListBox.Items.Add(target);
                            addedCount++;
                        }
                    }
                }
                
                if (addedCount > 0)
                {
                    LogManager.Info($"成功从剪贴板粘贴 {addedCount} 个路径");
                }
                else
                {
                    MessageBox.Show("没有有效的文件夹或EXE文件路径", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                LogManager.Error("粘贴路径失败", ex);
                MessageBox.Show($"粘贴失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// 添加文件夹菜单项点击事件
        /// Add folder menu item click event
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void addFolderToolStripMenuItem_Click(object sender, EventArgs e)
        {
            // 实现添加文件夹功能
        }

        /// <summary>
        /// 添加可执行文件菜单项点击事件
        /// Add executable file menu item click event
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void addExeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            // 实现添加可执行文件功能
        }

        /// <summary>
        /// 显示主窗体菜单项点击事件
        /// Show main form menu item click event
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
        /// Update rules menu item click event
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void updateRulesTrayToolStripMenuItem_Click(object sender, EventArgs e)
        {
            // 实现更新规则功能
        }

        /// <summary>
        /// 退出菜单项点击事件
        /// Exit menu item click event
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void exitToolStripMenuItem_Click(object sender, EventArgs e)
        {
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