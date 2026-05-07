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
    /// 白名单管理窗口
    /// 用于管理防火墙白名单
    /// </summary>
    public partial class WhitelistForm : Form
    {
        #region UI Controls
        // UI 控件定义
        private System.Windows.Forms.Button btnAdd;
        private System.Windows.Forms.Button btnRemove;
        private System.Windows.Forms.Button btnClear;
        private System.Windows.Forms.Button btnSave;
        private System.Windows.Forms.Button btnClose;
        private System.Windows.Forms.ListBox whitelistListBox;
        #endregion

        /// <summary>
        /// 白名单列表
        /// 当前窗口显示的白名单项目列表
        /// </summary>
        private List<string> whitelist = new List<string>();

        /// <summary>
        /// 静态白名单缓存
        /// 用于快速检查应用程序是否在白名单中
        /// </summary>
        private static List<string> whitelistCache = new List<string>();

        /// <summary>
        /// 白名单文件的最后修改时间
        /// </summary>
        private static DateTime lastModifiedTime = DateTime.MinValue;

        /// <summary>
        /// 用于确保线程安全的锁对象
        /// Lock object for ensuring thread safety
        /// </summary>
        private static readonly object whitelistLock = new object();

        /// <summary>
        /// 白名单文件监控器
        /// Whitelist file watcher
        /// </summary>
        private static System.IO.FileSystemWatcher whitelistWatcher;

        /// <summary>
        /// 防抖取消令牌源
        /// Debounce cancellation token source
        /// </summary>
        private static CancellationTokenSource debounceCts;

        /// <summary>
        /// 静态构造函数
        /// Static constructor
        /// 初始化文件系统监控器
        /// Initialize file system watcher
        /// </summary>
        static WhitelistForm()
        {
            try
            {
                // 初始化白名单文件监控器
                string configPath = Config.GetAppDataFilePath(Config.WHITELIST_FILE);
                string configDir = Path.GetDirectoryName(configPath);
                
                if (Directory.Exists(configDir))
                {
                    whitelistWatcher = new System.IO.FileSystemWatcher();
                    whitelistWatcher.Path = configDir;
                    whitelistWatcher.Filter = Config.WHITELIST_FILE;
                    whitelistWatcher.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size;
                    whitelistWatcher.Changed += WhitelistFileChanged;
                    whitelistWatcher.EnableRaisingEvents = true;
                    
                    LogManager.Info(LangManager.GetText("logMessages.whitelistFileWatcherInitialized"));
                }
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.initializeWhitelistFileWatcherFailed"), ex);
            }
        }

        /// <summary>
        /// 白名单文件变化事件处理（使用异步防抖模式）
        /// Whitelist file changed event handler (using async debounce pattern)
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private static async void WhitelistFileChanged(object sender, System.IO.FileSystemEventArgs e)
        {
            // 取消之前的延迟任务
            debounceCts?.Cancel();
            debounceCts = new CancellationTokenSource();
            
            try
            {
                // 使用异步延迟代替 Thread.Sleep，避免阻塞事件处理线程
                await Task.Delay(200, debounceCts.Token);
                
                // 在后台线程中刷新缓存，避免阻塞UI线程
                await Task.Run(() => RefreshWhitelistCache());
                
                LogManager.Info(LangManager.GetText("logMessages.whitelistFileChangedCacheRefreshed"));
            }
            catch (OperationCanceledException)
            {
                // 防抖取消是正常行为，不需要记录错误
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.processWhitelistFileChangeEventFailed"), ex);
            }
        }

        /// <summary>
        /// 释放静态资源
        /// Release static resources
        /// 用于在应用程序退出时清理文件监控器等资源
        /// Used to clean up resources like file watcher when application exits
        /// </summary>
        public static void ReleaseStaticResources()
        {
            try
            {
                // 取消防抖任务
                debounceCts?.Cancel();
                debounceCts?.Dispose();
                debounceCts = null;
                
                // 释放文件监控器
                if (whitelistWatcher != null)
                {
                    whitelistWatcher.EnableRaisingEvents = false;
                    whitelistWatcher.Changed -= WhitelistFileChanged;
                    whitelistWatcher.Dispose();
                    whitelistWatcher = null;
                    
                    LogManager.Info(LangManager.GetText("logMessages.whitelistFileWatcherReleased"));
                }
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.releaseWhitelistFileWatcherFailed"), ex);
            }
        }

        /// <summary>
        /// 构造函数
        /// Constructor
        /// 初始化白名单管理窗口，包括UI组件和白名单加载
        /// Initialize whitelist management window, including UI components and whitelist loading
        /// </summary>
        public WhitelistForm()
        {
            // 简单初始化
            this.Text = LangManager.GetText("forms.whitelistForm");
            this.Size = new Size(600, 400);
            
            // 创建基本控件
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
            
            // 布局 - 方案1：顶部按钮栏，底部操作按钮
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
            
            // 顶部按钮栏
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
            
            // 中间列表
            panel.Controls.Add(whitelistListBox, 0, 1);
            panel.SetColumnSpan(whitelistListBox, 4);
            
            // 底部关闭按钮
            panel.Controls.Add(btnClose, 0, 2);
            panel.SetColumnSpan(btnClose, 4);
            btnClose.Anchor = AnchorStyles.None;
            
            this.Controls.Add(panel);
            
            // 加载白名单
            LoadWhitelist();
        }

        /// <summary>
        /// 加载白名单
        /// Load whitelist
        /// </summary>
        private void LoadWhitelist()
        {
            try
            {
                string configPath = Config.GetAppDataFilePath(Config.WHITELIST_FILE);
                
                if (File.Exists(configPath))
                {
                    string json = File.ReadAllText(configPath, Encoding.UTF8);
                    whitelist = JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>();
                    
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
        /// 白名单保存事件
        /// Whitelist saved event
        /// 当白名单保存后触发，通知主窗体更新防火墙规则
        /// Triggered when whitelist is saved, notifies main form to update firewall rules
        /// </summary>
        public event EventHandler WhitelistSaved;
        
        /// <summary>
        /// 保存白名单
        /// Save whitelist
        /// </summary>
        private void SaveWhitelist()
        {
            try
            {
                string configPath = Config.GetAppDataFilePath(Config.WHITELIST_FILE);
                Directory.CreateDirectory(Path.GetDirectoryName(configPath));
                
                whitelist.Clear();
                foreach (var item in whitelistListBox.Items)
                {
                    whitelist.Add(item.ToString());
                }
                
                string json = JsonSerializer.Serialize(whitelist, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(configPath, json, Encoding.UTF8);
                
                LogManager.Info(LangManager.GetText("logMessages.saveWhitelistItems", whitelist.Count));
                MessageBox.Show(LangManager.GetText("messages.whitelistSaved"), LangManager.GetText("messages.successTitle"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                
                // 触发白名单保存事件
                WhitelistSaved?.Invoke(this, EventArgs.Empty);
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.saveWhitelistFailed"), ex);
                MessageBox.Show(LangManager.GetText("messages.saveWhitelistFailed", ex.Message), LangManager.GetText("messages.saveWhitelistFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// 添加按钮点击事件
        /// Add button click event
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void btnAdd_Click(object sender, EventArgs e)
        {
            // 打开文件选择对话框
            using (var openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Filter = LangManager.GetText("messages.exeFileFilter");
                openFileDialog.Title = LangManager.GetText("messages.selectExeFile");
                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    string selectedPath = openFileDialog.FileName;
                    if (!whitelistListBox.Items.Contains(selectedPath))
                    {
                        whitelistListBox.Items.Add(selectedPath);
                        LogManager.Info(LangManager.GetText("logMessages.addToWhitelist", selectedPath));
                    }
                }
            }
        }

        /// <summary>
        /// 移除按钮点击事件
        /// Remove button click event
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
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
        /// 清空按钮点击事件
        /// Clear button click event
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
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
        /// 保存按钮点击事件
        /// Save button click event
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void btnSave_Click(object sender, EventArgs e)
        {
            SaveWhitelist();
        }

        /// <summary>
        /// 关闭按钮点击事件
        /// Close button click event
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void btnClose_Click(object sender, EventArgs e)
        {
            this.Close();
        }
        
        /// <summary>
        /// 检查应用程序是否在白名单中
        /// Check if application is in whitelist
        /// 由于已有 FileSystemWatcher 监控文件变化并自动刷新缓存，
        /// 此方法直接读取缓存，无需重复检查文件修改时间
        /// Since FileSystemWatcher already monitors file changes and refreshes cache automatically,
        /// this method directly reads from cache without checking file modification time
        /// </summary>
        /// <param name="appPath">应用程序路径</param>
        /// <returns>是否在白名单中</returns>
        public static bool IsInWhitelist(string appPath)
        {
            lock (whitelistLock)
            {
                return whitelistCache.Any(path => path.Equals(appPath, StringComparison.OrdinalIgnoreCase));
            }
        }

        /// <summary>
        /// 刷新白名单缓存
        /// Refresh whitelist cache
        /// </summary>
        public static void RefreshWhitelistCache()
        {
            try
            {
                string configPath = Config.GetAppDataFilePath(Config.WHITELIST_FILE);
                
                if (File.Exists(configPath))
                {
                    // 获取锁，确保线程安全
                    lock (whitelistLock)
                    {
                        string json = File.ReadAllText(configPath, Encoding.UTF8);
                        whitelistCache = JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>();
                        lastModifiedTime = File.GetLastWriteTime(configPath);
                        LogManager.Info(LangManager.GetText("logMessages.whitelistCacheRefreshedManual", whitelistCache.Count));
                    }
                }
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.refreshWhitelistCacheFailed"), ex);
            }
        }
    }
}