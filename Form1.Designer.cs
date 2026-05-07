namespace FirewallManager
{
    /// <summary>
    /// FirewallManager应用程序的主窗体
    /// 负责显示UI界面，处理用户交互和管理防火墙规则
    /// </summary>
    partial class Form1
{
    #region UI Controls

    /// <summary>
    /// 必需的设计器变量
    /// 用于管理窗体组件的生命周期
    /// </summary>
    private System.ComponentModel.IContainer components = null;

    // 列表框：用于显示监控的文件夹和单个EXE文件
    // ListBox: Used to display monitored folders and individual EXE files
    private System.Windows.Forms.ListBox folderListBox;

    // 添加按钮：用于打开上下文菜单，选择添加文件夹或单个EXE文件
    // Add button: Used to open context menu for adding folders or individual EXE files
    private System.Windows.Forms.Button addButton;

    // 更新规则按钮：扫描监控文件夹并更新防火墙规则
    // Update rules button: Scans monitored folders and updates firewall rules
    private System.Windows.Forms.Button updateRulesButton;

    // 清空规则按钮：删除所有由本程序创建的防火墙规则
    // Clear rules button: Deletes all firewall rules created by this program
    private System.Windows.Forms.Button clearRulesButton;

    // 删除文件夹按钮：从监控列表中删除选中的文件夹或EXE文件
    // Remove folder button: Removes selected folder or EXE file from monitoring list
    private System.Windows.Forms.Button removeFolderButton;

    // 暂停按钮：暂停正在执行的扫描或规则更新操作
    // Pause button: Pauses ongoing scan or rule update operation
    private System.Windows.Forms.Button pauseButton;

    // 继续按钮：恢复被暂停的操作
    // Resume button: Resumes paused operation
    private System.Windows.Forms.Button resumeButton;

    // 终止按钮：取消正在执行的操作
    // Stop button: Cancels ongoing operation
    private System.Windows.Forms.Button stopButton;

    // 查看日志按钮：用于查看操作日志
    // View logs button: Used to view operation logs
    private System.Windows.Forms.Button viewLogsButton;

    // 白名单管理按钮：用于打开白名单管理窗口
    // Whitelist button: Used to open whitelist management window
    private System.Windows.Forms.Button whitelistButton;

    // 进度条：显示当前操作的进度
    // Progress bar: Displays progress of current operation
    private System.Windows.Forms.ProgressBar progressBar;

    // 状态标签：显示当前程序状态
    // Status label: Displays current program status
    private System.Windows.Forms.Label statusLabel;

    // 表格布局面板：用于组织UI控件布局
    // Table layout panel: Used for organizing UI control layout
    private System.Windows.Forms.TableLayoutPanel tableLayoutPanel;

    // 托盘图标：用于在系统托盘中显示程序图标
    // Notify icon: Used to display program icon in system tray
    private System.Windows.Forms.NotifyIcon trayIcon;

    // 文件夹浏览器对话框：用于选择要监控的文件夹
    // Folder browser dialog: Used to select folders to monitor
    private System.Windows.Forms.FolderBrowserDialog folderBrowserDialog;

    // 文件对话框：用于选择单个EXE文件
    // Open file dialog: Used to select individual EXE files
    private System.Windows.Forms.OpenFileDialog openFileDialog;

    // 列表框上下文菜单：用于列表框的右键菜单
    // Context menu strip: Used for list box right-click menu
    private System.Windows.Forms.ContextMenuStrip contextMenuStrip;

    // 粘贴菜单项：用于从剪贴板粘贴文件夹路径
    // Paste menu item: Used to paste folder paths from clipboard
    private System.Windows.Forms.ToolStripMenuItem pasteMenuItem;

    // 添加按钮上下文菜单：用于添加按钮的右键菜单
    // Add context menu: Used for add button menu
    private System.Windows.Forms.ContextMenuStrip addContextMenu;

    // 添加文件夹菜单项：用于添加监控文件夹
    // Add folder menu item: Used to add monitored folder
    private System.Windows.Forms.ToolStripMenuItem addFolderToolStripMenuItem;

    // 添加文件菜单项：用于添加单个EXE文件
    // Add EXE menu item: Used to add individual EXE file
    private System.Windows.Forms.ToolStripMenuItem addExeToolStripMenuItem;

    // 托盘菜单：用于托盘图标的右键菜单
    // Tray menu: Used for tray icon right-click menu
    private System.Windows.Forms.ContextMenuStrip trayMenu;

    // 显示主窗体菜单项：用于从托盘显示主窗体
    // Show main form menu item: Used to show main form from tray
    private System.Windows.Forms.ToolStripMenuItem showMainFormToolStripMenuItem;

    // 更新规则菜单项：用于从托盘更新规则
    // Update rules menu item: Used to update rules from tray
    private System.Windows.Forms.ToolStripMenuItem updateRulesTrayToolStripMenuItem;

    // 退出菜单项：用于退出应用程序
    // Exit menu item: Used to exit application
    private System.Windows.Forms.ToolStripMenuItem exitToolStripMenuItem;

    // 自动监控复选框：用于启用/禁用自动监控功能
    // Auto monitor checkbox: Used to enable/disable auto monitoring feature
    private System.Windows.Forms.CheckBox autoMonitorCheckBox;

    // 语言切换下拉框：用于切换应用程序语言
    // Language combo box: Used to switch application language
    private System.Windows.Forms.ComboBox languageComboBox;

    #endregion

    #region Windows Form Designer generated code

    /// <summary>
    /// 设计器支持所需的方法 - 不要使用代码编辑器修改此方法的内容
    /// 初始化所有UI控件，设置其属性、布局和事件处理程序
    /// </summary>
    /// <remarks>
    /// 此方法由Windows Forms设计器自动生成，不应手动修改
    /// 手动修改可能导致UI布局和功能出现问题
    /// </remarks>
    private void InitializeComponent()
        {
            // 初始化组件容器，用于管理UI控件和资源
            this.components = new System.ComponentModel.Container();
            // 初始化列表框：用于显示监控的文件夹和单个EXE文件
            this.folderListBox = new System.Windows.Forms.ListBox();
            // 初始化添加按钮：用于打开上下文菜单，选择添加文件夹或单个EXE文件
            this.addButton = new System.Windows.Forms.Button();
            // 初始化更新规则按钮：扫描监控文件夹并更新防火墙规则
            this.updateRulesButton = new System.Windows.Forms.Button();
            // 初始化清空规则按钮：删除所有由本程序创建的防火墙规则
            this.clearRulesButton = new System.Windows.Forms.Button();
            // 初始化删除文件夹按钮：从监控列表中删除选中的文件夹或EXE文件
            this.removeFolderButton = new System.Windows.Forms.Button();
            // 初始化暂停按钮：暂停正在执行的扫描或规则更新操作
            this.pauseButton = new System.Windows.Forms.Button();
            // 初始化继续按钮：恢复被暂停的操作
            this.resumeButton = new System.Windows.Forms.Button();
            // 初始化终止按钮：取消正在执行的操作
            this.stopButton = new System.Windows.Forms.Button();
            // 初始化进度条：显示当前操作的进度
            this.progressBar = new System.Windows.Forms.ProgressBar();
            // 初始化状态标签：显示当前程序状态
            this.statusLabel = new System.Windows.Forms.Label();
            // 初始化文件夹浏览器对话框：用于选择要监控的文件夹
            this.folderBrowserDialog = new System.Windows.Forms.FolderBrowserDialog();
            // 初始化文件对话框：用于选择单个EXE文件
            this.openFileDialog = new System.Windows.Forms.OpenFileDialog();
            // 初始化列表框上下文菜单：用于列表框的右键菜单
            this.contextMenuStrip = new System.Windows.Forms.ContextMenuStrip(this.components);
            // 初始化粘贴菜单项：用于从剪贴板粘贴文件夹路径
            this.pasteMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            // 初始化添加按钮上下文菜单：用于添加按钮的右键菜单
            this.addContextMenu = new System.Windows.Forms.ContextMenuStrip(this.components);
            // 初始化添加文件夹菜单项：用于添加监控文件夹
            this.addFolderToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            // 初始化添加文件菜单项：用于添加单个EXE文件
        this.addExeToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
        // 初始化查看日志按钮：用于查看操作日志
        this.viewLogsButton = new System.Windows.Forms.Button();
        // 初始化白名单管理按钮：用于打开白名单管理窗口
        this.whitelistButton = new System.Windows.Forms.Button();
        // 初始化自动监控复选框：用于启用/禁用自动监控功能
        this.autoMonitorCheckBox = new System.Windows.Forms.CheckBox();
        // 初始化语言切换下拉框：用于切换应用程序语言
        this.languageComboBox = new System.Windows.Forms.ComboBox();
        // 初始化托盘图标：用于系统托盘显示和操作
        this.trayIcon = new System.Windows.Forms.NotifyIcon(this.components);
        // 初始化托盘菜单：用于托盘图标的右键菜单
        this.trayMenu = new System.Windows.Forms.ContextMenuStrip(this.components);
        // 初始化显示主界面菜单项：用于从托盘打开主窗口
        this.showMainFormToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
        // 初始化更新规则菜单项：用于从托盘更新防火墙规则
        this.updateRulesTrayToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
        // 初始化退出菜单项：用于从托盘退出程序
        this.exitToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
        // 初始化表格布局面板：用于管理控件布局，确保在窗体大小变化时正确调整
        this.tableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
        this.SuspendLayout();
            // 
            // contextMenuStrip
            // 
            this.contextMenuStrip.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.pasteMenuItem});
            this.contextMenuStrip.Name = "contextMenuStrip";
            this.contextMenuStrip.Size = new System.Drawing.Size(101, 26);
            // 
            // pasteMenuItem
            // 
            this.pasteMenuItem.Name = "pasteMenuItem";
            this.pasteMenuItem.Size = new System.Drawing.Size(100, 22);
            this.pasteMenuItem.Click += new System.EventHandler(this.pasteMenuItem_Click);
            // 
            // addContextMenu
            // 
            this.addContextMenu.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.addFolderToolStripMenuItem,
            this.addExeToolStripMenuItem});
            this.addContextMenu.Name = "addContextMenu";
            this.addContextMenu.Size = new System.Drawing.Size(153, 48);
            // 
            // addFolderToolStripMenuItem
            // 
            this.addFolderToolStripMenuItem.Name = "addFolderToolStripMenuItem";
            this.addFolderToolStripMenuItem.Size = new System.Drawing.Size(152, 22);
            this.addFolderToolStripMenuItem.Click += new System.EventHandler(this.addFolderToolStripMenuItem_Click);
            // 
            // addExeToolStripMenuItem
            // 
            this.addExeToolStripMenuItem.Name = "addExeToolStripMenuItem";
            this.addExeToolStripMenuItem.Size = new System.Drawing.Size(152, 22);
            this.addExeToolStripMenuItem.Click += new System.EventHandler(this.addExeToolStripMenuItem_Click);
            // 
            // trayMenu
            // 
            this.trayMenu.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.showMainFormToolStripMenuItem,
            this.updateRulesTrayToolStripMenuItem,
            this.exitToolStripMenuItem});
            this.trayMenu.Name = "trayMenu";
            this.trayMenu.Size = new System.Drawing.Size(181, 70);
            // 
            // showMainFormToolStripMenuItem
            // 
            this.showMainFormToolStripMenuItem.Name = "showMainFormToolStripMenuItem";
            this.showMainFormToolStripMenuItem.Size = new System.Drawing.Size(180, 22);
            this.showMainFormToolStripMenuItem.Click += new System.EventHandler(this.showMainFormToolStripMenuItem_Click);
            // 
            // updateRulesTrayToolStripMenuItem
            // 
            this.updateRulesTrayToolStripMenuItem.Name = "updateRulesTrayToolStripMenuItem";
            this.updateRulesTrayToolStripMenuItem.Size = new System.Drawing.Size(180, 22);
            this.updateRulesTrayToolStripMenuItem.Click += new System.EventHandler(this.updateRulesTrayToolStripMenuItem_Click);
            // 
            // exitToolStripMenuItem
            // 
            this.exitToolStripMenuItem.Name = "exitToolStripMenuItem";
            this.exitToolStripMenuItem.Size = new System.Drawing.Size(180, 22);
            this.exitToolStripMenuItem.Click += new System.EventHandler(this.exitToolStripMenuItem_Click);
            // 
            // trayIcon
            // 
            this.trayIcon.ContextMenuStrip = this.trayMenu;
            this.trayIcon.Visible = true;
            // 使用应用程序图标作为系统托盘图标
            this.trayIcon.Icon = this.Icon;
            this.trayIcon.MouseDoubleClick += new System.Windows.Forms.MouseEventHandler(this.trayIcon_MouseDoubleClick);
            // 
            // tableLayoutPanel
            // 
            this.tableLayoutPanel.ColumnCount = 4;
            this.tableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 25F));
            this.tableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 25F));
            this.tableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 25F));
            this.tableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 25F));
            this.tableLayoutPanel.RowCount = 6;
            this.tableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 40F));
            this.tableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 40F));
            this.tableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 40F));
            this.tableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 30F));
            this.tableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 25F));
            this.tableLayoutPanel.GrowStyle = System.Windows.Forms.TableLayoutPanelGrowStyle.AddRows;
            this.tableLayoutPanel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tableLayoutPanel.Location = new System.Drawing.Point(0, 0);
            this.tableLayoutPanel.Name = "tableLayoutPanel";
            this.tableLayoutPanel.Size = new System.Drawing.Size(800, 450);
            this.tableLayoutPanel.TabIndex = 14;
            // 
            // folderListBox
            // 
            this.folderListBox.FormattingEnabled = true;
            this.folderListBox.ItemHeight = 15;
            this.folderListBox.Location = new System.Drawing.Point(3, 3);
            this.folderListBox.Name = "folderListBox";
            this.folderListBox.Size = new System.Drawing.Size(794, 229);
            this.folderListBox.ContextMenuStrip = this.contextMenuStrip;
            this.folderListBox.TabIndex = 0;
            this.folderListBox.Dock = System.Windows.Forms.DockStyle.Fill;
            // 
            // addButton
            // 
            this.addButton.Location = new System.Drawing.Point(3, 3);
            this.addButton.Name = "addButton";
            this.addButton.Size = new System.Drawing.Size(120, 30);
            this.addButton.TabIndex = 1;
            this.addButton.UseVisualStyleBackColor = true;
            this.addButton.Click += new System.EventHandler(this.addButton_Click);
            this.addButton.Anchor = System.Windows.Forms.AnchorStyles.None;
            // 
            // removeFolderButton
            // 
            this.removeFolderButton.Location = new System.Drawing.Point(3, 3);
            this.removeFolderButton.Name = "removeFolderButton";
            this.removeFolderButton.Size = new System.Drawing.Size(120, 30);
            this.removeFolderButton.TabIndex = 9;
            this.removeFolderButton.UseVisualStyleBackColor = true;
            this.removeFolderButton.Click += new System.EventHandler(this.removeFolderButton_Click);
            this.removeFolderButton.Anchor = System.Windows.Forms.AnchorStyles.None;
            // 
            // updateRulesButton
            // 
            this.updateRulesButton.Location = new System.Drawing.Point(3, 3);
            this.updateRulesButton.Name = "updateRulesButton";
            this.updateRulesButton.Size = new System.Drawing.Size(120, 30);
            this.updateRulesButton.TabIndex = 2;
            this.updateRulesButton.UseVisualStyleBackColor = true;
            this.updateRulesButton.Click += new System.EventHandler(this.updateRulesButton_Click);
            this.updateRulesButton.Anchor = System.Windows.Forms.AnchorStyles.None;
            // 
            // clearRulesButton
            // 
            this.clearRulesButton.Location = new System.Drawing.Point(3, 3);
            this.clearRulesButton.Name = "clearRulesButton";
            this.clearRulesButton.Size = new System.Drawing.Size(120, 30);
            this.clearRulesButton.TabIndex = 3;
            this.clearRulesButton.UseVisualStyleBackColor = true;
            this.clearRulesButton.Click += new System.EventHandler(this.clearRulesButton_Click);
            this.clearRulesButton.Anchor = System.Windows.Forms.AnchorStyles.None;
            // 

            // 
            // viewLogsButton
            // 
            this.viewLogsButton.Location = new System.Drawing.Point(3, 3);
            this.viewLogsButton.Name = "viewLogsButton";
            this.viewLogsButton.Size = new System.Drawing.Size(120, 30);
            this.viewLogsButton.TabIndex = 13;
            this.viewLogsButton.UseVisualStyleBackColor = true;
            this.viewLogsButton.Click += new System.EventHandler(this.viewLogsButton_Click);
            this.viewLogsButton.Anchor = System.Windows.Forms.AnchorStyles.None;
            // 
            // whitelistButton
            // 
            this.whitelistButton.Location = new System.Drawing.Point(3, 3);
            this.whitelistButton.Name = "whitelistButton";
            this.whitelistButton.Size = new System.Drawing.Size(120, 30);
            this.whitelistButton.TabIndex = 14;
            this.whitelistButton.UseVisualStyleBackColor = true;
            this.whitelistButton.Click += new System.EventHandler(this.whitelistButton_Click);
            this.whitelistButton.Anchor = System.Windows.Forms.AnchorStyles.None;
            // 
            // autoMonitorCheckBox
            // 
            this.autoMonitorCheckBox.AutoSize = true;
            this.autoMonitorCheckBox.Location = new System.Drawing.Point(3, 8);
            this.autoMonitorCheckBox.Name = "autoMonitorCheckBox";
            this.autoMonitorCheckBox.Size = new System.Drawing.Size(100, 17);
            this.autoMonitorCheckBox.TabIndex = 15;
            this.autoMonitorCheckBox.UseVisualStyleBackColor = true;
            this.autoMonitorCheckBox.CheckedChanged += new System.EventHandler(this.autoMonitorCheckBox_CheckedChanged);
            this.autoMonitorCheckBox.Anchor = System.Windows.Forms.AnchorStyles.None;
            // 
            // languageComboBox
            // 
            this.languageComboBox.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.languageComboBox.Location = new System.Drawing.Point(3, 3);
            this.languageComboBox.Name = "languageComboBox";
            this.languageComboBox.Size = new System.Drawing.Size(120, 23);
            this.languageComboBox.TabIndex = 16;
            this.languageComboBox.SelectedIndexChanged += new System.EventHandler(this.languageComboBox_SelectedIndexChanged);
            this.languageComboBox.Anchor = System.Windows.Forms.AnchorStyles.None;
            // 
            // openFileDialog
            // 
            
            // 
            // pauseButton
            // 
            this.pauseButton.Enabled = false;
            this.pauseButton.Location = new System.Drawing.Point(3, 3);
            this.pauseButton.Name = "pauseButton";
            this.pauseButton.Size = new System.Drawing.Size(120, 30);
            this.pauseButton.TabIndex = 4;
            this.pauseButton.UseVisualStyleBackColor = true;
            this.pauseButton.Click += new System.EventHandler(this.pauseButton_Click);
            this.pauseButton.Anchor = System.Windows.Forms.AnchorStyles.None;
            // 
            // resumeButton
            // 
            this.resumeButton.Enabled = false;
            this.resumeButton.Location = new System.Drawing.Point(3, 3);
            this.resumeButton.Name = "resumeButton";
            this.resumeButton.Size = new System.Drawing.Size(120, 30);
            this.resumeButton.TabIndex = 5;
            this.resumeButton.UseVisualStyleBackColor = true;
            this.resumeButton.Click += new System.EventHandler(this.resumeButton_Click);
            this.resumeButton.Anchor = System.Windows.Forms.AnchorStyles.None;
            // 
            // stopButton
            // 
            this.stopButton.Enabled = false;
            this.stopButton.Location = new System.Drawing.Point(3, 3);
            this.stopButton.Name = "stopButton";
            this.stopButton.Size = new System.Drawing.Size(120, 30);
            this.stopButton.TabIndex = 6;
            this.stopButton.UseVisualStyleBackColor = true;
            this.stopButton.Click += new System.EventHandler(this.stopButton_Click);
            this.stopButton.Anchor = System.Windows.Forms.AnchorStyles.None;
            // 
            // progressBar
            // 
            this.progressBar.Location = new System.Drawing.Point(3, 3);
            this.progressBar.Name = "progressBar";
            this.progressBar.Size = new System.Drawing.Size(794, 23);
            this.progressBar.TabIndex = 7;
            this.progressBar.Dock = System.Windows.Forms.DockStyle.Fill;
            // 
            // statusLabel
            // 
            this.statusLabel.AutoSize = true;
            this.statusLabel.Location = new System.Drawing.Point(3, 3);
            this.statusLabel.Name = "statusLabel";
            this.statusLabel.Size = new System.Drawing.Size(74, 15);
            this.statusLabel.TabIndex = 8;
            this.statusLabel.Anchor = System.Windows.Forms.AnchorStyles.None;
            // 
            // 将控件添加到表格布局面板中
            // 
            this.tableLayoutPanel.SetColumnSpan(this.folderListBox, 4);
            this.tableLayoutPanel.Controls.Add(this.folderListBox, 0, 0);
            
            // 第一行：主要操作按钮
            this.tableLayoutPanel.Controls.Add(this.addButton, 0, 1);
            this.tableLayoutPanel.Controls.Add(this.updateRulesButton, 1, 1);
            this.tableLayoutPanel.Controls.Add(this.clearRulesButton, 2, 1);
            this.tableLayoutPanel.Controls.Add(this.removeFolderButton, 3, 1);
            
            // 第二行：运行控制按钮
            this.tableLayoutPanel.Controls.Add(this.pauseButton, 0, 2);
            this.tableLayoutPanel.Controls.Add(this.resumeButton, 1, 2);
            this.tableLayoutPanel.Controls.Add(this.stopButton, 2, 2);
            
            // 第三行：辅助功能按钮
            this.tableLayoutPanel.Controls.Add(this.viewLogsButton, 0, 3);
            this.tableLayoutPanel.Controls.Add(this.whitelistButton, 1, 3);
            this.tableLayoutPanel.Controls.Add(this.autoMonitorCheckBox, 2, 3);
            this.tableLayoutPanel.Controls.Add(this.languageComboBox, 3, 3);
            
            // 第四行：进度条
            this.tableLayoutPanel.SetColumnSpan(this.progressBar, 4);
            this.tableLayoutPanel.Controls.Add(this.progressBar, 0, 4);
            
            // 第五行：状态标签
            this.tableLayoutPanel.SetColumnSpan(this.statusLabel, 4);
            this.tableLayoutPanel.Controls.Add(this.statusLabel, 0, 5);
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.tableLayoutPanel);
            this.Name = "Form1";
            this.Resize += new System.EventHandler(this.Form1_Resize);
            this.ShowInTaskbar = true;
            // 图标由项目文件中的 ApplicationIcon 设置自动处理
            this.ResumeLayout(false);
            this.PerformLayout();
        }

        #endregion
    }
}
