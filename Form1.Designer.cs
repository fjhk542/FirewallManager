namespace FirewallManager
{
    /// <summary>
    /// FirewallManager应用程序的主窗体
    /// 负责显示UI界面，处理用户交互和管理防火墙规则
    /// </summary>
    partial class Form1
{
    /// <summary>
    /// 必需的设计器变量
    /// 用于管理窗体组件的生命周期
    /// </summary>
    private System.ComponentModel.IContainer components = null;

    /// <summary>
    /// 清理所有正在使用的资源
    /// </summary>
    /// <param name="disposing">如果应释放托管资源则为true，否则为false</param>
    protected override void Dispose(bool disposing)
    {
        if (disposing && (components != null))
        {
            components.Dispose();
        }
        base.Dispose(disposing);
    }

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
            this.pasteMenuItem.Text = "粘贴";
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
            this.addFolderToolStripMenuItem.Text = "添加文件夹";
            this.addFolderToolStripMenuItem.Click += new System.EventHandler(this.addFolderToolStripMenuItem_Click);
            // 
            // addExeToolStripMenuItem
            // 
            this.addExeToolStripMenuItem.Name = "addExeToolStripMenuItem";
            this.addExeToolStripMenuItem.Size = new System.Drawing.Size(152, 22);
            this.addExeToolStripMenuItem.Text = "添加文件";
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
            this.showMainFormToolStripMenuItem.Text = "显示主界面";
            this.showMainFormToolStripMenuItem.Click += new System.EventHandler(this.showMainFormToolStripMenuItem_Click);
            // 
            // updateRulesTrayToolStripMenuItem
            // 
            this.updateRulesTrayToolStripMenuItem.Name = "updateRulesTrayToolStripMenuItem";
            this.updateRulesTrayToolStripMenuItem.Size = new System.Drawing.Size(180, 22);
            this.updateRulesTrayToolStripMenuItem.Text = "更新规则";
            this.updateRulesTrayToolStripMenuItem.Click += new System.EventHandler(this.updateRulesTrayToolStripMenuItem_Click);
            // 
            // exitToolStripMenuItem
            // 
            this.exitToolStripMenuItem.Name = "exitToolStripMenuItem";
            this.exitToolStripMenuItem.Size = new System.Drawing.Size(180, 22);
            this.exitToolStripMenuItem.Text = "退出";
            this.exitToolStripMenuItem.Click += new System.EventHandler(this.exitToolStripMenuItem_Click);
            // 
            // trayIcon
            // 
            this.trayIcon.ContextMenuStrip = this.trayMenu;
            this.trayIcon.Text = "防火墙出站规则管理工具";
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
            this.tableLayoutPanel.RowCount = 5;
            this.tableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
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
            this.addButton.Text = "添加";
            this.addButton.UseVisualStyleBackColor = true;
            this.addButton.ContextMenuStrip = this.addContextMenu;
            this.addButton.Click += new System.EventHandler(this.addButton_Click);
            this.addButton.Anchor = System.Windows.Forms.AnchorStyles.None;
            // 
            // removeFolderButton
            // 
            this.removeFolderButton.Location = new System.Drawing.Point(3, 3);
            this.removeFolderButton.Name = "removeFolderButton";
            this.removeFolderButton.Size = new System.Drawing.Size(120, 30);
            this.removeFolderButton.TabIndex = 9;
            this.removeFolderButton.Text = "删除文件夹";
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
            this.updateRulesButton.Text = "更新规则";
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
            this.clearRulesButton.Text = "清空规则";
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
            this.viewLogsButton.Text = "查看日志";
            this.viewLogsButton.UseVisualStyleBackColor = true;
            this.viewLogsButton.Click += new System.EventHandler(this.viewLogsButton_Click);
            this.viewLogsButton.Anchor = System.Windows.Forms.AnchorStyles.None;
            // 
            // openFileDialog
            // 
            this.openFileDialog.Filter = "可执行文件 (*.exe)|*.exe";
            this.openFileDialog.Title = "选择可执行文件";
            // 
            // pauseButton
            // 
            this.pauseButton.Enabled = false;
            this.pauseButton.Location = new System.Drawing.Point(3, 3);
            this.pauseButton.Name = "pauseButton";
            this.pauseButton.Size = new System.Drawing.Size(120, 30);
            this.pauseButton.TabIndex = 4;
            this.pauseButton.Text = "暂停";
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
            this.resumeButton.Text = "继续";
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
            this.stopButton.Text = "终止";
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
            this.statusLabel.Text = "就绪，等待操作";
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
            
            // 第二行：运行控制按钮和查看日志
            this.tableLayoutPanel.Controls.Add(this.pauseButton, 0, 2);
            this.tableLayoutPanel.Controls.Add(this.resumeButton, 1, 2);
            this.tableLayoutPanel.Controls.Add(this.stopButton, 2, 2);
            this.tableLayoutPanel.Controls.Add(this.viewLogsButton, 3, 2);
            
            // 第三行：进度条
            this.tableLayoutPanel.SetColumnSpan(this.progressBar, 4);
            this.tableLayoutPanel.Controls.Add(this.progressBar, 0, 3);
            
            // 第四行：状态标签
            this.tableLayoutPanel.SetColumnSpan(this.statusLabel, 4);
            this.tableLayoutPanel.Controls.Add(this.statusLabel, 0, 4);
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.tableLayoutPanel);
            this.Name = "Form1";
            this.Text = "防火墙出站规则管理工具";
            this.Resize += new System.EventHandler(this.Form1_Resize);
            this.ShowInTaskbar = true;
            // 图标由项目文件中的 ApplicationIcon 设置自动处理
            this.ResumeLayout(false);
            this.PerformLayout();
        }

        #endregion
    }
}
