using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace FirewallManager
{
    /// <summary>
    /// 日志查看窗口
    /// 用于显示和管理操作日志
    /// </summary>
    public partial class LogsForm : Form
    {
        #region UI Controls
        // UI 控件定义
        private System.Windows.Forms.Button btnRefresh;
        private System.Windows.Forms.Button btnClearLogs;
        private System.Windows.Forms.Button btnCopyLogs;
        private System.Windows.Forms.Button btnExportLogs;
        private System.Windows.Forms.Button btnClose;
        private System.Windows.Forms.SaveFileDialog saveFileDialog;
        private System.Windows.Forms.TextBox logsTextBox;
        #endregion

        /// <summary>
        /// 构造函数
        /// 初始化日志查看窗口，包括UI组件和日志加载
        /// </summary>
        public LogsForm()
        {
            // 初始化
            this.Text = LangManager.GetText("form.logs.title");
            this.Size = new Size(800, 600);
            
            // 创建基本控件
            logsTextBox = new TextBox();
            logsTextBox.Multiline = true;
            logsTextBox.Dock = DockStyle.Fill;
            logsTextBox.ReadOnly = true;
            logsTextBox.ScrollBars = ScrollBars.Vertical;
            // 使用系统默认字体
            logsTextBox.Font = new Font(SystemFonts.DefaultFont.FontFamily, 9F, FontStyle.Regular, GraphicsUnit.Point, ((byte)(0)));
            
            btnRefresh = new Button();
            btnRefresh.Text = LangManager.GetText("buttons.refresh");
            btnRefresh.Anchor = AnchorStyles.None;
            btnRefresh.Click += btnRefresh_Click;
            
            btnClearLogs = new Button();
            btnClearLogs.Text = LangManager.GetText("buttons.clearLogs");
            btnClearLogs.Anchor = AnchorStyles.None;
            btnClearLogs.Click += btnClearLogs_Click;
            
            btnCopyLogs = new Button();
            btnCopyLogs.Text = LangManager.GetText("buttons.copyLogs");
            btnCopyLogs.Anchor = AnchorStyles.None;
            btnCopyLogs.Click += btnCopyLogs_Click;
            
            btnExportLogs = new Button();
            btnExportLogs.Text = LangManager.GetText("buttons.exportLogs");
            btnExportLogs.Anchor = AnchorStyles.None;
            btnExportLogs.Click += btnExportLogs_Click;
            
            btnClose = new Button();
            btnClose.Text = LangManager.GetText("buttons.close");
            btnClose.Anchor = AnchorStyles.None;
            btnClose.Click += btnClose_Click;
            
            saveFileDialog = new SaveFileDialog();
            saveFileDialog.Filter = LangManager.GetText("messages.textFileFilter");
            saveFileDialog.Title = LangManager.GetText("messages.exportLogs");
            
            // 布局
            TableLayoutPanel panel = new TableLayoutPanel();
            panel.Dock = DockStyle.Fill;
            panel.ColumnCount = 5;
            panel.RowCount = 2;
            panel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            panel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 40F));
            panel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 20F));
            panel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 20F));
            panel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 20F));
            panel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 20F));
            panel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 20F));
            
            // 第一行：日志文本框（跨5列）
            panel.SetColumnSpan(logsTextBox, 5);
            panel.Controls.Add(logsTextBox, 0, 0);
            
            // 第二行：所有功能按钮
            panel.Controls.Add(btnRefresh, 0, 1);
            panel.Controls.Add(btnClearLogs, 1, 1);
            panel.Controls.Add(btnCopyLogs, 2, 1);
            panel.Controls.Add(btnExportLogs, 3, 1);
            panel.Controls.Add(btnClose, 4, 1);
            
            this.Controls.Add(panel);
            
            // 加载日志
            LoadLogs();
        }

        /// <summary>
        /// 加载日志
        /// 从LogManager读取日志内容并显示在文本框中
        /// </summary>
        private void LoadLogs()
        {
            try
            {
                // 从LogManager获取实际的日志内容
                var logLines = LogManager.ReadLogs();
                StringBuilder logContent = new StringBuilder();
                
                if (logLines.Count > 0)
                {
                    foreach (var line in logLines)
                    {
                        logContent.AppendLine(line);
                    }
                }
                else
                {
                    logContent.AppendLine(LangManager.GetText("messages.noLogs"));
                }
                
                logsTextBox.Text = logContent.ToString();
            }
            catch (Exception ex)
            {
                MessageBox.Show(LangManager.GetText("messages.loadLogsFailed", ex.Message), LangManager.GetText("messages.loadLogsFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// 刷新按钮点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void btnRefresh_Click(object sender, EventArgs e)
        {
            LoadLogs();
        }

        /// <summary>
        /// 清空日志按钮点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void btnClearLogs_Click(object sender, EventArgs e)
        {
            if (MessageBox.Show(LangManager.GetText("messages.clearLogsConfirm"), LangManager.GetText("messages.clearLogsConfirmTitle"), MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes)
            {
                try
                {
                    // 清空实际日志文件
                    LogManager.ClearLogs();
                    // 清空界面显示
                    logsTextBox.Clear();
                    // 显示暂无日志记录
                    logsTextBox.Text = LangManager.GetText("messages.noLogs");
                }
                catch (Exception ex)
                {
                    MessageBox.Show(LangManager.GetText("messages.clearLogsFailed", ex.Message), LangManager.GetText("messages.clearLogsFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        /// <summary>
        /// 复制日志按钮点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void btnCopyLogs_Click(object sender, EventArgs e)
        {
            try
            {
                if (!string.IsNullOrEmpty(logsTextBox.Text))
                {
                    Clipboard.SetText(logsTextBox.Text);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(LangManager.GetText("messages.copyLogsFailed", ex.Message), LangManager.GetText("messages.copyLogsFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// 导出日志按钮点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void btnExportLogs_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(logsTextBox.Text))
                {
                    MessageBox.Show(LangManager.GetText("messages.exportNoLogs"), LangManager.GetText("messages.exportNoLogsTitle"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                
                if (saveFileDialog.ShowDialog() == DialogResult.OK)
                {
                    string exportPath = saveFileDialog.FileName;
                    File.WriteAllText(exportPath, logsTextBox.Text, Encoding.UTF8);
                    MessageBox.Show(LangManager.GetText("messages.exportSuccess"), LangManager.GetText("messages.exportSuccessTitle"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception)
            {
                MessageBox.Show(LangManager.GetText("messages.exportFailed"), LangManager.GetText("messages.exportFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// 关闭按钮点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void btnClose_Click(object sender, EventArgs e)
        {
            this.Close();
        }
    }
}