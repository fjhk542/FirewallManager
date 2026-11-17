using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace FirewallManager
{
    /// <summary>
    /// Log Viewer Window
    /// Used to display and manage operation logs
    /// </summary>
    public partial class LogsForm : Form
    {
        #region UI Controls
        // UI control definitions
        private System.Windows.Forms.Button btnRefresh;
        private System.Windows.Forms.Button btnClearLogs;
        private System.Windows.Forms.Button btnCopyLogs;
        private System.Windows.Forms.Button btnExportLogs;
        private System.Windows.Forms.Button btnClose;
        private System.Windows.Forms.SaveFileDialog saveFileDialog;
        private System.Windows.Forms.TextBox logsTextBox;
        #endregion

        /// <summary>
        /// Constructor
        /// Initialize log viewer window, including UI components and log loading
        /// </summary>
        public LogsForm()
        {
            // Initialize
            this.Text = LangManager.GetText("form.logs.title");
            this.Size = new Size(800, 600);
            
            // Create basic controls
            logsTextBox = new TextBox();
            logsTextBox.Multiline = true;
            logsTextBox.Dock = DockStyle.Fill;
            logsTextBox.ReadOnly = true;
            logsTextBox.ScrollBars = ScrollBars.Vertical;
            // Use system default font
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
            
            // Layout
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
            
            // Row 1: Log text box (spans 5 columns)
            panel.SetColumnSpan(logsTextBox, 5);
            panel.Controls.Add(logsTextBox, 0, 0);
            
            // Row 2: All function buttons
            panel.Controls.Add(btnRefresh, 0, 1);
            panel.Controls.Add(btnClearLogs, 1, 1);
            panel.Controls.Add(btnCopyLogs, 2, 1);
            panel.Controls.Add(btnExportLogs, 3, 1);
            panel.Controls.Add(btnClose, 4, 1);
            
            this.Controls.Add(panel);
            
            // Load logs
            LoadLogs();
        }

        /// <summary>
        /// Load logs
        /// Read log content from LogManager and display in text box
        /// </summary>
        private void LoadLogs()
        {
            try
            {
                // Get actual log content from LogManager
                var logLines = LogManager.ReadLogs();
                StringBuilder logContent = new StringBuilder();
                
                // Limit displayed log content size (max 500KB) to prevent UI freeze
                const int maxLogDisplaySize = 500 * 1024;
                
                if (logLines.Count > 0)
                {
                    foreach (var line in logLines)
                    {
                        if (logContent.Length + line.Length + Environment.NewLine.Length > maxLogDisplaySize)
                        {
                            logContent.AppendLine(LangManager.GetText("messages.logContentTruncated"));
                            break;
                        }
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
        /// Refresh button click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void btnRefresh_Click(object sender, EventArgs e)
        {
            LoadLogs();
        }

        /// <summary>
        /// Clear logs button click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private void btnClearLogs_Click(object sender, EventArgs e)
        {
            if (MessageBox.Show(LangManager.GetText("messages.clearLogsConfirm"), LangManager.GetText("messages.clearLogsConfirmTitle"), MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes)
            {
                try
                {
                    // Clear actual log file
                    LogManager.ClearLogs();
                    // Clear UI display
                    logsTextBox.Clear();
                    // Display no logs message
                    logsTextBox.Text = LangManager.GetText("messages.noLogs");
                }
                catch (Exception ex)
                {
                    MessageBox.Show(LangManager.GetText("messages.clearLogsFailed", ex.Message), LangManager.GetText("messages.clearLogsFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        /// <summary>
        /// Copy logs button click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
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
        /// Export logs button click event
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
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
                    
                    // Validate export path security, prevent path traversal attacks
                    string normalizedExportPath = Path.GetFullPath(exportPath);
                    
                    // Check if export path contains UNC path or special device path prefixes
                    if (normalizedExportPath.StartsWith(@"\\", StringComparison.OrdinalIgnoreCase))
                    {
                        LogManager.Warning(LangManager.GetText("logMessages.exportPathUncNotAllowed"));
                        MessageBox.Show(LangManager.GetText("messages.exportPathInvalid"), LangManager.GetText("messages.exportPathInvalidTitle"), MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }
                    
                    // Verify target directory exists
                    string exportDir = Path.GetDirectoryName(normalizedExportPath);
                    if (!string.IsNullOrEmpty(exportDir) && !Directory.Exists(exportDir))
                    {
                        Directory.CreateDirectory(exportDir);
                    }
                    
                    File.WriteAllText(normalizedExportPath, logsTextBox.Text, Encoding.UTF8);
                    MessageBox.Show(LangManager.GetText("messages.exportSuccess"), LangManager.GetText("messages.exportSuccessTitle"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.exportLogFailed", ex.Message));
                MessageBox.Show(LangManager.GetText("messages.exportFailed"), LangManager.GetText("messages.exportFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
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
        /// Release resources
        /// </summary>
        /// <param name="disposing">Whether to release managed resources</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (saveFileDialog != null)
                {
                    saveFileDialog.Dispose();
                    saveFileDialog = null;
                }
            }
            base.Dispose(disposing);
        }
    }
}