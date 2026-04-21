using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace FirewallManager
{
    /// <summary>
    /// 白名单管理窗口
    /// Whitelist Management Window
    /// 用于管理防火墙白名单
    /// Used for managing firewall whitelist
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
        /// Whitelist list
        /// </summary>
        private List<string> whitelist = new List<string>();

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
                string configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FirewallManager", "whitelist.json");
                
                if (File.Exists(configPath))
                {
                    string json = File.ReadAllText(configPath, Encoding.UTF8);
                    whitelist = JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>();
                    
                    foreach (var item in whitelist)
                    {
                        whitelistListBox.Items.Add(item);
                    }
                    
                    LogManager.Info($"从配置文件加载了 {whitelist.Count} 个白名单项目");
                }
            }
            catch (Exception ex)
            {
                LogManager.Error("加载白名单失败", ex);
                MessageBox.Show(LangManager.GetText("messages.loadWhitelistFailed", ex.Message), LangManager.GetText("messages.loadWhitelistFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// 白名单保存事件
        /// Whitelist saved event
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
                string configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FirewallManager", "whitelist.json");
                Directory.CreateDirectory(Path.GetDirectoryName(configPath));
                
                whitelist.Clear();
                foreach (var item in whitelistListBox.Items)
                {
                    whitelist.Add(item.ToString());
                }
                
                string json = JsonSerializer.Serialize(whitelist, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(configPath, json, Encoding.UTF8);
                
                LogManager.Info($"保存了 {whitelist.Count} 个白名单项目到配置文件");
                MessageBox.Show("白名单已保存", "成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
                
                // 触发白名单保存事件
                WhitelistSaved?.Invoke(this, EventArgs.Empty);
            }
            catch (Exception ex)
            {
                LogManager.Error("保存白名单失败", ex);
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
                openFileDialog.Filter = "可执行文件 (*.exe)|*.exe|所有文件 (*.*)|*.*";
                openFileDialog.Title = "选择可执行文件";
                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    string selectedPath = openFileDialog.FileName;
                    if (!whitelistListBox.Items.Contains(selectedPath))
                    {
                        whitelistListBox.Items.Add(selectedPath);
                        LogManager.Info($"添加到白名单: {selectedPath}");
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
                LogManager.Info($"从白名单移除: {selectedItem}");
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
            if (MessageBox.Show("确定要清空所有白名单项目吗？", "确认", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes)
            {
                try
                {
                    whitelistListBox.Items.Clear();
                    LogManager.Info("白名单已清空");
                }
                catch (Exception ex)
                {
                    LogManager.Error("清空白名单失败", ex);
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
        /// </summary>
        /// <param name="appPath">应用程序路径</param>
        /// <returns>是否在白名单中</returns>
        public static bool IsInWhitelist(string appPath)
        {
            try
            {
                string configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FirewallManager", "whitelist.json");
                
                if (File.Exists(configPath))
                {
                    string json = File.ReadAllText(configPath, Encoding.UTF8);
                    List<string> whitelist = JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>();
                    
                    return whitelist.Any(path => path.Equals(appPath, StringComparison.OrdinalIgnoreCase));
                }
                
                return false;
            }
            catch (Exception ex)
            {
                LogManager.Error("检查白名单失败", ex);
                return false;
            }
        }
    }
}