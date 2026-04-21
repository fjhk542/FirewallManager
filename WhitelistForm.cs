using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
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
        private System.Windows.Forms.Button btnClose;
        private System.Windows.Forms.ListBox whitelistListBox;
        #endregion

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
            btnAdd.Dock = DockStyle.Top;
            btnAdd.Click += btnAdd_Click;
            
            btnRemove = new Button();
            btnRemove.Text = LangManager.GetText("buttons.remove");
            btnRemove.Dock = DockStyle.Top;
            btnRemove.Click += btnRemove_Click;
            
            btnClear = new Button();
            btnClear.Text = LangManager.GetText("buttons.clear");
            btnClear.Dock = DockStyle.Top;
            btnClear.Click += btnClear_Click;
            
            btnClose = new Button();
            btnClose.Text = LangManager.GetText("buttons.close");
            btnClose.Dock = DockStyle.Bottom;
            btnClose.Click += btnClose_Click;
            
            // 布局
            TableLayoutPanel panel = new TableLayoutPanel();
            panel.Dock = DockStyle.Fill;
            panel.ColumnCount = 1;
            panel.RowCount = 5;
            
            panel.Controls.Add(btnAdd, 0, 0);
            panel.Controls.Add(btnRemove, 0, 1);
            panel.Controls.Add(btnClear, 0, 2);
            panel.Controls.Add(whitelistListBox, 0, 3);
            panel.Controls.Add(btnClose, 0, 4);
            
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
                // 简单实现
                whitelistListBox.Items.Add("示例应用程序 1");
                whitelistListBox.Items.Add("示例应用程序 2");
            }
            catch (Exception ex)
            {
                MessageBox.Show(LangManager.GetText("messages.loadWhitelistFailed", ex.Message), LangManager.GetText("messages.loadWhitelistFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                openFileDialog.Filter = LangManager.GetText("dialogs.exeFilter");
                openFileDialog.Title = LangManager.GetText("dialogs.selectExe");
                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    string selectedPath = openFileDialog.FileName;
                    whitelistListBox.Items.Add(selectedPath);
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
                whitelistListBox.Items.Remove(whitelistListBox.SelectedItem);
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
            if (MessageBox.Show(LangManager.GetText("messages.clearWhitelistConfirm"), LangManager.GetText("messages.clearWhitelistConfirmTitle"), MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes)
            {
                try
                {
                    whitelistListBox.Items.Clear();
                }
                catch (Exception ex)
                {
                    MessageBox.Show(LangManager.GetText("messages.clearWhitelistFailed", ex.Message), LangManager.GetText("messages.clearWhitelistFailedTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
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
    }
}