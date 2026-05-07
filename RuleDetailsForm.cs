using System;
using System.Windows.Forms;

namespace FirewallManager
{
    /// <summary>
    /// 规则详情窗体
    /// 用于显示和管理单个防火墙规则的详细信息
    /// </summary>
    public partial class RuleDetailsForm : Form
    {
        private dynamic firewallRule;
        private string ruleName;
        
        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="rule">防火墙规则对象</param>
        /// <param name="name">规则名称</param>
        public RuleDetailsForm(dynamic rule, string name)
        {
            InitializeComponent();
            firewallRule = rule;
            ruleName = name;
            
            // 覆盖设计器生成的硬编码文本
            this.Text = LangManager.GetText("form.ruleDetails.title");
            label1.Text = LangManager.GetText("form.ruleDetails.ruleName");
            label2.Text = LangManager.GetText("form.ruleDetails.description");
            label3.Text = LangManager.GetText("form.ruleDetails.application");
            label4.Text = LangManager.GetText("form.ruleDetails.direction");
            label5.Text = LangManager.GetText("form.ruleDetails.action");
            
            // 更新下拉框选项
            cmbDirection.Items.Clear();
            cmbDirection.Items.AddRange(new object[] {
                LangManager.GetText("form.ruleDetails.inbound"),
                LangManager.GetText("form.ruleDetails.outbound")
            });
            
            cmbAction.Items.Clear();
            cmbAction.Items.AddRange(new object[] {
                LangManager.GetText("form.ruleDetails.block"),
                LangManager.GetText("form.ruleDetails.allow")
            });
            
            // 更新复选框和按钮文本
            chkEnabled.Text = LangManager.GetText("form.ruleDetails.enabled");
            btnSave.Text = LangManager.GetText("buttons.save");
            btnCancel.Text = LangManager.GetText("buttons.cancel");
            
            LoadRuleDetails();
        }
        
        /// <summary>
        /// 加载规则详情
        /// </summary>
        private void LoadRuleDetails()
        {
            try
            {
                txtRuleName.Text = ruleName;
                txtDescription.Text = firewallRule.Description;
                txtApplicationName.Text = firewallRule.ApplicationName;
                chkEnabled.Checked = firewallRule.Enabled;
                
                // 设置方向
                int direction = firewallRule.Direction;
                cmbDirection.SelectedIndex = direction == 1 ? 0 : 1; // 1 = 入站, 2 = 出站
                
                // 设置操作
                int action = firewallRule.Action;
                cmbAction.SelectedIndex = action; // 0 = 阻止, 1 = 允许
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.loadRuleDetailsFailed", ex.Message));
                MessageBox.Show(LangManager.GetText("messages.loadRuleDetailsFailed") + ": " + ex.Message, LangManager.GetText("messages.errorTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        
        /// <summary>
        /// 保存按钮点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void btnSave_Click(object sender, EventArgs e)
        {
            try
            {
                firewallRule.Name = txtRuleName.Text;
                firewallRule.Description = txtDescription.Text;
                firewallRule.Enabled = chkEnabled.Checked;
                firewallRule.Direction = cmbDirection.SelectedIndex == 0 ? 1 : 2; // 1 = 入站, 2 = 出站
                firewallRule.Action = cmbAction.SelectedIndex; // 0 = 阻止, 1 = 允许
                
                LogManager.Info(LangManager.GetText("logMessages.updateRule", txtRuleName.Text));
                MessageBox.Show(LangManager.GetText("messages.ruleUpdated"), LangManager.GetText("messages.successTitle"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                this.Close();
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.saveRuleFailed", ex.Message));
                MessageBox.Show(LangManager.GetText("messages.saveRuleFailed") + ": " + ex.Message, LangManager.GetText("messages.errorTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        
        /// <summary>
        /// 取消按钮点击事件
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private void btnCancel_Click(object sender, EventArgs e)
        {
            this.Close();
        }
        
        #region Windows 窗体设计器生成的代码
        /// <summary>
        /// 必需的设计器变量
        /// 用于管理窗体组件的生命周期
        /// </summary>
        private System.ComponentModel.IContainer components = null;
        
        /// <summary>
        /// 清理所有正在使用的资源
        /// </summary>
        /// <param name="disposing">如果应释放托管资源，为 true；否则为 false</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }
        
        /// <summary>
        /// 设计器支持所需的方法 - 不要使用代码编辑器修改此方法的内容
        /// 初始化所有UI控件，设置其属性、布局和事件处理程序
        /// </summary>
        private void InitializeComponent()
        {
            this.label1 = new System.Windows.Forms.Label();
            this.txtRuleName = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.txtDescription = new System.Windows.Forms.TextBox();
            this.label3 = new System.Windows.Forms.Label();
            this.txtApplicationName = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.cmbDirection = new System.Windows.Forms.ComboBox();
            this.label5 = new System.Windows.Forms.Label();
            this.cmbAction = new System.Windows.Forms.ComboBox();
            this.chkEnabled = new System.Windows.Forms.CheckBox();
            this.btnSave = new System.Windows.Forms.Button();
            this.btnCancel = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(12, 15);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(53, 13);
            this.label1.TabIndex = 0;
            // 
            // txtRuleName
            // 
            this.txtRuleName.Location = new System.Drawing.Point(71, 12);
            this.txtRuleName.Name = "txtRuleName";
            this.txtRuleName.Size = new System.Drawing.Size(300, 20);
            this.txtRuleName.TabIndex = 1;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(12, 41);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(53, 13);
            this.label2.TabIndex = 2;
            // 
            // txtDescription
            // 
            this.txtDescription.Location = new System.Drawing.Point(71, 38);
            this.txtDescription.Multiline = true;
            this.txtDescription.Name = "txtDescription";
            this.txtDescription.Size = new System.Drawing.Size(300, 60);
            this.txtDescription.TabIndex = 3;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(12, 104);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(53, 13);
            this.label3.TabIndex = 4;
            // 
            // txtApplicationName
            // 
            this.txtApplicationName.Location = new System.Drawing.Point(71, 101);
            this.txtApplicationName.Name = "txtApplicationName";
            this.txtApplicationName.ReadOnly = true;
            this.txtApplicationName.Size = new System.Drawing.Size(300, 20);
            this.txtApplicationName.TabIndex = 5;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(12, 130);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(53, 13);
            this.label4.TabIndex = 6;
            // 
            // cmbDirection
            // 
            this.cmbDirection.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cmbDirection.Items.AddRange(new object[] { });
            this.cmbDirection.Location = new System.Drawing.Point(71, 127);
            this.cmbDirection.Name = "cmbDirection";
            this.cmbDirection.Size = new System.Drawing.Size(100, 21);
            this.cmbDirection.TabIndex = 7;
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(193, 130);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(53, 13);
            this.label5.TabIndex = 8;
            // 
            // cmbAction
            // 
            this.cmbAction.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cmbAction.Items.AddRange(new object[] { });
            this.cmbAction.Location = new System.Drawing.Point(252, 127);
            this.cmbAction.Name = "cmbAction";
            this.cmbAction.Size = new System.Drawing.Size(119, 21);
            this.cmbAction.TabIndex = 9;
            // 
            // chkEnabled
            // 
            this.chkEnabled.AutoSize = true;
            this.chkEnabled.Location = new System.Drawing.Point(71, 154);
            this.chkEnabled.Name = "chkEnabled";
            this.chkEnabled.Size = new System.Drawing.Size(59, 17);
            this.chkEnabled.TabIndex = 10;
            this.chkEnabled.UseVisualStyleBackColor = true;
            // 
            // btnSave
            // 
            this.btnSave.Location = new System.Drawing.Point(155, 180);
            this.btnSave.Name = "btnSave";
            this.btnSave.Size = new System.Drawing.Size(75, 23);
            this.btnSave.TabIndex = 11;
            this.btnSave.UseVisualStyleBackColor = true;
            this.btnSave.Click += new System.EventHandler(this.btnSave_Click);
            // 
            // btnCancel
            // 
            this.btnCancel.Location = new System.Drawing.Point(236, 180);
            this.btnCancel.Name = "btnCancel";
            this.btnCancel.Size = new System.Drawing.Size(75, 23);
            this.btnCancel.TabIndex = 12;
            this.btnCancel.UseVisualStyleBackColor = true;
            this.btnCancel.Click += new System.EventHandler(this.btnCancel_Click);
            // 
            // RuleDetailsForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(384, 215);
            this.Controls.Add(this.btnCancel);
            this.Controls.Add(this.btnSave);
            this.Controls.Add(this.chkEnabled);
            this.Controls.Add(this.cmbAction);
            this.Controls.Add(this.label5);
            this.Controls.Add(this.cmbDirection);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.txtApplicationName);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.txtDescription);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.txtRuleName);
            this.Controls.Add(this.label1);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "RuleDetailsForm";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            this.ResumeLayout(false);
            this.PerformLayout();
        }
        
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox txtRuleName;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox txtDescription;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.TextBox txtApplicationName;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.ComboBox cmbDirection;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.ComboBox cmbAction;
        private System.Windows.Forms.CheckBox chkEnabled;
        private System.Windows.Forms.Button btnSave;
        private System.Windows.Forms.Button btnCancel;
        #endregion
    }
}