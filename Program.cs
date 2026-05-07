using System;
using System.Windows.Forms;

namespace FirewallManager
{
    static class Program
    {
        /// <summary>
        /// 应用程序的主入口点
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            
            // 注册应用程序退出事件，确保资源正确释放
            Application.ApplicationExit += Application_ApplicationExit;
            
            Application.Run(new Form1());
        }

        /// <summary>
        /// 应用程序退出事件处理程序
        /// 用于在应用程序退出时释放静态资源
        /// </summary>
        /// <param name="sender">发送者</param>
        /// <param name="e">事件参数</param>
        private static void Application_ApplicationExit(object sender, EventArgs e)
        {
            try
            {
                // 释放白名单监控器等静态资源
                WhitelistForm.ReleaseStaticResources();
                LogManager.Info(LangManager.GetText("logMessages.applicationExiting"));
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.exitCleanupFailed"), ex);
            }
        }
    }
}
