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
            // 注册全局未处理异常处理
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
            Application.ThreadException += Application_ThreadException;
            Application.ApplicationExit += Application_ApplicationExit;

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            
            Application.Run(new Form1());
        }

        /// <summary>
        /// 应用程序域未处理异常处理
        /// </summary>
        private static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            try
            {
                var ex = e.ExceptionObject as Exception;
                if (ex != null)
                {
                    LogManager.Error("Unhandled AppDomain exception", ex);
                }
                else
                {
                    LogManager.Error($"Unhandled AppDomain exception: {e.ExceptionObject}");
                }
            }
            catch
            {
                // 避免递归异常
            }
        }

        /// <summary>
        /// 应用程序线程未处理异常处理
        /// </summary>
        private static void Application_ThreadException(object sender, System.Threading.ThreadExceptionEventArgs e)
        {
            try
            {
                LogManager.Error("Unhandled thread exception", e.Exception);
                
                // 对于严重异常，提示用户并终止
                DialogResult result = MessageBox.Show(
                    "程序发生严重错误，是否继续运行？\n\n" + e.Exception.Message,
                    "严重错误",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Error);
                
                if (result == DialogResult.No)
                {
                    Application.Exit();
                }
            }
            catch
            {
                Application.Exit();
            }
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
                
                // 释放日志文件句柄
                LogManager.Dispose();
                
                // 尝试记录退出日志（此时可能已无法写入）
                try
                {
                    Console.WriteLine("FirewallManager application exited.");
                }
                catch { }
            }
            catch
            {
                // 退出时的异常不应影响程序终止
            }
        }
    }
}
