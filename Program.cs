using System;
using System.Windows.Forms;

namespace FirewallManager
{
    static class Program
    {
        /// <summary>
        /// Application main entry point
        /// </summary>
        [STAThread]
        static void Main()
        {
            // Register global unhandled exception handlers
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
            Application.ThreadException += Application_ThreadException;
            Application.ApplicationExit += Application_ApplicationExit;

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            
            Application.Run(new Form1());
        }

        /// <summary>
        /// AppDomain unhandled exception handler
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
                // Avoid recursive exceptions
            }
        }

        /// <summary>
        /// Application thread unhandled exception handler
        /// </summary>
        private static void Application_ThreadException(object sender, System.Threading.ThreadExceptionEventArgs e)
        {
            try
            {
                LogManager.Error("Unhandled thread exception", e.Exception);
                
                // For critical exceptions, prompt user and terminate
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
        /// Application exit event handler
        /// Used to release static resources when application exits
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event arguments</param>
        private static void Application_ApplicationExit(object sender, EventArgs e)
        {
            try
            {
                // Release whitelist watcher and other static resources
                WhitelistForm.ReleaseStaticResources();
                
                // Release log file handle
                LogManager.Dispose();
                
                // Try to log exit (may not be writable at this point)
                try
                {
                    Console.WriteLine("FirewallManager application exited.");
                }
                catch { }
            }
            catch
            {
                // Exceptions during exit should not affect program termination
            }
        }
    }
}
