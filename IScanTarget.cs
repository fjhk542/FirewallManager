using System;

namespace FirewallManager
{
    /// <summary>
    /// Minimal contract for a monitored target.
    /// FirewallService only needs these two properties — keeps the service decoupled from Form1's concrete ScanTarget class.
    /// </summary>
    public interface IScanTarget
    {
        /// <summary>
        /// Path of the scan target (folder or a single .exe file).
        /// </summary>
        string Path { get; }

        /// <summary>
        /// True if Path points to a single .exe file; false if it points to a folder.
        /// </summary>
        bool IsExe { get; }
    }
}
