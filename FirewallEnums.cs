using System;

namespace FirewallManager
{
    /// <summary>
    /// Firewall action enum
    /// </summary>
    public enum FirewallAction
    {
        /// <summary>
        /// Block
        /// </summary>
        Block = 0,
        
        /// <summary>
        /// Allow
        /// </summary>
        Allow = 1
    }

    /// <summary>
    /// Firewall direction enum
    /// </summary>
    public enum FirewallDirection
    {
        /// <summary>
        /// Inbound
        /// </summary>
        Inbound = 1,
        
        /// <summary>
        /// Outbound
        /// </summary>
        Outbound = 2
    }

    /// <summary>
    /// Work state enum
    /// </summary>
    public enum WorkState
    {
        /// <summary>
        /// Idle
        /// </summary>
        Idle,
        
        /// <summary>
        /// Running
        /// </summary>
        Running,
        
        /// <summary>
        /// Paused
        /// </summary>
        Paused,
        
        /// <summary>
        /// Stopping
        /// </summary>
        Stopping
    }
}
