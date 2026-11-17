using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace FirewallManager
{
    /// <summary>
    /// Firewall service interface
    /// Defines standard interface for firewall operations
    /// </summary>
    public interface IFirewallService : IDisposable
    {
        /// <summary>
        /// Initialize firewall component
        /// </summary>
        /// <returns>Whether initialization succeeded</returns>
        bool InitializeFirewallComponents();

        /// <summary>
        /// Sync local rule list with actual firewall rules
        /// </summary>
        void SyncRulesList();

        /// <summary>
        /// Check if firewall rule exists
        /// </summary>
        /// <param name="ruleName">Rule name</param>
        /// <returns>Whether rule exists</returns>
        bool CheckRuleExists(string ruleName);

        /// <summary>
        /// Create firewall rule for executable file
        /// </summary>
        /// <param name="exePath">Executable file path</param>
        /// <returns>Whether creation succeeded</returns>
        bool CreateRuleForExe(string exePath);

        /// <summary>
        /// Delete firewall rule
        /// </summary>
        /// <param name="ruleName">Rule name</param>
        /// <returns>Whether deletion succeeded</returns>
        bool DeleteRule(string ruleName);

        /// <summary>
        /// Delete all firewall rules created by this program
        /// </summary>
        /// <returns>Number of rules deleted</returns>
        int ClearAllRules();

        /// <summary>
        /// Update firewall rules
        /// Scan specified paths and create rules for all executable files
        /// </summary>
        /// <param name="monitoredTargets">Monitored target list</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <param name="updateUI">UI update callback</param>
        /// <returns>Processing result, including added and skipped rule counts</returns>
        Task<(int addedCount, int skippedCount)> UpdateFirewallRules(IEnumerable<IScanTarget> monitoredTargets, CancellationToken cancellationToken, Action<object, string> updateUI);

        /// <summary>
        /// Get rule details
        /// </summary>
        /// <param name="ruleName">Rule name</param>
        /// <returns>Rule object, or null if not found</returns>
        RuleDetailsInfo GetRuleDetails(string ruleName);
        bool UpdateRule(string ruleName, string description, bool enabled, int direction, int action);

        /// <summary>
        /// Get all rule names created by this program
        /// </summary>
        /// <returns>List of rule names</returns>
        List<string> GetAllRuleNames();

        /// <summary>
        /// Remove firewall rules for specified folder
        /// </summary>
        /// <param name="folderPath">Folder path</param>
        /// <returns>Number of rules deleted</returns>
        int RemoveFolderRules(string folderPath);
    }
}
