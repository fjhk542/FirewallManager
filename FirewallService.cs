using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FirewallManager
{
    /// <summary>
    /// Firewall service class
    /// Handles firewall-related operations
    /// </summary>
    public class FirewallService : IFirewallService
    {
        /// <summary>
        /// Firewall policy object (stored as object to support volatile, accessed via dynamic)
        /// </summary>
        private volatile object _firewallPolicy;

        /// <summary>
        /// List of added rules (used for ordered traversal and persistence)
        /// </summary>
        private List<string> addedRules;

        /// <summary>
        /// HashSet of added rules (for O(1) fast lookup)
        /// Kept in sync with addedRules to prevent CheckRuleExists from degrading to O(n) on large rule sets
        /// </summary>
        private HashSet<string> addedRulesLookup;

        /// <summary>
        /// Lock object for ensuring thread safety
        /// </summary>
        private readonly object addedRulesLock;

        /// <summary>
        /// Resource disposal flag (thread-safe)
        /// </summary>
        private volatile bool _disposed;

        /// <summary>
        /// Gets a dynamic view of firewallPolicy (thread-safe read of _firewallPolicy)
        /// </summary>
        private dynamic firewallPolicy
        {
            get { return _firewallPolicy; }
            set { _firewallPolicy = value; }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public FirewallService()
        {
            addedRules = new List<string>();
            addedRulesLookup = new HashSet<string>(StringComparer.Ordinal);
            addedRulesLock = new object();
        }

        private static bool SafeSetProperty(dynamic obj, string propertyName, object value)
        {
            return ComHelper.SafeSetProperty(obj, propertyName, value);
        }

        private static void ReleaseComObject(dynamic obj)
        {
            ComHelper.ReleaseComObject(obj);
        }

        /// <summary>
        /// Creates a firewall rule COM object and adds it to both the firewall policy and the local list
        /// Extracted from CreateRuleForExe and UpdateFirewallRules to eliminate duplicated property-setting/addition/release logic
        /// </summary>
        /// <param name="ruleName">Rule name</param>
        /// <param name="exePath">Executable file path</param>
        /// <param name="descriptionPrefix">Description prefix (distinguishes auto-monitoring from manual update)</param>
        /// <returns>Whether creation and addition succeeded</returns>
        private bool CreateAndAddFirewallRule(string ruleName, string exePath, string descriptionPrefix)
        {
            dynamic newRule = ComHelper.CreateComObjectWithClsid(
                Config.FIREWALL_RULE_CLSID,
                Config.FIREWALL_RULE_IID,
                Config.FIREWALL_RULE_PROGID);
            if (newRule == null)
            {
                LogManager.Error(LangManager.GetText("logMessages.createFirewallRuleInstanceFailed"));
                return false;
            }

            try
            {
                // Every property that defines the security semantics of the rule must be applied.
                // A partially configured rule would otherwise be stored as "block everything" (no
                // ApplicationName) or as a disabled/inbound rule that silently lets the target through.
                bool applied =
                    SafeSetProperty(newRule, "Name", ruleName) &&
                    SafeSetProperty(newRule, "ApplicationName", exePath) &&
                    SafeSetProperty(newRule, "Direction", (int)FirewallDirection.Outbound) &&
                    SafeSetProperty(newRule, "Action", (int)FirewallAction.Block) &&
                    SafeSetProperty(newRule, "Enabled", true) &&
                    SafeSetProperty(newRule, "Profiles", Config.ALL_FIREWALL_PROFILES);

                if (!applied)
                {
                    LogManager.Error($"Failed to set mandatory properties on rule '{ruleName}' for '{exePath}'; rule not created.");
                    return false;
                }

                // Description is informative only; do not discard the rule when it cannot be written.
                SafeSetProperty(newRule, "Description", descriptionPrefix + ": " + exePath);

                firewallPolicy.Rules.Add(newRule);

                // Verify that the stored rule really targets this executable. If ApplicationName was
                // dropped or rewritten the rule would apply machine-wide, so roll it back instead.
                // The value is read back from the policy store, not from newRule: querying the instance
                // we just configured would only echo our own writes and could not detect a lost property.
                string appliedApplication = string.Empty;
                object storedRule = null;
                try
                {
                    storedRule = firewallPolicy.Rules.Item(ruleName);
                    if (storedRule != null)
                    {
                        appliedApplication = ComHelper.SafeGetProperty<string>(storedRule, "ApplicationName", string.Empty);
                    }
                }
                catch (Exception readEx)
                {
                    LogManager.Warning($"Failed to read back rule '{ruleName}' from the policy store: {readEx.Message}");
                }
                finally
                {
                    if (storedRule != null)
                    {
                        ReleaseComObject(storedRule);
                    }
                }

                if (!string.Equals(appliedApplication, exePath, StringComparison.OrdinalIgnoreCase))
                {
                    LogManager.Error($"Rule '{ruleName}' does not target '{exePath}' (stored value: '{appliedApplication}'). Rolling back.");
                    try
                    {
                        firewallPolicy.Rules.Remove(ruleName);
                    }
                    catch (Exception removeEx)
                    {
                        LogManager.Warning($"Rollback of rule '{ruleName}' failed: {removeEx.Message}");
                    }
                    return false;
                }

                // Add to local list (HashSet and List stay synchronized)
                lock (addedRulesLock)
                {
                    if (addedRulesLookup.Add(ruleName))
                    {
                        addedRules.Add(ruleName);
                    }
                }

                return true;
            }
            finally
            {
                ReleaseComObject(newRule);
            }
        }

        /// <summary>
        /// Release resources
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Release resources
        /// Releases managed resources and COM objects
        /// </summary>
        /// <param name="disposing">Whether to release managed resources</param>
        protected virtual void Dispose(bool disposing)
        {
            // Use volatile field + lock to ensure thread safety
            if (_disposed)
            {
                return;
            }

            lock (addedRulesLock)
            {
                if (_disposed)
                {
                    return;
                }

                if (disposing)
                {
                    // Release managed resources
                    if (addedRules != null)
                    {
                        addedRules.Clear();
                    }
                    addedRulesLookup?.Clear();

                    // Release COM object (only on explicit Dispose to avoid accessing managed resources in finalizer)
                    if (_firewallPolicy != null)
                    {
                        try
                        {
                            System.Runtime.InteropServices.Marshal.ReleaseComObject(_firewallPolicy);
                            _firewallPolicy = null;
                            LogManager.Info(LangManager.GetText("logMessages.firewallPolicyCOMObjectReleased"));
                        }
                        catch (Exception ex)
                        {
                            LogManager.Error(LangManager.GetText("logMessages.releaseFirewallPolicyCOMObjectFailed"), ex);
                        }
                    }
                }
                else
                {
                    // When called from finalizer, only release unmanaged resources (COM object)
                    // Note: Must not access managed resources (e.g. LogManager) here as they may have been collected by GC
                    if (_firewallPolicy != null)
                    {
                        try
                        {
                            System.Runtime.InteropServices.Marshal.ReleaseComObject(_firewallPolicy);
                            _firewallPolicy = null;
                        }
                        catch
                        {
                            // Cannot log in finalizer since LogManager may have been collected
                            // Silently ignore exceptions
                        }
                    }
                }

                _disposed = true;
            }
        }

        /// <summary>
        /// Finalizer
        /// </summary>
        ~FirewallService()
        {
            Dispose(false);
        }

        /// <summary>
        /// Initialize firewall components
        /// Create COM object and test firewall policy interface, then sync local rule list
        /// </summary>
        /// <returns>Whether initialization succeeded</returns>
        public bool InitializeFirewallComponents()
        {
            try
            {
                LogManager.Info(LangManager.GetText("logMessages.startInitializeFirewallComponents"));
                LogManager.Info(LangManager.GetText("logMessages.tryCreateFirewallPolicyObject", Config.FIREWALL_POLICY_PROGID));

                firewallPolicy = ComHelper.CreateComObjectWithClsid(
                    Config.FIREWALL_POLICY_CLSID, 
                    Config.FIREWALL_POLICY_IID, 
                    Config.FIREWALL_POLICY_PROGID);

                if (firewallPolicy == null)
                {
                    LogManager.Error(LangManager.GetText("logMessages.firewallPolicyTypeNotFound"));
                    throw new Exception(LangManager.GetText("logMessages.firewallPolicyTypeNotFound"));
                }

                LogManager.Info(LangManager.GetText("logMessages.firewallPolicyInstanceCreated"));

                // Test getting CurrentProfileTypes property
                try
                {
                    var currentProfileTypes = firewallPolicy.CurrentProfileTypes;
                    LogManager.Info(LangManager.GetText("logMessages.currentProfileTypes", currentProfileTypes));
                }
                catch (Exception ex)
                {
                    LogManager.Error(LangManager.GetText("logMessages.gettingCurrentProfileTypesFailed", ex.Message));
                }

                // Test getting Rules property
                try
                {
                    var rules = firewallPolicy.Rules;
                    LogManager.Info(LangManager.GetText("logMessages.rulesObjectGetSuccess", rules.GetType().FullName));
                }
                catch (Exception ex)
                {
                    LogManager.Error(LangManager.GetText("logMessages.gettingRulesPropertyFailed", ex.Message));
                }

                // Sync local rule list with actual firewall rules
                SyncRulesList();

                LogManager.Info(LangManager.GetText("logMessages.firewallInitialized"));
                return true;
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.initializeFirewallFailed") + $": {ex.GetType().Name}: {ex.Message}");
                LogManager.Error(LangManager.GetText("logMessages.stackTrace", ex.StackTrace));
                return false;
            }
        }

        /// <summary>
        /// Sync local rule list with actual firewall rules
        /// </summary>
        public void SyncRulesList()
        {
            try
            {
                // Check if firewall policy is initialized
                if (firewallPolicy == null)
                {
                    LogManager.Warning(LangManager.GetText("logMessages.firewallPolicyNotInitialized"));
                    return;
                }

                var rules = firewallPolicy.Rules;
                var currentRules = new List<string>();

                // Collect all rule names
                foreach (var rule in rules)
                {
                    try
                    {
                        dynamic fwRule = rule;
                        string ruleName = fwRule.Name;
                        if (ruleName.StartsWith(Config.RULE_NAME_PREFIX))
                        {
                            currentRules.Add(ruleName);
                        }
                    }
                    catch (Exception ex)
                    {
                        LogManager.Warning(LangManager.GetText("logMessages.readRuleNameFailed", ex.Message));
                    }
                }

                // Update local rule list
                lock (addedRulesLock)
                {
                    addedRules.Clear();
                    addedRules.AddRange(currentRules);
                    addedRulesLookup = new HashSet<string>(currentRules, StringComparer.Ordinal);
                }

                LogManager.Info(LangManager.GetText("logMessages.syncRulesListCompleted", currentRules.Count));
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.syncRulesListFailed"), ex);
            }
        }

        /// <summary>
        /// Check if a firewall rule exists
        /// Uses HashSet for O(1) lookup, avoiding performance degradation on large rule sets
        /// </summary>
        /// <param name="ruleName">Rule name</param>
        /// <returns>Whether it exists</returns>
        public bool CheckRuleExists(string ruleName)
        {
            try
            {
                lock (addedRulesLock)
                {
                    return addedRulesLookup != null && addedRulesLookup.Contains(ruleName);
                }
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.checkRuleExistsFailed", ruleName), ex);
                return false;
            }
        }

        /// <summary>
        /// Create a firewall rule for an executable file
        /// Creates an outbound block rule after checking the whitelist and critical system programs
        /// </summary>
        /// <param name="exePath">Executable file path</param>
        /// <returns>Whether creation succeeded</returns>
        public bool CreateRuleForExe(string exePath)
        {
            try
            {
                // Check if the object has been disposed
                if (_disposed)
                {
                    throw new ObjectDisposedException(nameof(FirewallService));
                }

                // Check if firewall policy is initialized
                if (firewallPolicy == null)
                {
                    LogManager.Error(LangManager.GetText("logMessages.firewallPolicyNotInitialized"));
                    throw new InvalidOperationException(LangManager.GetText("logMessages.firewallPolicyNotInitialized"));
                }

                // Check if application is in whitelist
                if (WhitelistForm.IsInWhitelist(exePath))
                {
                    LogManager.Info(LangManager.GetText("logMessages.appInWhitelistSkipped", exePath));
                    return false;
                }

                // Skip only Windows' own executables. A name-only match is not enough: a binary
                // called "svchost.exe" dropped in a writable folder must still be blocked.
                if (ComHelper.IsCriticalSystemExecutable(exePath))
                {
                    LogManager.Warning($"Skipping critical system executable: {exePath}");
                    return false;
                }

                // Generate rule name (consistently delegates to RuleNamingService)
                string ruleName = RuleNamingService.BuildRuleName(exePath);

                // Check if rule already exists
                if (!CheckRuleExists(ruleName))
                {
                    if (CreateAndAddFirewallRule(ruleName, exePath, LangManager.GetText("firewall.ruleDescriptionAuto")))
                    {
                        LogManager.Info(LangManager.GetText("logMessages.autoCreateFirewallRule", ruleName, exePath));
                        return true;
                    }
                    return false;
                }
                return false;
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.createRuleForExeFailed", exePath), ex);
                return false;
            }
        }

        /// <summary>
        /// Clear all firewall rules created by this program
        /// Deletes rules from local list, then scans all Block_-prefixed rules in the firewall for removal
        /// Fix: added rule name format validation to prevent accidentally deleting rules created by other software
        /// </summary>
        /// <returns>Number of deleted rules</returns>
        public int ClearAllRules()
        {
            int deletedCount = 0;
            var rulesToDelete = new List<string>();

            try
            {
                LogManager.Info(LangManager.GetText("logMessages.clearingAllRules"));

                // Check if firewall policy is initialized
                if (firewallPolicy == null)
                {
                    LogManager.Warning(LangManager.GetText("logMessages.firewallPolicyNotInitialized"));
                    return deletedCount;
                }

                // Delete rules only when this program can prove it created them. The local
                // addedRules list is not proof: SyncRulesList fills it with every rule that merely
                // carries the Block_ prefix, so deleting by that list would let any Block_-prefixed
                // rule belonging to another product be removed. Ownership is verified per rule against
                // its own ApplicationName below.
                try
                {
                    var rules = firewallPolicy.Rules;
                    var candidates = new List<(string Name, string ApplicationName)>();

                    // Collect rule names together with their ApplicationName so ownership can be proven
                    foreach (var rule in rules)
                    {
                        try
                        {
                            dynamic fwRule = rule;
                            string ruleName = fwRule.Name;

                            string applicationName = null;
                            try
                            {
                                applicationName = fwRule.ApplicationName;
                            }
                            catch (Exception ex)
                            {
                                LogManager.Warning($"Failed to read ApplicationName for rule '{ruleName}': {ex.Message}");
                            }

                            candidates.Add((ruleName, applicationName));
                        }
                        catch (Exception ex)
                        {
                            LogManager.Warning(LangManager.GetText("logMessages.readRuleNameFailed", ex.Message));
                        }
                    }

                    // Only delete rules whose embedded path hash matches their own ApplicationName
                    foreach (var (ruleName, applicationName) in candidates)
                    {
                        if (rulesToDelete.Contains(ruleName))
                            continue;

                        if (!RuleNamingService.IsRuleOwnedByUs(ruleName, applicationName))
                        {
                            if (RuleNamingService.IsRuleCreatedByUs(ruleName))
                            {
                                LogManager.Warning($"Ignoring rule that merely matches the naming pattern but is not owned by this program: {ruleName}");
                            }
                            continue;
                        }

                        try
                        {
                            firewallPolicy.Rules.Remove(ruleName);
                            rulesToDelete.Add(ruleName);
                            deletedCount++;
                            LogManager.Info(LangManager.GetText("logMessages.deleteFirewallRule", ruleName));
                        }
                        catch (Exception ex)
                        {
                            LogManager.Warning(LangManager.GetText("logMessages.deleteRuleFailed", ruleName, ex.Message));
                        }
                    }
                }
                catch (Exception ex)
                {
                    LogManager.Error(LangManager.GetText("logMessages.scanFirewallRulesFailed"), ex);
                }

                // Re-synchronize the local list with the real firewall state instead of assuming all
                // deletions succeeded: rules that could not be removed must stay visible and deletable.
                SyncRulesList();

                LogManager.Info(LangManager.GetText("logMessages.clearRulesSuccess", deletedCount));
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.clearFirewallRulesFailed"), ex);
            }

            return deletedCount;
        }

        /// <summary>
        /// Validate whether a rule name is valid
        /// Rule name must not be empty and must not exceed 256 characters, to prevent injection attacks
        /// </summary>
        /// <param name="ruleName">Rule name</param>
        /// <returns>Whether it is valid</returns>
        private static bool IsValidRuleName(string ruleName)
            => !string.IsNullOrEmpty(ruleName) && ruleName.Length <= 256;

        /// <summary>
        /// Delete a firewall rule
        /// </summary>
        /// <param name="ruleName">Rule name</param>
        /// <returns>Whether deletion succeeded</returns>
        public bool DeleteRule(string ruleName)
        {
            try
            {
                // Validate rule name to prevent injection attacks (kept consistent with GetRuleDetails)
                if (!IsValidRuleName(ruleName))
                {
                    return false;
                }

                // Prove ownership before removing: recompute the rule name from the rule's own
                // ApplicationName. A rule that merely shares our naming pattern is left untouched.
                if (!IsRuleOwnedByCurrentProgram(ruleName))
                {
                    LogManager.Warning($"Refusing to delete rule that is not owned by this program: {ruleName}");
                    return false;
                }

                firewallPolicy.Rules.Remove(ruleName);
                
                lock (addedRulesLock)
                {
                    addedRules.Remove(ruleName);
                    addedRulesLookup.Remove(ruleName);
                }
                
                LogManager.Info(LangManager.GetText("logMessages.deleteFirewallRule", ruleName));
                return true;
            }
            catch (Exception ex)
            {
                LogManager.Warning(LangManager.GetText("logMessages.deleteRuleFailed", ruleName, ex.Message));
                return false;
            }
        }

        /// <summary>
        /// Looks the rule up in the live firewall policy and confirms that the name matches the one
        /// this program derives from the rule's ApplicationName.
        /// </summary>
        /// <param name="ruleName">Rule name to look up</param>
        /// <returns>true when the rule is provably owned by this program</returns>
        private bool IsRuleOwnedByCurrentProgram(string ruleName)
        {
            try
            {
                if (firewallPolicy == null)
                    return false;

                foreach (var rule in firewallPolicy.Rules)
                {
                    try
                    {
                        dynamic fwRule = rule;
                        string currentName = fwRule.Name;
                        if (!string.Equals(currentName, ruleName, StringComparison.OrdinalIgnoreCase))
                            continue;

                        string applicationName = null;
                        try
                        {
                            applicationName = fwRule.ApplicationName;
                        }
                        catch (Exception ex)
                        {
                            LogManager.Warning($"Failed to read ApplicationName for rule '{ruleName}': {ex.Message}");
                        }

                        return RuleNamingService.IsRuleOwnedByUs(currentName, applicationName);
                    }
                    catch (Exception ex)
                    {
                        LogManager.Warning(LangManager.GetText("logMessages.readRuleNameFailed", ex.Message));
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                LogManager.Warning($"Ownership check failed for rule '{ruleName}': {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Get all rule names created by this program
        /// </summary>
        /// <returns>List of rule names</returns>
        public List<string> GetAllRuleNames()
        {
            lock (addedRulesLock)
            {
                return new List<string>(addedRules);
            }
        }

        /// <summary>
        /// Update firewall rules
        /// Scan all executables in monitored targets and create or update a firewall rule for each
        /// </summary>
        /// <param name="monitoredTargets">List of monitored targets</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <param name="updateUI">Callback function to update UI</param>
        /// <returns>Processing result, containing added and skipped rule counts</returns>
        public async Task<(int addedCount, int skippedCount)> UpdateFirewallRules(IEnumerable<IScanTarget> monitoredTargets, CancellationToken cancellationToken, Action<object, string> updateUI)
        {
            int addedCount = 0;
            int skippedCount = 0;

            try
            {
                LogManager.Info(LangManager.GetText("logMessages.updatingRules"));
                updateUI("Running", LangManager.GetText("status.scanningTargets"));

                // Check if firewall policy is initialized
                if (firewallPolicy == null)
                {
                    LogManager.Warning(LangManager.GetText("logMessages.firewallPolicyNotInitialized"));
                    updateUI("Idle", LangManager.GetText("status.firewallNotInitialized"));
                    return (addedCount, skippedCount);
                }

                // Sync local rule list with actual firewall rules
                SyncRulesList();

                // Scan files in parallel to improve performance
                var scanTasks = monitoredTargets.Select(target => Task.Run(() =>
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    // A reparse point at the target itself would redirect the whole scan to an
                    // unrelated tree: the enumeration options below only filter children, not the root.
                    if (ComHelper.HasReparsePointInPath(target.Path))
                    {
                        LogManager.Warning($"Skipping monitored target that is a reparse point: {target.Path}");
                        return new List<string>();
                    }

                    if (target.IsExe)
                    {
                        if (File.Exists(target.Path))
                        {
                            return new List<string> { target.Path };
                        }
                    }
                    else if (Directory.Exists(target.Path))
                    {
                        try
                        {
                            LogManager.Info(LangManager.GetText("logMessages.startScanningFolder", target.Path));

                            // Do not follow reparse points: a junction inside a monitored folder would
                            // otherwise pull the scan into System32 and produce Block rules for
                            // Windows binaries, and it can also create recursion loops.
                            var enumerationOptions = new EnumerationOptions
                            {
                                RecurseSubdirectories = true,
                                IgnoreInaccessible = true,
                                AttributesToSkip = FileAttributes.ReparsePoint
                            };

                            string[] files = Directory.GetFiles(target.Path, Config.EXE_SEARCH_PATTERN, enumerationOptions);
                            LogManager.Info(LangManager.GetText("logMessages.scanCompleted", target.Path, files.Length));
                            return new List<string>(files);
                        }
                        catch (Exception ex)
                        {
                            LogManager.Warning(LangManager.GetText("logMessages.scanFolderFailed", target.Path, ex.Message));
                        }
                    }
                    return new List<string>();
                }, cancellationToken)).ToArray();

                // Wait for all scan tasks to complete
                await Task.WhenAll(scanTasks);

                // Merge results and deduplicate to avoid repeated processing
                List<string> exeFiles = scanTasks.SelectMany(t => t.Result).Distinct().ToList();

                LogManager.Info(LangManager.GetText("logMessages.foundExeFiles", exeFiles.Count));
                updateUI("Running", LangManager.GetText("status.creatingRules", exeFiles.Count));

                // Create firewall rules for each EXE file
                int processedCount = 0;
                foreach (var exeFile in exeFiles)
                {
                    // Check cancellation request
                    cancellationToken.ThrowIfCancellationRequested();

                    processedCount++;
                    updateUI("Running", LangManager.GetText("status.processingFile", processedCount, exeFiles.Count, System.IO.Path.GetFileName(exeFile)));

                    try
                    {
                        // Skip only Windows' own executables; blocking them would destabilize the system.
                        // Unsigned binaries must NOT be skipped: containing them is the whole point.
                        if (ComHelper.IsCriticalSystemExecutable(exeFile))
                        {
                            LogManager.Warning($"Skipping critical system executable: {exeFile}");
                            skippedCount++;
                            continue;
                        }

                        // Generate rule name containing file path hash to ensure uniqueness (consistently delegates to RuleNamingService)
                        string ruleName = RuleNamingService.BuildRuleName(exeFile);

                        // Check if application is in whitelist
                        if (WhitelistForm.IsInWhitelist(exeFile))
                        {
                            LogManager.Info(LangManager.GetText("logMessages.appInWhitelistSkipped", exeFile));

                            // Check if a rule exists for this application; if so, delete it
                            bool whitelistRuleExists = CheckRuleExists(ruleName);
                            if (whitelistRuleExists)
                            {
                                try
                                {
                                    firewallPolicy.Rules.Remove(ruleName);
                                    lock (addedRulesLock)
                                    {
                                        addedRules.Remove(ruleName);
                                        addedRulesLookup.Remove(ruleName);
                                    }
                                    LogManager.Info(LangManager.GetText("logMessages.deleteWhitelistAppRule", ruleName));
                                }
                                catch (Exception ex)
                                {
                                    LogManager.Warning(LangManager.GetText("logMessages.deleteWhitelistAppRuleFailed", ruleName, ex.Message));
                                }
                            }
                            skippedCount++;
                            continue;
                        }

                        // Check if rule already exists
                        if (!CheckRuleExists(ruleName))
                        {
                            if (CreateAndAddFirewallRule(ruleName, exeFile, LangManager.GetText("firewall.ruleDescription")))
                            {
                                addedCount++;
                                LogManager.Info(LangManager.GetText("logMessages.createFirewallRule", ruleName, exeFile));
                            }
                            else
                            {
                                skippedCount++;
                            }
                        }
                        else
                        {
                            skippedCount++;
                            LogManager.Info(LangManager.GetText("logMessages.ruleExistsSkip", ruleName));
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        throw; // Re-throw cancellation exception
                    }
                    catch (Exception ex)
                    {
                        LogManager.Error(LangManager.GetText("logMessages.processExeFailed", exeFile), ex);
                        skippedCount++;
                    }
                }

                LogManager.Info(LangManager.GetText("logMessages.updateCompleted", addedCount, skippedCount));
            }
            catch (OperationCanceledException)
            {
                LogManager.Info(LangManager.GetText("logMessages.updateCanceled"));
                throw;
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.updateError", ex.Message), ex);
            }

            return (addedCount, skippedCount);
        }

        /// <summary>
        /// Remove firewall rules for a specified folder
        /// </summary>
        /// <param name="folderPath">Folder path</param>
        /// <returns>Number of deleted rules</returns>
        public int RemoveFolderRules(string folderPath)
        {
            int deletedCount = 0;

            try
            {
                // Collect paths of all executables under this folder
                var exeFiles = new List<string>();
                if (Directory.Exists(folderPath))
                {
                    try
                    {
                        string[] files = Directory.GetFiles(folderPath, Config.EXE_SEARCH_PATTERN, new EnumerationOptions
                        {
                            RecurseSubdirectories = true,
                            IgnoreInaccessible = true,
                            AttributesToSkip = FileAttributes.ReparsePoint
                        });
                        exeFiles = new List<string>(files);
                    }
                    catch (Exception ex)
                    {
                        LogManager.Error(LangManager.GetText("logMessages.scanFolderFailed", folderPath, ""), ex);
                        return 0;
                    }
                }

                LogManager.Info(LangManager.GetText("logMessages.removingFolderRules", folderPath, exeFiles.Count));

                // Generate rule name for each executable and delete it (using RuleNamingService for consistency)
                foreach (var exeFile in exeFiles)
                {
                    try
                    {
                        string ruleName = RuleNamingService.BuildRuleName(exeFile);

                        // Check if rule exists
                        if (CheckRuleExists(ruleName))
                        {
                            try
                            {
                                firewallPolicy.Rules.Remove(ruleName);
                                lock (addedRulesLock)
                                {
                                    addedRules.Remove(ruleName);
                                    addedRulesLookup.Remove(ruleName);
                                }
                                deletedCount++;
                                LogManager.Info(LangManager.GetText("logMessages.deleteFirewallRule", ruleName));
                            }
                            catch (Exception ex)
                            {
                                LogManager.Warning(LangManager.GetText("logMessages.deleteRuleFailed", ruleName, ex.Message));
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        LogManager.Error(LangManager.GetText("logMessages.processFileFailed", exeFile), ex);
                    }
                }

                LogManager.Info(LangManager.GetText("logMessages.removingFolderRulesCompleted", folderPath));
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.removingFolderRulesFailed", ex.Message), ex);
            }

            return deletedCount;
        }

        /// <summary>
        /// Get firewall rule details
        /// Retrieve detailed information of a firewall rule by its name
        /// </summary>
        /// <param name="ruleName">Rule name</param>
        /// <returns>Rule object</returns>
        public RuleDetailsInfo GetRuleDetails(string ruleName)
        {
            try
            {
                // Validate rule name to prevent injection attacks
                if (!IsValidRuleName(ruleName))
                {
                    return null;
                }

                if (_disposed || firewallPolicy == null)
                {
                    return null;
                }

                dynamic rule = firewallPolicy.Rules.Item(ruleName);
                if (rule == null)
                    return null;

                // Validate the rule is a legitimate COM object (use CLSID validation to prevent ProgID hijacking)
                if (!ComHelper.ValidateComObjectType(rule, Config.FIREWALL_RULE_CLSID, Config.FIREWALL_RULE_IID))
                {
                    LogManager.Warning(LangManager.GetText("logMessages.firewallRuleTypeValidationFailed"));
                    return null;
                }

                return new RuleDetailsInfo
                {
                    Name = ComHelper.SafeGetProperty<string>(rule, "Name", string.Empty),
                    Description = ComHelper.SafeGetProperty<string>(rule, "Description", string.Empty),
                    ApplicationName = ComHelper.SafeGetProperty<string>(rule, "ApplicationName", string.Empty),
                    Enabled = ComHelper.SafeGetProperty<bool>(rule, "Enabled", false),
                    Direction = ComHelper.SafeGetProperty<int>(rule, "Direction", 2),
                    Action = ComHelper.SafeGetProperty<int>(rule, "Action", 0)
                };
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.getRuleDetailsFailed", ruleName), ex);
                return null;
            }
        }

        public bool UpdateRule(string ruleName, string description, bool enabled, int direction, int action)
        {
            try
            {
                // Validate rule name to prevent injection attacks (kept consistent with GetRuleDetails)
                if (!IsValidRuleName(ruleName))
                {
                    return false;
                }

                // Only rules this program can prove it created may be modified. Without this check an
                // arbitrary rule whose name happens to match could be switched from Block to Allow.
                if (!IsRuleOwnedByCurrentProgram(ruleName))
                {
                    LogManager.Warning($"Refusing to update rule '{ruleName}': ownership cannot be verified.");
                    return false;
                }

                dynamic rule = firewallPolicy.Rules.Item(ruleName);
                if (rule == null)
                    return false;

                if (!ComHelper.ValidateComObjectType(rule, Config.FIREWALL_RULE_CLSID, Config.FIREWALL_RULE_IID))
                {
                    LogManager.Warning(LangManager.GetText("logMessages.firewallRuleTypeValidationFailed"));
                    return false;
                }

                bool applied =
                    SafeSetProperty(rule, "Description", description) &&
                    SafeSetProperty(rule, "Enabled", enabled) &&
                    SafeSetProperty(rule, "Direction", direction) &&
                    SafeSetProperty(rule, "Action", action);

                if (!applied)
                {
                    LogManager.Error($"Failed to apply one or more properties to rule '{ruleName}'.");
                    return false;
                }

                LogManager.Info(LangManager.GetText("logMessages.updateRule", ruleName));
                return true;
            }
            catch (Exception ex)
            {
                LogManager.Error(LangManager.GetText("logMessages.saveRuleFailed", ex.Message), ex);
                return false;
            }
        }

    }
}