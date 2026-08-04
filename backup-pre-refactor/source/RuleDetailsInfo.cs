using System;

namespace FirewallManager
{
    public class RuleDetailsInfo
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string ApplicationName { get; set; }
        public bool Enabled { get; set; }
        public int Direction { get; set; }
        public int Action { get; set; }
    }
}