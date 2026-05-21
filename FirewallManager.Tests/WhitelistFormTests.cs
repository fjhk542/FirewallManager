using FirewallManager;

namespace FirewallManager.Tests;

public class WhitelistFormTests
{
    [Fact]
    public void IsInWhitelist_NullPath_ReturnsFalse()
    {
        bool result = WhitelistForm.IsInWhitelist(null);
        Assert.False(result);
    }

    [Fact]
    public void IsInWhitelist_EmptyPath_ReturnsFalse()
    {
        bool result = WhitelistForm.IsInWhitelist("");
        Assert.False(result);
    }

    [Fact]
    public void IsInWhitelist_WhitespacePath_ReturnsFalse()
    {
        bool result = WhitelistForm.IsInWhitelist("   ");
        Assert.False(result);
    }

    [Fact]
    public void IsInWhitelist_NonExistentPath_ReturnsFalse()
    {
        string tempFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".exe");
        bool result = WhitelistForm.IsInWhitelist(tempFile);
        Assert.False(result);
    }

    [Fact]
    public void IsInWhitelist_MultipleCalls_ReturnsConsistentResults()
    {
        string testPath = @"C:\Windows\System32\notepad.exe";
        bool result1 = WhitelistForm.IsInWhitelist(testPath);
        bool result2 = WhitelistForm.IsInWhitelist(testPath);
        Assert.Equal(result1, result2);
    }
}