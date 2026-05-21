using FirewallManager;

namespace FirewallManager.Tests;

public class ConfigTests
{
    [Fact]
    public void CRITICAL_PROGRAMS_NoDuplicates()
    {
        var duplicates = Config.CRITICAL_PROGRAMS
            .GroupBy(p => p, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        Assert.Empty(duplicates);
    }

    [Fact]
    public void CRITICAL_PROGRAMS_AllEndWithExe()
    {
        var nonExe = Config.CRITICAL_PROGRAMS
            .Where(p => !p.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.Empty(nonExe);
    }

    [Fact]
    public void CRITICAL_PROGRAMS_ContainsExpectedEntries()
    {
        Assert.Contains(Config.CRITICAL_PROGRAMS, p =>
            p.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(Config.CRITICAL_PROGRAMS, p =>
            p.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RULE_NAME_PREFIX_HasCorrectValue()
    {
        Assert.Equal("Block_", Config.RULE_NAME_PREFIX);
    }

    [Fact]
    public void DEFAULT_LANGUAGE_HasCorrectValue()
    {
        Assert.Equal("zh", Config.DEFAULT_LANGUAGE);
    }

    [Fact]
    public void WHITELIST_FILE_HasCorrectValue()
    {
        Assert.Equal("whitelist.json", Config.WHITELIST_FILE);
    }

    [Fact]
    public void LOG_FILE_NAME_HasCorrectValue()
    {
        Assert.Equal("firewall_manager.log", Config.LOG_FILE_NAME);
    }

    [Fact]
    public void APP_DATA_DIR_HasCorrectValue()
    {
        Assert.Equal("FirewallManager", Config.APP_DATA_DIR);
    }

    [Fact]
    public void GetAppDataFilePath_ReturnsValidPath()
    {
        string path = Config.GetAppDataFilePath("test.json");
        Assert.NotNull(path);
        Assert.False(string.IsNullOrEmpty(path));
        Assert.Contains("FirewallManager", path);
        Assert.EndsWith("test.json", path, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GetAppDataFilePath_DifferentFiles_DifferentPaths()
    {
        string path1 = Config.GetAppDataFilePath("file1.json");
        string path2 = Config.GetAppDataFilePath("file2.json");
        Assert.NotEqual(path1, path2);
    }
}