using System.Reflection;
using FirewallManager;

namespace FirewallManager.Tests;

public class FirewallServiceTests : IDisposable
{
    private readonly FirewallService _service;

    public FirewallServiceTests()
    {
        _service = new FirewallService();
    }

    public void Dispose()
    {
        _service.Dispose();
    }

    [Fact]
    public void GetPathHash_ReturnsConsistentHash()
    {
        string path = @"C:\Test\App.exe";
        string hash1 = _service.GetPathHash(path);
        string hash2 = _service.GetPathHash(path);
        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void GetPathHash_DifferentPaths_DifferentHashes()
    {
        string path1 = @"C:\Test\App1.exe";
        string path2 = @"C:\Test\App2.exe";
        string hash1 = _service.GetPathHash(path1);
        string hash2 = _service.GetPathHash(path2);
        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void GetPathHash_Returns16CharacterHexString()
    {
        string path = @"C:\Test\App.exe";
        string hash = _service.GetPathHash(path);
        Assert.Equal(16, hash.Length);
        Assert.Matches(@"^[0-9a-f]{16}$", hash);
    }

    [Fact]
    public void GetPathHash_SamePathDifferentCase_ReturnsDifferentHash()
    {
        string path1 = @"C:\Test\App.exe";
        string path2 = @"c:\test\app.EXE";
        string hash1 = _service.GetPathHash(path1);
        string hash2 = _service.GetPathHash(path2);
        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void SanitizeRuleName_RemovesSpecialCharacters()
    {
        string result = _service.SanitizeRuleName("my\"app'/test:*.exe");
        Assert.DoesNotContain("\"", result);
        Assert.DoesNotContain("'", result);
        Assert.DoesNotContain("/", result);
        Assert.DoesNotContain(":", result);
    }

    [Fact]
    public void SanitizeRuleName_ReplacesInvalidCharsWithUnderscore()
    {
        string result = _service.SanitizeRuleName("my:app.exe");
        Assert.Contains("_", result);
    }

    [Fact]
    public void SanitizeRuleName_HandlesNullInput()
    {
        string result = _service.SanitizeRuleName(null);
        Assert.Null(result);
    }

    [Fact]
    public void SanitizeRuleName_HandlesEmptyInput()
    {
        string result = _service.SanitizeRuleName("");
        Assert.Equal("", result);
    }

    [Fact]
    public void CheckRuleExists_NewService_ReturnsFalse()
    {
        bool exists = _service.CheckRuleExists("NonExistentRule");
        Assert.False(exists);
    }

    [Fact]
    public void CheckRuleExists_NullName_ReturnsFalse()
    {
        bool exists = _service.CheckRuleExists(null);
        Assert.False(exists);
    }
}

public class FirewallServicePrivateMethodTests
{
    [Fact]
    public void SafeGetProperty_NullObject_ReturnsDefault()
    {
        var method = typeof(FirewallService).GetMethod("SafeGetProperty", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var genericMethod = method.MakeGenericMethod(typeof(string));
        object result = genericMethod.Invoke(null, new object[] { null, "Name", null });
        Assert.Null(result);
    }

    [Fact]
    public void SafeGetProperty_ValidObject_ReturnsPropertyValue()
    {
        var method = typeof(FirewallService).GetMethod("SafeGetProperty", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var testObj = new { Name = "TestValue", Value = 42 };
        var genericMethod = method.MakeGenericMethod(typeof(string));
        object result = genericMethod.Invoke(null, new object[] { testObj, "Name", null });
        Assert.Equal("TestValue", result);
    }

    [Fact]
    public void SafeGetProperty_InvalidProperty_ReturnsDefault()
    {
        var method = typeof(FirewallService).GetMethod("SafeGetProperty", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var testObj = new { Name = "Test" };
        var genericMethod = method.MakeGenericMethod(typeof(string));
        object result = genericMethod.Invoke(null, new object[] { testObj, "NonExistent", "DefaultVal" });
        Assert.Equal("DefaultVal", result);
    }

    [Fact]
    public void SafeSetProperty_NullObject_ReturnsFalse()
    {
        var method = typeof(FirewallService).GetMethod("SafeSetProperty", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        object result = method.Invoke(null, new object[] { null, "Name", "Value" });
        Assert.False((bool)result);
    }

    [Fact]
    public void ValidateComObjectType_NullObject_ReturnsFalse()
    {
        var method = typeof(FirewallService).GetMethod("ValidateComObjectType", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        object result = method.Invoke(null, new object[] { null, "TestProgID" });
        Assert.False((bool)result);
    }

    [Fact]
    public void ValidateComObjectType_ValidObject_ReturnsTrue()
    {
        var method = typeof(FirewallService).GetMethod("ValidateComObjectType", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        object result = method.Invoke(null, new object[] { new object(), "TestProgID" });
        Assert.True((bool)result);
    }
}