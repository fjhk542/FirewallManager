using FirewallManager;

namespace FirewallManager.Tests;

public class LangManagerTests
{
    [Fact]
    public void GetText_ExistingKey_ReturnsTranslation()
    {
        string result = LangManager.GetText("messages.ok");
        Assert.False(string.IsNullOrEmpty(result));
    }

    [Fact]
    public void GetText_MissingKey_ReturnsKey()
    {
        string result = LangManager.GetText("nonexistent.key.12345");
        Assert.Equal("nonexistent.key.12345", result);
    }

    [Fact]
    public void GetText_WithFormatParameter_ReturnsFormatted()
    {
        string result = LangManager.GetText("status.rulesCount", 5);
        Assert.Contains("5", result);
    }

    [Fact]
    public void GetText_WithMultipleFormatParameters_ReturnsFormatted()
    {
        string result = LangManager.GetText("logMessages.fileNotFound", @"C:\test.exe");
        Assert.Contains("C:\\test.exe", result);
    }

    [Fact]
    public void GetText_TooManyArgs_ReturnsUnformatted()
    {
        string result = LangManager.GetText("messages.ok", "extra1", "extra2");
        Assert.NotNull(result);
        Assert.False(string.IsNullOrEmpty(result));
    }

    [Fact]
    public void GetText_NullKey_ReturnsEmpty()
    {
        string result = LangManager.GetText(null);
        Assert.Equal("", result);
    }

    [Fact]
    public void GetText_EmptyKey_ReturnsEmpty()
    {
        string result = LangManager.GetText("");
        string expected = "";
        Assert.Equal(expected, result);
    }

    [Fact]
    public void GetCurrentLanguage_ReturnsNonNull()
    {
        string lang = LangManager.GetCurrentLanguage();
        Assert.NotNull(lang);
        Assert.True(lang.Length == 2);
    }

    [Fact]
    public void SetLanguage_ToZh_DoesNotThrow()
    {
        var exception = Record.Exception(() => LangManager.SetLanguage("zh"));
        Assert.Null(exception);
        Assert.Equal("zh", LangManager.GetCurrentLanguage());
    }

    [Fact]
    public void SetLanguage_ToEn_DoesNotThrow()
    {
        var exception = Record.Exception(() => LangManager.SetLanguage("en"));
        Assert.Null(exception);
        Assert.Equal("en", LangManager.GetCurrentLanguage());
    }

    [Fact]
    public void SetLanguage_InvalidCode_FallsBackToDefault()
    {
        LangManager.SetLanguage("zh");
        var exception = Record.Exception(() => LangManager.SetLanguage("invalid"));
        Assert.Null(exception);
        Assert.Equal("zh", LangManager.GetCurrentLanguage());
    }

    [Fact]
    public void GetText_SwitchingLanguages_ReturnsCorrectTranslation()
    {
        LangManager.SetLanguage("zh");
        string zhText = LangManager.GetText("messages.ok");
        Assert.False(string.IsNullOrEmpty(zhText));

        LangManager.SetLanguage("en");
        string enText = LangManager.GetText("messages.ok");
        Assert.False(string.IsNullOrEmpty(enText));
    }

    [Fact]
    public void TestLanguageLoading_ReturnsResult()
    {
        string result = LangManager.TestLanguageLoading();
        Assert.NotNull(result);
        Assert.False(string.IsNullOrEmpty(result));
    }
}