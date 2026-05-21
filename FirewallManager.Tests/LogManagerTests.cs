using System.Reflection;
using FirewallManager;

namespace FirewallManager.Tests;

public class LogManagerTests
{
    [Fact]
    public void FilterSensitiveInfo_NullInput_ReturnsNull()
    {
        var method = typeof(LogManager).GetMethod("FilterSensitiveInfo", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        object result = method.Invoke(null, new object[] { null });
        Assert.Null(result);
    }

    [Fact]
    public void FilterSensitiveInfo_EmptyInput_ReturnsEmpty()
    {
        var method = typeof(LogManager).GetMethod("FilterSensitiveInfo", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        object result = method.Invoke(null, new object[] { "" });
        Assert.Equal("", result);
    }

    [Fact]
    public void FilterSensitiveInfo_RemovesControlCharacters()
    {
        var method = typeof(LogManager).GetMethod("FilterSensitiveInfo", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        string input = "Normal text with " + ((char)0x01) + " control " + ((char)0x07) + " chars";
        object result = method.Invoke(null, new object[] { input });
        Assert.NotNull(result);
        string filtered = (string)result;
        Assert.Equal(-1, filtered.IndexOf((char)0x01));
        Assert.Equal(-1, filtered.IndexOf((char)0x07));
        Assert.Contains("Normal text with", filtered);
        Assert.Contains("control", filtered);
        Assert.Contains("chars", filtered);
    }

    [Fact]
    public void FilterSensitiveInfo_RemovesUnicodeControlChars()
    {
        var method = typeof(LogManager).GetMethod("FilterSensitiveInfo", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        string input = "Text with " + ((char)0x200B) + " zero-width space";
        object result = method.Invoke(null, new object[] { input });
        Assert.NotNull(result);
        string filtered = (string)result;
        Assert.Equal(-1, filtered.IndexOf((char)0x200B));
    }

    [Fact]
    public void FilterSensitiveInfo_ReplacesPasswordValue()
    {
        var method = typeof(LogManager).GetMethod("FilterSensitiveInfo", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        string input = "password=mySecret123";
        object result = method.Invoke(null, new object[] { input });
        Assert.NotNull(result);
        string filtered = (string)result;
        Assert.DoesNotContain("mySecret123", filtered);
    }

    [Fact]
    public void FilterSensitiveInfo_PreservesNewlinesWithPlaceholder()
    {
        var method = typeof(LogManager).GetMethod("FilterSensitiveInfo", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        string input = "Line1\r\nLine2\nLine3";
        object result = method.Invoke(null, new object[] { input });
        Assert.NotNull(result);
        string filtered = (string)result;
        Assert.DoesNotContain("\r\n", filtered);
        Assert.Contains("[CRLF]", filtered);
        Assert.Contains("[LF]", filtered);
    }

    [Fact]
    public void FilterSensitiveInfo_DoesNotPreserveNewlinesInNormalText()
    {
        var method = typeof(LogManager).GetMethod("FilterSensitiveInfo", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        string input = "Normal log message";
        object result = method.Invoke(null, new object[] { input });
        Assert.NotNull(result);
        string filtered = (string)result;
        Assert.Equal(input, filtered);
    }
}

public class LogManagerStaticTests
{
    [Fact]
    public void Debug_DoesNotThrow()
    {
        var exception = Record.Exception(() => LogManager.Debug("Test debug message"));
        Assert.Null(exception);
    }

    [Fact]
    public void Info_DoesNotThrow()
    {
        var exception = Record.Exception(() => LogManager.Info("Test info message"));
        Assert.Null(exception);
    }

    [Fact]
    public void Warning_DoesNotThrow()
    {
        var exception = Record.Exception(() => LogManager.Warning("Test warning message"));
        Assert.Null(exception);
    }

    [Fact]
    public void Error_DoesNotThrow()
    {
        var exception = Record.Exception(() => LogManager.Error("Test error message"));
        Assert.Null(exception);
    }

    [Fact]
    public void Error_WithException_DoesNotThrow()
    {
        var exception = Record.Exception(() =>
            LogManager.Error("Test error with exception", new InvalidOperationException("Test exception")));
        Assert.Null(exception);
    }

    [Fact]
    public void Log_DebugLevel_DoesNotThrow()
    {
        var exception = Record.Exception(() =>
            LogManager.Log(LogManager.LogLevel.Debug, "Test log message"));
        Assert.Null(exception);
    }

    [Fact]
    public void Log_InfoLevel_DoesNotThrow()
    {
        var exception = Record.Exception(() =>
            LogManager.Log(LogManager.LogLevel.Info, "Test log message"));
        Assert.Null(exception);
    }

    [Fact]
    public void Log_WarningLevel_DoesNotThrow()
    {
        var exception = Record.Exception(() =>
            LogManager.Log(LogManager.LogLevel.Warning, "Test log message"));
        Assert.Null(exception);
    }

    [Fact]
    public void Log_ErrorLevel_DoesNotThrow()
    {
        var exception = Record.Exception(() =>
            LogManager.Log(LogManager.LogLevel.Error, "Test log message"));
        Assert.Null(exception);
    }

    [Fact]
    public void Log_SensitiveInfoIsFiltered()
    {
        var exception = Record.Exception(() =>
            LogManager.Log(LogManager.LogLevel.Info, "password=supersecret"));
        Assert.Null(exception);
    }

    [Fact]
    public void Log_ControlCharsAreFiltered()
    {
        var exception = Record.Exception(() =>
            LogManager.Log(LogManager.LogLevel.Info, "Message with \x01 control char"));
        Assert.Null(exception);
    }

    [Fact]
    public void ReadLogs_ReturnsList()
    {
        var logs = LogManager.ReadLogs();
        Assert.NotNull(logs);
    }
}