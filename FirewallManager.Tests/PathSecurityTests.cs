using System.Reflection;
using FirewallManager;

namespace FirewallManager.Tests;

public class PathSecurityTests
{
    [Fact]
    public void IsSymbolicLink_NullPath_ReturnsFalse()
    {
        var method = typeof(Form1).GetMethod("IsSymbolicLink", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        object result = method.Invoke(null, new object[] { null });
        Assert.False((bool)result);
    }

    [Fact]
    public void IsSymbolicLink_EmptyPath_ReturnsFalse()
    {
        var method = typeof(Form1).GetMethod("IsSymbolicLink", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        object result = method.Invoke(null, new object[] { "" });
        Assert.False((bool)result);
    }

    [Fact]
    public void IsSymbolicLink_NonExistentPath_ReturnsFalse()
    {
        var method = typeof(Form1).GetMethod("IsSymbolicLink", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        string nonExistent = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        object result = method.Invoke(null, new object[] { nonExistent });
        Assert.False((bool)result);
    }

    [Fact]
    public void IsSymbolicLink_ExistingFile_ReturnsFalse()
    {
        string tempFile = Path.GetTempFileName();
        try
        {
            var method = typeof(Form1).GetMethod("IsSymbolicLink", BindingFlags.NonPublic | BindingFlags.Static);
            Assert.NotNull(method);

            object result = method.Invoke(null, new object[] { tempFile });
            Assert.False((bool)result);
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void WaitForFileReady_NullPath_ReturnsFalse()
    {
        var method = typeof(Form1).GetMethod("WaitForFileReady",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        object result = method.Invoke(null, new object[] { null, 3, 100 });
        Assert.False((bool)result);
    }

    [Fact]
    public void WaitForFileReady_EmptyPath_ReturnsFalse()
    {
        var method = typeof(Form1).GetMethod("WaitForFileReady",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        object result = method.Invoke(null, new object[] { "", 3, 100 });
        Assert.False((bool)result);
    }

    [Fact]
    public void WaitForFileReady_NonExistentFile_ReturnsFalse()
    {
        var method = typeof(Form1).GetMethod("WaitForFileReady",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        string nonExistent = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".exe");
        object result = method.Invoke(null, new object[] { nonExistent, 3, 50 });
        Assert.False((bool)result);
    }

    [Fact]
    public void WaitForFileReady_ExistingFile_ReturnsTrue()
    {
        string tempFile = Path.GetTempFileName();
        try
        {
            var method = typeof(Form1).GetMethod("WaitForFileReady",
                BindingFlags.NonPublic | BindingFlags.Static);
            Assert.NotNull(method);

            File.WriteAllText(tempFile, "test content");
            object result = method.Invoke(null, new object[] { tempFile, 3, 50 });
            Assert.True((bool)result);
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void NormalizeAndValidatePath_NullPath_ReturnsNull()
    {
        using (var form = new Form1())
        {
            var method = typeof(Form1).GetMethod("NormalizeAndValidatePath",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(method);

            object result = method.Invoke(form, new object[] { null, true });
            Assert.Null(result);
        }
    }

    [Fact]
    public void NormalizeAndValidatePath_EmptyPath_ReturnsNull()
    {
        using (var form = new Form1())
        {
            var method = typeof(Form1).GetMethod("NormalizeAndValidatePath",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(method);

            object result = method.Invoke(form, new object[] { "", true });
            Assert.Null(result);
        }
    }

    [Fact]
    public void NormalizeAndValidatePath_ValidDirectory_ReturnsNormalizedPath()
    {
        using (var form = new Form1())
        {
            var method = typeof(Form1).GetMethod("NormalizeAndValidatePath",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(method);

            string validDir = Path.GetTempPath();
            object result = method.Invoke(form, new object[] { validDir, true });
            Assert.NotNull(result);
            string normalized = (string)result;
            Assert.Equal(Path.GetFullPath(validDir), normalized);
        }
    }

    [Fact]
    public void NormalizeAndValidatePath_NonExistentDirectory_ReturnsNull()
    {
        using (var form = new Form1())
        {
            var method = typeof(Form1).GetMethod("NormalizeAndValidatePath",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(method);

            string nonExistent = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            object result = method.Invoke(form, new object[] { nonExistent, true });
            Assert.Null(result);
        }
    }

    [Fact]
    public void NormalizeAndValidatePath_SystemRoot_ReturnsNull()
    {
        using (var form = new Form1())
        {
            var method = typeof(Form1).GetMethod("NormalizeAndValidatePath",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(method);

            string rootPath = Path.GetPathRoot(Environment.SystemDirectory);
            object result = method.Invoke(form, new object[] { rootPath, true });
            Assert.Null(result);
        }
    }
}