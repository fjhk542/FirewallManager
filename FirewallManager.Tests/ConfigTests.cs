using System;
using System.IO;
using Xunit;
using FluentAssertions;

namespace FirewallManager.Tests
{
    public class ConfigTests
    {
        [Fact]
        public void SaveConfigIntegrityHash_ValidFile_ReturnsTrue()
        {
            string tempFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".json");
            string content = "{\"test\": \"data\"}";
            File.WriteAllText(tempFile, content);

            try
            {
                bool result = Config.SaveConfigIntegrityHash(tempFile);
                result.Should().BeTrue();
                string integrityFile = tempFile + ".hmac";
                File.Exists(integrityFile).Should().BeTrue();
                File.ReadAllText(integrityFile).Should().NotBeNullOrEmpty();
            }
            finally
            {
                if (File.Exists(tempFile))
                    File.Delete(tempFile);
                if (File.Exists(tempFile + ".hmac"))
                    File.Delete(tempFile + ".hmac");
            }
        }

        [Fact]
        public void SaveConfigIntegrityHash_NonExistentFile_ReturnsFalse()
        {
            string nonExistentFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".json");
            
            bool result = Config.SaveConfigIntegrityHash(nonExistentFile);
            result.Should().BeFalse();
        }

        [Fact]
        public void VerifyConfigIntegrity_ValidFileWithIntegrityHash_ReturnsTrue()
        {
            string tempFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".json");
            string content = "{\"test\": \"data\"}";
            File.WriteAllText(tempFile, content);

            try
            {
                Config.SaveConfigIntegrityHash(tempFile);
                bool result = Config.VerifyConfigIntegrity(tempFile);
                result.Should().BeTrue();
            }
            finally
            {
                if (File.Exists(tempFile))
                    File.Delete(tempFile);
                if (File.Exists(tempFile + ".hmac"))
                    File.Delete(tempFile + ".hmac");
            }
        }

        [Fact]
        public void VerifyConfigIntegrity_TamperedFile_ReturnsFalse()
        {
            string tempFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".json");
            string content = "{\"test\": \"data\"}";
            File.WriteAllText(tempFile, content);

            try
            {
                Config.SaveConfigIntegrityHash(tempFile);
                File.WriteAllText(tempFile, "{\"test\": \"modified\"}");
                bool result = Config.VerifyConfigIntegrity(tempFile);
                result.Should().BeFalse();
            }
            finally
            {
                if (File.Exists(tempFile))
                    File.Delete(tempFile);
                if (File.Exists(tempFile + ".hmac"))
                    File.Delete(tempFile + ".hmac");
            }
        }

        [Fact]
        public void VerifyConfigIntegrity_NoIntegrityFile_ReturnsTrue()
        {
            string tempFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".json");
            string content = "{\"test\": \"data\"}";
            File.WriteAllText(tempFile, content);

            try
            {
                bool result = Config.VerifyConfigIntegrity(tempFile);
                result.Should().BeTrue();
                string integrityFile = tempFile + ".hmac";
                File.Exists(integrityFile).Should().BeTrue();
            }
            finally
            {
                if (File.Exists(tempFile))
                    File.Delete(tempFile);
                if (File.Exists(tempFile + ".hmac"))
                    File.Delete(tempFile + ".hmac");
            }
        }

        [Fact]
        public void VerifyConfigIntegrity_NonExistentFile_ReturnsFalse()
        {
            string nonExistentFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".json");
            
            bool result = Config.VerifyConfigIntegrity(nonExistentFile);
            result.Should().BeFalse();
        }

        [Fact]
        public void VerifyConfigIntegrity_EmptyIntegrityFile_ReturnsFalse()
        {
            string tempFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".json");
            string content = "{\"test\": \"data\"}";
            File.WriteAllText(tempFile, content);

            try
            {
                string integrityFile = tempFile + ".hmac";
                File.WriteAllText(integrityFile, string.Empty);
                
                bool result = Config.VerifyConfigIntegrity(tempFile);
                result.Should().BeFalse();
            }
            finally
            {
                if (File.Exists(tempFile))
                    File.Delete(tempFile);
                if (File.Exists(tempFile + ".hmac"))
                    File.Delete(tempFile + ".hmac");
            }
        }

        [Fact]
        public void GetAppDataFilePath_ReturnsValidPath()
        {
            string fileName = "test.txt";
            string result = Config.GetAppDataFilePath(fileName);
            
            result.Should().NotBeNullOrEmpty();
            result.Should().EndWith(fileName);
            Directory.Exists(Path.GetDirectoryName(result)).Should().BeTrue();
        }
    }
}
