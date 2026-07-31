using System.Security.Cryptography;
using System.Text;

namespace Dreamine.Identity.Tests;

public sealed class DreaminePasswordHasherTests
{
    [Fact]
    public void CurrentHash_RoundTripsWithoutUpgrade()
    {
        var hash = DreaminePasswordHasher.HashPassword("correct-horse-battery");

        var result = DreaminePasswordHasher.VerifyPassword("correct-horse-battery", hash, out var upgraded);

        Assert.True(DreaminePasswordHasher.IsDreamineHash(hash));
        Assert.Equal(PasswordHashVerificationResult.Success, result);
        Assert.Null(upgraded);
        Assert.True(DreaminePasswordHasher.VerifyPassword("correct-horse-battery", hash));
        Assert.False(DreaminePasswordHasher.VerifyPassword("wrong-password", hash));
        Assert.Equal(hash, DreaminePasswordHasher.HashPlainTextForStorage(hash));
    }

    [Fact]
    public void LegacyValues_AreAcceptedAndUpgraded()
    {
        const string password = "legacy-password";
        var sha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(password))).ToLowerInvariant();

        AssertUpgrade(password, sha256);
        AssertUpgrade(password, password);
        Assert.Equal(sha256, DreaminePasswordHasher.HashPlainTextForStorage(sha256));
        Assert.True(DreaminePasswordHasher.IsDreamineHash(DreaminePasswordHasher.HashPlainTextForStorage(password)));
    }

    [Theory]
    [InlineData("", "anything")]
    [InlineData("password", "")]
    [InlineData("password", "v1.invalid.salt.hash")]
    [InlineData("password", "v1.1.not-base64.not-base64")]
    public void InvalidValues_Fail(string password, string storedHash)
    {
        Assert.Equal(PasswordHashVerificationResult.Failed,
            DreaminePasswordHasher.VerifyPassword(password, storedHash, out var upgraded));
        Assert.Null(upgraded);
    }

    [Fact]
    public void EmptyPassword_CannotBeHashed()
    {
        Assert.Throws<ArgumentException>(() => DreaminePasswordHasher.HashPassword(" "));
        Assert.Equal(string.Empty, DreaminePasswordHasher.HashPlainTextForStorage(string.Empty));
    }

    private static void AssertUpgrade(string password, string storedHash)
    {
        var result = DreaminePasswordHasher.VerifyPassword(password, storedHash, out var upgraded);
        Assert.Equal(PasswordHashVerificationResult.SuccessRehashNeeded, result);
        Assert.NotNull(upgraded);
        Assert.True(DreaminePasswordHasher.IsDreamineHash(upgraded));
    }
}
