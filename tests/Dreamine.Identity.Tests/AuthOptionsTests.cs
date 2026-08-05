using Dreamine.Identity.Options;

namespace Dreamine.Identity.Tests;

public sealed class AuthOptionsTests
{
    [Fact]
    public void Defaults_AreSafeForAnUnconfiguredApplication()
    {
        var options = new AuthOptions();

        Assert.Equal("Authentication", AuthOptions.SectionName);
        Assert.Equal(".Dreamine.Identity", options.CookieName);
        Assert.Equal("Dreamine.Identity", options.DataProtectionApplicationName);
        Assert.False(options.Google.IsConfigured);
        Assert.False(options.Naver.IsConfigured);
        Assert.False(options.Kakao.IsConfigured);
    }

    [Theory]
    [InlineData("", "", false)]
    [InlineData("client", "", false)]
    [InlineData("", "secret", false)]
    [InlineData("client", "secret", true)]
    public void OAuthProvider_IsConfigured_RequiresBothValues(
        string clientId,
        string clientSecret,
        bool expected)
    {
        var options = new OAuthProviderOptions
        {
            ClientId = clientId,
            ClientSecret = clientSecret
        };

        Assert.Equal(expected, options.IsConfigured);
    }

    [Fact]
    public void AsConsumer_CopiesOnlySharedCookieSettings()
    {
        var options = new AuthOptions
        {
            CookieDomain = ".codemaru.co.kr",
            CookieName = ".Shared.Identity",
            DataProtectionKeysPath = "identity-keys",
            DataProtectionApplicationName = "CodeMaru.Identity",
            Google = new OAuthProviderOptions
            {
                ClientId = "google-client",
                ClientSecret = "google-secret"
            }
        };

        var consumer = options.AsConsumer();

        Assert.NotSame(options, consumer);
        Assert.Equal(options.CookieDomain, consumer.CookieDomain);
        Assert.Equal(options.CookieName, consumer.CookieName);
        Assert.Equal(options.DataProtectionKeysPath, consumer.DataProtectionKeysPath);
        Assert.Equal(
            options.DataProtectionApplicationName,
            consumer.DataProtectionApplicationName);
        Assert.False(consumer.Google.IsConfigured);
        Assert.False(consumer.Naver.IsConfigured);
        Assert.False(consumer.Kakao.IsConfigured);
    }
}
