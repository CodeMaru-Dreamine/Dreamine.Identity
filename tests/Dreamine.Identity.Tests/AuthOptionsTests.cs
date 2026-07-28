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
}
