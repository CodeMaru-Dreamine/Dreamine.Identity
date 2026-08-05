namespace Dreamine.Identity.Tests;

public sealed class DreamineIdentityPortalTests
{
    [Theory]
    [InlineData(
        "login",
        "https://portfolio.codemaru.co.kr/admin?tab=projects",
        "ko",
        "https://codemaru.co.kr/_identity/login?lang=ko&returnUrl=https%3A%2F%2Fportfolio.codemaru.co.kr%2Fadmin%3Ftab%3Dprojects")]
    [InlineData(
        "account/settings",
        "https://shop.codemaru.co.kr/",
        null,
        "https://codemaru.co.kr/_identity/account%2Fsettings?returnUrl=https%3A%2F%2Fshop.codemaru.co.kr%2F")]
    public void CreateUrl_EscapesRouteAndReturnUrl(
        string action,
        string returnUrl,
        string? language,
        string expected)
    {
        var actual = DreamineIdentityPortal.CreateUrl(action, returnUrl, language);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void CreateUrl_RejectsBlankRequiredValues()
    {
        Assert.Throws<ArgumentException>(
            () => DreamineIdentityPortal.CreateUrl("", "https://codemaru.co.kr/"));
        Assert.Throws<ArgumentException>(
            () => DreamineIdentityPortal.CreateUrl("login", ""));
    }
}
