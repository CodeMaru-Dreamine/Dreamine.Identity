using AspNet.Security.OAuth.Naver;
using Dreamine.Database.Abstractions;
using Dreamine.Identity.Options;
using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Dreamine.Identity.Tests;

public sealed class DreamineIdentityExtensionsTests
{
    [Fact]
    public void AddDreamineIdentityWpfHost_RegistersAnonymousAuthenticationState()
    {
        var services = new ServiceCollection();

        var result = services.AddDreamineIdentityWpfHost();

        Assert.Same(services, result);
        using var provider = services.BuildServiceProvider();
        Assert.IsType<AnonymousAuthenticationStateProvider>(
            provider.GetRequiredService<AuthenticationStateProvider>());
    }

    [Fact]
    public void AddDreamineIdentityWeb_RejectsInvalidArguments()
    {
        var services = new ServiceCollection();
        var options = new AuthOptions();

        Assert.Throws<ArgumentNullException>(
            () => DreamineIdentityExtensions.AddDreamineIdentityWeb(null!, options, "identity.db"));
        Assert.Throws<ArgumentNullException>(
            () => services.AddDreamineIdentityWeb(null!, "identity.db"));
        Assert.Throws<ArgumentException>(
            () => services.AddDreamineIdentityWeb(options, ""));
    }

    [Fact]
    public void AddDreamineIdentityWeb_RegistersConfiguredProvidersAndCookieOptions()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "dreamine-identity-tests",
            Guid.NewGuid().ToString("N"));
        var databasePath = Path.Combine(root, "data", "identity.db");
        var keyPath = Path.Combine(root, "keys");
        var services = new ServiceCollection();
        services.AddLogging();
        var options = new AuthOptions
        {
            CookieName = ".Shared.Identity",
            CookieDomain = ".codemaru.co.kr",
            DataProtectionKeysPath = keyPath,
            DataProtectionApplicationName = "Shared.Identity",
            Google = ConfiguredProvider(),
            Naver = ConfiguredProvider(),
            Kakao = ConfiguredProvider()
        };

        var result = services.AddDreamineIdentityWeb(options, databasePath);

        Assert.Same(services, result);
        Assert.True(Directory.Exists(Path.GetDirectoryName(databasePath)));
        Assert.True(Directory.Exists(keyPath));

        using var provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetRequiredService<IDatabaseProvider>());
        Assert.IsType<SqliteUserStore>(provider.GetRequiredService<IUserStore>());

        var forwarded = provider.GetRequiredService<IOptions<ForwardedHeadersOptions>>().Value;
        Assert.True(forwarded.ForwardedHeaders.HasFlag(ForwardedHeaders.XForwardedFor));
        Assert.True(forwarded.ForwardedHeaders.HasFlag(ForwardedHeaders.XForwardedProto));
        Assert.True(forwarded.ForwardedHeaders.HasFlag(ForwardedHeaders.XForwardedHost));
        Assert.Empty(forwarded.KnownNetworks);
        Assert.Empty(forwarded.KnownProxies);

        var cookies = provider
            .GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(CookieAuthenticationDefaults.AuthenticationScheme);
        Assert.Equal(".Shared.Identity", cookies.Cookie.Name);
        Assert.Equal(".codemaru.co.kr", cookies.Cookie.Domain);
        Assert.True(cookies.SlidingExpiration);
        Assert.Equal(TimeSpan.FromDays(30), cookies.ExpireTimeSpan);

        var google = provider
            .GetRequiredService<IOptionsMonitor<GoogleOptions>>()
            .Get(GoogleDefaults.AuthenticationScheme);
        Assert.Equal("client", google.ClientId);
        Assert.Equal("/signin-google", google.CallbackPath);

        var naver = provider
            .GetRequiredService<IOptionsMonitor<NaverAuthenticationOptions>>()
            .Get(NaverAuthenticationDefaults.AuthenticationScheme);
        Assert.Equal("client", naver.ClientId);
        Assert.Equal("/signin-naver", naver.CallbackPath);

        var kakao = provider
            .GetRequiredService<IOptionsMonitor<OAuthOptions>>()
            .Get("Kakao");
        Assert.Equal("client", kakao.ClientId);
        Assert.Contains("profile_nickname", kakao.Scope);
        Assert.Contains("profile_image", kakao.Scope);
    }

    [Fact]
    public void AddDreamineIdentityWeb_UsesDefaultCookieValuesWhenOptionalSettingsAreBlank()
    {
        var databasePath = Path.Combine(
            Path.GetTempPath(),
            "dreamine-identity-tests",
            Guid.NewGuid().ToString("N"),
            "identity.db");
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddDreamineIdentityWeb(
            new AuthOptions
            {
                CookieName = "",
                DataProtectionKeysPath = ""
            },
            databasePath);

        using var provider = services.BuildServiceProvider();
        var cookies = provider
            .GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(CookieAuthenticationDefaults.AuthenticationScheme);

        Assert.Equal(".Dreamine.Identity", cookies.Cookie.Name);
        Assert.Null(cookies.Cookie.Domain);
    }

    [Fact]
    public void OAuthJsonHelpers_ReadStringsNumbersAndMissingValues()
    {
        using var document = JsonDocument.Parse(
            """{"name":"Dreamine","id":42,"missingValue":null,"nested":{"value":"ok"}}""");
        var root = document.RootElement;

        Assert.Equal("Dreamine", InvokePrivate<string>("ReadString", root, "name"));
        Assert.Equal("42", InvokePrivate<string>("ReadString", root, "id"));
        Assert.Equal("", InvokePrivate<string>("ReadString", root, "missing"));
        Assert.Equal("", InvokePrivate<string>("ReadString", root, "missingValue"));
        Assert.Equal("", InvokePrivate<string>(
            "ReadString",
            JsonDocument.Parse("[]").RootElement,
            "name"));

        var nested = InvokePrivate<JsonElement?>("TryGetProperty", root, "nested");
        Assert.True(nested.HasValue);
        Assert.Equal("ok", InvokePrivate<string>("ReadString", nested.Value, "value"));
        Assert.Null(InvokePrivate<JsonElement?>("TryGetProperty", root, "missing"));
        Assert.Null(InvokePrivate<JsonElement?>(
            "TryGetProperty",
            JsonDocument.Parse("[]").RootElement,
            "name"));
    }

    [Fact]
    public void AddClaimIfNotEmpty_SkipsBlankAndDuplicateClaims()
    {
        var identity = new ClaimsIdentity();

        InvokePrivate<object?>("AddClaimIfNotEmpty", identity, ClaimTypes.Email, "");
        Assert.Empty(identity.Claims);

        InvokePrivate<object?>(
            "AddClaimIfNotEmpty",
            identity,
            ClaimTypes.Email,
            "user@example.com");
        InvokePrivate<object?>(
            "AddClaimIfNotEmpty",
            identity,
            ClaimTypes.Email,
            "replacement@example.com");

        var claim = Assert.Single(identity.Claims);
        Assert.Equal("user@example.com", claim.Value);
    }

    private static OAuthProviderOptions ConfiguredProvider() =>
        new()
        {
            ClientId = "client",
            ClientSecret = "secret"
        };

    private static T InvokePrivate<T>(string methodName, params object?[] arguments)
    {
        var method = typeof(DreamineIdentityExtensions).GetMethod(
            methodName,
            BindingFlags.Static | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException($"{methodName} was not found.");

        return (T)method.Invoke(null, arguments)!;
    }
}
