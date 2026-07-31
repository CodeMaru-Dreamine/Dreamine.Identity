using System.Reflection;
using System.Security.Claims;
using Dreamine.Identity.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;

namespace Dreamine.Identity.Tests;

public sealed class AuthEndpointsTests
{
    [Theory]
    [InlineData(null, "/")]
    [InlineData("", "/")]
    [InlineData(" ", "/")]
    [InlineData("/dashboard?tab=users", "/dashboard?tab=users")]
    [InlineData("//evil.example/path", "/")]
    [InlineData("javascript:alert(1)", "/")]
    [InlineData("https://codemaru.co.kr/account", "https://codemaru.co.kr/account")]
    [InlineData("https://admin.codemaru.co.kr/account", "https://admin.codemaru.co.kr/account")]
    [InlineData("http://localhost:5000/callback", "http://localhost:5000/callback")]
    [InlineData("http://127.0.0.1/callback", "http://127.0.0.1/callback")]
    [InlineData("http://[::1]/callback", "http://[::1]/callback")]
    [InlineData("https://evil.example/account", "/")]
    public void SafeReturnUrl_AllowsOnlyLocalAndTrustedDestinations(string? value, string expected)
    {
        Assert.Equal(expected, Invoke<string>("SafeReturnUrl", value));
    }

    [Theory]
    [InlineData("", false)]
    [InlineData(" ", false)]
    [InlineData("Mozilla/5.0", false)]
    [InlineData("KAKAOTALK 10.0", true)]
    [InlineData("NAVER(inapp; search)", true)]
    [InlineData("FBAN/FBIOS", true)]
    [InlineData("FBAV/1.0", true)]
    [InlineData("Instagram 300", true)]
    [InlineData("Line/14.0", true)]
    [InlineData("Mozilla/5.0 (Linux; Android 14; wv)", true)]
    [InlineData("Mozilla/5.0 (Linux; wv)", false)]
    public void IsEmbeddedMobileBrowser_DetectsKnownInAppBrowsers(string userAgent, bool expected)
    {
        Assert.Equal(expected, Invoke<bool>("IsEmbeddedMobileBrowser", userAgent));
    }

    [Fact]
    public void BuildLoginHtml_RendersLoginAndEscapesUntrustedContent()
    {
        var html = Invoke<string>(
            "BuildLoginHtml",
            "/orders?a=1&b=2",
            null!,
            "<saved>",
            "\"invalid\"",
            "/_identity");

        Assert.Contains("<title>로그인 | Dreamine Identity</title>", html);
        Assert.Contains("action=\"/_identity/login\"", html);
        Assert.Contains("&lt;saved&gt;", html);
        Assert.Contains("&quot;invalid&quot;", html);
        Assert.Contains("returnUrl=%2Forders%3Fa%3D1%26b%3D2", html);
        Assert.DoesNotContain("confirmPassword", html);
    }

    [Fact]
    public void BuildLoginHtml_RendersSignupFieldsAndSwitchLink()
    {
        var html = Invoke<string>(
            "BuildLoginHtml",
            "/",
            "SIGNUP",
            null!,
            null!,
            "");

        Assert.Contains("<title>회원가입 | Dreamine Identity</title>", html);
        Assert.Contains("action=\"/signup\"", html);
        Assert.Contains("name=\"displayName\"", html);
        Assert.Contains("name=\"confirmPassword\"", html);
        Assert.Contains("href=\"/login?returnUrl=%2F\"", html);
    }

    [Fact]
    public void BuildAccountHtml_RendersLocalAccountControls()
    {
        var user = CreateUser(
            provider: "Local",
            email: "",
            displayName: "<Admin \"One\">",
            avatarUrl: "");

        var html = Invoke<string>(
            "BuildAccountHtml",
            user,
            "/dashboard",
            "saved",
            "warning",
            "/_identity");

        Assert.Contains("비밀번호 변경", html);
        Assert.Contains("제공되지 않음", html);
        Assert.Contains("&lt;Admin &quot;One&quot;&gt;", html);
        Assert.Contains("action=\"/_identity/account\"", html);
        Assert.Contains("href=\"/_identity/signout?returnUrl=%2Fdashboard\"", html);
        Assert.Contains("avatar-fallback", html);
        Assert.Contains("class=\"message\">saved", html);
        Assert.Contains("class=\"error\">warning", html);
    }

    [Fact]
    public void BuildAccountHtml_RendersExternalProviderAndAvatar()
    {
        var user = CreateUser(
            provider: "Google",
            email: "user@example.com",
            displayName: "User",
            avatarUrl: "https://example.com/avatar.png?x=\"bad\"");

        var html = Invoke<string>(
            "BuildAccountHtml",
            user,
            "/",
            null!,
            null!,
            "");

        Assert.Contains("Google 로그인 계정", html);
        Assert.DoesNotContain("현재 비밀번호", html);
        Assert.Contains("user@example.com", html);
        Assert.Contains("&quot;bad", html);
        Assert.DoesNotContain("class=\"message\"", html);
        Assert.DoesNotContain("class=\"error\"", html);
    }

    [Theory]
    [InlineData("42", 42L)]
    [InlineData("0", 0L)]
    [InlineData("-1", null)]
    [InlineData("1.5", null)]
    [InlineData("not-a-number", null)]
    [InlineData(null, null)]
    public void GetCurrentUserId_ParsesOnlyInvariantIntegerClaims(string? claimValue, long? expected)
    {
        var context = new DefaultHttpContext();
        if (claimValue is not null)
        {
            context.User = new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim(DreamineIdentityExtensions.UserIdClaimType, claimValue)]));
        }

        Assert.Equal(expected, Invoke<long?>("GetCurrentUserId", context));
    }

    [Fact]
    public async Task LocalLogin_HandlesInvalidAndValidCredentials()
    {
        var store = new StubUserStore();
        var invalidContext = CreateFormContext(
            ("returnUrl", "/dashboard"),
            ("email", "user@example.com"),
            ("password", "wrong"));

        var invalid = await InvokeAsync(
            "HandleLocalLoginAsync",
            invalidContext,
            store,
            "/_identity");

        Assert.NotNull(invalid);
        store.ValidatedUser = CreateUser("Local", "user@example.com", "User", "");
        var validContext = CreateFormContext(
            ("returnUrl", "/dashboard"),
            ("email", "user@example.com"),
            ("password", "correct"));

        var valid = await InvokeAsync(
            "HandleLocalLoginAsync",
            validContext,
            store,
            "/_identity");

        Assert.NotNull(valid);
        Assert.NotNull(validContext.RequestServices
            .GetRequiredService<RecordingAuthenticationService>()
            .SignedInPrincipal);
    }

    [Fact]
    public async Task Signup_HandlesMismatchFailureAndSuccess()
    {
        var store = new StubUserStore();
        var mismatchContext = CreateFormContext(
            ("returnUrl", "/"),
            ("email", "user@example.com"),
            ("displayName", "User"),
            ("password", "password1"),
            ("confirmPassword", "different"));
        Assert.NotNull(await InvokeAsync(
            "HandleSignupAsync",
            mismatchContext,
            store,
            "/_identity"));

        store.CreateException = new InvalidOperationException("duplicate");
        var failureContext = CreateFormContext(
            ("returnUrl", "/"),
            ("email", "user@example.com"),
            ("displayName", "User"),
            ("password", "password1"),
            ("confirmPassword", "password1"));
        Assert.NotNull(await InvokeAsync(
            "HandleSignupAsync",
            failureContext,
            store,
            "/_identity"));

        store.CreateException = null;
        var successContext = CreateFormContext(
            ("returnUrl", "/welcome"),
            ("email", "new@example.com"),
            ("displayName", "New User"),
            ("password", "password1"),
            ("confirmPassword", "password1"));
        Assert.NotNull(await InvokeAsync(
            "HandleSignupAsync",
            successContext,
            store,
            "/_identity"));
    }

    [Fact]
    public async Task AccountPage_HandlesAnonymousMissingAndExistingUsers()
    {
        var store = new StubUserStore();
        Assert.NotNull(await InvokeAsync(
            "HandleAccountPageAsync",
            CreateContext(),
            store,
            "/",
            null!,
            null!,
            "/_identity"));

        var missingContext = CreateContext(userId: 42);
        Assert.NotNull(await InvokeAsync(
            "HandleAccountPageAsync",
            missingContext,
            store,
            "/",
            null!,
            null!,
            "/_identity"));
        Assert.True(missingContext.RequestServices
            .GetRequiredService<RecordingAuthenticationService>()
            .SignedOut);

        store.UserById = CreateUser("Google", "user@example.com", "User", "");
        Assert.NotNull(await InvokeAsync(
            "HandleAccountPageAsync",
            CreateContext(userId: 42),
            store,
            "/dashboard",
            "saved",
            null!,
            "/_identity"));
    }

    [Fact]
    public async Task AccountPost_HandlesProfilePasswordAndFailurePaths()
    {
        var store = new StubUserStore();
        Assert.NotNull(await InvokeAsync(
            "HandleAccountPostAsync",
            CreateFormContext(("accountAction", "profile")),
            store,
            "/_identity"));

        var mismatchContext = CreateFormContext(
            42,
            ("returnUrl", "/"),
            ("accountAction", "password"),
            ("currentPassword", "old"),
            ("newPassword", "new-password"),
            ("confirmPassword", "different"));
        Assert.NotNull(await InvokeAsync(
            "HandleAccountPostAsync",
            mismatchContext,
            store,
            "/_identity"));

        store.ChangePasswordException = new ArgumentException("invalid password");
        var failureContext = CreateFormContext(
            42,
            ("returnUrl", "/"),
            ("accountAction", "password"),
            ("currentPassword", "old"),
            ("newPassword", "new-password"),
            ("confirmPassword", "new-password"));
        Assert.NotNull(await InvokeAsync(
            "HandleAccountPostAsync",
            failureContext,
            store,
            "/_identity"));

        store.ChangePasswordException = null;
        store.ChangedUser = CreateUser("Local", "user@example.com", "User", "");
        Assert.NotNull(await InvokeAsync(
            "HandleAccountPostAsync",
            CreateFormContext(
                42,
                ("returnUrl", "/"),
                ("accountAction", "password"),
                ("currentPassword", "old"),
                ("newPassword", "new-password"),
                ("confirmPassword", "new-password")),
            store,
            "/_identity"));

        store.UpdatedUser = CreateUser("Local", "user@example.com", "Updated", "");
        Assert.NotNull(await InvokeAsync(
            "HandleAccountPostAsync",
            CreateFormContext(
                42,
                ("returnUrl", "/dashboard"),
                ("accountAction", "profile"),
                ("displayName", "Updated")),
            store,
            "/_identity"));
    }

    private static AuthUser CreateUser(
        string provider,
        string email,
        string displayName,
        string avatarUrl) =>
        new()
        {
            Id = 42,
            Provider = provider,
            ProviderKey = "provider-key",
            Email = email,
            DisplayName = displayName,
            AvatarUrl = avatarUrl
        };

    private static T Invoke<T>(string methodName, params object?[] arguments)
    {
        var type = typeof(DreamineIdentityExtensions).Assembly.GetType(
            "Dreamine.Identity.Internal.AuthEndpoints",
            throwOnError: true)!;
        var method = type.GetMethod(
            methodName,
            BindingFlags.Static | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException($"{methodName} was not found.");

        return (T)method.Invoke(null, arguments)!;
    }

    private static async Task<object> InvokeAsync(string methodName, params object?[] arguments)
    {
        var type = typeof(DreamineIdentityExtensions).Assembly.GetType(
            "Dreamine.Identity.Internal.AuthEndpoints",
            throwOnError: true)!;
        var method = type.GetMethod(
            methodName,
            BindingFlags.Static | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException($"{methodName} was not found.");
        var task = (Task)method.Invoke(null, arguments)!;

        await task;
        return task.GetType().GetProperty("Result")!.GetValue(task)!;
    }

    private static DefaultHttpContext CreateContext(long? userId = null)
    {
        var context = new DefaultHttpContext();
        var authentication = new RecordingAuthenticationService();
        context.RequestServices = new ServiceCollection()
            .AddSingleton(authentication)
            .AddSingleton<IAuthenticationService>(authentication)
            .BuildServiceProvider();
        if (userId.HasValue)
        {
            context.User = new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim(DreamineIdentityExtensions.UserIdClaimType, userId.Value.ToString())],
                "Test"));
        }

        return context;
    }

    private static DefaultHttpContext CreateFormContext(
        params (string Key, string Value)[] values) =>
        CreateFormContext(null, values);

    private static DefaultHttpContext CreateFormContext(
        long? userId,
        params (string Key, string Value)[] values)
    {
        var context = CreateContext(userId);
        var fields = values.ToDictionary(
            item => item.Key,
            item => new StringValues(item.Value));
        context.Request.Form = new FormCollection(fields);
        return context;
    }

    private sealed class RecordingAuthenticationService : IAuthenticationService
    {
        public ClaimsPrincipal? SignedInPrincipal { get; private set; }
        public bool SignedOut { get; private set; }

        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) =>
            Task.FromResult(AuthenticateResult.NoResult());

        public Task ChallengeAsync(
            HttpContext context,
            string? scheme,
            AuthenticationProperties? properties) =>
            Task.CompletedTask;

        public Task ForbidAsync(
            HttpContext context,
            string? scheme,
            AuthenticationProperties? properties) =>
            Task.CompletedTask;

        public Task SignInAsync(
            HttpContext context,
            string? scheme,
            ClaimsPrincipal principal,
            AuthenticationProperties? properties)
        {
            SignedInPrincipal = principal;
            return Task.CompletedTask;
        }

        public Task SignOutAsync(
            HttpContext context,
            string? scheme,
            AuthenticationProperties? properties)
        {
            SignedOut = true;
            return Task.CompletedTask;
        }
    }

    private sealed class StubUserStore : IUserStore
    {
        public AuthUser? ValidatedUser { get; set; }
        public AuthUser? UserById { get; set; }
        public AuthUser? UpdatedUser { get; set; }
        public AuthUser? ChangedUser { get; set; }
        public Exception? CreateException { get; set; }
        public Exception? ChangePasswordException { get; set; }

        public Task<AuthUser> UpsertAsync(
            string provider,
            string providerKey,
            string email,
            string displayName,
            string avatarUrl,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<AuthUser?> GetByIdAsync(
            long id,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(UserById);

        public Task<AuthUser?> UpdateDisplayNameAsync(
            long id,
            string displayName,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(UpdatedUser);

        public Task<AuthUser?> ChangeLocalPasswordAsync(
            long id,
            string currentPassword,
            string newPassword,
            CancellationToken cancellationToken = default) =>
            ChangePasswordException is null
                ? Task.FromResult(ChangedUser)
                : Task.FromException<AuthUser?>(ChangePasswordException);

        public Task<AuthUser> CreateLocalAsync(
            string email,
            string displayName,
            string password,
            CancellationToken cancellationToken = default) =>
            CreateException is null
                ? Task.FromResult(CreateUser("Local", email, displayName, ""))
                : Task.FromException<AuthUser>(CreateException);

        public Task<AuthUser?> ValidateLocalAsync(
            string email,
            string password,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(ValidatedUser);
    }
}
