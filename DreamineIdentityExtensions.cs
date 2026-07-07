using System.Security.Claims;
using AspNet.Security.OAuth.Naver;
using Dreamine.Database.Abstractions;
using Dreamine.Database.Sqlite;
#if WINDOWS
using Dreamine.Hybrid.Wpf.Hosting;
#endif
using Dreamine.Identity.Internal;
using Dreamine.Identity.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Dreamine.Identity;

/// <summary>
/// \brief Dreamine 계열 앱에 OAuth 로그인을 통합하는 확장 메서드입니다.
/// </summary>
public static class DreamineIdentityExtensions
{
    /// <summary>\brief User 클레임에 내부 Id 를 넣는 커스텀 클레임 이름입니다.</summary>
    public const string UserIdClaimType = "dreamine:userid";

    /// <summary>\brief User 클레임에 로그인한 프로바이더 이름을 넣는 커스텀 클레임 이름입니다.</summary>
    public const string ProviderClaimType = "dreamine:provider";

    private const string ProviderGoogle = "Google";
    private const string ProviderNaver = "Naver";
    private const string ProviderKakao = "Kakao";

    /// <summary>
    /// \brief WPF 호스트 DI 에 익명 인증 상태를 등록해 임베디드 Blazor WebView 가
    /// <c>AuthorizeView</c> 로 크래시하지 않게 합니다.
    /// </summary>
    /// <remarks>
    /// 실제 OAuth 흐름은 브라우저 (Blazor Server) 쪽에서만 유효하며 WPF 임베드는 항상 익명입니다.
    /// </remarks>
    public static IServiceCollection AddDreamineIdentityWpfHost(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddAuthorizationCore();
        services.AddCascadingAuthenticationState();
        services.AddScoped<AuthenticationStateProvider, AnonymousAuthenticationStateProvider>();
        return services;
    }

#if WINDOWS
    /// <summary>
    /// \brief Blazor Server 호스트 옵션에 Dreamine OAuth 로그인 인프라를 통합합니다.
    /// </summary>
    /// <param name="options">Dreamine Blazor Server 호스트 옵션.</param>
    /// <param name="authOptions">appsettings 등에서 파싱한 OAuth 자격증명.</param>
    /// <param name="databasePath">User 저장용 SQLite 파일 경로.</param>
    /// <remarks>
    /// - Cookie 인증 + Google + Naver + Kakao 등록 (자격증명이 있는 프로바이더만).
    /// - 로컬 이메일/비밀번호 가입 및 로그인 엔드포인트 등록.
    /// - OAuth 성공 시 <see cref="IUserStore"/> 를 통해 User 레코드 Upsert.
    /// - <c>/signin/google</c>, <c>/signin/naver</c>, <c>/signin/kakao</c>, <c>/signout</c> 엔드포인트 매핑.
    /// - Authorization middleware 및 파이프라인 순서 자동 배선.
    /// </remarks>
    public static DreamineBlazorServerHostOptions AddDreamineIdentity(
        this DreamineBlazorServerHostOptions options,
        AuthOptions authOptions,
        string databasePath)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(authOptions);
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);

        var previousConfigure = options.ConfigureServices;
        options.ConfigureServices = services =>
        {
            previousConfigure?.Invoke(services);
            RegisterAuthServices(services, authOptions, databasePath);
            services.Configure<ForwardedHeadersOptions>(forwarded =>
            {
                forwarded.ForwardedHeaders =
                    ForwardedHeaders.XForwardedFor |
                    ForwardedHeaders.XForwardedProto |
                    ForwardedHeaders.XForwardedHost;
                forwarded.KnownNetworks.Clear();
                forwarded.KnownProxies.Clear();
            });
        };

        var previousPipeline = options.ConfigurePipeline;
        options.ConfigurePipeline = app =>
        {
            app.UseForwardedHeaders();
            previousPipeline?.Invoke(app);
            app.UseAuthentication();
        };

        var previousAfterRouting = options.ConfigurePipelineAfterRouting;
        options.ConfigurePipelineAfterRouting = app =>
        {
            previousAfterRouting?.Invoke(app);
            app.UseAuthorization();
            app.MapAuthEndpoints();
        };

        return options;
    }
#endif

    /// <summary>
    /// \brief 일반 ASP.NET Core 웹앱에 Dreamine Identity 공유 쿠키 인증을 등록합니다.
    /// </summary>
    /// <remarks>
    /// WPF 호스트가 아닌 순수 웹앱에서 CodeMaru 중앙 로그인 쿠키를 읽어야 할 때 사용합니다.
    /// 로그인/계정 화면은 중앙 포털 링크를 사용하고, 이 앱은 같은 쿠키와 DataProtection 키로
    /// 인증 상태만 공유합니다.
    /// </remarks>
    public static IServiceCollection AddDreamineIdentityWeb(
        this IServiceCollection services,
        AuthOptions authOptions,
        string databasePath)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(authOptions);
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);

        RegisterAuthServices(services, authOptions, databasePath);
        services.Configure<ForwardedHeadersOptions>(forwarded =>
        {
            forwarded.ForwardedHeaders =
                ForwardedHeaders.XForwardedFor |
                ForwardedHeaders.XForwardedProto |
                ForwardedHeaders.XForwardedHost;
            forwarded.KnownNetworks.Clear();
            forwarded.KnownProxies.Clear();
        });

        return services;
    }

    /// <summary>
    /// \brief Dreamine Identity의 로컬 로그인/계정 엔드포인트를 현재 웹앱에도 매핑합니다.
    /// </summary>
    public static IEndpointRouteBuilder MapDreamineIdentityEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        endpoints.MapAuthEndpoints();
        return endpoints;
    }

    private static void RegisterAuthServices(
        IServiceCollection services,
        AuthOptions authOptions,
        string databasePath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(databasePath)!);

        var provider = new SqliteDatabaseProvider($"Data Source={databasePath}");
        services.AddSingleton<IDatabaseProvider>(provider);
        services.AddSingleton<IUserStore, SqliteUserStore>();

        if (!string.IsNullOrWhiteSpace(authOptions.DataProtectionKeysPath))
        {
            Directory.CreateDirectory(authOptions.DataProtectionKeysPath);
            services.AddDataProtection()
                .PersistKeysToFileSystem(new DirectoryInfo(authOptions.DataProtectionKeysPath))
                .SetApplicationName(string.IsNullOrWhiteSpace(authOptions.DataProtectionApplicationName)
                    ? "Dreamine.Identity"
                    : authOptions.DataProtectionApplicationName);
        }

        var authBuilder = services
            .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(cookie =>
            {
                cookie.LoginPath = "/_identity/login";
                cookie.LogoutPath = "/_identity/signout";
                cookie.AccessDeniedPath = "/";
                cookie.ExpireTimeSpan = TimeSpan.FromDays(30);
                cookie.SlidingExpiration = true;
                cookie.Cookie.Name = string.IsNullOrWhiteSpace(authOptions.CookieName)
                    ? ".Dreamine.Identity"
                    : authOptions.CookieName;
                if (!string.IsNullOrWhiteSpace(authOptions.CookieDomain))
                {
                    cookie.Cookie.Domain = authOptions.CookieDomain;
                }
            });

        if (authOptions.Google.IsConfigured)
        {
            authBuilder.AddGoogle(google =>
            {
                google.ClientId = authOptions.Google.ClientId;
                google.ClientSecret = authOptions.Google.ClientSecret;
                google.CallbackPath = "/signin-google";
                google.SaveTokens = false;
                google.Events.OnCreatingTicket = context => OnCreatingTicketAsync(context, ProviderGoogle);
            });
        }

        if (authOptions.Naver.IsConfigured)
        {
            authBuilder.AddNaver(naver =>
            {
                naver.ClientId = authOptions.Naver.ClientId;
                naver.ClientSecret = authOptions.Naver.ClientSecret;
                naver.CallbackPath = "/signin-naver";
                naver.SaveTokens = false;
                naver.Events.OnCreatingTicket = context => OnCreatingTicketAsync(context, ProviderNaver);
            });
        }

        if (authOptions.Kakao.IsConfigured)
        {
            authBuilder.AddOAuth(ProviderKakao, kakao =>
            {
                kakao.ClientId = authOptions.Kakao.ClientId;
                kakao.ClientSecret = authOptions.Kakao.ClientSecret;
                kakao.CallbackPath = "/signin-kakao";
                kakao.AuthorizationEndpoint = "https://kauth.kakao.com/oauth/authorize";
                kakao.TokenEndpoint = "https://kauth.kakao.com/oauth/token";
                kakao.UserInformationEndpoint = "https://kapi.kakao.com/v2/user/me";
                kakao.SaveTokens = false;
                // 카카오 개인 앱은 account_email 을 요청할 수 없음 (권한 없음 → KOE205).
                // 이메일이 필요하면 카카오 개발자 콘솔에서 "추가 기능 신청" 후 스코프 추가.
                kakao.Scope.Add("profile_nickname");
                kakao.Scope.Add("profile_image");
                kakao.Events.OnCreatingTicket = OnKakaoCreatingTicketAsync;
            });
        }

        services.AddAuthorization();
        services.AddCascadingAuthenticationState();
    }

    /// <summary>
    /// \brief 로그인 성공 콜백에서 사용자 레코드를 Upsert 하고 내부 Id 클레임을 추가합니다.
    /// </summary>
    private static async Task OnCreatingTicketAsync(OAuthCreatingTicketContext context, string providerName)
    {
        var principal = context.Principal;
        if (principal is null)
        {
            return;
        }

        var providerKey = principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;
        var email = principal.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
        var displayName = principal.FindFirstValue(ClaimTypes.Name)
                          ?? principal.FindFirstValue(ClaimTypes.GivenName)
                          ?? string.Empty;
        var avatarUrl = principal.FindFirstValue("urn:google:picture")
                        ?? principal.FindFirstValue("picture")
                        ?? principal.FindFirstValue("urn:naver:profile_image")
                        ?? principal.FindFirstValue("profileimage")
                        ?? string.Empty;

        if (string.IsNullOrEmpty(providerKey))
        {
            return;
        }

        await UpsertExternalUserAsync(
            context,
            providerName,
            providerKey,
            email,
            displayName,
            avatarUrl).ConfigureAwait(false);
    }

    private static async Task OnKakaoCreatingTicketAsync(OAuthCreatingTicketContext context)
    {
        if (string.IsNullOrWhiteSpace(context.AccessToken) || context.Principal?.Identity is not ClaimsIdentity identity)
        {
            return;
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        using var response = await context.Backchannel.SendAsync(
            request,
            context.HttpContext.RequestAborted).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync(context.HttpContext.RequestAborted)
            .ConfigureAwait(false);
        using var document = await JsonDocument.ParseAsync(
            stream,
            cancellationToken: context.HttpContext.RequestAborted).ConfigureAwait(false);

        var root = document.RootElement;
        var providerKey = ReadString(root, "id");
        if (string.IsNullOrWhiteSpace(providerKey))
        {
            return;
        }

        var account = TryGetProperty(root, "kakao_account");
        var profile = account.HasValue ? TryGetProperty(account.Value, "profile") : null;

        var email = account.HasValue ? ReadString(account.Value, "email") : string.Empty;
        var displayName = profile.HasValue ? ReadString(profile.Value, "nickname") : string.Empty;
        var avatarUrl = profile.HasValue ? ReadString(profile.Value, "profile_image_url") : string.Empty;

        AddClaimIfNotEmpty(identity, ClaimTypes.NameIdentifier, providerKey);
        AddClaimIfNotEmpty(identity, ClaimTypes.Email, email);
        AddClaimIfNotEmpty(identity, ClaimTypes.Name, displayName);
        AddClaimIfNotEmpty(identity, "picture", avatarUrl);

        await UpsertExternalUserAsync(
            context,
            ProviderKakao,
            providerKey,
            email,
            displayName,
            avatarUrl).ConfigureAwait(false);
    }

    private static async Task UpsertExternalUserAsync(
        OAuthCreatingTicketContext context,
        string providerName,
        string providerKey,
        string email,
        string displayName,
        string avatarUrl)
    {
        var principal = context.Principal;
        if (principal?.Identity is not ClaimsIdentity identity)
        {
            return;
        }

        var userStore = context.HttpContext.RequestServices.GetRequiredService<IUserStore>();
        var user = await userStore.UpsertAsync(
            providerName,
            providerKey,
            email,
            displayName,
            avatarUrl,
            context.HttpContext.RequestAborted).ConfigureAwait(false);

        identity.AddClaim(new Claim(UserIdClaimType, user.Id.ToString()));
        identity.AddClaim(new Claim(ProviderClaimType, providerName));
    }

    private static JsonElement? TryGetProperty(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value)
            ? value
            : null;

    private static string ReadString(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(name, out var value))
        {
            return string.Empty;
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() ?? string.Empty,
            JsonValueKind.Number => value.GetRawText(),
            _ => string.Empty
        };
    }

    private static void AddClaimIfNotEmpty(ClaimsIdentity identity, string type, string value)
    {
        if (!string.IsNullOrWhiteSpace(value) && !identity.HasClaim(claim => claim.Type == type))
        {
            identity.AddClaim(new Claim(type, value));
        }
    }
}
