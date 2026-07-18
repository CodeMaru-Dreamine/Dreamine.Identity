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
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Dreamine.Identity;

/// <summary>
/// \if KO
/// <para>Dreamine 애플리케이션에 공유 쿠키, 로컬 계정 및 OAuth 로그인을 통합하는 확장 메서드를 제공합니다.</para>
/// \endif
/// \if EN
/// <para>Provides extensions that integrate shared cookies, local accounts, and OAuth login into Dreamine applications.</para>
/// \endif
/// </summary>
public static class DreamineIdentityExtensions
{
    /// <summary>
    /// \if KO
    /// <para>내부 사용자 ID를 저장하는 사용자 지정 클레임 형식을 가져옵니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets the custom claim type that stores the internal user ID.</para>
    /// \endif
    /// </summary>
    public const string UserIdClaimType = "dreamine:userid";

    /// <summary>
    /// \if KO
    /// <para>로그인 공급자 이름을 저장하는 사용자 지정 클레임 형식을 가져옵니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets the custom claim type that stores the login-provider name.</para>
    /// \endif
    /// </summary>
    public const string ProviderClaimType = "dreamine:provider";

    /// <summary>
    /// \if KO
    /// <para>Provider Google 값을 보관합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Stores the provider google value.</para>
    /// \endif
    /// </summary>
    private const string ProviderGoogle = "Google";
    /// <summary>
    /// \if KO
    /// <para>Provider Naver 값을 보관합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Stores the provider naver value.</para>
    /// \endif
    /// </summary>
    private const string ProviderNaver = "Naver";
    /// <summary>
    /// \if KO
    /// <para>Provider Kakao 값을 보관합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Stores the provider kakao value.</para>
    /// \endif
    /// </summary>
    private const string ProviderKakao = "Kakao";

    /// <summary>
    /// \if KO
    /// <para>포함된 BlazorWebView가 AuthorizeView를 사용할 수 있도록 WPF 호스트 DI에 익명 인증 상태를 등록합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Registers anonymous authentication state in WPF host DI so an embedded BlazorWebView can use AuthorizeView.</para>
    /// \endif
    /// </summary>
    /// <remarks>
    /// \if KO
    /// <para>포함된 BlazorWebView가 AuthorizeView를 사용할 수 있도록 WPF 호스트 DI에 익명 인증 상태를 등록합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Registers anonymous authentication state in WPF host DI so an embedded BlazorWebView can use AuthorizeView.</para>
    /// \endif
    /// </remarks>
    /// <param name="services">
    /// \if KO
    /// <para>인증 서비스를 추가할 컬렉션입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The collection receiving authentication services.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>동일한 서비스 컬렉션입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The same service collection.</para>
    /// \endif
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// \if KO
    /// <para><paramref name="services"/>가 <see langword="null"/>인 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when <paramref name="services"/> is <see langword="null"/>.</para>
    /// \endif
    /// </exception>
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
    /// \if KO
    /// <para>일반 ASP.NET Core 웹 애플리케이션에 Dreamine Identity 공유 쿠키와 로그인 서비스를 등록합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Registers Dreamine Identity shared-cookie and login services in a regular ASP.NET Core web application.</para>
    /// \endif
    /// </summary>
    /// <param name="options">
    /// \if KO
    /// <para>수정할 Blazor Server 호스트 옵션입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The Blazor Server host options to modify.</para>
    /// \endif
    /// </param>
    /// <param name="authOptions">
    /// \if KO
    /// <para>인증 공급자와 쿠키 옵션입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The authentication-provider and cookie options.</para>
    /// \endif
    /// </param>
    /// <param name="databasePath">
    /// \if KO
    /// <para>사용자 SQLite 데이터베이스 파일 경로입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The user SQLite database-file path.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>수정된 동일한 호스트 옵션입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The same modified host options.</para>
    /// \endif
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// \if KO
    /// <para><paramref name="options"/> 또는 <paramref name="authOptions"/>가 <see langword="null"/>인 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when <paramref name="options"/> or <paramref name="authOptions"/> is <see langword="null"/>.</para>
    /// \endif
    /// </exception>
    /// <exception cref="ArgumentException">
    /// \if KO
    /// <para><paramref name="databasePath"/>가 비어 있거나 공백인 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when <paramref name="databasePath"/> is empty or white space.</para>
    /// \endif
    /// </exception>
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
            app.Use(EnforceRequiredConsentsAsync);
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
    /// \if KO
    /// <para>일반 ASP.NET Core 웹 애플리케이션에 Dreamine Identity 공유 쿠키와 로그인 서비스를 등록합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Registers Dreamine Identity shared-cookie and login services in a regular ASP.NET Core web application.</para>
    /// \endif
    /// </summary>
    /// <remarks>
    /// \if KO
    /// <para>일반 ASP.NET Core 웹 애플리케이션에 Dreamine Identity 공유 쿠키와 로그인 서비스를 등록합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Registers Dreamine Identity shared-cookie and login services in a regular ASP.NET Core web application.</para>
    /// \endif
    /// </remarks>
    /// <param name="services">
    /// \if KO
    /// <para>인증 서비스를 추가할 컬렉션입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The collection receiving authentication services.</para>
    /// \endif
    /// </param>
    /// <param name="authOptions">
    /// \if KO
    /// <para>인증 구성 옵션입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The authentication options.</para>
    /// \endif
    /// </param>
    /// <param name="databasePath">
    /// \if KO
    /// <para>사용자 SQLite 파일 경로입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The user SQLite-file path.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>동일한 서비스 컬렉션입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The same service collection.</para>
    /// \endif
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// \if KO
    /// <para><paramref name="services"/> 또는 <paramref name="authOptions"/>가 <see langword="null"/>인 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when <paramref name="services"/> or <paramref name="authOptions"/> is <see langword="null"/>.</para>
    /// \endif
    /// </exception>
    /// <exception cref="ArgumentException">
    /// \if KO
    /// <para><paramref name="databasePath"/>가 비어 있거나 공백인 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when <paramref name="databasePath"/> is empty or white space.</para>
    /// \endif
    /// </exception>
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
    /// \if KO
    /// <para>Dreamine Identity의 로컬 로그인, 가입, 동의 및 계정 엔드포인트를 현재 웹 애플리케이션에 매핑합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Maps Dreamine Identity local-login, signup, consent, and account endpoints into the current web application.</para>
    /// \endif
    /// </summary>
    /// <param name="endpoints">
    /// \if KO
    /// <para>인증 경로를 추가할 엔드포인트 작성기입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The endpoint builder receiving authentication routes.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>동일한 엔드포인트 작성기입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The same endpoint builder.</para>
    /// \endif
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// \if KO
    /// <para><paramref name="endpoints"/>가 <see langword="null"/>인 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when <paramref name="endpoints"/> is <see langword="null"/>.</para>
    /// \endif
    /// </exception>
    public static IEndpointRouteBuilder MapDreamineIdentityEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        endpoints.MapAuthEndpoints();
        return endpoints;
    }

    /// <summary>
    /// \if KO
    /// <para>사용자 저장소, 공유 쿠키, 구성된 OAuth 공급자 및 권한 서비스를 등록합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Registers the user store, shared cookie, configured OAuth providers, and authorization services.</para>
    /// \endif
    /// </summary>
    /// <param name="services">
    /// \if KO
    /// <para>등록 대상 서비스 컬렉션입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The target service collection.</para>
    /// \endif
    /// </param>
    /// <param name="authOptions">
    /// \if KO
    /// <para>인증 및 쿠키 구성입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The authentication and cookie configuration.</para>
    /// \endif
    /// </param>
    /// <param name="databasePath">
    /// \if KO
    /// <para>사용자 SQLite 파일 경로입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The user SQLite-file path.</para>
    /// \endif
    /// </param>
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
    /// \if KO
    /// <para>일반 OAuth 로그인 성공 시 공급자 클레임을 읽어 사용자를 저장하고 내부 클레임을 추가합니다.</para>
    /// \endif
    /// \if EN
    /// <para>On a general OAuth login success, reads provider claims, persists the user, and adds internal claims.</para>
    /// \endif
    /// </summary>
    /// <param name="context">
    /// \if KO
    /// <para>OAuth 티켓 생성 컨텍스트입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The OAuth ticket-creation context.</para>
    /// \endif
    /// </param>
    /// <param name="providerName">
    /// \if KO
    /// <para>저장할 공급자 이름입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The provider name to persist.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>사용자 저장 및 클레임 추가 작업입니다.</para>
    /// \endif
    /// \if EN
    /// <para>A task representing user persistence and claim addition.</para>
    /// \endif
    /// </returns>
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

    /// <summary>
    /// \if KO
    /// <para>Kakao 사용자 정보 API를 호출하여 프로필 클레임을 만들고 사용자를 저장합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Calls the Kakao user-information API, creates profile claims, and persists the user.</para>
    /// \endif
    /// </summary>
    /// <param name="context">
    /// \if KO
    /// <para>Kakao OAuth 티켓 생성 컨텍스트입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The Kakao OAuth ticket-creation context.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>사용자 정보 조회와 저장 작업입니다.</para>
    /// \endif
    /// \if EN
    /// <para>A task representing user-information retrieval and persistence.</para>
    /// \endif
    /// </returns>
    /// <exception cref="HttpRequestException">
    /// \if KO
    /// <para>Kakao 사용자 정보 응답이 성공 상태가 아닌 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when the Kakao user-information response is not successful.</para>
    /// \endif
    /// </exception>
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

    /// <summary>
    /// \if KO
    /// <para>외부 로그인 사용자를 저장하고 내부 사용자 및 공급자 클레임을 현재 ID에 추가합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Persists an external-login user and adds internal user and provider claims to the current identity.</para>
    /// \endif
    /// </summary>
    /// <param name="context">
    /// \if KO
    /// <para>OAuth 티켓 생성 컨텍스트입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The OAuth ticket-creation context.</para>
    /// \endif
    /// </param>
    /// <param name="providerName">
    /// \if KO
    /// <para>공급자 이름입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The provider name.</para>
    /// \endif
    /// </param>
    /// <param name="providerKey">
    /// \if KO
    /// <para>공급자 사용자 키입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The provider user key.</para>
    /// \endif
    /// </param>
    /// <param name="email">
    /// \if KO
    /// <para>사용자 이메일입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The user's email.</para>
    /// \endif
    /// </param>
    /// <param name="displayName">
    /// \if KO
    /// <para>사용자 표시 이름입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The user's display name.</para>
    /// \endif
    /// </param>
    /// <param name="avatarUrl">
    /// \if KO
    /// <para>프로필 이미지 URL입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The profile-image URL.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>사용자 저장 및 클레임 추가 작업입니다.</para>
    /// \endif
    /// \if EN
    /// <para>A task representing persistence and claim addition.</para>
    /// \endif
    /// </returns>
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

    /// <summary>
    /// \if KO
    /// <para>JSON 객체에서 선택적 속성을 안전하게 읽습니다.</para>
    /// \endif
    /// \if EN
    /// <para>Safely reads an optional property from a JSON object.</para>
    /// \endif
    /// </summary>
    /// <param name="element">
    /// \if KO
    /// <para>검사할 JSON 요소입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The JSON element to inspect.</para>
    /// \endif
    /// </param>
    /// <param name="name">
    /// \if KO
    /// <para>속성 이름입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The property name.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>속성 값 또는 없으면 <see langword="null"/>입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The property value, or <see langword="null"/> when absent.</para>
    /// \endif
    /// </returns>
    private static JsonElement? TryGetProperty(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value)
            ? value
            : null;

    /// <summary>
    /// \if KO
    /// <para>JSON 객체 속성의 문자열 또는 숫자 표현을 읽습니다.</para>
    /// \endif
    /// \if EN
    /// <para>Reads the string or numeric representation of a JSON object property.</para>
    /// \endif
    /// </summary>
    /// <param name="element">
    /// \if KO
    /// <para>JSON 객체입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The JSON object.</para>
    /// \endif
    /// </param>
    /// <param name="name">
    /// \if KO
    /// <para>읽을 속성 이름입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The property name to read.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>문자열 값이며 지원하지 않거나 없으면 빈 문자열입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The string value, or an empty string when absent or unsupported.</para>
    /// \endif
    /// </returns>
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

    /// <summary>
    /// \if KO
    /// <para>값이 있고 같은 형식의 클레임이 없을 때만 클레임을 추가합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Adds a claim only when its value is present and no claim of the same type exists.</para>
    /// \endif
    /// </summary>
    /// <param name="identity">
    /// \if KO
    /// <para>수정할 클레임 ID입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The claims identity to modify.</para>
    /// \endif
    /// </param>
    /// <param name="type">
    /// \if KO
    /// <para>클레임 형식입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The claim type.</para>
    /// \endif
    /// </param>
    /// <param name="value">
    /// \if KO
    /// <para>클레임 값입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The claim value.</para>
    /// \endif
    /// </param>
    private static void AddClaimIfNotEmpty(ClaimsIdentity identity, string type, string value)
    {
        if (!string.IsNullOrWhiteSpace(value) && !identity.HasClaim(claim => claim.Type == type))
        {
            identity.AddClaim(new Claim(type, value));
        }
    }

    /// <summary>
    /// \if KO
    /// <para>인증된 사용자의 필수 동의를 확인하고 미완료 사용자를 동의 화면으로 보냅니다.</para>
    /// \endif
    /// \if EN
    /// <para>Checks required consents for an authenticated user and redirects incomplete users to the consent page.</para>
    /// \endif
    /// </summary>
    /// <param name="context">
    /// \if KO
    /// <para>현재 HTTP 컨텍스트입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The current HTTP context.</para>
    /// \endif
    /// </param>
    /// <param name="next">
    /// \if KO
    /// <para>다음 미들웨어입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The next middleware delegate.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>동의 검사 또는 다음 미들웨어 실행 작업입니다.</para>
    /// \endif
    /// \if EN
    /// <para>A task representing consent inspection or execution of the next middleware.</para>
    /// \endif
    /// </returns>
    private static async Task EnforceRequiredConsentsAsync(HttpContext context, RequestDelegate next)
    {
        if (ShouldSkipConsentGate(context.Request.Path) ||
            context.User.Identity?.IsAuthenticated != true)
        {
            await next(context).ConfigureAwait(false);
            return;
        }

        var userIdValue = context.User.FindFirstValue(UserIdClaimType);
        if (!long.TryParse(
                userIdValue,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var userId))
        {
            await next(context).ConfigureAwait(false);
            return;
        }

        var userStore = context.RequestServices.GetService<IUserStore>();
        if (userStore is null)
        {
            await next(context).ConfigureAwait(false);
            return;
        }

        var user = await userStore.GetByIdAsync(userId, context.RequestAborted).ConfigureAwait(false);
        if (RequiredConsentPolicy.HasRequiredConsents(user))
        {
            await next(context).ConfigureAwait(false);
            return;
        }

        var returnUrl = Uri.EscapeDataString(BuildCurrentUrl(context.Request));
        context.Response.Redirect($"/_identity/consent?returnUrl={returnUrl}");
    }

    /// <summary>
    /// \if KO
    /// <para>인증, 정적 자산 및 프레임워크 경로가 동의 게이트를 건너뛰어야 하는지 확인합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Determines whether authentication, static-asset, or framework paths bypass the consent gate.</para>
    /// \endif
    /// </summary>
    /// <param name="path">
    /// \if KO
    /// <para>검사할 요청 경로입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The request path to inspect.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>게이트를 건너뛰면 <see langword="true"/>입니다.</para>
    /// \endif
    /// \if EN
    /// <para><see langword="true"/> when the gate should be skipped.</para>
    /// \endif
    /// </returns>
    private static bool ShouldSkipConsentGate(PathString path)
    {
        var value = path.Value ?? "/";
        if (value is "/" or "")
        {
            return false;
        }

        if (Path.HasExtension(value))
        {
            return true;
        }

        return value.StartsWith("/_identity", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("/signin", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("/login", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("/signup", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("/consent", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("/signout", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("/privacy", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("/terms", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("/_blazor", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("/_framework", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("/css", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("/js", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("/img", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("/bootstrap", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// \if KO
    /// <para>현재 요청의 경로 기준 반환 URL을 만듭니다.</para>
    /// \endif
    /// \if EN
    /// <para>Builds a path-based return URL for the current request.</para>
    /// \endif
    /// </summary>
    /// <param name="request">
    /// \if KO
    /// <para>현재 HTTP 요청입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The current HTTP request.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>경로, PathBase 및 쿼리를 포함한 반환 URL입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The return URL containing PathBase, path, and query.</para>
    /// \endif
    /// </returns>
    private static string BuildCurrentUrl(HttpRequest request)
    {
        var path = request.PathBase.Add(request.Path).ToString();
        var query = request.QueryString.HasValue ? request.QueryString.Value : string.Empty;
        return string.IsNullOrEmpty(path) ? $"/{query}" : $"{path}{query}";
    }
}
