using AspNet.Security.OAuth.Naver;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using System.Net;
using System.Security.Claims;
using System.Text;
using Dreamine.Identity.Models;

namespace Dreamine.Identity.Internal;

/// <summary>
/// \if KO
/// <para>로그인, 가입, 계정, 필수 동의 및 로그아웃 HTTP 엔드포인트를 매핑하고 해당 HTML을 생성합니다.</para>
/// \endif
/// \if EN
/// <para>Maps login, signup, account, required-consent, and sign-out HTTP endpoints and generates their HTML.</para>
/// \endif
/// </summary>
internal static class AuthEndpoints
{
    /// <summary>
    /// \if KO
    /// <para>Local Provider 값을 보관합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Stores the local provider value.</para>
    /// \endif
    /// </summary>
    private const string LocalProvider = "Local";

    /// <summary>
    /// \if KO
    /// <para>접두사가 있는 경로와 짧은 호환 경로에 모든 Dreamine 인증 엔드포인트를 등록합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Registers all Dreamine authentication endpoints under prefixed and short compatibility routes.</para>
    /// \endif
    /// </summary>
    /// <param name="endpoints">
    /// \if KO
    /// <para>경로를 등록할 엔드포인트 작성기입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The endpoint builder receiving the routes.</para>
    /// \endif
    /// </param>
    public static void MapAuthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/_identity/login", (HttpContext http, string? returnUrl, string? mode, string? message, string? error) =>
            Results.Content(
                BuildLoginHtml(SafeReturnUrl(returnUrl), mode, message, error, "/_identity"),
                "text/html; charset=utf-8"));

        endpoints.MapGet("/login", (HttpContext http, string? returnUrl, string? mode, string? message, string? error) =>
            Results.Content(
                BuildLoginHtml(SafeReturnUrl(returnUrl), mode, message, error),
                "text/html; charset=utf-8"));

        endpoints.MapPost("/_identity/login", async (HttpContext http, IUserStore userStore) =>
            await HandleLocalLoginAsync(http, userStore, "/_identity").ConfigureAwait(false));

        endpoints.MapPost("/login", async (HttpContext http, IUserStore userStore) =>
            await HandleLocalLoginAsync(http, userStore, string.Empty).ConfigureAwait(false));

        endpoints.MapPost("/_identity/signup", async (HttpContext http, IUserStore userStore) =>
            await HandleSignupAsync(http, userStore, "/_identity").ConfigureAwait(false));

        endpoints.MapPost("/signup", async (HttpContext http, IUserStore userStore) =>
            await HandleSignupAsync(http, userStore, string.Empty).ConfigureAwait(false));

        endpoints.MapGet("/signin/google", (HttpContext http, string? returnUrl) =>
        {
            var safeReturnUrl = SafeReturnUrl(returnUrl);
            if (IsEmbeddedMobileBrowser(http.Request.Headers.UserAgent.ToString()))
            {
                return Results.Redirect($"/_identity/login?returnUrl={Url(safeReturnUrl)}&error={Url("Google 로그인은 카카오톡/네이버앱 같은 앱 내부 브라우저에서 차단됩니다. 오른쪽 위 메뉴에서 '브라우저로 열기'를 선택한 뒤 다시 시도해 주세요. Naver/Kakao 로그인은 현재 화면에서도 사용할 수 있습니다.")}");
            }

            return Results.Challenge(
                new AuthenticationProperties { RedirectUri = safeReturnUrl },
                new[] { GoogleDefaults.AuthenticationScheme });
        });

        endpoints.MapGet("/signin/naver", (HttpContext http, string? returnUrl) =>
            Results.Challenge(
                new AuthenticationProperties { RedirectUri = SafeReturnUrl(returnUrl) },
                new[] { NaverAuthenticationDefaults.AuthenticationScheme }));

        endpoints.MapGet("/signin/kakao", (HttpContext http, string? returnUrl) =>
            Results.Challenge(
                new AuthenticationProperties { RedirectUri = SafeReturnUrl(returnUrl) },
                new[] { "Kakao" }));

        endpoints.MapGet("/_identity/account", async (HttpContext http, IUserStore userStore, string? returnUrl, string? message, string? error) =>
            await HandleAccountPageAsync(http, userStore, returnUrl, message, error, "/_identity").ConfigureAwait(false));

        endpoints.MapGet("/account", async (HttpContext http, IUserStore userStore, string? returnUrl, string? message, string? error) =>
            await HandleAccountPageAsync(http, userStore, returnUrl, message, error, string.Empty).ConfigureAwait(false));

        endpoints.MapGet("/_identity/consent", async (HttpContext http, IUserStore userStore, string? returnUrl, string? error) =>
            await HandleConsentPageAsync(http, userStore, returnUrl, error, "/_identity").ConfigureAwait(false));

        endpoints.MapGet("/consent", async (HttpContext http, IUserStore userStore, string? returnUrl, string? error) =>
            await HandleConsentPageAsync(http, userStore, returnUrl, error, string.Empty).ConfigureAwait(false));

        endpoints.MapPost("/_identity/account", async (HttpContext http, IUserStore userStore) =>
            await HandleAccountPostAsync(http, userStore, "/_identity").ConfigureAwait(false));

        endpoints.MapPost("/account", async (HttpContext http, IUserStore userStore) =>
            await HandleAccountPostAsync(http, userStore, string.Empty).ConfigureAwait(false));

        endpoints.MapPost("/_identity/consent", async (HttpContext http, IUserStore userStore) =>
            await HandleConsentPostAsync(http, userStore, "/_identity").ConfigureAwait(false));

        endpoints.MapPost("/consent", async (HttpContext http, IUserStore userStore) =>
            await HandleConsentPostAsync(http, userStore, string.Empty).ConfigureAwait(false));

        endpoints.MapGet("/_identity/signout", async (HttpContext http, string? returnUrl) =>
        {
            await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Results.Redirect(SafeReturnUrl(returnUrl));
        });

        endpoints.MapGet("/signout", async (HttpContext http, string? returnUrl) =>
        {
            await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Results.Redirect(SafeReturnUrl(returnUrl));
        });
    }

    /// <summary>
    /// \if KO
    /// <para>로컬 로그인 폼을 읽고 사용자를 검증하여 쿠키 로그인 또는 오류 리디렉션을 반환합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Reads a local-login form, validates the user, and returns a cookie sign-in or error redirect.</para>
    /// \endif
    /// </summary>
    /// <param name="http">
    /// \if KO
    /// <para>현재 HTTP 컨텍스트입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The current HTTP context.</para>
    /// \endif
    /// </param>
    /// <param name="userStore">
    /// \if KO
    /// <para>사용자 저장소입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The user store.</para>
    /// \endif
    /// </param>
    /// <param name="routePrefix">
    /// \if KO
    /// <para>인증 경로 접두사입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The authentication route prefix.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>로그인 결과입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The login result.</para>
    /// \endif
    /// </returns>
    private static async Task<IResult> HandleLocalLoginAsync(HttpContext http, IUserStore userStore, string routePrefix)
    {
        var loginPath = $"{routePrefix}/login";
        var form = await http.Request.ReadFormAsync(http.RequestAborted).ConfigureAwait(false);
        var returnUrl = SafeReturnUrl(form["returnUrl"]);
        var email = form["email"].ToString();
        var password = form["password"].ToString();

        var user = await userStore.ValidateLocalAsync(email, password, http.RequestAborted)
            .ConfigureAwait(false);
        if (user is null)
        {
            return Results.Redirect($"{loginPath}?returnUrl={Url(returnUrl)}&error={Url("직접 회원가입한 이메일/비밀번호가 올바르지 않습니다. Google, Naver, Kakao 계정은 아래 소셜 로그인 버튼을 사용해 주세요.")}");
        }

        await SignInAsync(http, user).ConfigureAwait(false);
        return Results.Redirect(returnUrl);
    }

    /// <summary>
    /// \if KO
    /// <para>가입 폼의 필수 동의와 비밀번호 확인을 검증하고 로컬 계정을 생성합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Validates required consents and password confirmation in a signup form, then creates a local account.</para>
    /// \endif
    /// </summary>
    /// <param name="http">
    /// \if KO
    /// <para>현재 HTTP 컨텍스트입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The current HTTP context.</para>
    /// \endif
    /// </param>
    /// <param name="userStore">
    /// \if KO
    /// <para>사용자 저장소입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The user store.</para>
    /// \endif
    /// </param>
    /// <param name="routePrefix">
    /// \if KO
    /// <para>인증 경로 접두사입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The authentication route prefix.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>가입, 로그인 또는 오류 리디렉션 결과입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The signup, sign-in, or error-redirect result.</para>
    /// \endif
    /// </returns>
    private static async Task<IResult> HandleSignupAsync(HttpContext http, IUserStore userStore, string routePrefix)
    {
        var loginPath = $"{routePrefix}/login";
        var form = await http.Request.ReadFormAsync(http.RequestAborted).ConfigureAwait(false);
        var returnUrl = SafeReturnUrl(form["returnUrl"]);
        var email = form["email"].ToString();
        var displayName = form["displayName"].ToString();
        var password = form["password"].ToString();
        var confirmPassword = form["confirmPassword"].ToString();

        if (!HasAcceptedRequiredSignupConsents(form))
        {
            return Results.Redirect($"{loginPath}?mode=signup&returnUrl={Url(returnUrl)}&error={Url("필수 약관, 개인정보처리방침, 만 14세 이상 확인에 모두 동의해야 가입할 수 있습니다.")}");
        }

        if (!string.Equals(password, confirmPassword, StringComparison.Ordinal))
        {
            return Results.Redirect($"{loginPath}?mode=signup&returnUrl={Url(returnUrl)}&error={Url("비밀번호 확인이 일치하지 않습니다.")}");
        }

        try
        {
            var user = await userStore.CreateLocalAsync(email, displayName, password, http.RequestAborted)
                .ConfigureAwait(false);
            user = await userStore.AcceptRequiredConsentsAsync(user.Id, DateTime.UtcNow, http.RequestAborted)
                .ConfigureAwait(false) ?? user;
            await SignInAsync(http, user).ConfigureAwait(false);
            return Results.Redirect(returnUrl);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return Results.Redirect($"{loginPath}?mode=signup&returnUrl={Url(returnUrl)}&error={Url(ex.Message)}");
        }
    }

    /// <summary>
    /// \if KO
    /// <para>현재 사용자를 조회하여 계정 페이지를 반환하거나 로그인을 요구합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Loads the current user and returns the account page or requires login.</para>
    /// \endif
    /// </summary>
    /// <param name="http">
    /// \if KO
    /// <para>현재 HTTP 컨텍스트입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The current HTTP context.</para>
    /// \endif
    /// </param>
    /// <param name="userStore">
    /// \if KO
    /// <para>사용자 저장소입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The user store.</para>
    /// \endif
    /// </param>
    /// <param name="returnUrl">
    /// \if KO
    /// <para>계정 화면에서 돌아갈 URL입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The URL to return to from the account page.</para>
    /// \endif
    /// </param>
    /// <param name="message">
    /// \if KO
    /// <para>선택적 성공 메시지입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The optional success message.</para>
    /// \endif
    /// </param>
    /// <param name="error">
    /// \if KO
    /// <para>선택적 오류 메시지입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The optional error message.</para>
    /// \endif
    /// </param>
    /// <param name="routePrefix">
    /// \if KO
    /// <para>인증 경로 접두사입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The authentication route prefix.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>계정 HTML 또는 리디렉션 결과입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The account HTML or redirect result.</para>
    /// \endif
    /// </returns>
    private static async Task<IResult> HandleAccountPageAsync(
        HttpContext http,
        IUserStore userStore,
        string? returnUrl,
        string? message,
        string? error,
        string routePrefix)
    {
        var loginPath = $"{routePrefix}/login";
        var accountPath = $"{routePrefix}/account";
        var userId = GetCurrentUserId(http);
        if (userId is null)
        {
            return Results.Redirect($"{loginPath}?returnUrl={Url(accountPath)}");
        }

        var user = await userStore.GetByIdAsync(userId.Value, http.RequestAborted).ConfigureAwait(false);
        if (user is null)
        {
            await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme).ConfigureAwait(false);
            return Results.Redirect($"{loginPath}?returnUrl={Url(accountPath)}");
        }

        return Results.Content(
            BuildAccountHtml(user, SafeReturnUrl(returnUrl), message, error, routePrefix),
            "text/html; charset=utf-8");
    }

    /// <summary>
    /// \if KO
    /// <para>계정 폼에서 표시 이름 또는 로컬 비밀번호 변경 요청을 처리합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Handles a display-name or local-password change submitted from the account form.</para>
    /// \endif
    /// </summary>
    /// <param name="http">
    /// \if KO
    /// <para>현재 HTTP 컨텍스트입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The current HTTP context.</para>
    /// \endif
    /// </param>
    /// <param name="userStore">
    /// \if KO
    /// <para>사용자 저장소입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The user store.</para>
    /// \endif
    /// </param>
    /// <param name="routePrefix">
    /// \if KO
    /// <para>인증 경로 접두사입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The authentication route prefix.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>계정 갱신 또는 오류 리디렉션 결과입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The account-update or error-redirect result.</para>
    /// \endif
    /// </returns>
    private static async Task<IResult> HandleAccountPostAsync(HttpContext http, IUserStore userStore, string routePrefix)
    {
        var loginPath = $"{routePrefix}/login";
        var accountPath = $"{routePrefix}/account";
        var userId = GetCurrentUserId(http);
        if (userId is null)
        {
            return Results.Redirect($"{loginPath}?returnUrl={Url(accountPath)}");
        }

        var form = await http.Request.ReadFormAsync(http.RequestAborted).ConfigureAwait(false);
        var returnUrl = SafeReturnUrl(form["returnUrl"]);
        var accountAction = form["accountAction"].ToString();

        try
        {
            AuthUser? user;
            string message;
            if (string.Equals(accountAction, "password", StringComparison.OrdinalIgnoreCase))
            {
                var currentPassword = form["currentPassword"].ToString();
                var newPassword = form["newPassword"].ToString();
                var confirmPassword = form["confirmPassword"].ToString();

                if (!string.Equals(newPassword, confirmPassword, StringComparison.Ordinal))
                {
                    return Results.Redirect($"{accountPath}?returnUrl={Url(returnUrl)}&error={Url("새 비밀번호 확인이 일치하지 않습니다.")}");
                }

                user = await userStore.ChangeLocalPasswordAsync(
                        userId.Value,
                        currentPassword,
                        newPassword,
                        http.RequestAborted)
                    .ConfigureAwait(false);
                message = "비밀번호가 변경되었습니다.";
            }
            else
            {
                var displayName = form["displayName"].ToString();
                user = await userStore.UpdateDisplayNameAsync(userId.Value, displayName, http.RequestAborted)
                    .ConfigureAwait(false);
                message = "계정 정보가 저장되었습니다.";
            }

            if (user is null)
            {
                await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme).ConfigureAwait(false);
                return Results.Redirect($"{loginPath}?returnUrl={Url(accountPath)}");
            }

            await SignInAsync(http, user).ConfigureAwait(false);
            return Results.Redirect($"{accountPath}?returnUrl={Url(returnUrl)}&message={Url(message)}");
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return Results.Redirect($"{accountPath}?returnUrl={Url(returnUrl)}&error={Url(ex.Message)}");
        }
    }

    /// <summary>
    /// \if KO
    /// <para>현재 사용자의 필수 동의를 확인하고 필요할 때 동의 페이지를 반환합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Checks the current user's required consents and returns the consent page when needed.</para>
    /// \endif
    /// </summary>
    /// <param name="http">
    /// \if KO
    /// <para>현재 HTTP 컨텍스트입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The current HTTP context.</para>
    /// \endif
    /// </param>
    /// <param name="userStore">
    /// \if KO
    /// <para>사용자 저장소입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The user store.</para>
    /// \endif
    /// </param>
    /// <param name="returnUrl">
    /// \if KO
    /// <para>동의 후 이동할 URL입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The URL to visit after consent.</para>
    /// \endif
    /// </param>
    /// <param name="error">
    /// \if KO
    /// <para>선택적 오류 메시지입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The optional error message.</para>
    /// \endif
    /// </param>
    /// <param name="routePrefix">
    /// \if KO
    /// <para>인증 경로 접두사입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The authentication route prefix.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>동의 HTML 또는 리디렉션 결과입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The consent HTML or redirect result.</para>
    /// \endif
    /// </returns>
    private static async Task<IResult> HandleConsentPageAsync(
        HttpContext http,
        IUserStore userStore,
        string? returnUrl,
        string? error,
        string routePrefix)
    {
        var loginPath = $"{routePrefix}/login";
        var userId = GetCurrentUserId(http);
        if (userId is null)
        {
            return Results.Redirect($"{loginPath}?returnUrl={Url($"{routePrefix}/consent")}");
        }

        var user = await userStore.GetByIdAsync(userId.Value, http.RequestAborted).ConfigureAwait(false);
        if (user is null)
        {
            await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme).ConfigureAwait(false);
            return Results.Redirect($"{loginPath}?returnUrl={Url($"{routePrefix}/consent")}");
        }

        var safeReturnUrl = SafeReturnUrl(returnUrl);
        if (RequiredConsentPolicy.HasRequiredConsents(user))
        {
            return Results.Redirect(safeReturnUrl);
        }

        return Results.Content(
            BuildConsentHtml(safeReturnUrl, error, routePrefix),
            "text/html; charset=utf-8");
    }

    /// <summary>
    /// \if KO
    /// <para>제출된 필수 동의를 검증하고 사용자 레코드 및 로그인 쿠키를 갱신합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Validates submitted required consents and updates the user record and login cookie.</para>
    /// \endif
    /// </summary>
    /// <param name="http">
    /// \if KO
    /// <para>현재 HTTP 컨텍스트입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The current HTTP context.</para>
    /// \endif
    /// </param>
    /// <param name="userStore">
    /// \if KO
    /// <para>사용자 저장소입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The user store.</para>
    /// \endif
    /// </param>
    /// <param name="routePrefix">
    /// \if KO
    /// <para>인증 경로 접두사입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The authentication route prefix.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>동의 처리 또는 리디렉션 결과입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The consent-processing or redirect result.</para>
    /// \endif
    /// </returns>
    private static async Task<IResult> HandleConsentPostAsync(HttpContext http, IUserStore userStore, string routePrefix)
    {
        var loginPath = $"{routePrefix}/login";
        var consentPath = $"{routePrefix}/consent";
        var userId = GetCurrentUserId(http);
        if (userId is null)
        {
            return Results.Redirect($"{loginPath}?returnUrl={Url(consentPath)}");
        }

        var form = await http.Request.ReadFormAsync(http.RequestAborted).ConfigureAwait(false);
        var returnUrl = SafeReturnUrl(form["returnUrl"]);
        if (!HasAcceptedRequiredSignupConsents(form))
        {
            return Results.Redirect($"{consentPath}?returnUrl={Url(returnUrl)}&error={Url("필수 항목에 모두 동의해야 서비스를 계속 이용할 수 있습니다.")}");
        }

        var user = await userStore.AcceptRequiredConsentsAsync(userId.Value, DateTime.UtcNow, http.RequestAborted)
            .ConfigureAwait(false);
        if (user is null)
        {
            await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme).ConfigureAwait(false);
            return Results.Redirect($"{loginPath}?returnUrl={Url(consentPath)}");
        }

        await SignInAsync(http, user).ConfigureAwait(false);
        return Results.Redirect(returnUrl);
    }

    /// <summary>
    /// \if KO
    /// <para>오픈 리디렉션을 막기 위해 로컬 경로 또는 허용된 CodeMaru/개발 호스트 URL만 반환합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Prevents open redirects by accepting only local paths or allowed CodeMaru and development-host URLs.</para>
    /// \endif
    /// </summary>
    /// <param name="returnUrl">
    /// \if KO
    /// <para>검증할 반환 URL입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The return URL to validate.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>안전한 반환 URL이며 유효하지 않으면 루트 경로입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The safe return URL, or the root path when invalid.</para>
    /// \endif
    /// </returns>
    private static string SafeReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl))
        {
            return "/";
        }

        // Open-redirect 방지:
        // - 같은 앱 내부 이동은 로컬 경로만 허용
        // - 중앙 로그인 포털에서 서브 서비스로 돌아갈 수 있도록 codemaru.co.kr 계열만 절대 URL 허용
        if (returnUrl.StartsWith("/", StringComparison.Ordinal)
            && !returnUrl.StartsWith("//", StringComparison.Ordinal))
        {
            return returnUrl;
        }

        if (!Uri.TryCreate(returnUrl, UriKind.Absolute, out var uri)
            || uri.Scheme is not ("https" or "http"))
        {
            return "/";
        }

        return IsAllowedReturnHost(uri.Host) ? uri.ToString() : "/";
    }

    /// <summary>
    /// \if KO
    /// <para>호스트가 CodeMaru 도메인 또는 허용된 로컬 개발 호스트인지 확인합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Determines whether a host is a CodeMaru domain or an allowed local development host.</para>
    /// \endif
    /// </summary>
    /// <param name="host">
    /// \if KO
    /// <para>검사할 호스트 이름입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The host name to inspect.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>허용된 호스트이면 <see langword="true"/>입니다.</para>
    /// \endif
    /// \if EN
    /// <para><see langword="true"/> for an allowed host.</para>
    /// \endif
    /// </returns>
    private static bool IsAllowedReturnHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return false;
        }

        return string.Equals(host, "codemaru.co.kr", StringComparison.OrdinalIgnoreCase)
               || host.EndsWith(".codemaru.co.kr", StringComparison.OrdinalIgnoreCase)
               || string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
               || string.Equals(host, "127.0.0.1", StringComparison.OrdinalIgnoreCase)
               || string.Equals(host, "::1", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// \if KO
    /// <para>사용자 프로필과 내부 식별 클레임으로 지속 인증 쿠키를 발급합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Issues a persistent authentication cookie with profile and internal-identity claims.</para>
    /// \endif
    /// </summary>
    /// <param name="http">
    /// \if KO
    /// <para>쿠키를 발급할 HTTP 컨텍스트입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The HTTP context receiving the cookie.</para>
    /// \endif
    /// </param>
    /// <param name="user">
    /// \if KO
    /// <para>로그인할 사용자입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The user to sign in.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>쿠키 로그인 작업입니다.</para>
    /// \endif
    /// \if EN
    /// <para>A task representing cookie sign-in.</para>
    /// \endif
    /// </returns>
    private static async Task SignInAsync(HttpContext http, AuthUser user)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.ProviderKey),
            new(ClaimTypes.Email, user.Email),
            new(ClaimTypes.Name, user.DisplayName),
            new(DreamineIdentityExtensions.UserIdClaimType, user.Id.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new(DreamineIdentityExtensions.ProviderClaimType, user.Provider)
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);
        await http.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            new AuthenticationProperties { IsPersistent = true }).ConfigureAwait(false);
    }

    /// <summary>
    /// \if KO
    /// <para>현재 사용자 클레임에서 내부 사용자 ID를 읽습니다.</para>
    /// \endif
    /// \if EN
    /// <para>Reads the internal user ID from the current user's claims.</para>
    /// \endif
    /// </summary>
    /// <param name="http">
    /// \if KO
    /// <para>현재 HTTP 컨텍스트입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The current HTTP context.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>파싱된 사용자 ID 또는 없으면 <see langword="null"/>입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The parsed user ID, or <see langword="null"/> when absent.</para>
    /// \endif
    /// </returns>
    private static long? GetCurrentUserId(HttpContext http)
    {
        var value = http.User.FindFirstValue(DreamineIdentityExtensions.UserIdClaimType);
        return long.TryParse(
            value,
            System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture,
            out var id)
            ? id
            : null;
    }

    /// <summary>
    /// \if KO
    /// <para>가입 폼의 세 필수 동의 확인란이 모두 선택되었는지 확인합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Determines whether all three required consent checkboxes are selected in a signup form.</para>
    /// \endif
    /// </summary>
    /// <param name="form">
    /// \if KO
    /// <para>검사할 가입 폼입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The signup form to inspect.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>모두 선택되었으면 <see langword="true"/>입니다.</para>
    /// \endif
    /// \if EN
    /// <para><see langword="true"/> when all are selected.</para>
    /// \endif
    /// </returns>
    private static bool HasAcceptedRequiredSignupConsents(IFormCollection form) =>
        IsChecked(form["termsAccepted"]) &&
        IsChecked(form["privacyAccepted"]) &&
        IsChecked(form["ageConfirmed"]);

    /// <summary>
    /// \if KO
    /// <para>폼 값이 일반적인 선택 상태 표현인지 확인합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Determines whether a form value represents a common checked state.</para>
    /// \endif
    /// </summary>
    /// <param name="value">
    /// \if KO
    /// <para>폼 값입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The form value.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>true, on 또는 1이면 <see langword="true"/>입니다.</para>
    /// \endif
    /// \if EN
    /// <para><see langword="true"/> for true, on, or 1.</para>
    /// \endif
    /// </returns>
    private static bool IsChecked(string? value) =>
        string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(value, "on", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(value, "1", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// \if KO
    /// <para>로그인 또는 가입 모드의 독립 실행형 HTML 문서를 만듭니다.</para>
    /// \endif
    /// \if EN
    /// <para>Builds a standalone HTML document in login or signup mode.</para>
    /// \endif
    /// </summary>
    /// <param name="returnUrl">
    /// \if KO
    /// <para>인증 후 이동할 안전한 URL입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The safe URL to visit after authentication.</para>
    /// \endif
    /// </param>
    /// <param name="mode">
    /// \if KO
    /// <para>signup이면 가입 화면을 선택하는 모드입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The mode selecting signup when equal to signup.</para>
    /// \endif
    /// </param>
    /// <param name="message">
    /// \if KO
    /// <para>선택적 안내 메시지입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The optional informational message.</para>
    /// \endif
    /// </param>
    /// <param name="error">
    /// \if KO
    /// <para>선택적 오류 메시지입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The optional error message.</para>
    /// \endif
    /// </param>
    /// <param name="routePrefix">
    /// \if KO
    /// <para>폼 작업 경로 접두사입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The form-action route prefix.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>완성된 로그인 또는 가입 HTML입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The completed login or signup HTML.</para>
    /// \endif
    /// </returns>
    private static string BuildLoginHtml(
        string returnUrl,
        string? mode,
        string? message,
        string? error,
        string routePrefix = "")
    {
        var isSignup = string.Equals(mode, "signup", StringComparison.OrdinalIgnoreCase);
        var title = isSignup ? "회원가입" : "로그인";
        var loginPath = $"{routePrefix}/login";
        var signupPath = $"{routePrefix}/signup";
        var action = isSignup ? signupPath : loginPath;
        var switchHref = isSignup
            ? $"{loginPath}?returnUrl={Url(returnUrl)}"
            : $"{loginPath}?mode=signup&returnUrl={Url(returnUrl)}";
        var switchText = isSignup ? "이미 계정이 있으신가요? 로그인" : "계정이 없으신가요? 회원가입";

        var builder = new StringBuilder();
        builder.Append($$"""
            <!DOCTYPE html>
            <html lang="ko">
            <head>
              <meta charset="utf-8" />
              <meta name="viewport" content="width=device-width, initial-scale=1" />
              <title>{{Html(title)}} | Dreamine Identity</title>
              <style>
                :root { color-scheme: dark; }
                * { box-sizing: border-box; }
                body {
                  margin: 0;
                  min-height: 100vh;
                  display: grid;
                  place-items: center;
                  font-family: "Segoe UI", Arial, sans-serif;
                  background: #0f172a;
                  color: #e5e7eb;
                }
                main {
                  width: min(420px, calc(100vw - 32px));
                  padding: 28px;
                  border: 1px solid rgba(148, 163, 184, .28);
                  border-radius: 8px;
                  background: #111827;
                  box-shadow: 0 24px 80px rgba(0, 0, 0, .36);
                }
                h1 { margin: 0 0 8px; font-size: 28px; letter-spacing: 0; }
                p { margin: 0 0 20px; color: #94a3b8; line-height: 1.5; }
                .form-hint { margin: 10px 0 0; color: #93c5fd; font-size: 13px; }
                label { display: block; margin: 14px 0 6px; color: #cbd5e1; font-size: 14px; }
                input {
                  width: 100%;
                  height: 44px;
                  padding: 0 12px;
                  border: 1px solid #334155;
                  border-radius: 6px;
                  background: #0b1220;
                  color: #f8fafc;
                  font-size: 15px;
                }
                input[type="checkbox"] {
                  width: 18px;
                  height: 18px;
                  flex: 0 0 auto;
                  padding: 0;
                  accent-color: #93c5fd;
                }
                .consents {
                  display: grid;
                  gap: 10px;
                  margin-top: 16px;
                  padding: 12px;
                  border: 1px solid #334155;
                  border-radius: 6px;
                  background: #0b1220;
                }
                .consent-row {
                  display: flex;
                  align-items: flex-start;
                  gap: 10px;
                  margin: 0;
                  line-height: 1.45;
                }
                .consent-row a { color: #93c5fd; }
                button, .social, .switch {
                  display: flex;
                  width: 100%;
                  height: 44px;
                  align-items: center;
                  justify-content: center;
                  gap: 8px;
                  border-radius: 6px;
                  text-decoration: none;
                  font-weight: 700;
                }
                button {
                  margin-top: 18px;
                  border: 0;
                  background: #e5e7eb;
                  color: #0f172a;
                  cursor: pointer;
                }
                .divider { display: flex; align-items: center; gap: 12px; margin: 22px 0; color: #64748b; }
                .divider::before, .divider::after { content: ""; height: 1px; flex: 1; background: #334155; }
                .socials { display: grid; gap: 10px; }
                .social.google { border: 1px solid #ef4444; color: #f8fafc; }
                .social.naver { border: 1px solid #10b981; color: #f8fafc; }
                .social.kakao { border: 1px solid #facc15; color: #fde047; }
                .browser-warning {
                  display: none;
                  margin: 0 0 12px;
                  padding: 12px;
                  border: 1px solid rgba(250, 204, 21, .38);
                  border-radius: 8px;
                  background: rgba(250, 204, 21, .10);
                  color: #fde68a;
                  font-size: 13px;
                  line-height: 1.55;
                }
                .browser-warning strong { color: #fef3c7; }
                body.embedded-browser .browser-warning { display: block; }
                .external-browser-actions {
                  display: none;
                  grid-template-columns: 1fr 1fr;
                  gap: 8px;
                  margin-top: 10px;
                }
                body.embedded-browser .external-browser-actions { display: grid; }
                .external-open {
                  display: flex;
                  min-height: 38px;
                  align-items: center;
                  justify-content: center;
                  padding: 8px 10px;
                  border: 1px solid rgba(147, 197, 253, .35);
                  border-radius: 6px;
                  color: #bfdbfe;
                  font-size: 13px;
                  font-weight: 700;
                  text-decoration: none;
                }
                body.embedded-browser .social.google {
                  opacity: .55;
                  border-color: rgba(239, 68, 68, .35);
                }
                .switch { margin-top: 16px; color: #93c5fd; font-weight: 600; }
                .message, .error {
                  padding: 10px 12px;
                  border-radius: 6px;
                  margin: 14px 0;
                  line-height: 1.45;
                }
                .message { background: rgba(14, 165, 233, .12); color: #bae6fd; }
                .error { background: rgba(239, 68, 68, .14); color: #fecaca; }
              </style>
            </head>
            <body>
              <main>
                <h1>{{Html(title)}}</h1>
                <p>하나의 계정으로 CodeMaru 및 Dreamine 계열 서비스를 이용합니다.</p>
            """);

        if (!string.IsNullOrWhiteSpace(message))
        {
            builder.Append($"""<div class="message">{Html(message)}</div>""");
        }

        if (!string.IsNullOrWhiteSpace(error))
        {
            builder.Append($"""<div class="error">{Html(error)}</div>""");
        }

        builder.Append($$"""
                <form method="post" action="{{action}}">
                  <input type="hidden" name="returnUrl" value="{{Html(returnUrl)}}" />
            """);

        if (isSignup)
        {
            builder.Append("""
                  <label for="displayName">이름</label>
                  <input id="displayName" name="displayName" autocomplete="name" />
                """);
        }

        builder.Append("""
                  <label for="email">이메일</label>
                  <input id="email" name="email" type="email" autocomplete="email" required />
                  <label for="password">비밀번호</label>
                  <input id="password" name="password" type="password" autocomplete="current-password" required minlength="8" />
                  <p class="form-hint">Google, Naver, Kakao로 가입한 계정은 아래 소셜 로그인 버튼을 사용하세요.</p>
            """);

        if (isSignup)
        {
            builder.Append($$"""
                  <label for="confirmPassword">비밀번호 확인</label>
                  <input id="confirmPassword" name="confirmPassword" type="password" autocomplete="new-password" required minlength="8" />
                  <div class="consents">
                    <label class="consent-row">
                      <input type="checkbox" name="termsAccepted" value="true" required />
                      <span><a href="/terms" target="_blank" rel="noopener">이용약관</a>에 동의합니다.</span>
                    </label>
                    <label class="consent-row">
                      <input type="checkbox" name="privacyAccepted" value="true" required />
                      <span><a href="/privacy" target="_blank" rel="noopener">개인정보처리방침</a>을 확인했고 개인정보 수집·이용에 동의합니다.</span>
                    </label>
                    <label class="consent-row">
                      <input type="checkbox" name="ageConfirmed" value="true" required />
                      <span>만 14세 이상입니다. 만 14세 미만은 법정대리인 동의 절차 확인 전 온라인 가입을 진행할 수 없습니다.</span>
                    </label>
                  </div>
                """);
        }

        builder.Append($$"""
                  <button type="submit">{{Html(title)}}</button>
                </form>
                <a class="switch" href="{{switchHref}}">{{Html(switchText)}}</a>
                <div class="divider">또는</div>
                <div class="browser-warning">
                  <strong>Google 로그인 안내</strong><br />
                  지금 화면이 앱 내부 브라우저라면 Google 로그인이 차단될 수 있습니다.
                  오른쪽 위 메뉴에서 <strong>브라우저로 열기</strong>를 선택한 뒤 Google 로그인을 다시 시도해 주세요.
                  <div class="external-browser-actions">
                    <a class="external-open" id="openChrome" href="#">Chrome으로 열기</a>
                    <a class="external-open" id="openSamsung" href="#">삼성인터넷으로 열기</a>
                  </div>
                </div>
                <div class="socials">
                  <a class="social google" id="googleLoginLink" href="/signin/google?returnUrl={{Url(returnUrl)}}">G Google</a>
                  <a class="social naver" href="/signin/naver?returnUrl={{Url(returnUrl)}}">N Naver</a>
                  <a class="social kakao" href="/signin/kakao?returnUrl={{Url(returnUrl)}}">Kakao</a>
                </div>
              </main>
              <script>
                (function () {
                  var ua = navigator.userAgent || "";
                  var isEmbedded =
                    /KAKAOTALK|NAVER\(inapp|FBAN|FBAV|Instagram|Line\//i.test(ua) ||
                    (/\bwv\b/i.test(ua) && /Android/i.test(ua));
                  if (!isEmbedded) return;

                  document.body.classList.add("embedded-browser");
                  var current = window.location.href;
                  var withoutScheme = current.replace(/^https?:\/\//i, "");
                  var chrome = document.getElementById("openChrome");
                  var samsung = document.getElementById("openSamsung");
                  if (chrome) {
                    chrome.href = "intent://" + withoutScheme + "#Intent;scheme=https;package=com.android.chrome;end";
                  }
                  if (samsung) {
                    samsung.href = "intent://" + withoutScheme + "#Intent;scheme=https;package=com.sec.android.app.sbrowser;end";
                  }

                  var google = document.getElementById("googleLoginLink");
                  if (!google) return;

                  google.addEventListener("click", function (event) {
                    event.preventDefault();
                    alert("Google 로그인은 현재 앱 내부 브라우저에서 차단될 수 있습니다. 오른쪽 위 메뉴에서 '브라우저로 열기'를 선택한 뒤 다시 시도해 주세요.");
                  });
                })();
              </script>
            </body>
            </html>
            """);

        return builder.ToString();
    }

    /// <summary>
    /// \if KO
    /// <para>이용약관, 개인정보 및 연령 확인 입력을 포함한 필수 동의 HTML을 만듭니다.</para>
    /// \endif
    /// \if EN
    /// <para>Builds required-consent HTML containing terms, privacy, and age-confirmation inputs.</para>
    /// \endif
    /// </summary>
    /// <param name="returnUrl">
    /// \if KO
    /// <para>동의 후 이동할 안전한 URL입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The safe URL to visit after consent.</para>
    /// \endif
    /// </param>
    /// <param name="error">
    /// \if KO
    /// <para>선택적 오류 메시지입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The optional error message.</para>
    /// \endif
    /// </param>
    /// <param name="routePrefix">
    /// \if KO
    /// <para>폼 작업 경로 접두사입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The form-action route prefix.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>완성된 동의 HTML입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The completed consent HTML.</para>
    /// \endif
    /// </returns>
    private static string BuildConsentHtml(string returnUrl, string? error, string routePrefix)
    {
        var consentPath = $"{routePrefix}/consent";
        var builder = new StringBuilder();
        builder.Append($$"""
            <!DOCTYPE html>
            <html lang="ko">
            <head>
              <meta charset="utf-8" />
              <meta name="viewport" content="width=device-width, initial-scale=1" />
              <title>필수 동의 | Dreamine Identity</title>
              <style>
                :root { color-scheme: dark; }
                * { box-sizing: border-box; }
                body {
                  margin: 0;
                  min-height: 100vh;
                  display: grid;
                  place-items: center;
                  font-family: "Segoe UI", Arial, sans-serif;
                  background: #0f172a;
                  color: #e5e7eb;
                }
                main {
                  width: min(480px, calc(100vw - 32px));
                  padding: 28px;
                  border: 1px solid rgba(148, 163, 184, .28);
                  border-radius: 8px;
                  background: #111827;
                  box-shadow: 0 24px 80px rgba(0, 0, 0, .36);
                }
                h1 { margin: 0 0 8px; font-size: 28px; letter-spacing: 0; }
                p { margin: 0 0 20px; color: #94a3b8; line-height: 1.5; }
                .error {
                  padding: 10px 12px;
                  border-radius: 6px;
                  margin: 14px 0;
                  background: rgba(239, 68, 68, .14);
                  color: #fecaca;
                  line-height: 1.45;
                }
                .consents {
                  display: grid;
                  gap: 12px;
                  margin-top: 16px;
                  padding: 14px;
                  border: 1px solid #334155;
                  border-radius: 6px;
                  background: #0b1220;
                }
                label {
                  display: flex;
                  align-items: flex-start;
                  gap: 10px;
                  line-height: 1.45;
                  color: #dbeafe;
                }
                input[type="checkbox"] {
                  width: 18px;
                  height: 18px;
                  flex: 0 0 auto;
                  accent-color: #93c5fd;
                }
                a { color: #93c5fd; }
                button {
                  display: flex;
                  width: 100%;
                  height: 44px;
                  align-items: center;
                  justify-content: center;
                  margin-top: 18px;
                  border: 0;
                  border-radius: 6px;
                  background: #e5e7eb;
                  color: #0f172a;
                  cursor: pointer;
                  font-weight: 700;
                }
              </style>
            </head>
            <body>
              <main>
                <h1>필수 동의</h1>
                <p>CodeMaru 및 Dreamine 계열 서비스를 계속 이용하려면 아래 항목을 확인해 주세요.</p>
            """);

        if (!string.IsNullOrWhiteSpace(error))
        {
            builder.Append($"""<div class="error">{Html(error)}</div>""");
        }

        builder.Append($$"""
                <form method="post" action="{{consentPath}}">
                  <input type="hidden" name="returnUrl" value="{{Html(returnUrl)}}" />
                  <div class="consents">
                    <label>
                      <input type="checkbox" name="termsAccepted" value="true" required />
                      <span><a href="/terms" target="_blank" rel="noopener">이용약관</a>에 동의합니다.</span>
                    </label>
                    <label>
                      <input type="checkbox" name="privacyAccepted" value="true" required />
                      <span><a href="/privacy" target="_blank" rel="noopener">개인정보처리방침</a>을 확인했고 개인정보 수집·이용에 동의합니다.</span>
                    </label>
                    <label>
                      <input type="checkbox" name="ageConfirmed" value="true" required />
                      <span>만 14세 이상입니다. 만 14세 미만은 법정대리인 동의 절차 확인 전 온라인 가입을 진행할 수 없습니다.</span>
                    </label>
                  </div>
                  <button type="submit">동의하고 계속</button>
                </form>
              </main>
            </body>
            </html>
            """);

        return builder.ToString();
    }

    /// <summary>
    /// \if KO
    /// <para>사용자 프로필과 로그인 방식에 맞는 계정 관리 HTML을 만듭니다.</para>
    /// \endif
    /// \if EN
    /// <para>Builds account-management HTML appropriate for the user's profile and login method.</para>
    /// \endif
    /// </summary>
    /// <param name="user">
    /// \if KO
    /// <para>표시할 사용자입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The user to display.</para>
    /// \endif
    /// </param>
    /// <param name="returnUrl">
    /// \if KO
    /// <para>계정 화면에서 돌아갈 안전한 URL입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The safe URL to return to from the account page.</para>
    /// \endif
    /// </param>
    /// <param name="message">
    /// \if KO
    /// <para>선택적 성공 메시지입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The optional success message.</para>
    /// \endif
    /// </param>
    /// <param name="error">
    /// \if KO
    /// <para>선택적 오류 메시지입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The optional error message.</para>
    /// \endif
    /// </param>
    /// <param name="routePrefix">
    /// \if KO
    /// <para>폼 및 링크 경로 접두사입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The form and link route prefix.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>완성된 계정 HTML입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The completed account HTML.</para>
    /// \endif
    /// </returns>
    private static string BuildAccountHtml(
        AuthUser user,
        string returnUrl,
        string? message,
        string? error,
        string routePrefix = "")
    {
        var accountPath = $"{routePrefix}/account";
        var signoutPath = $"{routePrefix}/signout";
        var provider = string.IsNullOrWhiteSpace(user.Provider) ? "Unknown" : user.Provider;
        var email = string.IsNullOrWhiteSpace(user.Email) ? "제공되지 않음" : user.Email;
        var isLocal = string.Equals(user.Provider, LocalProvider, StringComparison.OrdinalIgnoreCase);
        var avatar = string.IsNullOrWhiteSpace(user.AvatarUrl)
            ? "<div class=\"avatar-fallback\">U</div>"
            : $"""<img class="avatar" src="{Html(user.AvatarUrl)}" alt="" />""";
        var passwordSection = isLocal
            ? $$"""
                <section>
                  <h2>비밀번호 변경</h2>
                  <form method="post" action="{{accountPath}}">
                    <input type="hidden" name="returnUrl" value="{{Html(returnUrl)}}" />
                    <input type="hidden" name="accountAction" value="password" />
                    <label for="currentPassword">현재 비밀번호</label>
                    <input id="currentPassword" name="currentPassword" type="password" autocomplete="current-password" required />
                    <label for="newPassword">새 비밀번호</label>
                    <input id="newPassword" name="newPassword" type="password" autocomplete="new-password" required minlength="8" />
                    <label for="confirmPassword">새 비밀번호 확인</label>
                    <input id="confirmPassword" name="confirmPassword" type="password" autocomplete="new-password" required minlength="8" />
                    <button type="submit">비밀번호 변경</button>
                  </form>
                </section>
                """
            : $$"""
                <section>
                  <h2>비밀번호</h2>
                  <p class="note">{{Html(provider)}} 로그인 계정은 CodeMaru에 별도 비밀번호가 없습니다. 비밀번호 변경은 해당 로그인 제공자에서 진행해 주세요.</p>
                </section>
                """;

        var builder = new StringBuilder();
        builder.Append($$"""
            <!DOCTYPE html>
            <html lang="ko">
            <head>
              <meta charset="utf-8" />
              <meta name="viewport" content="width=device-width, initial-scale=1" />
              <title>내 계정 | Dreamine Identity</title>
              <style>
                :root { color-scheme: dark; }
                * { box-sizing: border-box; }
                body {
                  margin: 0;
                  min-height: 100vh;
                  display: grid;
                  place-items: center;
                  font-family: "Segoe UI", Arial, sans-serif;
                  background: #0f172a;
                  color: #e5e7eb;
                }
                main {
                  width: min(480px, calc(100vw - 32px));
                  padding: 28px;
                  border: 1px solid rgba(148, 163, 184, .28);
                  border-radius: 8px;
                  background: #111827;
                  box-shadow: 0 24px 80px rgba(0, 0, 0, .36);
                }
                .head { display: flex; align-items: center; gap: 14px; margin-bottom: 18px; }
                .avatar, .avatar-fallback {
                  width: 54px;
                  height: 54px;
                  border-radius: 50%;
                  object-fit: cover;
                  display: grid;
                  place-items: center;
                  background: #1e293b;
                  color: #cbd5e1;
                  font-weight: 800;
                }
                h1 { margin: 0; font-size: 28px; letter-spacing: 0; }
                h2 { margin: 0 0 12px; font-size: 18px; letter-spacing: 0; }
                p { margin: 6px 0 0; color: #94a3b8; line-height: 1.5; }
                section { margin-top: 22px; padding-top: 20px; border-top: 1px solid #263244; }
                dl { display: grid; gap: 10px; margin: 20px 0; }
                div.row {
                  display: grid;
                  grid-template-columns: 110px minmax(0, 1fr);
                  gap: 12px;
                  padding: 10px 0;
                  border-bottom: 1px solid #263244;
                }
                dt { color: #94a3b8; }
                dd { margin: 0; overflow-wrap: anywhere; }
                label { display: block; margin: 16px 0 6px; color: #cbd5e1; font-size: 14px; }
                input {
                  width: 100%;
                  height: 44px;
                  padding: 0 12px;
                  border: 1px solid #334155;
                  border-radius: 6px;
                  background: #0b1220;
                  color: #f8fafc;
                  font-size: 15px;
                }
                .actions { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-top: 18px; }
                button, a.button {
                  display: flex;
                  height: 44px;
                  align-items: center;
                  justify-content: center;
                  border-radius: 6px;
                  text-decoration: none;
                  font-weight: 700;
                }
                button { border: 0; background: #e5e7eb; color: #0f172a; cursor: pointer; }
                a.button { border: 1px solid #334155; color: #e5e7eb; }
                form > button { width: 100%; margin-top: 18px; }
                .note {
                  padding: 12px;
                  border: 1px solid #334155;
                  border-radius: 6px;
                  background: #0b1220;
                }
                .message, .error {
                  padding: 10px 12px;
                  border-radius: 6px;
                  margin: 14px 0;
                  line-height: 1.45;
                }
                .message { background: rgba(14, 165, 233, .12); color: #bae6fd; }
                .error { background: rgba(239, 68, 68, .14); color: #fecaca; }
              </style>
            </head>
            <body>
              <main>
                <div class="head">
                  {{avatar}}
                  <div>
                    <h1>내 계정</h1>
                    <p>CodeMaru 및 Dreamine 계열 서비스에서 사용할 기본 정보를 관리합니다.</p>
                  </div>
                </div>
            """);

        if (!string.IsNullOrWhiteSpace(message))
        {
            builder.Append($"""<div class="message">{Html(message)}</div>""");
        }

        if (!string.IsNullOrWhiteSpace(error))
        {
            builder.Append($"""<div class="error">{Html(error)}</div>""");
        }

        builder.Append($$"""
                <dl>
                  <div class="row"><dt>로그인 방식</dt><dd>{{Html(provider)}}</dd></div>
                  <div class="row"><dt>이메일</dt><dd>{{Html(email)}}</dd></div>
                </dl>
                <form method="post" action="{{accountPath}}">
                  <input type="hidden" name="returnUrl" value="{{Html(returnUrl)}}" />
                  <input type="hidden" name="accountAction" value="profile" />
                  <label for="displayName">표시 이름</label>
                  <input id="displayName" name="displayName" autocomplete="name" required value="{{Html(user.DisplayName)}}" />
                  <div class="actions">
                    <button type="submit">저장</button>
                    <a class="button" href="{{Html(returnUrl)}}">돌아가기</a>
                    <a class="button" href="{{signoutPath}}?returnUrl={{Url(returnUrl)}}">로그아웃</a>
                  </div>
                </form>
                {{passwordSection}}
              </main>
            </body>
            </html>
            """);

        return builder.ToString();
    }

    /// <summary>
    /// \if KO
    /// <para>선택적 값을 HTML 텍스트 또는 특성에 안전하게 인코딩합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Safely HTML-encodes an optional value for text or attribute use.</para>
    /// \endif
    /// </summary>
    /// <param name="value">
    /// \if KO
    /// <para>인코딩할 값입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The value to encode.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>HTML 인코딩된 문자열입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The HTML-encoded string.</para>
    /// \endif
    /// </returns>
    private static string Html(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);

    /// <summary>
    /// \if KO
    /// <para>선택적 값을 URL 쿼리 구성 요소로 이스케이프합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Escapes an optional value for use as a URL query component.</para>
    /// \endif
    /// </summary>
    /// <param name="value">
    /// \if KO
    /// <para>이스케이프할 값입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The value to escape.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>URL 이스케이프된 문자열입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The URL-escaped string.</para>
    /// \endif
    /// </returns>
    private static string Url(string? value) => Uri.EscapeDataString(value ?? string.Empty);

    /// <summary>
    /// \if KO
    /// <para>사용자 에이전트가 알려진 모바일 앱 내부 브라우저인지 확인합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Determines whether a user agent belongs to a known embedded mobile-app browser.</para>
    /// \endif
    /// </summary>
    /// <param name="userAgent">
    /// \if KO
    /// <para>검사할 User-Agent 헤더 값입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The User-Agent header value to inspect.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>알려진 앱 내부 브라우저이면 <see langword="true"/>입니다.</para>
    /// \endif
    /// \if EN
    /// <para><see langword="true"/> for a known embedded app browser.</para>
    /// \endif
    /// </returns>
    private static bool IsEmbeddedMobileBrowser(string userAgent)
    {
        if (string.IsNullOrWhiteSpace(userAgent))
        {
            return false;
        }

        return userAgent.Contains("KAKAOTALK", StringComparison.OrdinalIgnoreCase)
               || userAgent.Contains("NAVER(inapp", StringComparison.OrdinalIgnoreCase)
               || userAgent.Contains("FBAN", StringComparison.OrdinalIgnoreCase)
               || userAgent.Contains("FBAV", StringComparison.OrdinalIgnoreCase)
               || userAgent.Contains("Instagram", StringComparison.OrdinalIgnoreCase)
               || userAgent.Contains("Line/", StringComparison.OrdinalIgnoreCase)
               || (userAgent.Contains("; wv)", StringComparison.OrdinalIgnoreCase)
                   && userAgent.Contains("Android", StringComparison.OrdinalIgnoreCase));
    }
}
