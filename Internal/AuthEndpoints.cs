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
/// \brief 로그인/로그아웃 HTTP 엔드포인트를 매핑합니다.
/// </summary>
internal static class AuthEndpoints
{
    private const string LocalProvider = "Local";

    public static void MapAuthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/_identity/login", (HttpContext http, string? returnUrl, string? mode, string? message, string? error) =>
            Results.Content(
                BuildLoginHtmlLocalized(SafeReturnUrl(returnUrl), mode, message, error, "/_identity", IdentityLocalization.Resolve(http)),
                "text/html; charset=utf-8"));

        endpoints.MapGet("/login", (HttpContext http, string? returnUrl, string? mode, string? message, string? error) =>
            Results.Content(
                BuildLoginHtmlLocalized(SafeReturnUrl(returnUrl), mode, message, error, string.Empty, IdentityLocalization.Resolve(http)),
                "text/html; charset=utf-8"));

        endpoints.MapPost("/_identity/login", async (HttpContext http, IUserStore userStore) =>
            await HandleLocalLoginAsync(http, userStore, "/_identity").ConfigureAwait(false));

        endpoints.MapPost("/login", async (HttpContext http, IUserStore userStore) =>
            await HandleLocalLoginAsync(http, userStore, string.Empty).ConfigureAwait(false));

        endpoints.MapPost("/_identity/signup", async (HttpContext http, IUserStore userStore) =>
            await HandleSignupAsync(http, userStore, "/_identity").ConfigureAwait(false));

        endpoints.MapPost("/signup", async (HttpContext http, IUserStore userStore) =>
            await HandleSignupAsync(http, userStore, string.Empty).ConfigureAwait(false));

        endpoints.MapGet("/signin/google", (HttpContext http, string? returnUrl, string? lang) =>
        {
            var safeReturnUrl = SafeReturnUrl(returnUrl);
            if (IsEmbeddedMobileBrowser(http.Request.Headers.UserAgent.ToString()))
            {
                return Results.Redirect($"/_identity/login?lang={Url(IdentityLocalization.NormalizeLanguage(lang))}&returnUrl={Url(safeReturnUrl)}&error={Url("Google 로그인은 카카오톡/네이버앱 같은 앱 내부 브라우저에서 차단됩니다. 오른쪽 위 메뉴에서 '브라우저로 열기'를 선택한 뒤 다시 시도해 주세요. Naver/Kakao 로그인은 현재 화면에서도 사용할 수 있습니다.")}");
            }

            return Results.Challenge(
                CreateSocialAuthenticationProperties(safeReturnUrl, null, lang),
                new[] { GoogleDefaults.AuthenticationScheme });
        });

        endpoints.MapGet("/signin/naver", (string? returnUrl, string? lang) =>
            Results.Challenge(
                CreateSocialAuthenticationProperties(SafeReturnUrl(returnUrl), null, lang),
                new[] { NaverAuthenticationDefaults.AuthenticationScheme }));

        endpoints.MapGet("/signin/kakao", (string? returnUrl, string? lang) =>
            Results.Challenge(
                CreateSocialAuthenticationProperties(SafeReturnUrl(returnUrl), null, lang),
                new[] { "Kakao" }));

        endpoints.MapPost("/signin/google", async (HttpContext http) =>
            await HandleSocialSignupAsync(http, GoogleDefaults.AuthenticationScheme).ConfigureAwait(false));

        endpoints.MapPost("/signin/naver", async (HttpContext http) =>
            await HandleSocialSignupAsync(http, NaverAuthenticationDefaults.AuthenticationScheme).ConfigureAwait(false));

        endpoints.MapPost("/signin/kakao", async (HttpContext http) =>
            await HandleSocialSignupAsync(http, "Kakao").ConfigureAwait(false));

        endpoints.MapGet("/_identity/account", async (HttpContext http, IUserStore userStore, string? returnUrl, string? message, string? error) =>
            await HandleAccountPageAsync(http, userStore, returnUrl, message, error, "/_identity").ConfigureAwait(false));

        endpoints.MapGet("/account", async (HttpContext http, IUserStore userStore, string? returnUrl, string? message, string? error) =>
            await HandleAccountPageAsync(http, userStore, returnUrl, message, error, string.Empty).ConfigureAwait(false));

        endpoints.MapPost("/_identity/account", async (HttpContext http, IUserStore userStore) =>
            await HandleAccountPostAsync(http, userStore, "/_identity").ConfigureAwait(false));

        endpoints.MapPost("/account", async (HttpContext http, IUserStore userStore) =>
            await HandleAccountPostAsync(http, userStore, string.Empty).ConfigureAwait(false));

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

    private static async Task<IResult> HandleLocalLoginAsync(HttpContext http, IUserStore userStore, string routePrefix)
    {
        var loginPath = $"{routePrefix}/login";
        var form = await http.Request.ReadFormAsync(http.RequestAborted).ConfigureAwait(false);
        var returnUrl = SafeReturnUrl(form["returnUrl"]);
        var language = IdentityLocalization.NormalizeLanguage(form["lang"]);
        var email = form["email"].ToString();
        var password = form["password"].ToString();

        var user = await userStore.ValidateLocalAsync(email, password, http.RequestAborted)
            .ConfigureAwait(false);
        if (user is null)
        {
            return Results.Redirect($"{loginPath}?lang={Url(language)}&returnUrl={Url(returnUrl)}&error={Url("직접 회원가입한 이메일/비밀번호가 올바르지 않습니다. Google, Naver, Kakao 계정은 아래 소셜 로그인 버튼을 사용해 주세요.")}");
        }

        await SignInAsync(http, user).ConfigureAwait(false);
        return Results.Redirect(returnUrl);
    }

    private static async Task<IResult> HandleSignupAsync(HttpContext http, IUserStore userStore, string routePrefix)
    {
        var loginPath = $"{routePrefix}/login";
        var form = await http.Request.ReadFormAsync(http.RequestAborted).ConfigureAwait(false);
        var returnUrl = SafeReturnUrl(form["returnUrl"]);
        var language = IdentityLocalization.NormalizeLanguage(form["lang"]);
        var email = form["email"].ToString();
        var displayName = form["displayName"].ToString();
        var password = form["password"].ToString();
        var confirmPassword = form["confirmPassword"].ToString();
        var termsAccepted = IsChecked(form["termsAccepted"]);
        var privacyAccepted = IsChecked(form["privacyAccepted"]);
        var minimumAgeConfirmed = IsChecked(form["minimumAgeConfirmed"]);

        if (!termsAccepted || !privacyAccepted)
        {
            return Results.Redirect($"{loginPath}?mode=signup&lang={Url(language)}&returnUrl={Url(returnUrl)}&error={Url("이용약관과 개인정보 수집·이용에 모두 동의해야 합니다.")}");
        }

        if (!minimumAgeConfirmed)
        {
            return Results.Redirect($"{loginPath}?mode=signup&lang={Url(language)}&returnUrl={Url(returnUrl)}&error={Url("만 14세 이상임을 확인해야 가입할 수 있습니다.")}");
        }

        if (!string.Equals(password, confirmPassword, StringComparison.Ordinal))
        {
            return Results.Redirect($"{loginPath}?mode=signup&lang={Url(language)}&returnUrl={Url(returnUrl)}&error={Url("비밀번호 확인이 일치하지 않습니다.")}");
        }

        try
        {
            var consent = IdentityConsentPolicy.Create(DateTime.UtcNow);
            var user = await userStore.CreateLocalAsync(email, displayName, password, consent, http.RequestAborted)
                .ConfigureAwait(false);
            await SignInAsync(http, user).ConfigureAwait(false);
            return Results.Redirect(returnUrl);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return Results.Redirect($"{loginPath}?mode=signup&lang={Url(language)}&returnUrl={Url(returnUrl)}&error={Url(ex.Message)}");
        }
    }

    private static AuthenticationProperties CreateSocialAuthenticationProperties(
        string returnUrl,
        string? registrationConsent,
        string? language)
    {
        var properties = new AuthenticationProperties { RedirectUri = returnUrl };
        properties.Items[DreamineIdentityExtensions.LanguageProperty] =
            IdentityLocalization.NormalizeLanguage(language);
        if (string.Equals(registrationConsent, "accepted", StringComparison.Ordinal))
        {
            properties.Items[DreamineIdentityExtensions.RegistrationConsentProperty] = "accepted";
            properties.Items[DreamineIdentityExtensions.TermsVersionProperty] = IdentityConsentPolicy.CurrentTermsVersion;
            properties.Items[DreamineIdentityExtensions.PrivacyVersionProperty] = IdentityConsentPolicy.CurrentPrivacyVersion;
        }

        return properties;
    }

    private static async Task<IResult> HandleSocialSignupAsync(HttpContext http, string authenticationScheme)
    {
        var form = await http.Request.ReadFormAsync(http.RequestAborted).ConfigureAwait(false);
        var returnUrl = SafeReturnUrl(form["returnUrl"]);
        var language = IdentityLocalization.NormalizeLanguage(form["lang"]);
        var hasRequiredConsent = IsChecked(form["termsAccepted"])
                                 && IsChecked(form["privacyAccepted"])
                                 && IsChecked(form["minimumAgeConfirmed"]);
        if (!hasRequiredConsent)
        {
            return Results.Redirect(
                $"/_identity/login?mode=signup&lang={Url(language)}&returnUrl={Url(returnUrl)}&error={Url(IdentityLocalization.Consent(language).ConsentRequiredMessage)}");
        }

        if (string.Equals(authenticationScheme, GoogleDefaults.AuthenticationScheme, StringComparison.Ordinal)
            && IsEmbeddedMobileBrowser(http.Request.Headers.UserAgent.ToString()))
        {
            return Results.Redirect(
                $"/_identity/login?mode=signup&lang={Url(language)}&returnUrl={Url(returnUrl)}&error={Url("Google 로그인은 앱 내부 브라우저에서 차단될 수 있습니다. Chrome 또는 삼성인터넷으로 연 뒤 다시 시도해 주세요.")}");
        }

        return Results.Challenge(
            CreateSocialAuthenticationProperties(returnUrl, "accepted", language),
            [authenticationScheme]);
    }

    private static bool IsChecked(Microsoft.Extensions.Primitives.StringValues value)
    {
        var text = value.ToString();
        return string.Equals(text, "on", StringComparison.OrdinalIgnoreCase)
               || string.Equals(text, "true", StringComparison.OrdinalIgnoreCase)
               || string.Equals(text, "accepted", StringComparison.OrdinalIgnoreCase)
               || string.Equals(text, "1", StringComparison.Ordinal);
    }

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
            BuildAccountHtmlLocalized(user, SafeReturnUrl(returnUrl), message, error, routePrefix, IdentityLocalization.Resolve(http)),
            "text/html; charset=utf-8");
    }

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
               || string.Equals(host, "::1", StringComparison.OrdinalIgnoreCase)
               || string.Equals(host, "[::1]", StringComparison.OrdinalIgnoreCase);
    }

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

    private static string BuildLoginHtml(
        string returnUrl,
        string? mode,
        string? message,
        string? error,
        string routePrefix = "") =>
        BuildLoginHtmlLocalized(returnUrl, mode, message, error, routePrefix, IdentityLocalization.Default);

    private static string BuildLoginHtmlLocalized(
        string returnUrl,
        string? mode,
        string? message,
        string? error,
        string routePrefix,
        IdentityLocalization.Copy copy)
    {
        var isSignup = string.Equals(mode, "signup", StringComparison.OrdinalIgnoreCase);
        var title = isSignup ? copy.Signup : copy.Login;
        var language = IdentityLocalization.LanguageKey(copy);
        var consent = IdentityLocalization.Consent(copy);
        var loginPath = $"{routePrefix}/login";
        var signupPath = $"{routePrefix}/signup";
        var action = isSignup ? signupPath : loginPath;
        var commonQuery = $"lang={Url(language)}&returnUrl={Url(returnUrl)}";
        var loginTabHref = $"{loginPath}?{commonQuery}";
        var signupTabHref = $"{loginPath}?mode=signup&{commonQuery}";
        var switchHref = isSignup
            ? loginTabHref
            : signupTabHref;
        var switchText = isSignup ? copy.HasAccount : copy.NoAccount;
        var languageOptions = string.Join(
            string.Empty,
            IdentityLocalization.Languages.Select(option =>
                $"<option value=\"{Html(option.Code)}\"{(string.Equals(option.Code, language, StringComparison.OrdinalIgnoreCase) ? " selected" : string.Empty)}>{Html(option.Flag)} · {Html(option.NativeName)}</option>"));

        var builder = new StringBuilder();
        builder.Append($$"""
            <!DOCTYPE html>
            <html lang="{{copy.HtmlLanguage}}">
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
                  padding: 24px 0;
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
                .identity-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 14px; margin-bottom: 22px; }
                .identity-brand { color: #f8fafc; font-size: 14px; font-weight: 800; letter-spacing: .04em; text-decoration: none; }
                .language-select {
                  min-width: 128px;
                  height: 36px;
                  padding: 0 30px 0 10px;
                  border: 1px solid #334155;
                  border-radius: 999px;
                  background: #0b1220;
                  color: #dbeafe;
                  font-size: 13px;
                }
                h1 { margin: 0 0 8px; font-size: 28px; letter-spacing: 0; }
                p { margin: 0 0 20px; color: #94a3b8; line-height: 1.5; }
                .auth-tabs { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; margin: 20px 0; padding: 4px; border-radius: 10px; background: #0b1220; }
                .auth-tab { display: flex; min-height: 42px; align-items: center; justify-content: center; border-radius: 7px; color: #94a3b8; font-size: 14px; font-weight: 700; text-decoration: none; }
                .auth-tab.active { background: #1e293b; color: #f8fafc; box-shadow: inset 0 0 0 1px rgba(147, 197, 253, .24); }
                .signup-notice, .legal-notice { padding: 12px 14px; border-radius: 8px; font-size: 12px; line-height: 1.55; }
                .signup-notice { margin: 0 0 16px; border: 1px solid rgba(96, 165, 250, .24); background: rgba(30, 64, 175, .12); color: #bfdbfe; }
                .legal-notice { margin-top: 18px; border: 1px solid rgba(148, 163, 184, .18); background: rgba(15, 23, 42, .45); color: #94a3b8; }
                .legal-notice a { color: #bfdbfe; text-underline-offset: 3px; }
                .form-hint { margin: 10px 0 0; color: #93c5fd; font-size: 13px; }
                label { display: block; margin: 14px 0 6px; color: #cbd5e1; font-size: 14px; }
                input:not([type="checkbox"]) {
                  width: 100%;
                  height: 44px;
                  padding: 0 12px;
                  border: 1px solid #334155;
                  border-radius: 6px;
                  background: #0b1220;
                  color: #f8fafc;
                  font-size: 15px;
                }
                .consents {
                  display: grid;
                  gap: 10px;
                  margin-top: 18px;
                  padding: 14px;
                  border: 1px solid rgba(148, 163, 184, .24);
                  border-radius: 8px;
                  background: rgba(15, 23, 42, .55);
                }
                .consent-row {
                  display: grid;
                  grid-template-columns: 20px 1fr;
                  gap: 9px;
                  align-items: start;
                  margin: 0;
                  color: #dbeafe;
                  font-size: 13px;
                  line-height: 1.5;
                }
                .consent-row input { width: 18px; height: 18px; margin: 1px 0 0; accent-color: #60a5fa; }
                .consent-row a { color: #93c5fd; text-underline-offset: 3px; }
                .consent-note { margin: 0; color: #94a3b8; font-size: 12px; line-height: 1.5; }
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
                button.social { margin: 0; background: transparent; cursor: pointer; }
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
                <div class="identity-toolbar">
                  <a class="identity-brand" href="https://codemaru.co.kr/?lang={{Url(language)}}">CodeMaru ID</a>
                  <select class="language-select" id="identityLanguage" aria-label="Language">{{languageOptions}}</select>
                </div>
                <h1>{{Html(title)}}</h1>
                <p>{{Html(copy.LoginLead)}}</p>
                <nav class="auth-tabs" aria-label="Account access">
                  <a class="auth-tab {{(!isSignup ? "active" : string.Empty)}}" href="{{Html(loginTabHref)}}">{{Html(copy.Login)}}</a>
                  <a class="auth-tab {{(isSignup ? "active" : string.Empty)}}" href="{{Html(signupTabHref)}}">{{Html(copy.Signup)}}</a>
                </nav>
            """);

        if (!isSignup)
        {
            builder.Append($"""<div class="signup-notice">{Html(consent.SignupNotice)}</div>""");
        }

        if (!string.IsNullOrWhiteSpace(message))
        {
            builder.Append($"""<div class="message">{Html(message)}</div>""");
        }

        if (!string.IsNullOrWhiteSpace(error))
        {
            builder.Append($"""<div class="error">{Html(error)}</div>""");
        }

        builder.Append($$"""
                <form id="identityForm" method="post" action="{{action}}">
                  <input type="hidden" name="returnUrl" value="{{Html(returnUrl)}}" />
                  <input type="hidden" name="lang" value="{{Html(language)}}" />
            """);

        if (isSignup)
        {
            builder.Append($$"""
                  <label for="displayName">{{Html(copy.Name)}}</label>
                  <input id="displayName" name="displayName" autocomplete="name" />
                """);
        }

        builder.Append($$"""
                  <label for="email">{{Html(copy.Email)}}</label>
                  <input id="email" name="email" type="email" autocomplete="email" required />
                  <label for="password">{{Html(copy.Password)}}</label>
                  <input id="password" name="password" type="password" autocomplete="current-password" required minlength="8" />
                  <p class="form-hint">{{Html(copy.SocialHint)}}</p>
            """);

        if (isSignup)
        {
            builder.Append($$"""
                  <label for="confirmPassword">{{Html(copy.ConfirmPassword)}}</label>
                  <input id="confirmPassword" name="confirmPassword" type="password" autocomplete="new-password" required minlength="8" />
                  <div class="consents" aria-label="{{Html(consent.RequiredConsents)}}">
                    <label class="consent-row" for="termsAccepted">
                      <input id="termsAccepted" name="termsAccepted" type="checkbox" required />
                      <span>[{{Html(consent.RequiredPrefix)}}] <a href="https://codemaru.co.kr/terms?lang={{Url(language)}}" target="_blank" rel="noopener noreferrer">{{Html(consent.TermsAgreement)}}</a></span>
                    </label>
                    <label class="consent-row" for="privacyAccepted">
                      <input id="privacyAccepted" name="privacyAccepted" type="checkbox" required />
                      <span>[{{Html(consent.RequiredPrefix)}}] <a href="https://codemaru.co.kr/privacy?lang={{Url(language)}}" target="_blank" rel="noopener noreferrer">{{Html(consent.PrivacyAgreement)}}</a></span>
                    </label>
                    <label class="consent-row" for="minimumAgeConfirmed">
                      <input id="minimumAgeConfirmed" name="minimumAgeConfirmed" type="checkbox" required />
                      <span>[{{Html(consent.RequiredPrefix)}}] {{Html(consent.MinimumAgeConfirmation)}}</span>
                    </label>
                    <p class="consent-note">{{Html(consent.MinimumAgeNotice)}}</p>
                  </div>
                """);
        }

        builder.Append($$"""
                  <button type="submit">{{Html(title)}}</button>
                </form>
                <a class="switch" href="{{Html(switchHref)}}">{{Html(switchText)}}</a>
                <div class="divider">{{Html(copy.Or)}}</div>
                <div class="browser-warning">
                  <strong>{{Html(copy.GoogleGuide)}}</strong><br />
                  {{Html(copy.EmbeddedWarning)}}
                  <div class="external-browser-actions">
                    <a class="external-open" id="openChrome" href="#">{{Html(copy.OpenChrome)}}</a>
                    <a class="external-open" id="openSamsung" href="#">{{Html(copy.OpenSamsung)}}</a>
                  </div>
                </div>
                <div class="socials">
            """);

        if (isSignup)
        {
            builder.Append("""
                  <button class="social google" id="googleLoginLink" type="submit" form="identityForm" formaction="/signin/google" formmethod="post" formnovalidate data-requires-consent>G Google</button>
                  <button class="social naver" type="submit" form="identityForm" formaction="/signin/naver" formmethod="post" formnovalidate data-requires-consent>N Naver</button>
                  <button class="social kakao" type="submit" form="identityForm" formaction="/signin/kakao" formmethod="post" formnovalidate data-requires-consent>Kakao</button>
                """);
        }
        else
        {
            builder.Append($$"""
                  <a class="social google" id="googleLoginLink" href="/signin/google?lang={{Url(language)}}&returnUrl={{Url(returnUrl)}}">G Google</a>
                  <a class="social naver" href="/signin/naver?lang={{Url(language)}}&returnUrl={{Url(returnUrl)}}">N Naver</a>
                  <a class="social kakao" href="/signin/kakao?lang={{Url(language)}}&returnUrl={{Url(returnUrl)}}">Kakao</a>
                """);
        }

        builder.Append($$"""
                </div>
                <div class="legal-notice">
                  {{Html(consent.LegalNotice)}}<br />
                  <a href="https://codemaru.co.kr/terms?lang={{Url(language)}}" target="_blank" rel="noopener noreferrer">{{Html(consent.TermsAgreement)}}</a>
                  ·
                  <a href="https://codemaru.co.kr/privacy?lang={{Url(language)}}" target="_blank" rel="noopener noreferrer">{{Html(consent.PrivacyAgreement)}}</a>
                </div>
              </main>
              <script>
                (function () {
                  var languageSelect = document.getElementById("identityLanguage");
                  if (languageSelect) {
                    languageSelect.addEventListener("change", function () {
                      var url = new URL(window.location.href);
                      url.searchParams.set("lang", languageSelect.value);
                      document.cookie = "dreamine-language=" + encodeURIComponent(languageSelect.value) + "; path=/; max-age=31536000; samesite=lax";
                      window.location.assign(url.toString());
                    });
                  }

                  var consentLinks = document.querySelectorAll("[data-requires-consent]");
                  consentLinks.forEach(function (link) {
                    link.addEventListener("click", function (event) {
                      var ids = ["termsAccepted", "privacyAccepted", "minimumAgeConfirmed"];
                      var accepted = ids.every(function (id) {
                        var input = document.getElementById(id);
                        return input && input.checked;
                      });
                      if (!accepted) {
                        event.preventDefault();
                        alert({{System.Text.Json.JsonSerializer.Serialize(consent.ConsentRequiredMessage)}});
                      }
                    });
                  });

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
                    alert({{System.Text.Json.JsonSerializer.Serialize(copy.EmbeddedWarning)}});
                  });
                })();
              </script>
            </body>
            </html>
            """);

        return builder.ToString();
    }

    private static string BuildAccountHtml(
        AuthUser user,
        string returnUrl,
        string? message,
        string? error,
        string routePrefix = "") =>
        BuildAccountHtmlLocalized(user, returnUrl, message, error, routePrefix, IdentityLocalization.Default);

    private static string BuildAccountHtmlLocalized(
        AuthUser user,
        string returnUrl,
        string? message,
        string? error,
        string routePrefix,
        IdentityLocalization.Copy copy)
    {
        var accountPath = $"{routePrefix}/account";
        var signoutPath = $"{routePrefix}/signout";
        var provider = string.IsNullOrWhiteSpace(user.Provider) ? "Unknown" : user.Provider;
        var email = string.IsNullOrWhiteSpace(user.Email) ? copy.NotProvided : user.Email;
        var isLocal = string.Equals(user.Provider, LocalProvider, StringComparison.OrdinalIgnoreCase);
        var avatar = string.IsNullOrWhiteSpace(user.AvatarUrl)
            ? "<div class=\"avatar-fallback\">U</div>"
            : $"""<img class="avatar" src="{Html(user.AvatarUrl)}" alt="" />""";
        var passwordSection = isLocal
            ? $$"""
                <section>
                  <h2>{{Html(copy.ChangePassword)}}</h2>
                  <form method="post" action="{{accountPath}}">
                    <input type="hidden" name="returnUrl" value="{{Html(returnUrl)}}" />
                    <input type="hidden" name="accountAction" value="password" />
                    <label for="currentPassword">{{Html(copy.CurrentPassword)}}</label>
                    <input id="currentPassword" name="currentPassword" type="password" autocomplete="current-password" required />
                    <label for="newPassword">{{Html(copy.NewPassword)}}</label>
                    <input id="newPassword" name="newPassword" type="password" autocomplete="new-password" required minlength="8" />
                    <label for="confirmPassword">{{Html(copy.ConfirmNewPassword)}}</label>
                    <input id="confirmPassword" name="confirmPassword" type="password" autocomplete="new-password" required minlength="8" />
                    <button type="submit">{{Html(copy.ChangePassword)}}</button>
                  </form>
                </section>
                """
            : $$"""
                <section>
                  <h2>{{Html(copy.PasswordTitle)}}</h2>
                  <p class="note">{{Html(string.Format(System.Globalization.CultureInfo.InvariantCulture, copy.ExternalPassword, provider))}}</p>
                </section>
                """;

        var builder = new StringBuilder();
        builder.Append($$"""
            <!DOCTYPE html>
            <html lang="{{copy.HtmlLanguage}}">
            <head>
              <meta charset="utf-8" />
              <meta name="viewport" content="width=device-width, initial-scale=1" />
              <title>{{Html(copy.Account)}} | Dreamine Identity</title>
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
                    <h1>{{Html(copy.Account)}}</h1>
                    <p>{{Html(copy.AccountLead)}}</p>
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
                  <div class="row"><dt>{{Html(copy.LoginMethod)}}</dt><dd>{{Html(provider)}}</dd></div>
                  <div class="row"><dt>{{Html(copy.Email)}}</dt><dd>{{Html(email)}}</dd></div>
                </dl>
                <form method="post" action="{{accountPath}}">
                  <input type="hidden" name="returnUrl" value="{{Html(returnUrl)}}" />
                  <input type="hidden" name="accountAction" value="profile" />
                  <label for="displayName">{{Html(copy.DisplayName)}}</label>
                  <input id="displayName" name="displayName" autocomplete="name" required value="{{Html(user.DisplayName)}}" />
                  <div class="actions">
                    <button type="submit">{{Html(copy.Save)}}</button>
                    <a class="button" href="{{Html(returnUrl)}}">{{Html(copy.Back)}}</a>
                    <a class="button" href="{{signoutPath}}?returnUrl={{Url(returnUrl)}}">{{Html(copy.Logout)}}</a>
                  </div>
                </form>
                {{passwordSection}}
              </main>
            </body>
            </html>
            """);

        return builder.ToString();
    }

    private static string Html(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);

    private static string Url(string? value) => Uri.EscapeDataString(value ?? string.Empty);

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
