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
            Results.Challenge(
                new AuthenticationProperties { RedirectUri = SafeReturnUrl(returnUrl) },
                new[] { GoogleDefaults.AuthenticationScheme }));

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

    private static async Task<IResult> HandleSignupAsync(HttpContext http, IUserStore userStore, string routePrefix)
    {
        var loginPath = $"{routePrefix}/login";
        var form = await http.Request.ReadFormAsync(http.RequestAborted).ConfigureAwait(false);
        var returnUrl = SafeReturnUrl(form["returnUrl"]);
        var email = form["email"].ToString();
        var displayName = form["displayName"].ToString();
        var password = form["password"].ToString();
        var confirmPassword = form["confirmPassword"].ToString();

        if (!string.Equals(password, confirmPassword, StringComparison.Ordinal))
        {
            return Results.Redirect($"{loginPath}?mode=signup&returnUrl={Url(returnUrl)}&error={Url("비밀번호 확인이 일치하지 않습니다.")}");
        }

        try
        {
            var user = await userStore.CreateLocalAsync(email, displayName, password, http.RequestAborted)
                .ConfigureAwait(false);
            await SignInAsync(http, user).ConfigureAwait(false);
            return Results.Redirect(returnUrl);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return Results.Redirect($"{loginPath}?mode=signup&returnUrl={Url(returnUrl)}&error={Url(ex.Message)}");
        }
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
            BuildAccountHtml(user, SafeReturnUrl(returnUrl), message, error, routePrefix),
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
               || string.Equals(host, "::1", StringComparison.OrdinalIgnoreCase);
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
            builder.Append("""
                  <label for="confirmPassword">비밀번호 확인</label>
                  <input id="confirmPassword" name="confirmPassword" type="password" autocomplete="new-password" required minlength="8" />
                """);
        }

        builder.Append($$"""
                  <button type="submit">{{Html(title)}}</button>
                </form>
                <a class="switch" href="{{switchHref}}">{{Html(switchText)}}</a>
                <div class="divider">또는</div>
                <div class="socials">
                  <a class="social google" href="/signin/google?returnUrl={{Url(returnUrl)}}">G Google</a>
                  <a class="social naver" href="/signin/naver?returnUrl={{Url(returnUrl)}}">N Naver</a>
                  <a class="social kakao" href="/signin/kakao?returnUrl={{Url(returnUrl)}}">Kakao</a>
                </div>
              </main>
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

    private static string Html(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);

    private static string Url(string? value) => Uri.EscapeDataString(value ?? string.Empty);
}
