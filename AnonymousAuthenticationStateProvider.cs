using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;

namespace Dreamine.Identity;

/// <summary>
/// \if KO
/// <para>항상 익명 인증 상태를 반환하는 <see cref="AuthenticationStateProvider"/>입니다.</para>
/// \endif
/// \if EN
/// <para>Provides an <see cref="AuthenticationStateProvider"/> that always returns an anonymous state.</para>
/// \endif
/// </summary>
/// <remarks>
/// \if KO
/// <para>WPF에 포함된 BlazorWebView는 브라우저 OAuth 흐름과 분리되어 실제 로그인 상태를 알 수 없습니다. AuthorizeView에 필요한 공급자는 제공하되 항상 로그아웃 상태로 취급합니다.</para>
/// \endif
/// \if EN
/// <para>An embedded WPF BlazorWebView is isolated from the browser OAuth flow and cannot know its login state. This provider satisfies components such as AuthorizeView while treating the embedded view as signed out.</para>
/// \endif
/// </remarks>
public sealed class AnonymousAuthenticationStateProvider : AuthenticationStateProvider
{
    /// <summary>
    /// \if KO
    /// <para>Anonymous State 값을 보관합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Stores the anonymous state value.</para>
    /// \endif
    /// </summary>
    private static readonly Task<AuthenticationState> AnonymousState =
        Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())));

    /// <summary>
    /// \if KO
    /// <para>캐시된 익명 인증 상태를 반환합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Returns the cached anonymous authentication state.</para>
    /// \endif
    /// </summary>
    /// <returns>
    /// \if KO
    /// <para>익명 ClaimsPrincipal을 포함한 완료된 작업입니다.</para>
    /// \endif
    /// \if EN
    /// <para>A completed task containing an anonymous ClaimsPrincipal.</para>
    /// \endif
    /// </returns>
    public override Task<AuthenticationState> GetAuthenticationStateAsync() => AnonymousState;
}
