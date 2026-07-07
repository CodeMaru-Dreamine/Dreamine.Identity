using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;

namespace Dreamine.Identity;

/// <summary>
/// \brief 항상 익명 상태를 반환하는 <see cref="AuthenticationStateProvider"/> 입니다.
/// </summary>
/// <remarks>
/// WPF 안에 임베드된 Blazor WebView 는 브라우저 OAuth 흐름과 분리된 컨텍스트라
/// 실제 로그인 상태를 알 수 없습니다. <c>AuthorizeView</c> 등의 컴포넌트가
/// 존재만 해도 <see cref="AuthenticationStateProvider"/> 가 필요하므로 익명 구현체를 등록해
/// WPF 임베드에서는 항상 비로그인 상태로 취급합니다.
/// </remarks>
public sealed class AnonymousAuthenticationStateProvider : AuthenticationStateProvider
{
    private static readonly Task<AuthenticationState> AnonymousState =
        Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())));

    public override Task<AuthenticationState> GetAuthenticationStateAsync() => AnonymousState;
}
