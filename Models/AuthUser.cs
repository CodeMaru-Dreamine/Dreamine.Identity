using Dreamine.Database.Abstractions.Mapping;

namespace Dreamine.Identity.Models;

/// <summary>
/// \brief 소셜 로그인으로 인증된 사용자 레코드입니다.
/// </summary>
/// <remarks>
/// (Provider, ProviderKey) 조합이 논리적 자연키입니다.
/// 동일 이메일이라도 프로바이더가 다르면 별도 계정으로 취급합니다.
/// </remarks>
[DatabaseTable("Users")]
public sealed class AuthUser
{
    /// <summary>\brief 내부 사용자 식별자입니다.</summary>
    [DatabaseKey]
    [DatabaseGenerated]
    public long Id { get; set; }

    /// <summary>\brief OAuth 프로바이더 이름입니다 (예: "Google", "Naver").</summary>
    public string Provider { get; set; } = string.Empty;

    /// <summary>\brief 프로바이더가 부여한 사용자 식별자입니다.</summary>
    public string ProviderKey { get; set; } = string.Empty;

    /// <summary>\brief 사용자 이메일입니다.</summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>\brief 표시 이름입니다.</summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>\brief 프로필 사진 URL 입니다.</summary>
    public string AvatarUrl { get; set; } = string.Empty;

    /// <summary>\brief 로컬 이메일 로그인용 비밀번호 해시입니다.</summary>
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>\brief 최초 가입 시각 (UTC) 입니다.</summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>\brief 마지막 로그인 시각 (UTC) 입니다.</summary>
    public DateTime LastLoginAt { get; set; }
}
