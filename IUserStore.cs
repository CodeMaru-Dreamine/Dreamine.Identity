using Dreamine.Identity.Models;

namespace Dreamine.Identity;

/// <summary>
/// \brief 소셜 로그인 사용자 저장소 계약입니다.
/// </summary>
public interface IUserStore
{
    /// <summary>
    /// \brief 프로바이더가 준 정보로 사용자 레코드를 Upsert 하고 최신 상태를 반환합니다.
    /// </summary>
    Task<AuthUser> UpsertAsync(
        string provider,
        string providerKey,
        string email,
        string displayName,
        string avatarUrl,
        CancellationToken cancellationToken = default);

    /// <summary>\brief 내부 Id 로 사용자 조회.</summary>
    Task<AuthUser?> GetByIdAsync(long id, CancellationToken cancellationToken = default);

    /// <summary>\brief 사용자 표시 이름을 수정합니다.</summary>
    Task<AuthUser?> UpdateDisplayNameAsync(
        long id,
        string displayName,
        CancellationToken cancellationToken = default);

    /// <summary>\brief 로컬 계정 비밀번호를 변경합니다.</summary>
    Task<AuthUser?> ChangeLocalPasswordAsync(
        long id,
        string currentPassword,
        string newPassword,
        CancellationToken cancellationToken = default);

    /// <summary>\brief 이메일/비밀번호 기반 로컬 계정을 생성합니다.</summary>
    Task<AuthUser> CreateLocalAsync(
        string email,
        string displayName,
        string password,
        CancellationToken cancellationToken = default);

    /// <summary>\brief 이메일/비밀번호로 로컬 계정을 검증합니다.</summary>
    Task<AuthUser?> ValidateLocalAsync(
        string email,
        string password,
        CancellationToken cancellationToken = default);
}
