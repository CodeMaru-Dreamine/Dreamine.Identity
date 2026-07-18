using Dreamine.Identity.Models;

namespace Dreamine.Identity;

/// <summary>
/// \if KO
/// <para>외부 및 로컬 로그인 사용자의 저장·조회·계정 관리 계약을 정의합니다.</para>
/// \endif
/// \if EN
/// <para>Defines persistence, lookup, and account-management operations for external and local login users.</para>
/// \endif
/// </summary>
public interface IUserStore
{
    /// <summary>
    /// \if KO
    /// <para>공급자가 제공한 정보로 사용자를 추가하거나 갱신하고 최신 레코드를 반환합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Inserts or updates a user from provider data and returns the current record.</para>
    /// \endif
    /// </summary>
    /// <param name="provider">
    /// \if KO
    /// <para>로그인 공급자 이름입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The login-provider name.</para>
    /// \endif
    /// </param>
    /// <param name="providerKey">
    /// \if KO
    /// <para>공급자 사용자 식별자입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The provider user identifier.</para>
    /// \endif
    /// </param>
    /// <param name="email">
    /// \if KO
    /// <para>공급자가 제공한 이메일입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The email supplied by the provider.</para>
    /// \endif
    /// </param>
    /// <param name="displayName">
    /// \if KO
    /// <para>공급자가 제공한 표시 이름입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The display name supplied by the provider.</para>
    /// \endif
    /// </param>
    /// <param name="avatarUrl">
    /// \if KO
    /// <para>공급자가 제공한 프로필 이미지 URL입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The profile-image URL supplied by the provider.</para>
    /// \endif
    /// </param>
    /// <param name="cancellationToken">
    /// \if KO
    /// <para>저장 작업 취소 토큰입니다.</para>
    /// \endif
    /// \if EN
    /// <para>A token used to cancel persistence.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>추가되거나 갱신된 사용자입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The inserted or updated user.</para>
    /// \endif
    /// </returns>
    Task<AuthUser> UpsertAsync(
        string provider,
        string providerKey,
        string email,
        string displayName,
        string avatarUrl,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// \if KO
    /// <para>내부 식별자로 사용자를 조회합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Finds a user by internal identifier.</para>
    /// \endif
    /// </summary>
    /// <param name="id">
    /// \if KO
    /// <para>내부 사용자 식별자입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The internal user identifier.</para>
    /// \endif
    /// </param>
    /// <param name="cancellationToken">
    /// \if KO
    /// <para>조회 취소 토큰입니다.</para>
    /// \endif
    /// \if EN
    /// <para>A token used to cancel the lookup.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>찾은 사용자 또는 없으면 <see langword="null"/>입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The matching user, or <see langword="null"/> when absent.</para>
    /// \endif
    /// </returns>
    Task<AuthUser?> GetByIdAsync(long id, CancellationToken cancellationToken = default);

    /// <summary>
    /// \if KO
    /// <para>사용자의 표시 이름을 갱신합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Updates a user's display name.</para>
    /// \endif
    /// </summary>
    /// <param name="id">
    /// \if KO
    /// <para>내부 사용자 식별자입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The internal user identifier.</para>
    /// \endif
    /// </param>
    /// <param name="displayName">
    /// \if KO
    /// <para>저장할 표시 이름입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The display name to store.</para>
    /// \endif
    /// </param>
    /// <param name="cancellationToken">
    /// \if KO
    /// <para>갱신 취소 토큰입니다.</para>
    /// \endif
    /// \if EN
    /// <para>A token used to cancel the update.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>갱신된 사용자 또는 사용자가 없으면 <see langword="null"/>입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The updated user, or <see langword="null"/> when the user is absent.</para>
    /// \endif
    /// </returns>
    Task<AuthUser?> UpdateDisplayNameAsync(
        long id,
        string displayName,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// \if KO
    /// <para>필수 약관, 개인정보 및 연령 확인 동의를 기록합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Records required terms, privacy, and age-confirmation consent.</para>
    /// \endif
    /// </summary>
    /// <param name="id">
    /// \if KO
    /// <para>내부 사용자 식별자입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The internal user identifier.</para>
    /// \endif
    /// </param>
    /// <param name="acceptedAtUtc">
    /// \if KO
    /// <para>모든 필수 동의를 수락한 UTC 시각입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The UTC time at which all required consents were accepted.</para>
    /// \endif
    /// </param>
    /// <param name="cancellationToken">
    /// \if KO
    /// <para>갱신 취소 토큰입니다.</para>
    /// \endif
    /// \if EN
    /// <para>A token used to cancel the update.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>갱신된 사용자 또는 없으면 <see langword="null"/>입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The updated user, or <see langword="null"/> when absent.</para>
    /// \endif
    /// </returns>
    Task<AuthUser?> AcceptRequiredConsentsAsync(
        long id,
        DateTime acceptedAtUtc,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// \if KO
    /// <para>로컬 계정의 현재 비밀번호를 검증하고 새 비밀번호로 변경합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Verifies and changes the password of a local account.</para>
    /// \endif
    /// </summary>
    /// <param name="id">
    /// \if KO
    /// <para>내부 사용자 식별자입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The internal user identifier.</para>
    /// \endif
    /// </param>
    /// <param name="currentPassword">
    /// \if KO
    /// <para>현재 평문 비밀번호입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The current plain-text password.</para>
    /// \endif
    /// </param>
    /// <param name="newPassword">
    /// \if KO
    /// <para>새 평문 비밀번호입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The new plain-text password.</para>
    /// \endif
    /// </param>
    /// <param name="cancellationToken">
    /// \if KO
    /// <para>변경 취소 토큰입니다.</para>
    /// \endif
    /// \if EN
    /// <para>A token used to cancel the change.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>갱신된 사용자 또는 없으면 <see langword="null"/>입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The updated user, or <see langword="null"/> when absent.</para>
    /// \endif
    /// </returns>
    Task<AuthUser?> ChangeLocalPasswordAsync(
        long id,
        string currentPassword,
        string newPassword,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// \if KO
    /// <para>이메일과 비밀번호를 사용하는 로컬 계정을 만듭니다.</para>
    /// \endif
    /// \if EN
    /// <para>Creates a local account backed by an email address and password.</para>
    /// \endif
    /// </summary>
    /// <param name="email">
    /// \if KO
    /// <para>정규화할 이메일 주소입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The email address to normalize.</para>
    /// \endif
    /// </param>
    /// <param name="displayName">
    /// \if KO
    /// <para>선택한 표시 이름입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The chosen display name.</para>
    /// \endif
    /// </param>
    /// <param name="password">
    /// \if KO
    /// <para>해시할 평문 비밀번호입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The plain-text password to hash.</para>
    /// \endif
    /// </param>
    /// <param name="cancellationToken">
    /// \if KO
    /// <para>생성 취소 토큰입니다.</para>
    /// \endif
    /// \if EN
    /// <para>A token used to cancel creation.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>생성된 로컬 사용자입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The created local user.</para>
    /// \endif
    /// </returns>
    Task<AuthUser> CreateLocalAsync(
        string email,
        string displayName,
        string password,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// \if KO
    /// <para>이메일과 비밀번호로 로컬 계정을 검증합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Validates a local account using an email address and password.</para>
    /// \endif
    /// </summary>
    /// <param name="email">
    /// \if KO
    /// <para>정규화할 이메일 주소입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The email address to normalize.</para>
    /// \endif
    /// </param>
    /// <param name="password">
    /// \if KO
    /// <para>검증할 평문 비밀번호입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The plain-text password to verify.</para>
    /// \endif
    /// </param>
    /// <param name="cancellationToken">
    /// \if KO
    /// <para>검증 취소 토큰입니다.</para>
    /// \endif
    /// \if EN
    /// <para>A token used to cancel validation.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>인증된 사용자 또는 실패하면 <see langword="null"/>입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The authenticated user, or <see langword="null"/> when validation fails.</para>
    /// \endif
    /// </returns>
    Task<AuthUser?> ValidateLocalAsync(
        string email,
        string password,
        CancellationToken cancellationToken = default);
}
