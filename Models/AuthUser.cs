using Dreamine.Database.Abstractions.Mapping;

namespace Dreamine.Identity.Models;

/// <summary>
/// \if KO
/// <para>소셜 또는 로컬 로그인으로 인증된 사용자 레코드를 나타냅니다.</para>
/// \endif
/// \if EN
/// <para>Represents a user record authenticated through social or local login.</para>
/// \endif
/// </summary>
/// <remarks>
/// \if KO
/// <para>Provider와 ProviderKey의 조합이 논리적 자연 키입니다. 이메일이 같아도 공급자가 다르면 별도 계정으로 취급합니다.</para>
/// \endif
/// \if EN
/// <para>The Provider and ProviderKey pair is the logical natural key. Identical email addresses from different providers are treated as separate accounts.</para>
/// \endif
/// </remarks>
[DatabaseTable("Users")]
public sealed class AuthUser
{
    /// <summary>
    /// \if KO
    /// <para>데이터베이스에서 생성된 내부 사용자 식별자를 가져오거나 설정합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets or sets the database-generated internal user identifier.</para>
    /// \endif
    /// </summary>
    [DatabaseKey]
    [DatabaseGenerated]
    public long Id { get; set; }

    /// <summary>
    /// \if KO
    /// <para>로그인 공급자 이름을 가져오거나 설정합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets or sets the login-provider name.</para>
    /// \endif
    /// </summary>
    public string Provider { get; set; } = string.Empty;

    /// <summary>
    /// \if KO
    /// <para>공급자가 부여한 사용자 식별자를 가져오거나 설정합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets or sets the user identifier assigned by the provider.</para>
    /// \endif
    /// </summary>
    public string ProviderKey { get; set; } = string.Empty;

    /// <summary>
    /// \if KO
    /// <para>사용자 이메일 주소를 가져오거나 설정합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets or sets the user's email address.</para>
    /// \endif
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// \if KO
    /// <para>사용자 표시 이름을 가져오거나 설정합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets or sets the user's display name.</para>
    /// \endif
    /// </summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// \if KO
    /// <para>프로필 이미지 URL을 가져오거나 설정합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets or sets the profile-image URL.</para>
    /// \endif
    /// </summary>
    public string AvatarUrl { get; set; } = string.Empty;

    /// <summary>
    /// \if KO
    /// <para>로컬 이메일 로그인용 비밀번호 해시를 가져오거나 설정합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets or sets the password hash used for local email login.</para>
    /// \endif
    /// </summary>
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>
    /// \if KO
    /// <para>이용약관에 동의한 UTC 시각을 가져오거나 설정합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets or sets the UTC time at which the terms were accepted.</para>
    /// \endif
    /// </summary>
    public DateTime? TermsAcceptedAtUtc { get; set; }

    /// <summary>
    /// \if KO
    /// <para>개인정보처리방침에 동의한 UTC 시각을 가져오거나 설정합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets or sets the UTC time at which the privacy policy was accepted.</para>
    /// \endif
    /// </summary>
    public DateTime? PrivacyPolicyAcceptedAtUtc { get; set; }

    /// <summary>
    /// \if KO
    /// <para>만 14세 이상임을 확인한 UTC 시각을 가져오거나 설정합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets or sets the UTC time at which the minimum-age confirmation was recorded.</para>
    /// \endif
    /// </summary>
    public DateTime? AgeConfirmedAtUtc { get; set; }

    /// <summary>
    /// \if KO
    /// <para>최초 가입 UTC 시각을 가져오거나 설정합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets or sets the UTC registration time.</para>
    /// \endif
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// \if KO
    /// <para>마지막 로그인 UTC 시각을 가져오거나 설정합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets or sets the UTC time of the most recent login.</para>
    /// \endif
    /// </summary>
    public DateTime LastLoginAt { get; set; }
}
