using Dreamine.Identity.Models;

namespace Dreamine.Identity.Internal;

/// <summary>
/// \if KO
/// <para>인증 사용자의 필수 약관 동의 완료 여부를 판정합니다.</para>
/// \endif
/// \if EN
/// <para>Evaluates whether an authenticated user has completed all required consents.</para>
/// \endif
/// </summary>
internal static class RequiredConsentPolicy
{
    /// <summary>
    /// \if KO
    /// <para>이용약관, 개인정보처리방침 및 연령 확인 시각이 모두 기록되었는지 확인합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Determines whether terms, privacy, and age-confirmation timestamps are all recorded.</para>
    /// \endif
    /// </summary>
    /// <param name="user">
    /// \if KO
    /// <para>검사할 사용자이며 없을 수 있습니다.</para>
    /// \endif
    /// \if EN
    /// <para>The user to inspect, which may be absent.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>모든 필수 동의가 있으면 <see langword="true"/>, 그렇지 않으면 <see langword="false"/>입니다.</para>
    /// \endif
    /// \if EN
    /// <para><see langword="true"/> when every required consent is present; otherwise, <see langword="false"/>.</para>
    /// \endif
    /// </returns>
    public static bool HasRequiredConsents(AuthUser? user) =>
        user is not null &&
        user.TermsAcceptedAtUtc.HasValue &&
        user.PrivacyPolicyAcceptedAtUtc.HasValue &&
        user.AgeConfirmedAtUtc.HasValue;
}
