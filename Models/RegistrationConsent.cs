namespace Dreamine.Identity.Models;

/// <summary>
/// \brief 신규 계정 생성 시 확인된 필수 동의의 시각과 문서 버전을 보관합니다.
/// </summary>
public sealed record RegistrationConsent(
    DateTime TermsAcceptedAtUtc,
    string TermsVersion,
    DateTime PrivacyAcceptedAtUtc,
    string PrivacyVersion,
    DateTime MinimumAgeConfirmedAtUtc);

/// <summary>
/// \brief CodeMaru 신규 가입에 적용되는 현재 약관 및 개인정보처리방침 버전입니다.
/// </summary>
public static class IdentityConsentPolicy
{
    /// <summary>\brief 현재 이용약관 버전입니다.</summary>
    public const string CurrentTermsVersion = "2026-08-20";

    /// <summary>\brief 현재 개인정보처리방침 버전입니다.</summary>
    public const string CurrentPrivacyVersion = "2026-08-20";

    /// <summary>\brief 서버 시각을 기준으로 현재 필수 동의 기록을 생성합니다.</summary>
    public static RegistrationConsent Create(DateTime utcNow)
    {
        var normalized = utcNow.Kind == DateTimeKind.Utc ? utcNow : utcNow.ToUniversalTime();
        return new RegistrationConsent(
            normalized,
            CurrentTermsVersion,
            normalized,
            CurrentPrivacyVersion,
            normalized);
    }
}
