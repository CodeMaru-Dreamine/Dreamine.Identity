namespace Dreamine.Identity.Options;

/// <summary>
/// \brief OAuth 로그인 프로바이더 자격증명 옵션입니다.
/// </summary>
/// <remarks>
/// 실제 값은 <c>appsettings.Local.json</c>, <c>dotnet user-secrets</c>,
/// 또는 배포 환경변수로 주입합니다.
/// </remarks>
public sealed class AuthOptions
{
    /// <summary>\brief 구성 섹션 이름입니다.</summary>
    public const string SectionName = "Authentication";

    /// <summary>\brief Google OAuth 자격증명입니다.</summary>
    public OAuthProviderOptions Google { get; set; } = new();

    /// <summary>\brief Naver OAuth 자격증명입니다.</summary>
    public OAuthProviderOptions Naver { get; set; } = new();

    /// <summary>\brief Kakao OAuth 자격증명입니다. 현재는 설정 슬롯만 제공합니다.</summary>
    public OAuthProviderOptions Kakao { get; set; } = new();

    /// <summary>\brief 서브도메인 간 로그인 공유용 쿠키 도메인입니다. 예: .codemaru.co.kr</summary>
    public string CookieDomain { get; set; } = string.Empty;

    /// <summary>\brief 서브도메인 앱들이 공유할 인증 쿠키 이름입니다.</summary>
    public string CookieName { get; set; } = ".Dreamine.Identity";

    /// <summary>\brief 여러 프로세스가 같은 인증 쿠키를 복호화하기 위한 DataProtection 키 폴더입니다.</summary>
    public string DataProtectionKeysPath { get; set; } = string.Empty;

    /// <summary>\brief DataProtection 격리 이름입니다. 모든 공유 로그인 앱에서 같은 값을 사용합니다.</summary>
    public string DataProtectionApplicationName { get; set; } = "Dreamine.Identity";
}

/// <summary>
/// \brief 개별 OAuth 프로바이더 자격증명입니다.
/// </summary>
public sealed class OAuthProviderOptions
{
    /// <summary>\brief 프로바이더에서 발급한 Client ID 입니다.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>\brief 프로바이더에서 발급한 Client Secret 입니다.</summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>\brief 자격증명이 모두 채워져 있는지 여부입니다.</summary>
    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(ClientId) && !string.IsNullOrWhiteSpace(ClientSecret);
}
