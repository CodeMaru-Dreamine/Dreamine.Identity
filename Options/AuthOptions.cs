namespace Dreamine.Identity.Options;

/// <summary>
/// \if KO
/// <para>OAuth 로그인 공급자와 공유 인증 쿠키의 구성 옵션입니다.</para>
/// \endif
/// \if EN
/// <para>Represents configuration options for OAuth login providers and the shared authentication cookie.</para>
/// \endif
/// </summary>
/// <remarks>
/// \if KO
/// <para>실제 자격 증명은 appsettings.Local.json, 사용자 비밀 또는 배포 환경 변수로 주입합니다.</para>
/// \endif
/// \if EN
/// <para>Supply real credentials through appsettings.Local.json, user secrets, or deployment environment variables.</para>
/// \endif
/// </remarks>
public sealed class AuthOptions
{
    /// <summary>
    /// \if KO
    /// <para>기본 구성 섹션 이름을 가져옵니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets the default configuration-section name.</para>
    /// \endif
    /// </summary>
    public const string SectionName = "Authentication";

    /// <summary>
    /// \if KO
    /// <para>Google OAuth 자격 증명을 가져오거나 설정합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets or sets the Google OAuth credentials.</para>
    /// \endif
    /// </summary>
    public OAuthProviderOptions Google { get; set; } = new();

    /// <summary>
    /// \if KO
    /// <para>Naver OAuth 자격 증명을 가져오거나 설정합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets or sets the Naver OAuth credentials.</para>
    /// \endif
    /// </summary>
    public OAuthProviderOptions Naver { get; set; } = new();

    /// <summary>
    /// \if KO
    /// <para>Kakao OAuth 자격 증명을 가져오거나 설정합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets or sets the Kakao OAuth credentials.</para>
    /// \endif
    /// </summary>
    public OAuthProviderOptions Kakao { get; set; } = new();

    /// <summary>
    /// \if KO
    /// <para>서브도메인 간 로그인 공유용 쿠키 도메인을 가져오거나 설정합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets or sets the cookie domain used to share login across subdomains.</para>
    /// \endif
    /// </summary>
    public string CookieDomain { get; set; } = string.Empty;

    /// <summary>
    /// \if KO
    /// <para>서브도메인 애플리케이션이 공유할 인증 쿠키 이름을 가져오거나 설정합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets or sets the authentication-cookie name shared by subdomain applications.</para>
    /// \endif
    /// </summary>
    public string CookieName { get; set; } = ".Dreamine.Identity";

    /// <summary>
    /// \if KO
    /// <para>여러 프로세스가 동일한 인증 쿠키를 해독하는 데 사용할 Data Protection 키 디렉터리를 가져오거나 설정합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets or sets the Data Protection key directory used by multiple processes to decrypt the same authentication cookie.</para>
    /// \endif
    /// </summary>
    public string DataProtectionKeysPath { get; set; } = string.Empty;

    /// <summary>
    /// \if KO
    /// <para>공유 로그인 애플리케이션이 동일하게 사용해야 하는 Data Protection 애플리케이션 이름을 가져오거나 설정합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets or sets the Data Protection application name that must match across shared-login applications.</para>
    /// \endif
    /// </summary>
    public string DataProtectionApplicationName { get; set; } = "Dreamine.Identity";
}

/// <summary>
/// \if KO
/// <para>개별 OAuth 공급자의 클라이언트 자격 증명을 나타냅니다.</para>
/// \endif
/// \if EN
/// <para>Represents client credentials for an individual OAuth provider.</para>
/// \endif
/// </summary>
public sealed class OAuthProviderOptions
{
    /// <summary>
    /// \if KO
    /// <para>공급자가 발급한 클라이언트 ID를 가져오거나 설정합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets or sets the client ID issued by the provider.</para>
    /// \endif
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// \if KO
    /// <para>공급자가 발급한 클라이언트 비밀을 가져오거나 설정합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets or sets the client secret issued by the provider.</para>
    /// \endif
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// \if KO
    /// <para>클라이언트 ID와 비밀이 모두 구성되었는지 여부를 가져옵니다.</para>
    /// \endif
    /// \if EN
    /// <para>Gets whether both the client ID and client secret are configured.</para>
    /// \endif
    /// </summary>
    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(ClientId) && !string.IsNullOrWhiteSpace(ClientSecret);
}
