namespace Dreamine.Identity;

/// <summary>중앙 Dreamine Identity 포털 URL을 생성합니다.</summary>
public static class DreamineIdentityPortal
{
    /// <summary>운영 환경의 중앙 Identity 포털 주소입니다.</summary>
    public const string BaseUrl = "https://codemaru.co.kr/_identity";

    /// <summary>중앙 로그인, 계정 또는 로그아웃 URL을 생성합니다.</summary>
    public static string CreateUrl(string action, string returnUrl, string? language = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(action);
        ArgumentException.ThrowIfNullOrWhiteSpace(returnUrl);

        var url = $"{BaseUrl}/{Uri.EscapeDataString(action)}";
        if (!string.IsNullOrWhiteSpace(language))
        {
            url += $"?lang={Uri.EscapeDataString(language)}&";
        }
        else
        {
            url += "?";
        }

        return url + $"returnUrl={Uri.EscapeDataString(returnUrl)}";
    }
}
