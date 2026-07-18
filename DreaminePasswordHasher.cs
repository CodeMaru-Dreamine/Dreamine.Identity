using System.Security.Cryptography;
using System.Text;

namespace Dreamine.Identity;

/// <summary>
/// \if KO
/// <para>Dreamine 계열 서비스가 공통으로 사용하는 버전 지정 PBKDF2 비밀번호 해시 기능을 제공합니다.</para>
/// \endif
/// \if EN
/// <para>Provides versioned PBKDF2 password hashing shared by Dreamine services.</para>
/// \endif
/// </summary>
public static class DreaminePasswordHasher
{
    /// <summary>
    /// \if KO
    /// <para>Version 값을 보관합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Stores the version value.</para>
    /// \endif
    /// </summary>
    private const string Version = "v1";
    /// <summary>
    /// \if KO
    /// <para>Salt Size 값을 보관합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Stores the salt size value.</para>
    /// \endif
    /// </summary>
    private const int SaltSize = 16;
    /// <summary>
    /// \if KO
    /// <para>Hash Size 값을 보관합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Stores the hash size value.</para>
    /// \endif
    /// </summary>
    private const int HashSize = 32;
    /// <summary>
    /// \if KO
    /// <para>Current Iterations 값을 보관합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Stores the current iterations value.</para>
    /// \endif
    /// </summary>
    private const int CurrentIterations = 600_000;

    /// <summary>
    /// \if KO
    /// <para>임의 솔트와 현재 반복 횟수를 사용하여 비밀번호를 PBKDF2-SHA256 형식으로 해시합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Hashes a password in the PBKDF2-SHA256 format using a random salt and the current iteration count.</para>
    /// \endif
    /// </summary>
    /// <param name="password">
    /// \if KO
    /// <para>해시할 평문 비밀번호입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The plain-text password to hash.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>버전, 반복 횟수, 솔트 및 해시를 포함한 저장 문자열입니다.</para>
    /// \endif
    /// \if EN
    /// <para>A storage string containing the version, iteration count, salt, and hash.</para>
    /// \endif
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// \if KO
    /// <para><paramref name="password"/>가 <see langword="null"/>인 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when <paramref name="password"/> is <see langword="null"/>.</para>
    /// \endif
    /// </exception>
    /// <exception cref="ArgumentException">
    /// \if KO
    /// <para><paramref name="password"/>가 비어 있거나 공백인 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when <paramref name="password"/> is empty or white space.</para>
    /// \endif
    /// </exception>
    public static string HashPassword(string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            CurrentIterations,
            HashAlgorithmName.SHA256,
            HashSize);

        return string.Join(
            '.',
            Version,
            CurrentIterations.ToString(System.Globalization.CultureInfo.InvariantCulture),
            Convert.ToBase64String(salt),
            Convert.ToBase64String(hash));
    }

    /// <summary>
    /// \if KO
    /// <para>PBKDF2, 레거시 SHA-256 또는 이전 평문 저장값과 비밀번호를 비교하고 필요하면 새 해시를 제공합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Verifies a password against PBKDF2, legacy SHA-256, or former plain-text storage and supplies an upgraded hash when needed.</para>
    /// \endif
    /// </summary>
    /// <param name="password">
    /// \if KO
    /// <para>검증할 평문 비밀번호입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The plain-text password to verify.</para>
    /// \endif
    /// </param>
    /// <param name="storedHash">
    /// \if KO
    /// <para>저장된 해시 또는 레거시 값입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The stored hash or legacy value.</para>
    /// \endif
    /// </param>
    /// <param name="upgradedHash">
    /// \if KO
    /// <para>재해시가 필요하면 새 PBKDF2 해시를 받습니다.</para>
    /// \endif
    /// \if EN
    /// <para>Receives a new PBKDF2 hash when rehashing is required.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>실패, 성공 또는 재해시 필요 상태입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The failed, successful, or rehash-required verification state.</para>
    /// \endif
    /// </returns>
    public static PasswordHashVerificationResult VerifyPassword(
        string password,
        string storedHash,
        out string? upgradedHash)
    {
        upgradedHash = null;

        if (string.IsNullOrEmpty(password) || string.IsNullOrWhiteSpace(storedHash))
        {
            return PasswordHashVerificationResult.Failed;
        }

        var pbkdf2Result = VerifyPbkdf2(password, storedHash, out var needsRehash);
        if (pbkdf2Result)
        {
            if (needsRehash)
            {
                upgradedHash = HashPassword(password);
                return PasswordHashVerificationResult.SuccessRehashNeeded;
            }

            return PasswordHashVerificationResult.Success;
        }

        if (VerifyLegacySha256(password, storedHash) || FixedTimeEquals(password, storedHash))
        {
            upgradedHash = HashPassword(password);
            return PasswordHashVerificationResult.SuccessRehashNeeded;
        }

        return PasswordHashVerificationResult.Failed;
    }

    /// <summary>
    /// \if KO
    /// <para>비밀번호가 저장된 값과 일치하는지 확인합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Determines whether a password matches the stored value.</para>
    /// \endif
    /// </summary>
    /// <param name="password">
    /// \if KO
    /// <para>검증할 평문 비밀번호입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The plain-text password to verify.</para>
    /// \endif
    /// </param>
    /// <param name="storedHash">
    /// \if KO
    /// <para>저장된 해시 또는 레거시 값입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The stored hash or legacy value.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>일치하면 <see langword="true"/>, 그렇지 않으면 <see langword="false"/>입니다.</para>
    /// \endif
    /// \if EN
    /// <para><see langword="true"/> when the password matches; otherwise, <see langword="false"/>.</para>
    /// \endif
    /// </returns>
    public static bool VerifyPassword(string password, string storedHash) =>
        VerifyPassword(password, storedHash, out _) is not PasswordHashVerificationResult.Failed;

    /// <summary>
    /// \if KO
    /// <para>입력이 이미 지원되는 해시가 아니면 저장용 PBKDF2 해시로 변환합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Converts input to a PBKDF2 storage hash unless it is already a supported hash.</para>
    /// \endif
    /// </summary>
    /// <param name="passwordOrHash">
    /// \if KO
    /// <para>평문 비밀번호 또는 기존 해시입니다.</para>
    /// \endif
    /// \if EN
    /// <para>A plain-text password or existing hash.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>그대로 유지한 기존 해시 또는 새 PBKDF2 해시입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The preserved existing hash or a new PBKDF2 hash.</para>
    /// \endif
    /// </returns>
    public static string HashPlainTextForStorage(string passwordOrHash)
    {
        if (string.IsNullOrWhiteSpace(passwordOrHash) ||
            IsDreamineHash(passwordOrHash) ||
            IsLegacySha256Hash(passwordOrHash))
        {
            return passwordOrHash;
        }

        return HashPassword(passwordOrHash);
    }

    /// <summary>
    /// \if KO
    /// <para>값이 현재 Dreamine 버전 지정 해시 접두사로 시작하는지 확인합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Determines whether a value starts with the current versioned Dreamine hash prefix.</para>
    /// \endif
    /// </summary>
    /// <param name="value">
    /// \if KO
    /// <para>검사할 값입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The value to inspect.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>Dreamine 해시 형식이면 <see langword="true"/>입니다.</para>
    /// \endif
    /// \if EN
    /// <para><see langword="true"/> when the value has the Dreamine hash format.</para>
    /// \endif
    /// </returns>
    public static bool IsDreamineHash(string value) =>
        value.StartsWith($"{Version}.", StringComparison.Ordinal);

    /// <summary>
    /// \if KO
    /// <para>버전 지정 PBKDF2 저장 문자열을 구문 분석하고 고정 시간으로 검증합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Parses and fixed-time verifies a versioned PBKDF2 storage string.</para>
    /// \endif
    /// </summary>
    /// <param name="password">
    /// \if KO
    /// <para>평문 비밀번호입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The plain-text password.</para>
    /// \endif
    /// </param>
    /// <param name="storedHash">
    /// \if KO
    /// <para>저장된 PBKDF2 문자열입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The stored PBKDF2 string.</para>
    /// \endif
    /// </param>
    /// <param name="needsRehash">
    /// \if KO
    /// <para>검증 성공 후 반복 횟수 업그레이드가 필요한지 받습니다.</para>
    /// \endif
    /// \if EN
    /// <para>Receives whether the iteration count needs upgrading after successful verification.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>해시가 일치하면 <see langword="true"/>입니다.</para>
    /// \endif
    /// \if EN
    /// <para><see langword="true"/> when the hash matches.</para>
    /// \endif
    /// </returns>
    private static bool VerifyPbkdf2(string password, string storedHash, out bool needsRehash)
    {
        needsRehash = false;

        var parts = storedHash.Split('.');
        if (parts.Length != 4 || parts[0] != Version)
        {
            return false;
        }

        if (!int.TryParse(
                parts[1],
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var iterations))
        {
            return false;
        }

        try
        {
            var salt = Convert.FromBase64String(parts[2]);
            var expected = Convert.FromBase64String(parts[3]);
            var actual = Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                iterations,
                HashAlgorithmName.SHA256,
                expected.Length);

            var verified = CryptographicOperations.FixedTimeEquals(actual, expected);
            needsRehash = verified && iterations < CurrentIterations;
            return verified;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <summary>
    /// \if KO
    /// <para>비밀번호를 레거시 소문자 SHA-256 16진수 해시와 비교합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Compares a password with a legacy lowercase SHA-256 hexadecimal hash.</para>
    /// \endif
    /// </summary>
    /// <param name="password">
    /// \if KO
    /// <para>평문 비밀번호입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The plain-text password.</para>
    /// \endif
    /// </param>
    /// <param name="storedHash">
    /// \if KO
    /// <para>저장된 레거시 해시입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The stored legacy hash.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>일치하면 <see langword="true"/>입니다.</para>
    /// \endif
    /// \if EN
    /// <para><see langword="true"/> when the values match.</para>
    /// \endif
    /// </returns>
    private static bool VerifyLegacySha256(string password, string storedHash)
    {
        if (!IsLegacySha256Hash(storedHash))
        {
            return false;
        }

        var actual = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(password))).ToLowerInvariant();
        return FixedTimeEquals(actual, storedHash.ToLowerInvariant());
    }

    /// <summary>
    /// \if KO
    /// <para>값이 64자 SHA-256 16진수 형식인지 확인합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Determines whether a value has the 64-character SHA-256 hexadecimal form.</para>
    /// \endif
    /// </summary>
    /// <param name="storedHash">
    /// \if KO
    /// <para>검사할 값입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The value to inspect.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>레거시 형식이면 <see langword="true"/>입니다.</para>
    /// \endif
    /// \if EN
    /// <para><see langword="true"/> for the legacy format.</para>
    /// \endif
    /// </returns>
    private static bool IsLegacySha256Hash(string storedHash) =>
        storedHash.Length == 64 && storedHash.All(Uri.IsHexDigit);

    /// <summary>
    /// \if KO
    /// <para>UTF-8 문자열을 길이 노출을 최소화하는 고정 시간 비교로 검사합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Compares UTF-8 strings using fixed-time byte comparison after a length check.</para>
    /// \endif
    /// </summary>
    /// <param name="left">
    /// \if KO
    /// <para>첫 번째 값입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The first value.</para>
    /// \endif
    /// </param>
    /// <param name="right">
    /// \if KO
    /// <para>두 번째 값입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The second value.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>값이 같으면 <see langword="true"/>입니다.</para>
    /// \endif
    /// \if EN
    /// <para><see langword="true"/> when the values are equal.</para>
    /// \endif
    /// </returns>
    private static bool FixedTimeEquals(string left, string right)
    {
        var leftBytes = Encoding.UTF8.GetBytes(left);
        var rightBytes = Encoding.UTF8.GetBytes(right);
        return leftBytes.Length == rightBytes.Length &&
               CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }
}

/// <summary>
/// \if KO
/// <para>비밀번호 해시 검증 결과와 재해시 필요 여부를 나타냅니다.</para>
/// \endif
/// \if EN
/// <para>Represents a password-hash verification result and whether rehashing is required.</para>
/// \endif
/// </summary>
public enum PasswordHashVerificationResult
{
    /// <summary>
    /// \if KO
    /// <para>비밀번호가 일치하지 않습니다.</para>
    /// \endif
    /// \if EN
    /// <para>The password does not match.</para>
    /// \endif
    /// </summary>
    Failed,
    /// <summary>
    /// \if KO
    /// <para>비밀번호가 일치하며 현재 형식입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The password matches and uses the current format.</para>
    /// \endif
    /// </summary>
    Success,
    /// <summary>
    /// \if KO
    /// <para>비밀번호는 일치하지만 새 형식으로 다시 해시해야 합니다.</para>
    /// \endif
    /// \if EN
    /// <para>The password matches but should be rehashed in the current format.</para>
    /// \endif
    /// </summary>
    SuccessRehashNeeded
}
