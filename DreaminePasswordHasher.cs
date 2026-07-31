using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Dreamine.Identity;

/// <summary>Provides versioned PBKDF2 password hashing shared by Dreamine services.</summary>
public static class DreaminePasswordHasher
{
    private const string Version = "v1";
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const int CurrentIterations = 600_000;

    public static string HashPassword(string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, CurrentIterations, HashAlgorithmName.SHA256, HashSize);
        return string.Join('.', Version, CurrentIterations.ToString(CultureInfo.InvariantCulture), Convert.ToBase64String(salt), Convert.ToBase64String(hash));
    }

    public static PasswordHashVerificationResult VerifyPassword(string password, string storedHash, out string? upgradedHash)
    {
        upgradedHash = null;
        if (string.IsNullOrEmpty(password) || string.IsNullOrWhiteSpace(storedHash))
            return PasswordHashVerificationResult.Failed;

        if (VerifyPbkdf2(password, storedHash, out var needsRehash))
        {
            if (!needsRehash) return PasswordHashVerificationResult.Success;
            upgradedHash = HashPassword(password);
            return PasswordHashVerificationResult.SuccessRehashNeeded;
        }

        if (!VerifyLegacySha256(password, storedHash) && !FixedTimeEquals(password, storedHash))
            return PasswordHashVerificationResult.Failed;

        upgradedHash = HashPassword(password);
        return PasswordHashVerificationResult.SuccessRehashNeeded;
    }

    public static bool VerifyPassword(string password, string storedHash) =>
        VerifyPassword(password, storedHash, out _) is not PasswordHashVerificationResult.Failed;

    public static string HashPlainTextForStorage(string passwordOrHash)
    {
        if (string.IsNullOrWhiteSpace(passwordOrHash) || IsDreamineHash(passwordOrHash) || IsLegacySha256Hash(passwordOrHash))
            return passwordOrHash;
        return HashPassword(passwordOrHash);
    }

    public static bool IsDreamineHash(string value) => value.StartsWith($"{Version}.", StringComparison.Ordinal);

    private static bool VerifyPbkdf2(string password, string storedHash, out bool needsRehash)
    {
        needsRehash = false;
        var parts = storedHash.Split('.');
        if (parts.Length != 4 || parts[0] != Version ||
            !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var iterations)) return false;
        try
        {
            var salt = Convert.FromBase64String(parts[2]);
            var expected = Convert.FromBase64String(parts[3]);
            var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
            var verified = CryptographicOperations.FixedTimeEquals(actual, expected);
            needsRehash = verified && iterations < CurrentIterations;
            return verified;
        }
        catch (FormatException) { return false; }
        catch (ArgumentException) { return false; }
    }

    private static bool VerifyLegacySha256(string password, string storedHash)
    {
        if (!IsLegacySha256Hash(storedHash)) return false;
        var actual = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(password))).ToLowerInvariant();
        return FixedTimeEquals(actual, storedHash.ToLowerInvariant());
    }

    private static bool IsLegacySha256Hash(string value) => value.Length == 64 && value.All(Uri.IsHexDigit);

    private static bool FixedTimeEquals(string left, string right)
    {
        var leftBytes = Encoding.UTF8.GetBytes(left);
        var rightBytes = Encoding.UTF8.GetBytes(right);
        return leftBytes.Length == rightBytes.Length && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }
}

public enum PasswordHashVerificationResult
{
    Failed,
    Success,
    SuccessRehashNeeded
}
