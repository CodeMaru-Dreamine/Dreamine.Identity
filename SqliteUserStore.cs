using Dreamine.Database.Abstractions;
using Dreamine.Identity.Models;
using System.Security.Cryptography;

namespace Dreamine.Identity;

/// <summary>
/// \brief SQLite 기반 <see cref="IUserStore"/> 구현입니다.
/// </summary>
public sealed class SqliteUserStore : IUserStore
{
    private const string SelectSql =
        "SELECT Id, Provider, ProviderKey, Email, DisplayName, AvatarUrl, PasswordHash, " +
        "TermsAcceptedAtUtc, TermsVersion, PrivacyAcceptedAtUtc, PrivacyVersion, MinimumAgeConfirmedAtUtc, " +
        "CreatedAt, LastLoginAt " +
        "FROM Users WHERE Provider = @Provider AND ProviderKey = @ProviderKey LIMIT 1";

    private const string LocalProvider = "Local";
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const int Iterations = 210_000;

    private readonly IDatabaseProvider _database;

    public SqliteUserStore(IDatabaseProvider database)
    {
        _database = database ?? throw new ArgumentNullException(nameof(database));
        _database.CreateTable<AuthUser>();
        EnsureSchema();
    }

    public async Task<AuthUser> UpsertAsync(
        string provider,
        string providerKey,
        string email,
        string displayName,
        string avatarUrl,
        RegistrationConsent? registrationConsent = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(provider);
        ArgumentException.ThrowIfNullOrWhiteSpace(providerKey);

        var now = DateTime.UtcNow;
        var existing = (await _database.QueryAsync<AuthUser>(
            SelectSql,
            new { Provider = provider, ProviderKey = providerKey },
            cancellationToken).ConfigureAwait(false)).FirstOrDefault();

        if (existing is not null)
        {
            existing.Email = email ?? string.Empty;
            existing.DisplayName = displayName ?? string.Empty;
            existing.AvatarUrl = avatarUrl ?? string.Empty;
            existing.LastLoginAt = now;
            if (registrationConsent is not null && existing.TermsAcceptedAtUtc is null)
            {
                ApplyRegistrationConsent(existing, registrationConsent);
            }
            await _database.UpdateAsync(existing, cancellationToken).ConfigureAwait(false);
            return existing;
        }

        ValidateRegistrationConsent(registrationConsent);
        var created = new AuthUser
        {
            Provider = provider,
            ProviderKey = providerKey,
            Email = email ?? string.Empty,
            DisplayName = displayName ?? string.Empty,
            AvatarUrl = avatarUrl ?? string.Empty,
            PasswordHash = string.Empty,
            CreatedAt = now,
            LastLoginAt = now
        };
        ApplyRegistrationConsent(created, registrationConsent!);

        await _database.InsertAsync(created, cancellationToken).ConfigureAwait(false);

        return (await _database.QueryAsync<AuthUser>(
            SelectSql,
            new { Provider = provider, ProviderKey = providerKey },
            cancellationToken).ConfigureAwait(false)).First();
    }

    public async Task<AuthUser?> FindByProviderAsync(
        string provider,
        string providerKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(provider);
        ArgumentException.ThrowIfNullOrWhiteSpace(providerKey);
        return (await _database.QueryAsync<AuthUser>(
            SelectSql,
            new { Provider = provider, ProviderKey = providerKey },
            cancellationToken).ConfigureAwait(false)).FirstOrDefault();
    }

    public async Task<AuthUser?> GetByIdAsync(long id, CancellationToken cancellationToken = default)
    {
        var rows = await _database.QueryAsync<AuthUser>(
            "SELECT Id, Provider, ProviderKey, Email, DisplayName, AvatarUrl, PasswordHash, " +
            "TermsAcceptedAtUtc, TermsVersion, PrivacyAcceptedAtUtc, PrivacyVersion, MinimumAgeConfirmedAtUtc, " +
            "CreatedAt, LastLoginAt " +
            "FROM Users WHERE Id = @Id LIMIT 1",
            new { Id = id },
            cancellationToken).ConfigureAwait(false);

        return rows.FirstOrDefault();
    }

    public async Task<AuthUser?> UpdateDisplayNameAsync(
        long id,
        string displayName,
        CancellationToken cancellationToken = default)
    {
        var user = await GetByIdAsync(id, cancellationToken).ConfigureAwait(false);
        if (user is null)
        {
            return null;
        }

        displayName = displayName.Trim();
        if (string.IsNullOrWhiteSpace(displayName))
        {
            throw new InvalidOperationException("표시 이름을 입력해 주세요.");
        }

        user.DisplayName = displayName;
        await _database.UpdateAsync(user, cancellationToken).ConfigureAwait(false);
        return user;
    }

    public async Task<AuthUser?> ChangeLocalPasswordAsync(
        long id,
        string currentPassword,
        string newPassword,
        CancellationToken cancellationToken = default)
    {
        var user = await GetByIdAsync(id, cancellationToken).ConfigureAwait(false);
        if (user is null)
        {
            return null;
        }

        if (!string.Equals(user.Provider, LocalProvider, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("소셜 로그인 계정의 비밀번호는 해당 로그인 제공자에서 관리됩니다.");
        }

        if (!VerifyPassword(currentPassword, user.PasswordHash))
        {
            throw new InvalidOperationException("현재 비밀번호가 올바르지 않습니다.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(newPassword);
        if (newPassword.Length < 8)
        {
            throw new InvalidOperationException("새 비밀번호는 8자 이상이어야 합니다.");
        }

        user.PasswordHash = HashPassword(newPassword);
        await _database.UpdateAsync(user, cancellationToken).ConfigureAwait(false);
        return user;
    }

    public async Task<AuthUser> CreateLocalAsync(
        string email,
        string displayName,
        string password,
        RegistrationConsent registrationConsent,
        CancellationToken cancellationToken = default)
    {
        ValidateRegistrationConsent(registrationConsent);
        email = NormalizeEmail(email);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        if (password.Length < 8)
        {
            throw new InvalidOperationException("비밀번호는 8자 이상이어야 합니다.");
        }

        var existing = await FindLocalByEmailAsync(email, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
        {
            throw new InvalidOperationException("이미 가입된 이메일입니다.");
        }

        var now = DateTime.UtcNow;
        var user = new AuthUser
        {
            Provider = LocalProvider,
            ProviderKey = email,
            Email = email,
            DisplayName = string.IsNullOrWhiteSpace(displayName) ? email : displayName.Trim(),
            AvatarUrl = string.Empty,
            PasswordHash = HashPassword(password),
            CreatedAt = now,
            LastLoginAt = now
        };
        ApplyRegistrationConsent(user, registrationConsent);

        await _database.InsertAsync(user, cancellationToken).ConfigureAwait(false);

        return (await FindLocalByEmailAsync(email, cancellationToken).ConfigureAwait(false))!;
    }

    public async Task<AuthUser?> ValidateLocalAsync(
        string email,
        string password,
        CancellationToken cancellationToken = default)
    {
        email = NormalizeEmail(email);
        var user = await FindLocalByEmailAsync(email, cancellationToken).ConfigureAwait(false);
        if (user is null || !VerifyPassword(password, user.PasswordHash))
        {
            return null;
        }

        user.LastLoginAt = DateTime.UtcNow;
        await _database.UpdateAsync(user, cancellationToken).ConfigureAwait(false);
        return user;
    }

    private async Task<AuthUser?> FindLocalByEmailAsync(
        string email,
        CancellationToken cancellationToken)
    {
        var rows = await _database.QueryAsync<AuthUser>(
            "SELECT Id, Provider, ProviderKey, Email, DisplayName, AvatarUrl, PasswordHash, " +
            "TermsAcceptedAtUtc, TermsVersion, PrivacyAcceptedAtUtc, PrivacyVersion, MinimumAgeConfirmedAtUtc, " +
            "CreatedAt, LastLoginAt " +
            "FROM Users WHERE Provider = @Provider AND ProviderKey = @ProviderKey LIMIT 1",
            new { Provider = LocalProvider, ProviderKey = email },
            cancellationToken).ConfigureAwait(false);

        return rows.FirstOrDefault();
    }

    private void EnsureSchema()
    {
        var columns = _database.Query<TableColumn>("PRAGMA table_info(Users)")
            .Select(column => column.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (!columns.Contains(nameof(AuthUser.PasswordHash)))
        {
            _database.ExecuteNonQuery("ALTER TABLE Users ADD COLUMN PasswordHash TEXT NOT NULL DEFAULT ''");
        }

        AddColumnIfMissing(columns, nameof(AuthUser.TermsAcceptedAtUtc), "TEXT NULL");
        AddColumnIfMissing(columns, nameof(AuthUser.TermsVersion), "TEXT NOT NULL DEFAULT ''");
        AddColumnIfMissing(columns, nameof(AuthUser.PrivacyAcceptedAtUtc), "TEXT NULL");
        AddColumnIfMissing(columns, nameof(AuthUser.PrivacyVersion), "TEXT NOT NULL DEFAULT ''");
        AddColumnIfMissing(columns, nameof(AuthUser.MinimumAgeConfirmedAtUtc), "TEXT NULL");
    }

    private void AddColumnIfMissing(ISet<string> columns, string name, string sqlType)
    {
        if (!columns.Contains(name))
        {
            _database.ExecuteNonQuery($"ALTER TABLE Users ADD COLUMN {name} {sqlType}");
            columns.Add(name);
        }
    }

    private static void ValidateRegistrationConsent(RegistrationConsent? consent)
    {
        if (consent is null
            || consent.TermsAcceptedAtUtc == default
            || consent.PrivacyAcceptedAtUtc == default
            || consent.MinimumAgeConfirmedAtUtc == default
            || !string.Equals(consent.TermsVersion, IdentityConsentPolicy.CurrentTermsVersion, StringComparison.Ordinal)
            || !string.Equals(consent.PrivacyVersion, IdentityConsentPolicy.CurrentPrivacyVersion, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("필수 약관 동의와 만 14세 이상 확인이 필요합니다.");
        }
    }

    private static void ApplyRegistrationConsent(AuthUser user, RegistrationConsent consent)
    {
        user.TermsAcceptedAtUtc = consent.TermsAcceptedAtUtc;
        user.TermsVersion = consent.TermsVersion;
        user.PrivacyAcceptedAtUtc = consent.PrivacyAcceptedAtUtc;
        user.PrivacyVersion = consent.PrivacyVersion;
        user.MinimumAgeConfirmedAtUtc = consent.MinimumAgeConfirmedAtUtc;
    }

    private static string NormalizeEmail(string email)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        return email.Trim().ToLowerInvariant();
    }

    private static string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            Iterations,
            HashAlgorithmName.SHA256,
            HashSize);

        return string.Join(
            '.',
            "v1",
            Iterations.ToString(System.Globalization.CultureInfo.InvariantCulture),
            Convert.ToBase64String(salt),
            Convert.ToBase64String(hash));
    }

    private static bool VerifyPassword(string password, string storedHash)
    {
        var parts = storedHash.Split('.');
        if (parts.Length != 4 || parts[0] != "v1")
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

        var salt = Convert.FromBase64String(parts[2]);
        var expected = Convert.FromBase64String(parts[3]);
        var actual = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            expected.Length);

        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private sealed class TableColumn
    {
        public string Name { get; set; } = string.Empty;
    }
}
