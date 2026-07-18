using Dreamine.Database.Abstractions;
using Dreamine.Identity.Models;

namespace Dreamine.Identity;

/// <summary>
/// \if KO
/// <para>Dreamine 데이터베이스 추상화를 사용하는 SQLite 기반 <see cref="IUserStore"/> 구현입니다.</para>
/// \endif
/// \if EN
/// <para>Provides a SQLite-backed <see cref="IUserStore"/> implementation using the Dreamine database abstractions.</para>
/// \endif
/// </summary>
public sealed class SqliteUserStore : IUserStore
{
    /// <summary>
    /// \if KO
    /// <para>Select Sql 값을 보관합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Stores the select sql value.</para>
    /// \endif
    /// </summary>
    private const string SelectSql =
        "SELECT Id, Provider, ProviderKey, Email, DisplayName, AvatarUrl, PasswordHash, " +
        "TermsAcceptedAtUtc, PrivacyPolicyAcceptedAtUtc, AgeConfirmedAtUtc, CreatedAt, LastLoginAt " +
        "FROM Users WHERE Provider = @Provider AND ProviderKey = @ProviderKey LIMIT 1";

    /// <summary>
    /// \if KO
    /// <para>Local Provider 값을 보관합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Stores the local provider value.</para>
    /// \endif
    /// </summary>
    private const string LocalProvider = "Local";

    /// <summary>
    /// \if KO
    /// <para>database 값을 보관합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Stores the database value.</para>
    /// \endif
    /// </summary>
    private readonly IDatabaseProvider _database;

    /// <summary>
    /// \if KO
    /// <para>데이터베이스 공급자로 저장소를 초기화하고 사용자 테이블과 필수 열을 보장합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Initializes the store with a database provider and ensures the user table and required columns.</para>
    /// \endif
    /// </summary>
    /// <param name="database">
    /// \if KO
    /// <para>사용자 데이터를 저장할 데이터베이스 공급자입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The database provider used to store user data.</para>
    /// \endif
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// \if KO
    /// <para><paramref name="database"/>가 <see langword="null"/>인 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when <paramref name="database"/> is <see langword="null"/>.</para>
    /// \endif
    /// </exception>
    public SqliteUserStore(IDatabaseProvider database)
    {
        _database = database ?? throw new ArgumentNullException(nameof(database));
        _database.CreateTable<AuthUser>();
        EnsureSchema();
    }

    /// <summary>
    /// \if KO
    /// <para>외부 공급자 키로 사용자를 추가하거나 프로필과 마지막 로그인 시각을 갱신합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Inserts a user by external provider key or updates the profile and last-login time.</para>
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
    /// <para>공급자 사용자 키입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The provider user key.</para>
    /// \endif
    /// </param>
    /// <param name="email">
    /// \if KO
    /// <para>사용자 이메일입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The user's email.</para>
    /// \endif
    /// </param>
    /// <param name="displayName">
    /// \if KO
    /// <para>사용자 표시 이름입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The user's display name.</para>
    /// \endif
    /// </param>
    /// <param name="avatarUrl">
    /// \if KO
    /// <para>프로필 이미지 URL입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The profile-image URL.</para>
    /// \endif
    /// </param>
    /// <param name="cancellationToken">
    /// \if KO
    /// <para>저장 취소 토큰입니다.</para>
    /// \endif
    /// \if EN
    /// <para>A token used to cancel persistence.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>저장된 최신 사용자 레코드입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The current persisted user record.</para>
    /// \endif
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// \if KO
    /// <para><paramref name="provider"/> 또는 <paramref name="providerKey"/>가 <see langword="null"/>인 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when <paramref name="provider"/> or <paramref name="providerKey"/> is <see langword="null"/>.</para>
    /// \endif
    /// </exception>
    /// <exception cref="ArgumentException">
    /// \if KO
    /// <para><paramref name="provider"/> 또는 <paramref name="providerKey"/>가 비어 있거나 공백인 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when <paramref name="provider"/> or <paramref name="providerKey"/> is empty or white space.</para>
    /// \endif
    /// </exception>
    public async Task<AuthUser> UpsertAsync(
        string provider,
        string providerKey,
        string email,
        string displayName,
        string avatarUrl,
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
            await _database.UpdateAsync(existing, cancellationToken).ConfigureAwait(false);
            return existing;
        }

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

        await _database.InsertAsync(created, cancellationToken).ConfigureAwait(false);

        return (await _database.QueryAsync<AuthUser>(
            SelectSql,
            new { Provider = provider, ProviderKey = providerKey },
            cancellationToken).ConfigureAwait(false)).First();
    }

    /// <summary>
    /// \if KO
    /// <para>내부 식별자로 사용자를 비동기 조회합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Asynchronously finds a user by internal identifier.</para>
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
    public async Task<AuthUser?> GetByIdAsync(long id, CancellationToken cancellationToken = default)
    {
        var rows = await _database.QueryAsync<AuthUser>(
            "SELECT Id, Provider, ProviderKey, Email, DisplayName, AvatarUrl, PasswordHash, " +
            "TermsAcceptedAtUtc, PrivacyPolicyAcceptedAtUtc, AgeConfirmedAtUtc, CreatedAt, LastLoginAt " +
            "FROM Users WHERE Id = @Id LIMIT 1",
            new { Id = id },
            cancellationToken).ConfigureAwait(false);

        return rows.FirstOrDefault();
    }

    /// <summary>
    /// \if KO
    /// <para>사용자의 공백 제거된 표시 이름을 갱신합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Updates a user's trimmed display name.</para>
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
    /// <para>갱신된 사용자 또는 없으면 <see langword="null"/>입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The updated user, or <see langword="null"/> when absent.</para>
    /// \endif
    /// </returns>
    /// <exception cref="NullReferenceException">
    /// \if KO
    /// <para><paramref name="displayName"/>이 <see langword="null"/>인 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when <paramref name="displayName"/> is <see langword="null"/>.</para>
    /// \endif
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// \if KO
    /// <para>공백을 제거한 표시 이름이 비어 있는 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when the trimmed display name is empty.</para>
    /// \endif
    /// </exception>
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

    /// <summary>
    /// \if KO
    /// <para>사용자의 세 필수 동의 시각을 동일한 UTC 값으로 기록합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Records the same UTC value for all three required user consents.</para>
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
    /// <para>동의를 수락한 UTC 시각입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The UTC acceptance time.</para>
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
    public async Task<AuthUser?> AcceptRequiredConsentsAsync(
        long id,
        DateTime acceptedAtUtc,
        CancellationToken cancellationToken = default)
    {
        var user = await GetByIdAsync(id, cancellationToken).ConfigureAwait(false);
        if (user is null)
        {
            return null;
        }

        user.TermsAcceptedAtUtc = acceptedAtUtc;
        user.PrivacyPolicyAcceptedAtUtc = acceptedAtUtc;
        user.AgeConfirmedAtUtc = acceptedAtUtc;
        await _database.UpdateAsync(user, cancellationToken).ConfigureAwait(false);
        return user;
    }

    /// <summary>
    /// \if KO
    /// <para>로컬 사용자의 현재 비밀번호를 검증하고 강도가 확인된 새 해시를 저장합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Verifies a local user's current password and stores a strength-checked new hash.</para>
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
    /// <exception cref="ArgumentNullException">
    /// \if KO
    /// <para><paramref name="newPassword"/>가 <see langword="null"/>인 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when <paramref name="newPassword"/> is <see langword="null"/>.</para>
    /// \endif
    /// </exception>
    /// <exception cref="ArgumentException">
    /// \if KO
    /// <para><paramref name="newPassword"/>가 비어 있거나 공백인 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when <paramref name="newPassword"/> is empty or white space.</para>
    /// \endif
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// \if KO
    /// <para>소셜 계정이거나 현재 비밀번호가 틀렸거나 새 비밀번호가 8자 미만인 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown for a social account, an incorrect current password, or a new password shorter than eight characters.</para>
    /// \endif
    /// </exception>
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

        if (!DreaminePasswordHasher.VerifyPassword(currentPassword, user.PasswordHash))
        {
            throw new InvalidOperationException("현재 비밀번호가 올바르지 않습니다.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(newPassword);
        if (newPassword.Length < 8)
        {
            throw new InvalidOperationException("새 비밀번호는 8자 이상이어야 합니다.");
        }

        user.PasswordHash = DreaminePasswordHasher.HashPassword(newPassword);
        await _database.UpdateAsync(user, cancellationToken).ConfigureAwait(false);
        return user;
    }

    /// <summary>
    /// \if KO
    /// <para>이메일을 정규화하고 중복 및 비밀번호 길이를 검증한 뒤 로컬 계정을 만듭니다.</para>
    /// \endif
    /// \if EN
    /// <para>Normalizes the email, validates uniqueness and password length, then creates a local account.</para>
    /// \endif
    /// </summary>
    /// <param name="email">
    /// \if KO
    /// <para>로컬 계정 이메일입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The local-account email.</para>
    /// \endif
    /// </param>
    /// <param name="displayName">
    /// \if KO
    /// <para>선택적 표시 이름이며 비어 있으면 이메일을 사용합니다.</para>
    /// \endif
    /// \if EN
    /// <para>The optional display name; the email is used when empty.</para>
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
    /// <para>데이터베이스에서 다시 읽은 생성 사용자입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The created user read back from the database.</para>
    /// \endif
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// \if KO
    /// <para><paramref name="email"/> 또는 <paramref name="password"/>가 <see langword="null"/>인 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when <paramref name="email"/> or <paramref name="password"/> is <see langword="null"/>.</para>
    /// \endif
    /// </exception>
    /// <exception cref="ArgumentException">
    /// \if KO
    /// <para><paramref name="email"/> 또는 <paramref name="password"/>가 비어 있거나 공백인 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when <paramref name="email"/> or <paramref name="password"/> is empty or white space.</para>
    /// \endif
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// \if KO
    /// <para>비밀번호가 8자 미만이거나 이메일이 이미 등록된 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when the password is shorter than eight characters or the email is already registered.</para>
    /// \endif
    /// </exception>
    public async Task<AuthUser> CreateLocalAsync(
        string email,
        string displayName,
        string password,
        CancellationToken cancellationToken = default)
    {
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
            PasswordHash = DreaminePasswordHasher.HashPassword(password),
            CreatedAt = now,
            LastLoginAt = now
        };

        await _database.InsertAsync(user, cancellationToken).ConfigureAwait(false);

        return (await FindLocalByEmailAsync(email, cancellationToken).ConfigureAwait(false))!;
    }

    /// <summary>
    /// \if KO
    /// <para>로컬 이메일과 비밀번호를 검증하고 마지막 로그인 및 필요한 해시 업그레이드를 저장합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Validates a local email and password, persisting the last-login time and any required hash upgrade.</para>
    /// \endif
    /// </summary>
    /// <param name="email">
    /// \if KO
    /// <para>정규화할 이메일입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The email to normalize.</para>
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
    /// <para>The authenticated user, or <see langword="null"/> on failure.</para>
    /// \endif
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// \if KO
    /// <para><paramref name="email"/>이 <see langword="null"/>인 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when <paramref name="email"/> is <see langword="null"/>.</para>
    /// \endif
    /// </exception>
    /// <exception cref="ArgumentException">
    /// \if KO
    /// <para><paramref name="email"/>이 비어 있거나 공백인 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when <paramref name="email"/> is empty or white space.</para>
    /// \endif
    /// </exception>
    public async Task<AuthUser?> ValidateLocalAsync(
        string email,
        string password,
        CancellationToken cancellationToken = default)
    {
        email = NormalizeEmail(email);
        var user = await FindLocalByEmailAsync(email, cancellationToken).ConfigureAwait(false);
        if (user is null)
        {
            return null;
        }

        var verification = DreaminePasswordHasher.VerifyPassword(password, user.PasswordHash, out var upgradedHash);
        if (verification is PasswordHashVerificationResult.Failed)
        {
            return null;
        }

        user.LastLoginAt = DateTime.UtcNow;
        if (verification is PasswordHashVerificationResult.SuccessRehashNeeded && upgradedHash is not null)
        {
            user.PasswordHash = upgradedHash;
        }

        await _database.UpdateAsync(user, cancellationToken).ConfigureAwait(false);
        return user;
    }

    /// <summary>
    /// \if KO
    /// <para>정규화된 이메일을 로컬 공급자 키로 사용해 사용자를 조회합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Finds a local user using the normalized email as the provider key.</para>
    /// \endif
    /// </summary>
    /// <param name="email">
    /// \if KO
    /// <para>정규화된 이메일입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The normalized email.</para>
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
    /// <para>찾은 로컬 사용자 또는 없으면 <see langword="null"/>입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The matching local user, or <see langword="null"/> when absent.</para>
    /// \endif
    /// </returns>
    private async Task<AuthUser?> FindLocalByEmailAsync(
        string email,
        CancellationToken cancellationToken)
    {
        var rows = await _database.QueryAsync<AuthUser>(
            "SELECT Id, Provider, ProviderKey, Email, DisplayName, AvatarUrl, PasswordHash, " +
            "TermsAcceptedAtUtc, PrivacyPolicyAcceptedAtUtc, AgeConfirmedAtUtc, CreatedAt, LastLoginAt " +
            "FROM Users WHERE Provider = @Provider AND ProviderKey = @ProviderKey LIMIT 1",
            new { Provider = LocalProvider, ProviderKey = email },
            cancellationToken).ConfigureAwait(false);

        return rows.FirstOrDefault();
    }

    /// <summary>
    /// \if KO
    /// <para>기존 Users 테이블에 비밀번호 및 필수 동의 열이 존재하도록 마이그레이션합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Migrates an existing Users table to ensure password and required-consent columns exist.</para>
    /// \endif
    /// </summary>
    private void EnsureSchema()
    {
        var columns = _database.Query<TableColumn>("PRAGMA table_info(Users)")
            .Select(column => column.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (!columns.Contains(nameof(AuthUser.PasswordHash)))
        {
            _database.ExecuteNonQuery("ALTER TABLE Users ADD COLUMN PasswordHash TEXT NOT NULL DEFAULT ''");
        }

        AddNullableDateColumnIfMissing(columns, nameof(AuthUser.TermsAcceptedAtUtc));
        AddNullableDateColumnIfMissing(columns, nameof(AuthUser.PrivacyPolicyAcceptedAtUtc));
        AddNullableDateColumnIfMissing(columns, nameof(AuthUser.AgeConfirmedAtUtc));
    }

    /// <summary>
    /// \if KO
    /// <para>열 집합에 없으면 nullable 날짜 텍스트 열을 Users 테이블에 추가합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Adds a nullable date-text column to Users when it is absent from the column set.</para>
    /// \endif
    /// </summary>
    /// <param name="columns">
    /// \if KO
    /// <para>현재 열 이름 집합입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The current set of column names.</para>
    /// \endif
    /// </param>
    /// <param name="columnName">
    /// \if KO
    /// <para>확인하고 추가할 열 이름입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The column name to check and add.</para>
    /// \endif
    /// </param>
    private void AddNullableDateColumnIfMissing(HashSet<string> columns, string columnName)
    {
        if (!columns.Contains(columnName))
        {
            _database.ExecuteNonQuery($"ALTER TABLE Users ADD COLUMN {columnName} TEXT NULL");
        }
    }

    /// <summary>
    /// \if KO
    /// <para>이메일 양끝 공백을 제거하고 소문자 불변 문화권 형식으로 정규화합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Normalizes an email by trimming it and converting it to invariant lowercase.</para>
    /// \endif
    /// </summary>
    /// <param name="email">
    /// \if KO
    /// <para>정규화할 이메일입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The email to normalize.</para>
    /// \endif
    /// </param>
    /// <returns>
    /// \if KO
    /// <para>정규화된 이메일입니다.</para>
    /// \endif
    /// \if EN
    /// <para>The normalized email.</para>
    /// \endif
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// \if KO
    /// <para><paramref name="email"/>이 <see langword="null"/>인 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when <paramref name="email"/> is <see langword="null"/>.</para>
    /// \endif
    /// </exception>
    /// <exception cref="ArgumentException">
    /// \if KO
    /// <para><paramref name="email"/>이 비어 있거나 공백인 경우 발생합니다.</para>
    /// \endif
    /// \if EN
    /// <para>Thrown when <paramref name="email"/> is empty or white space.</para>
    /// \endif
    /// </exception>
    private static string NormalizeEmail(string email)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        return email.Trim().ToLowerInvariant();
    }

    /// <summary>
    /// \if KO
    /// <para>SQLite PRAGMA table_info 결과에서 열 이름만 매핑하는 내부 모델입니다.</para>
    /// \endif
    /// \if EN
    /// <para>Represents the internal name-only mapping of a SQLite PRAGMA table_info row.</para>
    /// \endif
    /// </summary>
    private sealed class TableColumn
    {
        /// <summary>
        /// \if KO
        /// <para>데이터베이스 열 이름을 가져오거나 설정합니다.</para>
        /// \endif
        /// \if EN
        /// <para>Gets or sets the database column name.</para>
        /// \endif
        /// </summary>
        public string Name { get; set; } = string.Empty;
    }
}
