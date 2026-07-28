using Dreamine.Database.Sqlite;
using Microsoft.Data.Sqlite;

namespace Dreamine.Identity.Tests;

public sealed class SqliteUserStoreTests : IDisposable
{
    private readonly string _databasePath =
        Path.Combine(Path.GetTempPath(), $"dreamine-identity-{Guid.NewGuid():N}.db");

    [Fact]
    public async Task LocalAccount_CanBeCreatedValidatedAndUpdated()
    {
        var store = CreateStore();

        var created = await store.CreateLocalAsync(
            "  USER@Example.com ",
            "  테스트 사용자  ",
            "correct-horse-battery");

        Assert.True(created.Id > 0);
        Assert.Equal("Local", created.Provider);
        Assert.Equal("user@example.com", created.Email);
        Assert.Equal("테스트 사용자", created.DisplayName);
        Assert.NotEqual("correct-horse-battery", created.PasswordHash);

        Assert.Null(await store.ValidateLocalAsync("user@example.com", "wrong-password"));

        var validated = await store.ValidateLocalAsync(
            "USER@example.com",
            "correct-horse-battery");
        Assert.NotNull(validated);
        Assert.Equal(created.Id, validated.Id);

        var renamed = await store.UpdateDisplayNameAsync(created.Id, "  새 이름  ");
        Assert.Equal("새 이름", renamed?.DisplayName);
    }

    [Fact]
    public async Task LocalAccount_RejectsDuplicatesAndWeakPasswords()
    {
        var store = CreateStore();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.CreateLocalAsync("user@example.com", "사용자", "short"));

        await store.CreateLocalAsync("user@example.com", "사용자", "long-enough-password");

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.CreateLocalAsync("USER@example.com", "다른 사용자", "another-password"));
    }

    [Fact]
    public async Task LocalPassword_CanBeChangedOnlyWithTheCurrentPassword()
    {
        var store = CreateStore();
        var user = await store.CreateLocalAsync(
            "user@example.com",
            "사용자",
            "old-password");

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.ChangeLocalPasswordAsync(user.Id, "incorrect", "new-password"));

        var changed = await store.ChangeLocalPasswordAsync(
            user.Id,
            "old-password",
            "new-password");

        Assert.NotNull(changed);
        Assert.Null(await store.ValidateLocalAsync("user@example.com", "old-password"));
        Assert.NotNull(await store.ValidateLocalAsync("user@example.com", "new-password"));
    }

    [Fact]
    public async Task ExternalAccount_IsUpsertedByProviderIdentity()
    {
        var store = CreateStore();

        var created = await store.UpsertAsync(
            "Google",
            "provider-key",
            "old@example.com",
            "Old Name",
            "https://example.com/old.png");
        var updated = await store.UpsertAsync(
            "Google",
            "provider-key",
            "new@example.com",
            "New Name",
            "https://example.com/new.png");

        Assert.Equal(created.Id, updated.Id);
        Assert.Equal("new@example.com", updated.Email);
        Assert.Equal("New Name", updated.DisplayName);
        Assert.Equal("https://example.com/new.png", updated.AvatarUrl);
        Assert.NotNull(await store.GetByIdAsync(updated.Id));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.ChangeLocalPasswordAsync(updated.Id, "old-password", "new-password"));
    }

    private SqliteUserStore CreateStore()
    {
        var provider = new SqliteDatabaseProvider($"Data Source={_databasePath}");
        return new SqliteUserStore(provider);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();

        if (File.Exists(_databasePath))
        {
            File.Delete(_databasePath);
        }
    }
}
