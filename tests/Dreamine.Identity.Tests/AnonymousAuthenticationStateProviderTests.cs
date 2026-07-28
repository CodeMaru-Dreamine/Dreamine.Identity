using Microsoft.Extensions.DependencyInjection;

namespace Dreamine.Identity.Tests;

public sealed class AnonymousAuthenticationStateProviderTests
{
    [Fact]
    public async Task Provider_ReturnsAnUnauthenticatedPrincipal()
    {
        var provider = new AnonymousAuthenticationStateProvider();

        var state = await provider.GetAuthenticationStateAsync();

        Assert.False(state.User.Identity?.IsAuthenticated);
        Assert.Empty(state.User.Claims);
    }

    [Fact]
    public void WpfHostRegistration_IsNullSafeAndChainable()
    {
        var services = new ServiceCollection();

        var returned = services.AddDreamineIdentityWpfHost();

        Assert.Same(services, returned);
        Assert.Throws<ArgumentNullException>(
            () => DreamineIdentityExtensions.AddDreamineIdentityWpfHost(null!));
    }
}
