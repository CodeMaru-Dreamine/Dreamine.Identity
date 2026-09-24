using Dreamine.Identity.Models;
using System.Reflection;
using Microsoft.AspNetCore.Http;

namespace Dreamine.Identity.Tests;

public sealed class RegistrationConsentTests
{
    [Theory]
    [InlineData(DateTimeKind.Utc)]
    [InlineData(DateTimeKind.Local)]
    [InlineData(DateTimeKind.Unspecified)]
    public void ConsentUsesOneUtcInstantAndCurrentDocumentVersions(DateTimeKind kind)
    {
        var input=new DateTime(2026,9,24,12,30,0,kind);
        var result=IdentityConsentPolicy.Create(input);
        Assert.Equal(input.ToUniversalTime(),result.TermsAcceptedAtUtc);
        Assert.Equal(DateTimeKind.Utc,result.TermsAcceptedAtUtc.Kind);
        Assert.Equal(result.TermsAcceptedAtUtc,result.PrivacyAcceptedAtUtc);
        Assert.Equal(result.TermsAcceptedAtUtc,result.MinimumAgeConfirmedAtUtc);
        Assert.Equal(IdentityConsentPolicy.CurrentTermsVersion,result.TermsVersion);
        Assert.Equal(IdentityConsentPolicy.CurrentPrivacyVersion,result.PrivacyVersion);
    }
    [Theory]
    [InlineData("ko")][InlineData("en")][InlineData("es")][InlineData("fr")]
    [InlineData("it")][InlineData("pt")][InlineData("ja")][InlineData("zh-hans")]
    [InlineData("zh-hant")][InlineData("vi")]
    public void EveryLoginLanguageHasMatchingRequiredConsentCopy(string language)
    {
        var type=typeof(DreamineIdentityExtensions).Assembly.GetType("Dreamine.Identity.Internal.IdentityLocalization",true)!;
        var flags=BindingFlags.Static|BindingFlags.NonPublic;
        var http=new DefaultHttpContext(); http.Request.QueryString=new QueryString("?lang="+language);
        var copy=type.GetMethod("Resolve",flags)!.Invoke(null,[http])!;
        var consent=type.GetMethod("Consent",flags,null,[copy.GetType()],null)!.Invoke(null,[copy])!;
        var direct=type.GetMethod("Consent",flags,null,[typeof(string)],null)!.Invoke(null,[language]);
        Assert.Equal(direct,consent);
        foreach(var property in new[]{"TermsAgreement","PrivacyAgreement","MinimumAgeConfirmation","ConsentRequiredMessage"})
            Assert.False(string.IsNullOrWhiteSpace((string?)consent.GetType().GetProperty(property)!.GetValue(consent)));
    }
}
