using DqxClarity.Models;
using DqxClarity.Updates;
using Xunit;

namespace DqxClarity.Tests;

// The language pack option that points server-side translations at another
// repo laid out like dqx-custom-translations.
public class CustomTranslationsUrlTests
{
    [Theory]
    [InlineData("https://github.com/my-org/my-repo",
                "https://github.com/my-org/my-repo/archive/refs/heads/main.zip")]
    [InlineData("  https://github.com/my-org/my-repo/  ",
                "https://github.com/my-org/my-repo/archive/refs/heads/main.zip")]
    [InlineData("https://github.com/my-org/my-repo.git",
                "https://github.com/my-org/my-repo/archive/refs/heads/main.zip")]
    [InlineData("https://www.github.com/My.Org/my_repo",
                "https://github.com/My.Org/my_repo/archive/refs/heads/main.zip")]
    [InlineData("https://github.com/my-repo",
                "https://github.com/dqx-translation-project/my-repo/archive/refs/heads/main.zip")]
    [InlineData("https://github.com/my-org/my-repo/tree/dev",
                "https://github.com/my-org/my-repo/archive/refs/heads/dev.zip")]
    [InlineData("https://github.com/dqx-translation-project/dqx-custom-translations",
                TranslationConstants.CustomTranslationsZipUrl)]
    public void GithubRepoLinksBecomeZipDownloads(string link, string expected)
    {
        Assert.True(TranslationConstants.TryGetCustomTranslationsZipUrl(link, out var zip));
        Assert.Equal(expected, zip);
        Assert.Equal(expected, TranslationConstants.ResolveCustomTranslationsZipUrl(link));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("github.com/my-org/my-repo")]                 // no scheme
    [InlineData("https://gitlab.com/my-org/my-repo")]          // not GitHub
    [InlineData("https://github.com/")]                        // no repo
    [InlineData("https://github.com/my-org/my-repo/blob/main/x.json")]
    [InlineData("https://github.com/my-org/my-repo?tab=readme")]
    [InlineData("https://github.com/my%20org/my-repo")]
    [InlineData("ftp://github.com/my-org/my-repo")]
    public void AnythingElseFallsBackToTheDefault(string? link)
    {
        Assert.False(TranslationConstants.TryGetCustomTranslationsZipUrl(link, out var zip));
        Assert.Null(zip);
        Assert.Equal(TranslationConstants.CustomTranslationsZipUrl,
            TranslationConstants.ResolveCustomTranslationsZipUrl(link));
    }

    [Fact]
    public void FieldIsLeftOutOfTheHeaderWhenUnset()
    {
        var json = System.Text.Json.JsonSerializer.Serialize(new ClpkMetadata { Language = "en" });
        Assert.DoesNotContain("custom_translations_url", json);
    }

    [Fact]
    public void FieldRoundTrips()
    {
        using var ms = new MemoryStream();
        ClpkFormat.Write(ms, new byte[] { (byte)'P', (byte)'K', 3, 4 },
            new ClpkMetadata { Language = "es", CustomTranslationsUrl = "https://github.com/my-org/my-repo" });

        Assert.True(ClpkFormat.TryReadHeader(ms, out var meta, out _, out _));
        Assert.Equal("https://github.com/my-org/my-repo", meta!.CustomTranslationsUrl);
    }
}
