using System.IO.Compression;
using System.Text;
using DqxClarity.Models;
using DqxClarity.Updates;
using Xunit;

namespace DqxClarity.Tests;

// Name files (monsters, NPCs, items, ...) a language pack bundles under
// dqxclarity/json/ instead of dqxclarity downloading them.
public class PackNameFilesTests
{
    private static string WritePack(params (string Path, string Text)[] entries)
    {
        using var zipStream = new MemoryStream();
        using (var zip = new ZipArchive(zipStream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (path, text) in entries)
            {
                using var s = zip.CreateEntry(path).Open();
                s.Write(Encoding.UTF8.GetBytes(text));
            }
        }

        var file = Path.Combine(Path.GetTempPath(), $"dqxclarity-test-{Guid.NewGuid():N}.clpk");
        using var fs = File.Create(file);
        ClpkFormat.Write(fs, zipStream.ToArray(), new ClpkMetadata { Language = "fr" });
        return file;
    }

    [Fact]
    public void ReadsOnlyTheKnownFilesFromTheDataFolder()
    {
        var pack = WritePack(
            ("dqxclarity/json/subPackage05Client.json", "items"),
            ("dqxclarity/json/SUBPACKAGE02CLIENT.json", "monsters"),  // case doesn't matter
            ("dqxclarity/json/other.json", "ignored"),                 // not one of the six
            ("dqxclarity/json/sub/subPackage41Client.json", "ignored"), // sub-folder
            ("common/subPackage41Client.json", "ignored"));             // game file
        try
        {
            var files = TranslationUpdater.ReadPackTranslationFiles(pack);

            Assert.Equal(2, files.Count);
            Assert.Equal("items", Encoding.UTF8.GetString(files["subPackage05Client.json"]));
            Assert.Equal("monsters", Encoding.UTF8.GetString(files["subPackage02Client.json"]));
        }
        finally { File.Delete(pack); }
    }

    [Fact]
    public void NoPackOrNoFilesMeansDownloadEverything()
    {
        Assert.Empty(TranslationUpdater.ReadPackTranslationFiles(null));
        Assert.Empty(TranslationUpdater.ReadPackTranslationFiles(Path.Combine(Path.GetTempPath(), "missing.clpk")));

        var pack = WritePack(("common/data.etp", "x"));
        try { Assert.Empty(TranslationUpdater.ReadPackTranslationFiles(pack)); }
        finally { File.Delete(pack); }
    }

    [Fact]
    public void UnreadablePackMeansDownloadEverything()
    {
        var file = Path.Combine(Path.GetTempPath(), $"dqxclarity-test-{Guid.NewGuid():N}.clpk");
        File.WriteAllText(file, "not a pack");
        try { Assert.Empty(TranslationUpdater.ReadPackTranslationFiles(file)); }
        finally { File.Delete(file); }
    }

    [Fact]
    public void FileNamesMatchTheRepo()
    {
        var names = TranslationConstants.TranslationFiles.Select(f => TranslationConstants.SourceFileName(f.Url)).ToArray();
        Assert.Equal(new[]
        {
            "subPackage02Client.json", "smldt_msg_pkg_NPC_DB.json", "subPackage05Client.json",
            "subPackage41Client.json", "eventTextSysQuestaClient.json", "eventTextSysEventaClient.json",
        }, names);
    }

    // ── Bundled custom translations (dqxclarity/custom-translations/) ──

    [Fact]
    public void BundledCustomTranslationsAreRead()
    {
        var pack = WritePack(
            ("dqxclarity/custom-translations/json/custom_lottery_prizes.json", "{}"),
            ("dqxclarity/custom-translations/json/custom_trainee_logbook.json", "{}"),
            ("dqxclarity/custom-translations/csv/merge.xlsx", "xlsx"),
            ("dqxclarity/custom-translations/csv/glossary.csv", "\uFEFFja,en"),
            ("dqxclarity/custom-translations/generate_glossary/ignore.py", "IGNORE = {}"),
            ("dqxclarity/json/subPackage05Client.json", "{}"),        // name file, not custom
            ("common/json/not_custom.json", "{}"));                  // game file
        try
        {
            Assert.True(TranslationUpdater.PackHasCustomTranslations(pack));
            var parts = TranslationUpdater.ReadPackCustomTranslations(pack);

            Assert.NotNull(parts);
            Assert.Equal(new[] { "custom_lottery_prizes", "custom_trainee_logbook" },
                parts!.Json.Select(j => j.Name).OrderBy(n => n).ToArray());
            Assert.Equal("xlsx", Encoding.UTF8.GetString(parts.MergeXlsx!));
            Assert.Equal("ja,en", parts.GlossaryCsv); // BOM dropped, as with the repo
            Assert.Equal("IGNORE = {}", parts.IgnorePy);
        }
        finally { File.Delete(pack); }
    }

    [Fact]
    public void FolderWithMissingPartsStillCountsAsBundled()
    {
        // Only json: merge.xlsx, glossary.csv and ignore.py are absent -- nothing is
        // downloaded to fill them in.
        var pack = WritePack(("dqxclarity/custom-translations/json/a.json", "{}"));
        try
        {
            var parts = TranslationUpdater.ReadPackCustomTranslations(pack);
            Assert.NotNull(parts);
            Assert.Single(parts!.Json);
            Assert.Null(parts.MergeXlsx);
            Assert.Null(parts.GlossaryCsv);
            Assert.Null(parts.IgnorePy);
        }
        finally { File.Delete(pack); }
    }

    [Fact]
    public void NoFolderMeansDownload()
    {
        // Name files alone don't count: custom translations are still downloaded.
        var pack = WritePack(("dqxclarity/json/subPackage05Client.json", "{}"), ("common/a.etp", "x"));
        try
        {
            Assert.False(TranslationUpdater.PackHasCustomTranslations(pack));
            Assert.Null(TranslationUpdater.ReadPackCustomTranslations(pack));
        }
        finally { File.Delete(pack); }

        Assert.Null(TranslationUpdater.ReadPackCustomTranslations(null));
        Assert.False(TranslationUpdater.PackHasCustomTranslations(null));
    }

    [Theory]
    [InlineData("dqxclarity", true)]
    [InlineData("dqxclarity/json/subPackage05Client.json", true)]
    [InlineData("DQXClarity/json/x.json", true)]
    [InlineData("dqxclarity/custom-translations/csv/merge.xlsx", true)]
    [InlineData("dqxclarity-extra/file", false)]
    [InlineData("common/dqxclarity/file", false)]
    [InlineData("plugins/textfix.dll", false)]
    public void OnlyTheDataFolderIsKeptOutOfGameMods(string entry, bool isData) =>
        Assert.Equal(isData, TranslationConstants.IsPackDataEntry(entry));
}
