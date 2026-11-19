using System.Text;
using DqxClarity.Models;
using DqxClarity.Translation;
using Xunit;

namespace DqxClarity.Tests;

// The optional text settings a language pack can carry in its CLPK header
// (accented characters kept, dialogue box size) and what the translation logic
// does with them.
public class ClpkTextOptionsTests
{
    private static readonly byte[] TinyZip = { (byte)'P', (byte)'K', 3, 4 };

    private static (string Json, ClpkMetadata Meta) WriteAndRead(ClpkMetadata meta)
    {
        using var ms = new MemoryStream();
        ClpkFormat.Write(ms, TinyZip, meta);
        var bytes = ms.ToArray();
        var jsonLength = (bytes[5] << 8) | bytes[6];
        var json = Encoding.UTF8.GetString(bytes, 7, jsonLength);

        Assert.True(ClpkFormat.TryReadHeader(ms, out var read, out _, out _));
        return (json, read!);
    }

    [Fact]
    public void PackWithoutTextSettingsHasTheSameHeaderAsBefore()
    {
        var (json, meta) = WriteAndRead(new ClpkMetadata { Author = "a", Language = "en", BuiltAt = 1 });

        Assert.DoesNotContain("disable_text_normalization", json);
        Assert.DoesNotContain("max_chars_per_line", json);
        Assert.DoesNotContain("max_lines_per_box", json);
        Assert.Equal(ClpkTextOptions.Default, ClpkTextOptions.From(meta));
        Assert.True(ClpkTextOptions.From(meta).IsDefault);
    }

    [Fact]
    public void TextSettingsRoundTrip()
    {
        var (json, meta) = WriteAndRead(new ClpkMetadata
        {
            Author = "a", Language = "es", BuiltAt = 1,
            DisableTextNormalization = true, MaxCharsPerLine = 60, MaxLinesPerBox = 4,
        });

        Assert.Contains("\"disable_text_normalization\":true", json);
        Assert.Contains("\"max_chars_per_line\":60", json);
        Assert.Contains("\"max_lines_per_box\":4", json);
        Assert.Equal(new ClpkTextOptions(true, 60, 4), ClpkTextOptions.From(meta));
    }

    // A header written by a build script (or an older dqxclarity) that knows
    // nothing about these fields.
    [Fact]
    public void HeaderWithoutTheFieldsReadsAsDefaults()
    {
        var json = Encoding.UTF8.GetBytes(
            "{\"sha\":\"00\",\"language\":\"en\",\"author\":\"dqxclarity team\",\"builtAt\":1,\"download_url\":\"\"}");
        using var ms = new MemoryStream();
        ms.Write("CLPK"u8);
        ms.WriteByte(1);
        ms.WriteByte((byte)(json.Length >> 8));
        ms.WriteByte((byte)json.Length);
        ms.Write(json);
        ms.Write(TinyZip);

        Assert.True(ClpkFormat.TryReadHeader(ms, out var meta, out _, out _));
        Assert.Equal(ClpkTextOptions.Default, ClpkTextOptions.From(meta));
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(-5, -1)]
    [InlineData(9, 21)]
    [InlineData(100000, 500)]
    public void OutOfRangeValuesFallBackToDefaults(int chars, int lines)
    {
        var options = ClpkTextOptions.From(new ClpkMetadata { MaxCharsPerLine = chars, MaxLinesPerBox = lines });

        Assert.Equal(ClpkTextOptions.DefaultMaxCharsPerLine, options.MaxCharsPerLine);
        Assert.Equal(ClpkTextOptions.DefaultMaxLinesPerBox, options.MaxLinesPerBox);
    }

    [Fact]
    public void NullMetadataIsDefaults() =>
        Assert.Equal(ClpkTextOptions.Default, ClpkTextOptions.From(null));
}

public class DialoguePageBreakTests
{
    private static string Lines(int count) => string.Join('\n', Enumerable.Range(1, count).Select(i => $"L{i}"));

    [Fact]
    public void ThreeLinesPerBoxIsTheOriginalBehaviour()
    {
        Assert.Equal("L1\nL2\nL3\n<br>\nL4\nL5\nL6\n<br>\nL7", TextWrapping.InjectBrEveryNLines(Lines(7), 3));
        Assert.Equal(TextWrapping.InjectBrEvery3Lines(Lines(10)), TextWrapping.InjectBrEveryNLines(Lines(10), 3));
    }

    [Fact]
    public void ABoxThatFitsExactlyGetsNoPageBreak() =>
        Assert.Equal("L1\nL2\nL3", TextWrapping.InjectBrEveryNLines(Lines(3), 3));

    [Fact]
    public void FourLinesPerBox() =>
        Assert.Equal("L1\nL2\nL3\nL4\n<br>\nL5\nL6\nL7\nL8\n<br>\nL9",
            TextWrapping.InjectBrEveryNLines(Lines(9), 4));

    [Fact]
    public void NonsenseLinesPerBoxUsesTheDefault() =>
        Assert.Equal(TextWrapping.InjectBrEveryNLines(Lines(8), 3), TextWrapping.InjectBrEveryNLines(Lines(8), 0));
}

public class TranslatorTextOptionsTests
{
    private const string Japanese = "こんにちは";

    [Fact]
    public void AccentsAreStrippedByDefault()
    {
        var translator = TestDependencies.CreateTranslator(new FixedReplyBackend("¡Hola, señor!"));

        Assert.Equal("Hola, senor!", translator.Translate(Japanese, wrapWidth: 46));
    }

    [Fact]
    public void AccentsAreKeptWhenNormalizationIsOff()
    {
        var translator = TestDependencies.CreateTranslator(new FixedReplyBackend("¡Hola, señor!"));
        translator.UpdateTextOptions(disableNormalization: true);

        Assert.Equal("¡Hola, señor!", translator.Translate(Japanese, wrapWidth: 46));
    }

    // With normalisation on, a reply with no Latin letters at all looks like a
    // failed translation and is thrown away; with it off, it is a translation.
    [Fact]
    public void NonLatinAlphabetsOnlySurviveWithNormalizationOff()
    {
        var translator = TestDependencies.CreateTranslator(new FixedReplyBackend("Привет"));
        Assert.Equal("", translator.Translate(Japanese, wrapWidth: 46));

        translator.UpdateTextOptions(disableNormalization: true);
        Assert.Equal("Привет", translator.Translate(Japanese, wrapWidth: 46));
    }

    // A reply that is still Japanese is not a translation, whichever way the switch is set.
    [Fact]
    public void AnUntranslatedReplyIsRejectedEitherWay()
    {
        var translator = TestDependencies.CreateTranslator(new FixedReplyBackend(Japanese));
        Assert.Equal("", translator.Translate(Japanese, wrapWidth: 46));

        translator.UpdateTextOptions(disableNormalization: true);
        Assert.Equal("", translator.Translate(Japanese, wrapWidth: 46));
    }

    [Fact]
    public void WrapWidthAndLinesPerBoxShapeTheDialogue()
    {
        var translator = TestDependencies.CreateTranslator(new FixedReplyBackend("aaaa bbbb cccc dddd eeee"));

        Assert.Equal("aaaa\nbbbb\ncccc\n<br>\ndddd\neeee", translator.Translate(Japanese, wrapWidth: 4));
        Assert.Equal("aaaa\nbbbb\n<br>\ncccc\ndddd\n<br>\neeee",
            translator.Translate(Japanese, wrapWidth: 4, linesPerBox: 2));
        Assert.Equal("aaaa bbbb\ncccc dddd\neeee", translator.Translate(Japanese, wrapWidth: 9, linesPerBox: 4));
    }
}
