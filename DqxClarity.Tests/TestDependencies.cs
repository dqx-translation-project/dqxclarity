using DqxClarity.Data;
using DqxClarity.Packets;
using DqxClarity.Translation;
using DqxClarity.Translation.Backends;

namespace DqxClarity.Tests;

// PacketDependencies for tests: a fresh, EMPTY translation database (created
// from the app's own embedded schema), the "None" translation service (no
// machine translation, no network), and a romanizer chosen by the test.
//
// With an empty database every dictionary lookup misses, so the only thing that
// can change a packet is the romanizer -- which is what lets the tests tell
// "nothing to translate" apart from "translated something".
public static class TestDependencies
{
    private static ClarityDb CreateEmptyDb()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dqxclarity-tests");
        System.IO.Directory.CreateDirectory(dir);
        var db = new ClarityDb(Path.Combine(dir, Guid.NewGuid().ToString("N") + ".db"));
        db.CreateSchema();
        return db;
    }

    // A Translator over an empty glossary with the given backend, for testing the
    // translation pipeline itself.
    public static Translator CreateTranslator(ITranslationBackend backend) =>
        new(backend, GlossaryCache.Load(CreateEmptyDb()));

    public static PacketDependencies Create(IRomanizer romanizer)
    {
        var db = CreateEmptyDb();

        return new PacketDependencies
        {
            Db = db,
            Translator = new Translator(new NoneBackend(), GlossaryCache.Load(db)),
            Romanizer = romanizer,
        };
    }
}

// A translation service that answers every phrase with the same fixed text.
public sealed class FixedReplyBackend(string reply) : ITranslationBackend
{
    public string Name => "fixed";
    public Action<string>? OnError { get; set; }
    public IReadOnlyList<string> Translate(IReadOnlyList<string> phrases) =>
        phrases.Select(_ => reply).ToList();
}

// Returns names unchanged: with an empty database, nothing gets translated.
public sealed class IdentityRomanizer : IRomanizer
{
    public string ToRomaji(string text, int maxLength = 10) => text;
}

// Turns any name containing Japanese into "Romaji", so every romaji fallback
// fires and the packet classes have to rebuild their packets.
public sealed class MarkingRomanizer : IRomanizer
{
    public string ToRomaji(string text, int maxLength = 10) =>
        Translator.IsTextJapanese(text) ? "Romaji" : text;
}
