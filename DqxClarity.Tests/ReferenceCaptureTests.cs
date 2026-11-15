using DqxClarity.Packets;
using Xunit;

namespace DqxClarity.Tests;

// Every captured packet in docs/packets/references, through the packet class
// the router sends it to. A capture whose opcode/marker isn't routed (an
// unhandled or disabled packet) passes trivially.
//
// What a failure means:
//   CaptureIsAccepted -- the class threw on a real packet the server sent. In
//     the running app PacketGuard would pass that packet through untranslated
//     and file a mismatch report. Either the class broke, or the capture is
//     from an older game version and the layout has since changed (then
//     replace the capture with a current one).
//   NothingToTranslateLeavesPacketUntouched -- with no dictionary entries and
//     nothing romanized, the class still changed the packet. That's how the
//     old Memory list bug looked (untranslated titles cut to 29 bytes on every
//     arrival). If a class is MEANT to change packets regardless (see
//     AlwaysRewrites), add it there with the reason.
//   TranslatedPacketIsStillAccepted -- after romanizing every name, the
//     rebuilt packet no longer parses with the same class: the rebuild broke
//     the layout (a wrong length field, a lost terminator, a shifted field).
public class ReferenceCaptureTests
{
    public static IEnumerable<object[]> Captures => ReferenceCaptures.All();

    // Packet types that change a packet even when nothing is translated, on purpose.
    private static readonly (string Prefix, string Reason)[] AlwaysRewrites =
    {
        ("Entity", "player/party/fellow names always get the \\x04 prefix that stops the client showing them as GMs"),
        ("ServerList", "server names come from a table built into the class, not the database"),
        ("ImportantNotice", "the streaming and maintenance notices have English built into the class"),
        ("QuestPackList", "QuestRewardFormatter has a built-in translation for the experience-point reward line"),
    };

    [Theory]
    [MemberData(nameof(Captures))]
    public void CaptureIsAccepted(string file)
    {
        var capture = ReferenceCaptures.Load(file);
        var packet = Route(capture, capture.Data, new IdentityRomanizer());
        packet?.Build(); // throws on a layout it doesn't accept
    }

    [Theory]
    [MemberData(nameof(Captures))]
    public void NothingToTranslateLeavesPacketUntouched(string file)
    {
        var capture = ReferenceCaptures.Load(file);
        if (AlwaysRewrites.Any(a => capture.PacketName.StartsWith(a.Prefix, StringComparison.Ordinal))) return;

        var packet = Route(capture, capture.Data, new IdentityRomanizer());
        if (packet == null) return;
        packet.Build();

        if (packet.ModifiedData is { } modified)
            Assert.True(modified.AsSpan().SequenceEqual(capture.Data),
                $"{capture.PacketName} ({file}) changed the packet with nothing to translate: " +
                $"{capture.Data.Length} bytes in, {modified.Length} out");
    }

    [Theory]
    [MemberData(nameof(Captures))]
    public void TranslatedPacketIsStillAccepted(string file)
    {
        var capture = ReferenceCaptures.Load(file);
        var packet = Route(capture, capture.Data, new MarkingRomanizer());
        if (packet == null) return;
        packet.Build();
        if (packet.ModifiedData is not { } modified) return;

        // Feed the rebuilt packet back through the same class.
        var again = Route(capture, modified, new MarkingRomanizer());
        Assert.NotNull(again);
        again!.Build();
    }

    private static IPacket? Route(ReferenceCaptures.Capture capture, byte[] data, Translation.IRomanizer romanizer)
    {
        var dispatcher = DataPacketRouter.BuildDefaultDispatcher(TestDependencies.Create(romanizer));
        return dispatcher(capture.OpCode, capture.Marker, data);
    }
}
