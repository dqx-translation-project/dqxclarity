namespace DqxClarity.Packets;

// Wraps the packet dispatcher so that any packet class that throws -- while
// parsing in its constructor or in Build() -- is treated as "this packet's
// layout is not what we expect": the packet is left untouched (the game gets
// the original bytes) and a mismatch report is filed. Exceptions were already
// being swallowed further up and the original forwarded; this adds the report,
// and gives packet classes a way to bail out on purpose by throwing
// PacketLayoutException when something doesn't add up.
public static class PacketGuard
{
    public static DataPacketRouter.Dispatcher Wrap(DataPacketRouter.Dispatcher inner, MismatchReporter reporter) =>
        (opCode, marker, data) =>
        {
            IPacket? packet;
            try
            {
                packet = inner(opCode, marker, data);
            }
            catch (Exception ex)
            {
                reporter.Report(opCode, marker, data, ex);
                return null;
            }

            return packet == null ? null : new GuardedPacket(packet, opCode, marker, data, reporter);
        };

    private sealed class GuardedPacket : IPacket
    {
        private readonly IPacket _inner;
        private readonly byte _opCode;
        private readonly ushort _marker;
        private readonly byte[] _data;
        private readonly MismatchReporter _reporter;

        public byte[]? ModifiedData { get; private set; }

        public GuardedPacket(IPacket inner, byte opCode, ushort marker, byte[] data, MismatchReporter reporter)
        {
            _inner = inner;
            _opCode = opCode;
            _marker = marker;
            _data = data;
            _reporter = reporter;
        }

        public void Build()
        {
            try
            {
                _inner.Build();
                var modified = _inner.ModifiedData;
                ModifiedData = modified is { Length: > 0 } ? modified : null;
            }
            catch (Exception ex)
            {
                ModifiedData = null;
                _reporter.Report(_opCode, _marker, _data, ex);
            }
        }
    }
}
