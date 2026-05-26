namespace DqxClarity.Packets;

// Common contract for a parsed game packet type.
//
// Implementations parse their fields in the constructor from the payload
// (already stripped of opcode + marker by DataPacketRouter), call Build() to
// serialize a modified payload. ModifiedData stays null if there's no change.
public interface IPacket
{
    void Build();
    byte[]? ModifiedData { get; }
}
