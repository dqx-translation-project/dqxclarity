using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DqxClarity.Launcher.Services;

namespace DqxClarity.Launcher.Models;

/// <summary>
/// Metadata header stored in a CLPK container, serialized as UTF-8 JSON.
/// </summary>
public record ClpkMetadata
{
    [JsonPropertyName("sha256")]
    public string Sha256 { get; init; } = "";

    [JsonPropertyName("author")]
    public string Author { get; init; } = "";

    [JsonPropertyName("language")]
    public string Language { get; init; } = "";

    /// <summary>Creation time as a Unix timestamp (seconds since epoch).</summary>
    [JsonPropertyName("builtAt")]
    public long BuiltAt { get; init; }

    [JsonPropertyName("downloadUrl")]
    public string DownloadUrl { get; init; } = "";

    [JsonPropertyName("gameMods")]
    public List<string> GameMods { get; init; } = [];
}

/// <summary>
/// CLPK ("Clarity Pack") binary container format. Stamps a small metadata header in front of a
/// plain ZIP payload so packs carry a sha256 + provenance for distribution.
///
/// Byte layout:
///   offset 0,   4 bytes : ASCII magic "CLPK"
///   offset 4,   1 byte  : format version (0x01)
///   offset 5,   2 bytes : u16 BIG-ENDIAN length N of the JSON metadata
///   offset 7,   N bytes : UTF-8 JSON metadata
///   offset 7+N..EOF     : the ZIP payload (sha256 is computed over THIS range only)
/// </summary>
public static class ClpkFormat
{
    public const string Magic = "CLPK";
    public const byte Version = 1;

    private static readonly byte[] MagicBytes = "CLPK"u8.ToArray();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    /// <summary>True if the first four bytes are the ASCII letters C, L, P, K.</summary>
    public static bool LooksLikeClpk(ReadOnlySpan<byte> first4) =>
        first4.Length >= 4 && first4[0] == (byte)'C' && first4[1] == (byte)'L'
        && first4[2] == (byte)'P' && first4[3] == (byte)'K';

    /// <summary>
    /// Reads and validates a CLPK header from a stream positioned at 0. Returns false (with null/0
    /// outs) for any non-CLPK or malformed file — never throws on bad input.
    /// </summary>
    public static bool TryReadHeader(Stream s, out ClpkMetadata? meta, out long payloadOffset, out long payloadLength)
    {
        meta = null;
        payloadOffset = 0;
        payloadLength = 0;

        try
        {
            s.Position = 0;

            var head = new byte[7];
            if (!ReadExactly(s, head, 0, 7)) return false;

            if (!LooksLikeClpk(head)) return false;
            if (head[4] != Version) return false;

            var jsonLength = BinaryPrimitives.ReadUInt16BigEndian(head.AsSpan(5, 2));

            var jsonBytes = new byte[jsonLength];
            if (!ReadExactly(s, jsonBytes, 0, jsonLength)) return false;

            var parsed = JsonSerializer.Deserialize<ClpkMetadata>(jsonBytes, JsonOptions);
            if (parsed == null) return false;

            meta = parsed;
            payloadOffset = 7 + jsonLength;
            payloadLength = s.Length - payloadOffset;
            if (payloadLength < 0)
            {
                meta = null;
                payloadOffset = 0;
                payloadLength = 0;
                return false;
            }
            return true;
        }
        catch
        {
            meta = null;
            payloadOffset = 0;
            payloadLength = 0;
            return false;
        }
    }

    /// <summary>
    /// Opens the ZIP payload of a pack file. For a CLPK file, returns a <see cref="SubStream"/>
    /// windowed over the payload (with the parsed metadata); for a plain zip or anything else,
    /// returns the whole file stream (with null metadata). The returned stream OWNS the underlying
    /// file — disposing it closes the file. The caller must dispose the returned stream.
    /// </summary>
    public static (Stream payload, ClpkMetadata? meta) OpenPayload(string path)
    {
        var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            var first4 = new byte[4];
            var read = ReadExactly(fs, first4, 0, 4);
            fs.Position = 0;

            if (read && LooksLikeClpk(first4)
                && TryReadHeader(fs, out var meta, out var payloadOffset, out var payloadLength))
            {
                // SubStream takes ownership of the FileStream (leaveOpen:false), so disposing the
                // returned payload stream closes the underlying file.
                return (new SubStream(fs, payloadOffset, payloadLength, leaveOpen: false), meta);
            }

            // Not a CLPK (plain zip or other) — hand back the whole file.
            fs.Position = 0;
            return (fs, null);
        }
        catch
        {
            fs.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Computes the lowercase hex SHA-256 of <paramref name="payload"/> from start to end. Seeks the
    /// passed stream to 0 first.
    /// </summary>
    public static string ComputeSha256Hex(Stream payload)
    {
        if (payload.CanSeek)
            payload.Position = 0;
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(payload);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Writes a CLPK container to <paramref name="output"/>: magic, version, u16 BE JSON length,
    /// UTF-8 JSON metadata (with sha256 computed over <paramref name="zipBytes"/>), then the zip bytes.
    /// </summary>
    public static void Write(Stream output, byte[] zipBytes, ClpkMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(zipBytes);
        ArgumentNullException.ThrowIfNull(metadata);

        using var sha = SHA256.Create();
        var sha256Hex = Convert.ToHexString(sha.ComputeHash(zipBytes)).ToLowerInvariant();

        // sha256 is always computed here from the payload; ignore any caller-supplied value.
        var meta = metadata with { Sha256 = sha256Hex };

        var json = JsonSerializer.SerializeToUtf8Bytes(meta, JsonOptions);
        if (json.Length > ushort.MaxValue)
            throw new InvalidDataException($"CLPK metadata JSON is too large ({json.Length} bytes; max {ushort.MaxValue}).");

        Span<byte> head = stackalloc byte[7];
        MagicBytes.CopyTo(head);
        head[4] = Version;
        BinaryPrimitives.WriteUInt16BigEndian(head.Slice(5, 2), (ushort)json.Length);

        output.Write(head);
        output.Write(json, 0, json.Length);
        output.Write(zipBytes, 0, zipBytes.Length);
    }

    private static bool ReadExactly(Stream s, byte[] buffer, int offset, int count)
    {
        var total = 0;
        while (total < count)
        {
            var read = s.Read(buffer, offset + total, count - total);
            if (read == 0) return false;
            total += read;
        }
        return true;
    }
}
