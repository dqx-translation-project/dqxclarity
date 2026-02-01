from common.lib import get_project_root
from hooking.hooks.packets.gamepacket import GamePacket
from loguru import logger as log


_log_file = get_project_root("logs/packet_logger.txt")


def hexdump(data: bytes, bytes_per_line: int = 16) -> str:
    """Format bytes as a hex dump with offset, hex, and ASCII columns.

    Args:
        data: Bytes to format.
        bytes_per_line: Number of bytes per line.

    Returns:
        Formatted hex dump string.
    """
    lines = []
    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset : offset + bytes_per_line]

        # hex column
        hex_parts = [f"{b:02X}" for b in chunk]
        hex_str = " ".join(hex_parts).ljust(bytes_per_line * 3 - 1)

        # ascii column
        ascii_str = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)

        lines.append(f"{offset:08X}  {hex_str}  |{ascii_str}|")

    return "\n".join(lines)


def on_message(message, data, script):
    """Message handler for packet_logger hook.

    Args:
        message: Message dict from Frida script
        data: Binary data (packet bytes) from Frida script
        script: Frida script instance for posting responses
    """
    if message["type"] == "send":
        payload = message["payload"]
        msg_type = payload.get("type", "unknown")

        if msg_type == "packet_data":
            if data:
                packet_length = len(data)
                hex_view = hexdump(data)

                #log.debug(f"{packet_length} bytes =>\n{hex_view}")

                packet = GamePacket(data)
                packet.parse_data()

                if packet.modified_data and packet.original_size:
                    # send modified packet back to frida with binary data
                    script.post({
                        "type": "modified_packet",
                        "modified": True,
                        "size": packet.original_size
                    }, packet.modified_data)

                    #log.info(f"Modified ({len(packet.modified_data)} bytes) =>\n{hexdump(packet.modified_data)}")

                else:
                    # no modification, but still send original_size for return value
                    script.post({
                        "type": "modified_packet",
                        "modified": False,
                        "size": packet.original_size
                    })

                with open(_log_file, "a+") as f:
                    f.write(f"{packet_length} bytes =>\n{hex_view}\n\n")
            else:
                # no data, unblock frida
                script.post({
                    "type": "modified_packet",
                    "modified": False
                })

        elif msg_type == "info":
            log.debug(f"{payload['payload']}")
        elif msg_type == "error":
            log.error(f"{payload['payload']}")
        else:
            log.debug(f"{payload}")

    elif message["type"] == "error":
        log.error(f"[JS ERROR] {message.get('stack', message)}")
