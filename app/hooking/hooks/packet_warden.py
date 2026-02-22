"""
Hooks an area during packet stream parsing that provides
access to all incoming traffic to the client.
"""

from hooking.hooks.packets.gamepacket import GamePacket
from loguru import logger as log


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
                packet = GamePacket(data)
                packet.parse_data()

                if packet.modified_data and packet.original_size:
                    script.post(
                        {"type": "modified_packet", "modified": True, "size": packet.original_size}, packet.modified_data
                    )
                else:
                    # no modification, but still send original_size for return value
                    script.post({"type": "modified_packet", "modified": False, "size": packet.original_size})

            else:
                # no data, unblock frida
                script.post({"type": "modified_packet", "modified": False})

        elif msg_type == "info":
            log.debug(f"{payload['payload']}")
        elif msg_type == "error":
            log.error(f"{payload['payload']}")
        else:
            log.debug(f"{payload}")

    elif message["type"] == "error":
        log.error(f"[JS ERROR] {message.get('stack', message)}")
