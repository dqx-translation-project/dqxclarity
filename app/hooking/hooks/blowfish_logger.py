"""Logs blowfish decryption keys used for game files."""

import os
from common.lib import get_project_root
from loguru import logger as log


# Module-level file handle for efficient appending
_log_file = None


def _init_log_file():
    """Initialize the blowfish log file if not already opened."""
    global _log_file

    if _log_file is not None:
        return _log_file

    log_path = get_project_root("logs/blowfish_log.csv")

    # create with header if doesn't exist
    if not os.path.exists(log_path) or os.path.getsize(log_path) == 0:
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("filepath,file_size,blowfish_key\n")

    # open in append mode, line buffering for real-time writing
    _log_file = open(log_path, "a", encoding="utf-8", buffering=1)  # noqa: SIM115
    return _log_file


def on_message(message, data, script):
    """Message handler for blowfish_logger hook.

    Args:
        message: Message dict from Frida script
        data: Binary data (if any) from Frida script
        script: Frida script instance for posting responses
    """
    if message["type"] == "send":
        payload = message["payload"]
        msg_type = payload.get("type", "unknown")

        if msg_type == "blowfish_data":
            filename = payload.get("filename", "")
            file_size = payload.get("file_size", 0)
            blowfish_key = payload.get("blowfish_key", "")

            try:
                log_file = _init_log_file()
                log_file.write(f'"{filename}",{file_size},"{blowfish_key}"\n')

            except Exception as e:
                log.exception(f"Failed to log: {e}")

        elif msg_type == "info":
            log.debug(f"{payload['payload']}")
        elif msg_type == "error":
            log.error(f"{payload['payload']}")
        else:
            log.debug(f"{payload}")

    elif message["type"] == "error":
        log.error(f"[JS ERROR] {message.get('stack', message)}")
