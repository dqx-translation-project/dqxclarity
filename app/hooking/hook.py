import os
from collections.abc import Callable

# from hooking.hooks.blowfish_logger import on_message as blowfish_logger_on_message
# from hooking.hooks.corner_text import on_message as corner_text_on_message
# from hooking.hooks.dialogue import on_message as dialogue_on_message
from hooking.hooks.packet_logger import on_message as packet_logger_on_message

# from hooking.hooks.hash_logger import on_message as hash_logger_on_message
# from hooking.hooks.nameplates import on_message as nameplates_on_message
# from hooking.hooks.network_text import on_message as network_text_on_message
# from hooking.hooks.player import on_message as player_on_message
# from hooking.hooks.quest import on_message as quest_on_message
# from hooking.hooks.walkthrough import on_message as walkthrough_on_message
from loguru import logger as log


PROCESS_NAME = "DQXGame.exe"
SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), "scripts")


class FridaHook:
    """Defines a Frida hook configuration.

    Each hook runs as an independent Frida script, allowing for:
    - Fault isolation (one hook crashing doesn't affect others)
    - Individual enable/disable
    - Independent debugging
    - Runtime loading/unloading
    """

    def __init__(
        self,
        name: str,
        signature: str,
        script_file: str,
        message_handler: Callable,
        enabled: bool = True,
    ):
        """Initialize a hook configuration.

        Args:
            name: Name for this hook (used in logging and debugging)
            signature: Byte pattern to locate the target function (wildcards: ??)
            script_file: JavaScript file to execute (relative to scripts/ folder)
            message_handler: Python function that handles messages from this hook's Frida script
                           Signature: (message: dict, data: any, script: frida.Script) -> None
            enabled: Whether this hook should be loaded at startup
        """
        self.name = name
        self.signature = signature
        self.script_file = script_file
        self.message_handler = message_handler
        self.enabled = enabled

    def __repr__(self):
        status = "enabled" if self.enabled else "disabled"
        return f"FridaHook(name={self.name}, script={self.script_file}, {status})"


class HookScript:
    """Manages a single hook's Frida script."""

    def __init__(self, hook: FridaHook, hook_id: int, session):
        self.hook = hook
        self.hook_id = hook_id
        self.session = session
        self.script = None

    def load(self):
        """Load and attach this hook's script."""
        script_code = self._load_script_file()
        self.script = self.session.create_script(script_code)
        self.script.on("message", self._on_message)
        self.script.load()
        log.success(f"{self.hook.name} loaded")

    def _load_script_file(self) -> str:
        """Load and prepare the hook script from file."""
        script_path = os.path.join(SCRIPTS_DIR, self.hook.script_file)

        if not os.path.exists(script_path):
            raise FileNotFoundError(f"Script file not found: {script_path}")

        with open(script_path, encoding="utf-8") as f:
            script_template = f.read()

        # replace placeholders in the script
        script = script_template.replace("{{HOOK_ID}}", str(self.hook_id))
        script = script.replace("{{HOOK_NAME}}", self.hook.name)
        script = script.replace("{{SIGNATURE}}", self.hook.signature)

        return script

    def _on_message(self, message, data):
        """Delegate message handling to the hook-specific message handler."""
        if self.hook.message_handler:
            self.hook.message_handler(message, data, self.script)
        else:
            log.error(f"No message handler defined for {self.hook.name}")

    def unload(self):
        """Unload this hook's script."""
        if self.script:
            self.script.unload()
            log.success(f"{self.hook.name} unloaded")


# hooks are structured by a top level grouping category.
HOOKS = {
    "default": [
    #     FridaHook(
    #         name="corner_text",
    #         signature="55 8B EC 8B 45 ?? 83 EC ?? 53 8B 5D ?? 56 8B F1 57 85 C0",
    #         script_file="corner_text.ts",
    #         message_handler=corner_text_on_message,
    #         enabled=True,
    #     ),
    #     FridaHook(
    #         name="network_text",
    #         signature="55 8B EC 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 8B 45 ?? 8B 0D ?? ?? ?? ?? 89 45 ?? 64 A1",
    #         script_file="network_text.ts",
    #         message_handler=network_text_on_message,
    #         enabled=True,
    #     ),
    #     FridaHook(
    #         name="player",
    #         signature="55 8B EC 56 8B F1 57 8B 46 58 85 C0",
    #         script_file="player.ts",
    #         message_handler=player_on_message,
    #         enabled=True,
    #     ),
    ],
    "nameplates": [
    #     FridaHook(
    #         name="nameplates",
    #         signature="55 8B EC 56 8B B1 ?? ?? ?? ?? 85 F6 74 ?? 8B 45",
    #         script_file="nameplates.ts",
    #         message_handler=nameplates_on_message,
    #         enabled=True,
    #     ),
    ],
    "communication_window": [
    #     FridaHook(
    #         name="dialogue",
    #         signature="55 8B EC 56 8B F1 80 BE ?? ?? ?? ?? ?? 74 ?? C6 86 ?? ?? ?? ?? ?? FF 75",
    #         script_file="dialogue.ts",
    #         message_handler=dialogue_on_message,
    #         enabled=True,
    #     ),
    #     FridaHook(
    #         name="quest",
    #         signature="88 86 57 03 00 00 5E 5B 5D C2 04 00",
    #         script_file="quest.ts",
    #         message_handler=quest_on_message,
    #         enabled=True,
    #     ),
    #     FridaHook(
    #         name="walkthrough",
    #         signature="E8 ?? ?? ?? ?? 8D B8 ?? ?? ?? ?? 8B CF 8D 51",
    #         script_file="walkthrough.ts",
    #         message_handler=walkthrough_on_message,
    #         enabled=True,
    #     ),
    ],
    "community_logging": [
    #     FridaHook(
    #         name="hash_logger",
    #         signature="55 8B EC 8B 55 08 85 D2 75 04 33 C0 5D C3 53",
    #         script_file="hash_logger.ts",
    #         message_handler=hash_logger_on_message,
    #         enabled=False,
    #     ),
    #     FridaHook(
    #         name="blowfish_logger",
    #         signature="55 8B EC 53 57 8B 79 24 85 FF 74 ?? 83 7D 08 00",
    #         script_file="blowfish_logger.ts",
    #         message_handler=blowfish_logger_on_message,
    #         enabled=True,
    #     ),
        FridaHook(
            name="packet_logger",
            signature="55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 83 7D ?? ?? 53 8B 5D ?? 56 8B F1",
            script_file="packet_logger.ts",
            message_handler=packet_logger_on_message,
            enabled=False,
        ),
    ],
}
