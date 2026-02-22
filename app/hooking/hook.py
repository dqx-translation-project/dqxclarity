import os
from collections.abc import Callable
from hooking.hooks.blowfish_logger import on_message as blowfish_logger_on_message
from hooking.hooks.hash_logger import on_message as hash_logger_on_message
from hooking.hooks.packet_warden import on_message as packet_logger_on_message
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
        script_file: str,
        message_handler: Callable,
        enabled: bool = True,
    ):
        """Initialize a hook configuration.

        Args:
            name: Name for this hook (used in logging and debugging)
            script_file: JavaScript file to execute (relative to scripts/ folder)
            message_handler: Python function that handles messages from this hook's Frida script
                           Signature: (message: dict, data: any, script: frida.Script) -> None
            enabled: Whether this hook should be loaded at startup
        """
        self.name = name
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

        return script_template

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
        FridaHook(
            name="packet_warden",
            script_file="packet_warden.ts",
            message_handler=packet_logger_on_message,
            enabled=False,
        ),
    ],
    "community_logging": [
        FridaHook(
            name="hash_logger",
            script_file="hash_logger.ts",
            message_handler=hash_logger_on_message,
            enabled=False,
        ),
        FridaHook(
            name="blowfish_logger",
            script_file="blowfish_logger.ts",
            message_handler=blowfish_logger_on_message,
            enabled=True,
        ),
    ],
}
