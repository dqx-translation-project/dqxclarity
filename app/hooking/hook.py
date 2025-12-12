from common.memory import MemWriter
from common.signatures import (
    corner_text_trigger,
    dialog_trigger,
    mem_chr_trigger,
    network_text_trigger,
    player_sibling_name_trigger,
    quest_text_trigger,
)
from hooking.trampoline import Trampoline
from loguru import logger as log


def translate_detour():
    """Hooks the dialog window to translate text."""
    from hooking.dialog import translate_shellcode

    trampoline = Trampoline(
        name="game_dialogue",
        signature=dialog_trigger,
        num_bytes_to_steal=10,
    )

    if not trampoline.initialized:
        log.error(f"Trampoline {trampoline.name} failed to initialize.")
        return None

    esi, esp, shellcode_addr = trampoline.esi, trampoline.esp, trampoline.shellcode

    shellcode = translate_shellcode(esi_address=esi, esp_address=esp)
    trampoline.writer.write_string(address=shellcode_addr, text=shellcode)

    return trampoline


def quest_text_detour():
    """Hooks the quest dialog window and translates it."""
    from hooking.quest import quest_text_shellcode

    trampoline = Trampoline(
        name="quests",
        signature=quest_text_trigger,
        num_bytes_to_steal=6,
    )

    if not trampoline.initialized:
        log.error(f"Trampoline {trampoline.name} failed to initialize.")
        return None

    eax, shellcode_addr = trampoline.eax, trampoline.shellcode

    shellcode = quest_text_shellcode(address=eax)
    trampoline.writer.write_string(address=shellcode_addr, text=shellcode)

    return trampoline


def network_text_detour():
    """Translates single string 'network text'."""
    from hooking.network_text import network_text_shellcode

    trampoline = Trampoline(
        name="network_text",
        signature=network_text_trigger,
        num_bytes_to_steal=5,
    )

    if not trampoline.initialized:
        log.error(f"Trampoline {trampoline.name} failed to initialize.")
        return None

    edx, ebx, shellcode_addr = trampoline.edx, trampoline.ebx, trampoline.shellcode

    shellcode = network_text_shellcode(edx_address=edx, ebx_address=ebx)
    trampoline.writer.write_string(address=shellcode_addr, text=shellcode)

    return trampoline


def player_name_detour():
    """Updates strings in the database with the logged in player's name."""
    from hooking.player import player_name_shellcode

    trampoline = Trampoline(
        name="player_name",
        signature=player_sibling_name_trigger,
        num_bytes_to_steal=6,
    )

    if not trampoline.initialized:
        log.error(f"Trampoline {trampoline.name} failed to initialize.")
        return None

    eax, shellcode_addr = trampoline.eax, trampoline.shellcode

    shellcode = player_name_shellcode(eax_address=eax)
    trampoline.writer.write_string(address=shellcode_addr, text=shellcode)

    return trampoline


def corner_text_detour():
    """Detours function when top-right corner text is about to happen and
    translates it."""
    from hooking.corner_text import corner_text_shellcode

    trampoline = Trampoline(
        name="corner_text",
        signature=corner_text_trigger,
        num_bytes_to_steal=5,
    )

    if not trampoline.initialized:
        log.error(f"Trampoline {trampoline.name} failed to initialize.")
        return None

    eax, shellcode_addr = trampoline.eax, trampoline.shellcode

    shellcode = corner_text_shellcode(eax_address=eax)
    trampoline.writer.write_string(address=shellcode_addr, text=shellcode)

    return trampoline


def mem_chr_detour():
    """Detours function where text is sent to memchr()."""
    from hooking.memchr import memchr_shellcode

    trampoline = Trampoline(
        name="memchr",
        signature=mem_chr_trigger,
        num_bytes_to_steal=5,
    )

    if not trampoline.initialized:
        log.error(f"Trampoline {trampoline.name} failed to initialize.")
        return None

    esp, shellcode_addr = trampoline.esp, trampoline.shellcode

    shellcode = memchr_shellcode(esp_address=esp)
    trampoline.writer.write_string(address=shellcode_addr, text=shellcode)

    return trampoline


def activate_hooks(communication_window: bool) -> None:
    """Activates all hooks.

    :param communication_window: True if user requested to translate
        game dialogue.
    :returns: A list of hook objects that can be enabled or disabled.
    """
    # activates all hooks. add any new hooks to this list
    hooks = []
    if hook := player_name_detour():
        hooks.append(hook)
    if hook := network_text_detour():
        hooks.append(hook)
    if hook := corner_text_detour():
        hooks.append(hook)

    if communication_window:
        if hook := translate_detour():
            hooks.append(hook)
        if hook := quest_text_detour():
            hooks.append(hook)
        # if hook := mem_chr_detour():
        #     hooks.append(hook)

    if hooks:
        for hook in hooks:
            hook.enable()

    return hooks
