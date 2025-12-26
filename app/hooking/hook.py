from hooking.trampoline import Trampoline
from loguru import logger as log


def translate_detour():
    """Hooks the dialog window to translate text."""
    from common.signatures import dialog_trigger
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
    from common.signatures import quest_text_trigger
    from hooking.quest import quest_text_shellcode

    trampoline = Trampoline(
        name="quest_list",
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


def accept_quest_text_detour():
    """Hooks the accept quest window and translates it."""
    from common.signatures import accept_quest_text_trigger
    from hooking.accept_quest import accept_quest_text_shellcode

    trampoline = Trampoline(
        name="accept_quest",
        signature=accept_quest_text_trigger,
        num_bytes_to_steal=6,
    )

    if not trampoline.initialized:
        log.error(f"Trampoline {trampoline.name} failed to initialize.")
        return None

    ebx, esi, shellcode_addr = trampoline.ebx, trampoline.esi, trampoline.shellcode

    shellcode = accept_quest_text_shellcode(ebx_address=ebx, esi_address=esi)
    trampoline.writer.write_string(address=shellcode_addr, text=shellcode)

    return trampoline


def network_text_detour():
    """Translates single string 'network text'."""
    from common.signatures import network_text_trigger
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
    from common.signatures import player_sibling_name_trigger
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
    from common.signatures import corner_text_trigger
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
    from common.signatures import mem_chr_trigger
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


def walkthrough_detour():
    """Detours function where walkthrough text is accessed."""
    from common.signatures import walkthrough_trigger
    from hooking.walkthrough import walkthrough_shellcode

    trampoline = Trampoline(
        name="walkthrough",
        signature=walkthrough_trigger,
        num_bytes_to_steal=8,
    )

    if not trampoline.initialized:
        log.error(f"Trampoline {trampoline.name} failed to initialize.")
        return None

    edi, shellcode_addr = trampoline.edi, trampoline.shellcode

    shellcode = walkthrough_shellcode(edi_address=edi)
    trampoline.writer.write_string(address=shellcode_addr, text=shellcode)

    return trampoline


def nameplates_detour():
    """Detours function where nameplates are visible."""
    from common.signatures import nameplates_trigger
    from hooking.nameplates import nameplates_shellcode

    trampoline = Trampoline(
        name="nameplates",
        signature=nameplates_trigger,
        num_bytes_to_steal=10,
    )

    if not trampoline.initialized:
        log.error(f"Trampoline {trampoline.name} failed to initialize.")
        return None

    esp, shellcode_addr = trampoline.esp, trampoline.shellcode

    shellcode = nameplates_shellcode(esp_address=esp)
    trampoline.writer.write_string(address=shellcode_addr, text=shellcode)

    return trampoline


def hash_logger_detour():
    """Detours function where filenames and hashes are read.

    This should always be called with hash_logger_start_detour() as
    well.
    """
    from common.signatures import hash_logger_end_trigger
    from hooking.hash_logger import hash_logger_shellcode

    # where we found our address is a little high, but gives us a unique
    # address. we need to move passed a relative jump to get towards the
    # bottom of the function so we get the real hash value found in ecx.
    trampoline = Trampoline(
        name="hash_logger",
        signature=hash_logger_end_trigger,
        num_bytes_to_steal=5,
        offset=6,
    )

    if not trampoline.initialized:
        log.error(f"Trampoline {trampoline.name} failed to initialize.")
        return None

    ecx, esp, shellcode_addr = trampoline.ecx, trampoline.esp, trampoline.shellcode

    shellcode = hash_logger_shellcode(ecx_address=ecx, esp_address=esp)
    trampoline.writer.write_string(address=shellcode_addr, text=shellcode)

    return trampoline


def blowfish_logger_detour():
    """Detours function where blowfish keys are logged."""
    from common.signatures import blowfish_logger_trigger
    from hooking.blowfish_logger import blowfish_logger_shellcode

    trampoline = Trampoline(
        name="blowfish_logger",
        signature=blowfish_logger_trigger,
        num_bytes_to_steal=5,
    )

    if not trampoline.initialized:
        log.error(f"Trampoline {trampoline.name} failed to initialize.")
        return None

    esp, shellcode_addr = trampoline.esp, trampoline.shellcode

    shellcode = blowfish_logger_shellcode(esp_address=esp)
    trampoline.writer.write_string(address=shellcode_addr, text=shellcode)

    return trampoline


def activate_hooks(
    communication_window: bool, nameplates: bool, community_logging: bool
) -> None:
    """Activates all hooks.

    :param communication_window: True if user requested to translate
        game dialogue.
    :param community_logging: True if user requested to enable community
        logging.
    :returns: A list of hook objects that can be enabled or disabled.
    """
    # activates all hooks. add any new hooks to this list
    hooks = []
    if hook := corner_text_detour():
        hooks.append(hook)
    if hook := network_text_detour():
        hooks.append(hook)
    if hook := player_name_detour():
        hooks.append(hook)

    if nameplates:
        if hook := nameplates_detour():
            hooks.append(hook)

    if community_logging:
        if hook := hash_logger_detour():
            hooks.append(hook)
        if hook := blowfish_logger_detour():
            hooks.append(hook)

    if communication_window:
        if hook := translate_detour():
            hooks.append(hook)
        if hook := accept_quest_text_detour():
            hooks.append(hook)
        if hook := quest_text_detour():
            hooks.append(hook)
        if hook := walkthrough_detour():
            hooks.append(hook)

    if hooks:
        for hook in hooks:
            hook.enable()

    return hooks
