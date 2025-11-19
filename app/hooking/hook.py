from common.lib import setup_logging
from common.memory import MemWriter
from common.signatures import (
    bad_flow,
    corner_text_trigger,
    dialog_trigger,
    good_flow,
    network_text_trigger,
    player_sibling_name_trigger,
    quest_text_trigger,
)
from hooking.easydetour import EasyDetour

import sys


def translate_detour(simple_str_addr: int):
    """Hooks the dialog window to translate text and write English instead."""
    from hooking.dialog import translate_shellcode

    writer = MemWriter()

    hook_obj = EasyDetour(
        hook_name="game_dialog",
        signature=dialog_trigger,
        num_bytes_to_steal=10,
        simple_str_addr=simple_str_addr,
    )

    esi = hook_obj.address_dict["attrs"]["esi"]
    esp = hook_obj.address_dict["attrs"]["esp"]
    shellcode = translate_shellcode(esi_address=esi, esp_address=esp)
    shellcode_addr = hook_obj.address_dict["attrs"]["shellcode"]
    writer.write_string(address=shellcode_addr, text=shellcode)

    return hook_obj


def quest_text_detour(simple_str_addr: int):
    """Hook the quest dialog window and translate to english."""
    from hooking.quest import quest_text_shellcode

    writer = MemWriter()

    hook_obj = EasyDetour(
        hook_name="quests",
        signature=quest_text_trigger,
        num_bytes_to_steal=6,
        simple_str_addr=simple_str_addr,
    )

    eax = hook_obj.address_dict["attrs"]["eax"]
    shellcode = quest_text_shellcode(address=eax)
    shellcode_addr = hook_obj.address_dict["attrs"]["shellcode"]
    writer.write_string(address=shellcode_addr, text=shellcode)

    return hook_obj


def network_text_detour(simple_str_addr: int):
    """Translates single string 'network text'."""
    from hooking.network_text import network_text_shellcode

    writer = MemWriter()

    hook_obj = EasyDetour(
        hook_name="network_text",
        signature=network_text_trigger,
        num_bytes_to_steal=5,
        simple_str_addr=simple_str_addr,
    )
    edx = hook_obj.address_dict["attrs"]["edx"]
    ebx = hook_obj.address_dict["attrs"]["ebx"]
    shellcode = network_text_shellcode(edx, ebx)
    shellcode_addr = hook_obj.address_dict["attrs"]["shellcode"]
    writer.write_string(address=shellcode_addr, text=shellcode)

    return hook_obj


def player_name_detour(simple_str_addr: int):
    """Updates strings in the database with the logged in player's name."""
    from hooking.player import player_name_shellcode

    writer = MemWriter()

    hook_obj = EasyDetour(
        hook_name="player_name",
        signature=player_sibling_name_trigger,
        num_bytes_to_steal=6,
        simple_str_addr=simple_str_addr,
    )

    eax = hook_obj.address_dict["attrs"]["eax"]
    shellcode = player_name_shellcode(eax_address=eax)
    shellcode_addr = hook_obj.address_dict["attrs"]["shellcode"]
    writer.write_string(address=shellcode_addr, text=shellcode)

    return hook_obj


def corner_text_detour(simple_str_addr: int):
    """Detours function when top-right corner text is about to happen and
    replaces it with English."""
    from hooking.corner_text import corner_text_shellcode

    writer = MemWriter()

    hook_obj = EasyDetour(
        hook_name="corner_text",
        signature=corner_text_trigger,
        num_bytes_to_steal=5,
        simple_str_addr=simple_str_addr
    )

    eax = hook_obj.address_dict["attrs"]["eax"]
    shellcode = corner_text_shellcode(eax_address=eax)
    shellcode_addr = hook_obj.address_dict["attrs"]["shellcode"]
    writer.write_string(address=shellcode_addr, text=shellcode)

    return hook_obj


def freedom():
    """If you don't know, don't worry about it."""
    writer = MemWriter()

    good_flow_result = writer.pattern_scan(
        pattern=good_flow,
        module="DQXGame.exe"
    )

    if not good_flow_result:
        log.error("Unable to enable hooks. dqxclarity may need an update. Exiting.")
        sys.exit(1)

    good_bytes = writer.read_bytes(
        address=good_flow_result,
        size=5
    )

    bad_flow_result = writer.pattern_scan(
        pattern=bad_flow,
        module="DQXGame.exe"
    )

    if not bad_flow_result:
        log.error(
            "Unable to enable hooks. If a game update didn't just happen, make sure "
            "you didn't re-run dqxclarity without closing DQX. Otherwise, you will "
            "need to wait for dqxclarity to put out an update to fix this. Exiting."
        )
        sys.exit(1)

    writer.write_bytes(
        address=bad_flow_result,
        value=good_bytes
    )


def activate_hooks(player_names: bool, communication_window: bool) -> None:
    """Activates all hooks and kicks off hook manager."""
    # configure logging. this function runs in multiprocessing, so it does not
    # have the same access to the main log handler.
    writer = MemWriter()

    freedom()

    simple_str_addr = writer.inject_python()

    # activates all hooks. add any new hooks to this list
    hooks = []
    hooks.append(player_name_detour(simple_str_addr=simple_str_addr))
    hooks.append(network_text_detour(simple_str_addr=simple_str_addr))
    hooks.append(corner_text_detour(simple_str_addr=simple_str_addr))

    if communication_window:
        hooks.append(translate_detour(simple_str_addr=simple_str_addr))
        hooks.append(quest_text_detour(simple_str_addr=simple_str_addr))

    for hook in hooks:
        hook.enable()
