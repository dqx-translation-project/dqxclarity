from common.memory import (
    allocate_memory,
    calc_rel_addr,
    dqx_mem,
    pattern_scan,
    read_bytes,
    write_bytes,
    write_string,
)
from common.signatures import (
    accept_quest_trigger,
    dialog_trigger,
    integrity_check,
    network_text_trigger,
    player_sibling_name_trigger,
    quest_text_trigger,
)
from hooking.dialog import translate_shellcode
from hooking.easydetour import EasyDetour
from hooking.hide_hooks import load_hooks
from hooking.network_text import network_text_shellcode
from hooking.player import player_name_shellcode
from hooking.quest import quest_text_shellcode
from loguru import logger

import struct
import traceback


def inject_python_dll():
    """Injects a Python dll."""
    try:
        PYM_PROCESS.inject_python_interpreter()
        if PYM_PROCESS._python_injected:
            if PYM_PROCESS.py_run_simple_string:
                logger.success(f"Python injected.")
                return PYM_PROCESS.py_run_simple_string
        logger.error(f"Python dll failed to inject. Details:\n{PYM_PROCESS.__dict__}")
        return False
    except Exception:
        logger.error(f"Python dll failed to inject. Error: \n{str(traceback.print_exc())}\nDetails:\n{PYM_PROCESS.__dict__}")
        return False


def translate_detour(simple_str_addr: int):
    """Hooks the dialog window to translate text and write English instead."""
    hook_obj = EasyDetour(
        hook_name="game_dialog",
        signature=dialog_trigger,
        num_bytes_to_steal=10,
        simple_str_addr=simple_str_addr,
    )

    esi = hook_obj.address_dict["attrs"]["esi"]
    shellcode = translate_shellcode(esi_address=esi)
    shellcode_addr = hook_obj.address_dict["attrs"]["shellcode"]
    write_string(address=shellcode_addr, text=shellcode)

    return hook_obj


def quest_text_detour(simple_str_addr: int):
    """Hook the quest dialog window and translate to english."""
    hook_obj = EasyDetour(
        hook_name="quests",
        signature=quest_text_trigger,
        num_bytes_to_steal=6,
        simple_str_addr=simple_str_addr,
    )

    eax = hook_obj.address_dict["attrs"]["eax"]
    shellcode = quest_text_shellcode(address=eax)
    shellcode_addr = hook_obj.address_dict["attrs"]["shellcode"]
    write_string(address=shellcode_addr, text=shellcode)

    return hook_obj


def network_text_detour(simple_str_addr: int):
    """tbd."""
    hook_obj = EasyDetour(
        hook_name="network_text",
        signature=network_text_trigger,
        num_bytes_to_steal=5,
        simple_str_addr=simple_str_addr,
    )
    ecx = hook_obj.address_dict["attrs"]["ecx"]
    esp = hook_obj.address_dict["attrs"]["esp"]
    shellcode = network_text_shellcode(ecx, esp)
    shellcode_addr = hook_obj.address_dict["attrs"]["shellcode"]
    write_string(address=shellcode_addr, text=shellcode)

    return hook_obj


def accept_quest_detour(simple_str_addr: int):
    """Detours function when you accept a quest and the quest text pops up on
    your screen."""
    hook_obj = EasyDetour(
        hook_name="accept_quest",
        signature=accept_quest_trigger,
        num_bytes_to_steal=6,
        simple_str_addr=simple_str_addr,
        debug=debug,
    )

    esi = hook_obj.address_dict["attrs"]["esi"]
    shellcode = quest_text_shellcode(address=esi)
    shellcode_addr = hook_obj.address_dict["attrs"]["shellcode"]
    write_string(address=shellcode_addr, text=shellcode)

    return hook_obj


def player_name_detour(simple_str_addr: int):
    """Detours function when you accept a quest and the quest text pops up on
    your screen."""
    hook_obj = EasyDetour(
        hook_name="player_name",
        signature=player_sibling_name_trigger,
        num_bytes_to_steal=6,
        simple_str_addr=simple_str_addr,
    )

    eax = hook_obj.address_dict["attrs"]["eax"]
    shellcode = player_name_shellcode(eax_address=eax)
    shellcode_addr = hook_obj.address_dict["attrs"]["shellcode"]
    write_string(address=shellcode_addr, text=shellcode)

    return hook_obj


def activate_hooks(player_names: bool, debug=False):
    """Activates all hooks and kicks off hook manager."""
    simple_str_addr = inject_python_dll()
    if not simple_str_addr:
        logger.exception("Since Python injection failed, we will not try to hook. Exiting.")
        return False

    # activates all hooks. add any new hooks to this list
    hooks = []
    hooks.append(translate_detour(simple_str_addr=simple_str_addr))
    hooks.append(quest_text_detour(simple_str_addr=simple_str_addr))
    hooks.append(player_name_detour(simple_str_addr=simple_str_addr))
    hooks.append(network_text_detour(simple_str_addr=simple_str_addr))

    # construct our asm to detach hooks
    unhook_bytecode = b""
    for hook in hooks:
        data = hook.address_dict["attrs"]
        orig_address = data["game_func"]
        orig_bytes = data["game_bytes"]
        for byte in orig_bytes:
            packed_address = struct.pack("<i", orig_address)
            unhook_bytecode += b"\xC6\x05"  # mov byte ptr
            unhook_bytecode += packed_address  # address to move byte to
            unhook_bytecode += byte.to_bytes(1, "little")  # byte to move
            orig_address += 1

    # allocate memory to write our unhook
    unhook_addr = allocate_memory(len(unhook_bytecode))

    # also allocate memory to give the integrity function a place to tell us it ran
    state_addr = allocate_memory(10)

    # get address we want to put our detour
    integrity_addr = pattern_scan(pattern=integrity_check, module="DQXGame.exe")

    # write to our state address telling us this func was run
    packed_address = struct.pack("<i", state_addr)
    unhook_bytecode += b"\xC6\x05"  # move byte ptr
    unhook_bytecode += packed_address  # address to move byte to
    unhook_bytecode += b"\x01"  # 01 will tell us func was run

    # get bytes we want to steal and append to unhook bytecode
    stolen_bytes = read_bytes(integrity_addr, 5)
    unhook_bytecode += stolen_bytes

    # calculate difference between addresses for jump and add to unhook bytecode
    unhook_bytecode += b"\xE9" + calc_rel_addr(unhook_addr + len(unhook_bytecode), integrity_addr)

    # write to our allocated mem
    write_bytes(unhook_addr, unhook_bytecode)

    # finally, write our detour over the integrity function
    detour_bytecode = b"\xE9" + calc_rel_addr(integrity_addr, unhook_addr)
    write_bytes(integrity_addr, detour_bytecode)
    logger.debug(f"unhook :: hook ({hex(unhook_addr)}) :: detour ({hex(integrity_addr)})")
    logger.debug(f"state  :: addr ({hex(state_addr)})")

    load_hooks(hook_list=hooks, state_addr=state_addr, player_names=player_names, debug=debug)


PYM_PROCESS = dqx_mem()
