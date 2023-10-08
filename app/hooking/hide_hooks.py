from clarity import scan_for_comm_names, scan_for_sibling_name
from common.lib import is_dqx_process_running, setup_logging
from common.memory import read_bytes, write_bytes
from loguru import logger as log
from multiprocessing import Process

import pymem
import sys
import time


def load_hooks(hook_list: list, state_addr: int, player_names: bool):
    """Reload our hooks if they've been unhooked.

    :param hook_list: List of hook objects created by EasyDetour
    :param state_addr: Address that the integrity check writes at to let
        us know when it's unhooked
    :param debug: Enable log debugging
    :returns: Nothing. This is an infinite loop that runs as a process
    """
    # initially enable hooks
    for hook in hook_list:
        hook.enable()

    while True:
        try:
            curr_state = read_bytes(state_addr, 1)
            if curr_state == b"\x01":  # we've been unhooked
                log.debug("Hooks disabled.")
                # these integrity scans happen pretty much instantly after we've noticed.
                # let's just give it a moment to be safe and then we'll rehook
                time.sleep(1)
                for hook in hook_list:
                    hook.enable()
                write_bytes(state_addr, b"\x00")  # reset our state byte since we're hooked again

                if player_names:
                    # since this timing is sensitive, kick these processes off in the background
                    Process(name="Sibling scan", target=scan_for_sibling_name, args=()).start()
                    Process(name="Comms scan", target=scan_for_comm_names, args=()).start()
                log.debug("Hooks enabled.")
            time.sleep(0.25)
        except TypeError:
            log.error(f"Unable to talk to DQXGame.exe. Exiting.")
            sys.exit()
        except pymem.exception.WinAPIError as e:
            if e.error_code == 299:
                log.debug("WinApi error 299: Impartial read. Ignoring.")
            elif e.error_code == 5:
                log.debug("Cannot find DQXGame.exe process. dqxclarity will exit.")
                sys.exit(1)
            else:
                raise
        except KeyboardInterrupt:
            for hook in hook_list:
                hook.disable()
            sys.exit(1)
        except Exception as e:
            if not is_dqx_process_running():
                sys.exit(0)
            else:
                log.exception("An exception occurred. dqxclarity will exit.")
                sys.exit(1)
