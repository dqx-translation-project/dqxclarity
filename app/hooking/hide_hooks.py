from clarity import scan_for_comm_names, scan_for_sibling_name
from common.memory import MemWriter
from common.process import is_dqx_process_running
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
    writer = MemWriter()
    for hook in hook_list:
        hook.enable()

    while True:
        try:
            curr_state = writer.read_bytes(state_addr, 1)
            if curr_state == b"\x01":  # we've been unhooked
                # these integrity scans happen pretty much instantly after we've noticed.
                # let's just give it a moment to be safe and then we'll rehook
                time.sleep(1)
                for hook in hook_list:
                    hook.enable()
                writer.write_bytes(state_addr, b"\x00")  # reset our state byte since we're hooked again

                if player_names:
                    # since this timing is sensitive, kick these processes off in the background
                    Process(name="Sibling scan", target=scan_for_sibling_name, args=()).start()
                    Process(name="Comms scan", target=scan_for_comm_names, args=()).start()
            time.sleep(0.25)
        except TypeError:
            log.error(f"Unable to talk to DQXGame.exe. Exiting.")
            sys.exit(1)
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
