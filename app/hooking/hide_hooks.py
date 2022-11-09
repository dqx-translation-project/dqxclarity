from multiprocessing import Process
import sys
import time
from loguru import logger
from common.memory import read_bytes, write_bytes
from clarity import scan_for_adhoc_files, scan_for_sibling_names


def load_hooks(hook_list: list, state_addr: int, debug: bool):
    """
    Reload our hooks if they've been unhooked.

    :param hook_list: List of hook objects created by EasyDetour
    :param state_addr: Address that the integrity check writes at to let us know when it's unhooked
    :param debug: Enable log debugging
    :returns: Nothing. This is an infinite loop that runs as a process
    """
    logger.remove()
    if debug:
        logger.add(sys.stderr, level="DEBUG")
    else:
        logger.add(sys.stderr, level="INFO")

    # initially enable hooks
    for hook in hook_list:
        hook.enable()

    while True:
        try:
            curr_state = read_bytes(state_addr, 1)
            if curr_state == b"\x01":  # we've been unhooked
                logger.info("Hooks disabled.")
                # these integrity scans happen pretty much instantly after we've noticed.
                # let's just give it a moment to be safe and then we'll rehook
                time.sleep(1)
                for hook in hook_list:
                    hook.enable()
                write_bytes(state_addr, b"\x00")  # reset our state byte since we're hooked again
                # during the loading screen, we might have missed a file getting loaded.
                # also, since this timing is so sensitive, kick this process off in the background
                Process(name="Adhoc scan", target=scan_for_adhoc_files, args=(debug,)).start()
                Process(name="Sibling scan", target=scan_for_sibling_names, args=()).start()
                logger.info("Hooks enabled.")
            time.sleep(0.25)
        except TypeError:
            logger.error(f"Unable to talk to DQXGame.exe. Exiting.")
            sys.exit()
        except Exception as e:
            logger.error(f"Unable to talk to DQXGame.exe. Exiting. Error: {e}")
            for hook in hook_list:
                hook.disable()
            sys.exit()
