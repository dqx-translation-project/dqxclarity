from common.db_ops import generate_m00_dict
from common.errors import MemoryReadError
from common.lib import setup_logging
from common.process import is_dqx_process_running
from pymem.exception import WinAPIError
from scans.comms import scan_for_comm_names
from scans.npc_names import scan_for_concierge_names
from scans.player_names import scan_for_menu_ai_names

import sys


def run_scans(player_names: bool, npc_names: bool, ready_event):
    """Run chosen scans.

    :param player_names: Run player name scans.
    :param npc_names: Run NPC name scans.
    :param communication_window: Run adhoc scans.
    """
    # configure logging. this function runs in multiprocessing, so it does not
    # have the same access to the main log handler.
    global log
    log = setup_logging()

    players = generate_m00_dict(files="'custom_npc_name_overrides', 'local_player_names'")
    mytown_names = generate_m00_dict(files="'custom_concierge_mail_names', 'local_mytown_names'")

    if ready_event:
        ready_event.set()

    while True:
        try:
            if player_names:
                scan_for_menu_ai_names(players)
                scan_for_comm_names()
            if npc_names:
                scan_for_concierge_names(mytown_names)
        except UnicodeDecodeError:
            pass
        except MemoryReadError:
            continue
        except WinAPIError as e:
            if e.error_code == 299:  # memory page changed
                continue
            elif e.error_code == 5:  # game closed
                continue
            else:
                raise e
        except KeyboardInterrupt:
            sys.exit(1)
        except Exception:
            if is_dqx_process_running():
                log.exception("An exception occurred. dqxclarity will exit.")
                sys.exit(1)
            else:
                sys.exit(0)
