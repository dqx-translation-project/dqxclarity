from multiprocessing import Process
import sys
import threading
import time
from loguru import logger
import click
from common.lib import setup_logging, is_dqx_running
from common.update import check_for_updates, download_custom_files
from dqxcrypt.dqxcrypt import start_logger


debug = False
if "v" in sys.argv[1]:
    debug = True
setup_logging(debug=debug)

# fmt: off
@click.command()
@click.option('-v', '--debug', is_flag=True, help="Turns on additional logging to console.")
@click.option('-u', '--disable-update-check', is_flag=True, help="Disables checking for updates on each launch.")
@click.option('-c', '--communication-window', is_flag=True,help="Writes hooks into the game to translate the dialog window with a live translation service.")
@click.option('-p', '--player-names', is_flag=True,help="Scans for player names and changes them to their Romaji counterpart.")
@click.option('-n', '--npc-names', is_flag=True, help="Scans for NPC names and changes them to their Romaji counterpart.")
@click.option('-l', '--community-logging', is_flag=True, help="Enables dumping important game information that the dqxclarity devs need to continue this project.")
@click.option('-z', '--disable-translations', is_flag=True, help="Only runs initialization of dqxclarity, which checks for updates and validity of your user_settings.ini file.")
# fmt: on


def blast_off(
    disable_update_check=False,
    communication_window=False,
    player_names=False,
    npc_names=False,
    disable_translations=False,
    community_logging=False,
    debug=False,
):

    logger.info("Getting started. DO NOT TOUCH THE GAME OR REMOVE YOUR MEMORY CARD.")
    if not disable_update_check:
        check_for_updates()
        download_custom_files()

    try:
        if not disable_translations:
            # Imports are done here as the program requires the game to be open otherwise.
            # This allows us to test config and translate settings without launching everything.
            from hooking.hook import activate_hooks
            from clarity import loop_scan_for_walkthrough, run_scans

            def start_process(name: str, target, args: tuple):
                p = Process(name=name, target=target, args=args)
                p.start()
                time.sleep(.5)
                while not p.is_alive():
                    time.sleep(0.25)

            if communication_window:
                start_process(name="Hook loader", target=activate_hooks, args=(player_names,debug))
                start_process(name="Walkthrough scanner", target=loop_scan_for_walkthrough, args=())
            if community_logging:
                logger.info("Thanks for enabling logging!")
                threading.Thread(name="Community logging", target=start_logger, args=(), daemon=True).start()
            start_process(name="Flavortown scanner", target=run_scans, args=(player_names, npc_names, debug))
            # fmt: on

            logger.success("Done! Keep this window open (minimize it) and have fun on your adventure!")
    except Exception:
        if is_dqx_running():
            logger.exception(f"An exception occurred. dqxclarity will exit.")
            sys.exit(1)
        else:
            logger.info("DQX has been closed. Exiting.")
            sys.exit(0)


if __name__ == "__main__":
    blast_off()
