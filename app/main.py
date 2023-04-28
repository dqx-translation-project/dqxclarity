from multiprocessing import Process
import sys
import time
import click
from loguru import logger
from common.update import check_for_updates
from common.translate import load_user_config, refresh_glossary_id

# fmt: off
@click.command()
@click.option('-v', '--debug', is_flag=True, help="Turns on additional logging to console.")
@click.option('-u', '--disable-update-check', is_flag=True, help="Disables checking for updates on each launch.")
@click.option('-c', '--communication-window', is_flag=True,help="Writes hooks into the game to translate the dialog window with a live translation service.")
@click.option('-p', '--player-names', is_flag=True,help="Scans for player names and changes them to their Romaji counterpart.")
@click.option('-n', '--npc-names', is_flag=True, help="Scans for NPC names and changes them to their Romaji counterpart.")
@click.option('-z', '--disable-translations', is_flag=True, help="Only runs initialization of dqxclarity, which checks for updates and validity of your user_settings.ini file.")
# fmt: on


def blast_off(
    disable_update_check=False,
    communication_window=False,
    player_names=False,
    npc_names=False,
    disable_translations=False,
    debug=False,
):
    """A command line tool that assists in translating the game Dragon Quest X."""
    logger.info("Getting started. DO NOT TOUCH THE GAME OR REMOVE YOUR MEMORY CARD.")
    if not disable_update_check:
        check_for_updates()
    user_config = load_user_config()
    if user_config["translation"]["enabledeepltranslate"] == "True":
        refresh_glossary_id()

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
                start_process(name="Hook loader", target=activate_hooks, args=(debug,))
                start_process(name="Walkthrough scanner", target=loop_scan_for_walkthrough, args=())

            start_process(name="Flavortown scanner", target=run_scans, args=(player_names, npc_names, communication_window, debug))
            # fmt: on

            logger.info("Done! Keep this window open (minimize it) and have fun on your adventure!")
    except Exception as e:
        logger.error(f"Can't find DQX process. Exiting. Error: {e}")
        sys.exit()


if __name__ == "__main__":
    blast_off()
