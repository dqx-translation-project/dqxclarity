from clarity import loop_scan_for_walkthrough, run_scans
from common.db_ops import create_db_schema, sync_existing_tables
from common.lib import get_project_root, setup_logging
from common.process import wait_for_dqx_to_launch
from common.translate import determine_translation_service
from common.update import (
    check_for_updates,
    download_custom_files,
    download_dat_files,
)
from dqxcrypt.dqxcrypt import start_logger
from hooking.hook import activate_hooks
from multiprocessing import Process
from pathlib import Path

import click
import sys
import threading
import time


# fmt: off
@click.command()
@click.option('-v', '--debug', is_flag=True, help="Turns on additional logging to console. This will be removed in a future update.")
@click.option('-u', '--disable-update-check', is_flag=True, help="Disables checking for updates on each launch.")
@click.option('-c', '--communication-window', is_flag=True,help="Writes hooks into the game to translate the dialog window with a live translation service.")
@click.option('-p', '--player-names', is_flag=True,help="Scans for player names and changes them to their Romaji counterpart.")
@click.option('-n', '--npc-names', is_flag=True, help="Scans for NPC names and changes them to their Romaji counterpart.")
@click.option('-l', '--community-logging', is_flag=True, help="Enables dumping important game information that the dqxclarity devs need to continue this project.")
@click.option('-d', '--update-dat', is_flag=True, help="Update the translated idx and dat file with the latest from Github. Requires the game to be closed.")


def blast_off(
    disable_update_check=False,
    communication_window=False,
    player_names=False,
    npc_names=False,
    community_logging=False,
    update_dat=False,
    debug=False  # this will be removed in a future update.
):

    # configure logging
    logs_dir = Path(get_project_root("logs"))
    logs_dir.mkdir(parents=True, exist_ok=True)

    log_path = get_project_root("logs/console.log")
    Path(log_path).unlink(missing_ok=True)

    log = setup_logging()

    log.info("Getting started. DO NOT TOUCH THE GAME OR REMOVE YOUR MEMORY CARD.",)

    log.info("Ensuring db structure.")
    create_db_schema()
    sync_existing_tables()

    if update_dat:
        log.info("Updating DAT mod.")
        download_dat_files()
    if not disable_update_check:
        log.info("Updating custom text in db.")
        check_for_updates(update=True)
        download_custom_files()

    log.info("Checking user_settings.ini.")
    determine_translation_service(communication_window_enabled=communication_window)

    try:
        wait_for_dqx_to_launch()

        def start_process(name: str, target, args: tuple):
            p = Process(name=name, target=target, args=args)
            p.start()
            time.sleep(.5)
            while not p.is_alive():
                time.sleep(0.25)

        start_process(name="Hook loader", target=activate_hooks, args=(player_names,communication_window,))

        if communication_window:
            start_process(name="Walkthrough scanner", target=loop_scan_for_walkthrough, args=())

        if community_logging:
            log.info("Thanks for enabling logging! Logs for this feature are found in the 'logs' folder. If you don't ever intend on sharing these logs with the dqxclarity team, this feature doesn't do anything.")
            threading.Thread(name="Community logging", target=start_logger, daemon=True).start()

        start_process(name="Flavortown scanner", target=run_scans, args=(player_names, npc_names))

        log.success("Done! Keep this window open (minimize it) and have fun on your adventure!")
    except Exception:
        log.exception(f"An exception occurred. dqxclarity will exit.")
        sys.exit(1)


if __name__ == "__main__":
    blast_off()
