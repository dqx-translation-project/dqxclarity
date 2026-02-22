import argparse
import sys
import time
from common.config import UserConfig
from common.db_ops import create_db_schema, delete_translation_cache
from common.lib import get_project_root, setup_logging
from common.process import is_dqx_process_running, wait_for_dqx_to_launch
from common.update import check_for_updates, download_custom_files, download_dat_files, import_name_overrides
from hooking.activate import activate_hooks, cleanup_hooks
from pathlib import Path


def parse_arguments():
    parser = argparse.ArgumentParser(description="dqxclarity: A Japanese to English translation tool for Dragon Quest X.")

    parser.add_argument(
        "-u", "--disable-update-check", action="store_true", help="Disables checking for updates on each launch."
    )
    parser.add_argument(
        "-c",
        "--communication-window",
        action="store_true",
        help="Writes hooks into the game to translate the dialog window with a live translation service.",
    )
    parser.add_argument(
        "-n",
        "--nameplates",
        action="store_true",
        help="Scans for nameplate names and transliterates them to their Romaji counterpart.",
    )
    parser.add_argument(
        "-l",
        "--community-logging",
        action="store_true",
        help="Enables dumping important game information that the dqxclarity devs need to continue this project.",
    )
    parser.add_argument(
        "-d",
        "--update-dat",
        action="store_true",
        help="Update the translated idx and dat file with the latest from Github. Requires the game to be closed.",
    )
    parser.add_argument(
        "-f",
        "--purge-cache",
        action="store_true",
        help="Purges all rows from the sqlite dialog table, which is used for caching translations.",
    )
    parser.add_argument("-v", "--debug", action="store_true", help="Enable debug level logging.")

    return parser.parse_args()


def main():
    args = parse_arguments()

    # configure logging
    logs_dir = Path(get_project_root("logs"))
    logs_dir.mkdir(parents=True, exist_ok=True)

    log_path = get_project_root("logs/console.log")
    Path(log_path).unlink(missing_ok=True)

    log_level = "DEBUG" if args.debug else "INFO"
    log = setup_logging(level=log_level)

    log.info('Running. Please wait until this window says "Done!" before logging into your character.')

    log.debug("Ensuring db structure.")
    create_db_schema()

    if args.purge_cache:
        log.info("Deleting translation cache.")
        delete_translation_cache()

    # we don't do anything with the config here, but this will validate the config is ok before running.
    log.debug("Checking user_settings.ini.")
    UserConfig()

    if args.update_dat:
        log.info("Updating DAT mod.")
        download_dat_files()
    if not args.disable_update_check:
        log.info("Updating custom text in db.")
        check_for_updates(update=True)
        download_custom_files()

    import_name_overrides()

    try:
        if not any(vars(args).values()):
            log.success("No options were selected. dqxclarity will exit.")
            time.sleep(3)
            sys.exit(0)

        wait_for_dqx_to_launch()

        activate_hooks(
            communication_window=args.communication_window,
            nameplates=args.nameplates,
            community_logging=args.community_logging,
        )

        log.success("Done! Keep this window open (minimize it) and have fun on your adventure!")

        # keep the program running to maintain Frida hooks
        log.info("Press Ctrl+C to stop...")

        try:
            # keep running while dqx is open.
            while True:
                time.sleep(0.5)
                if not is_dqx_process_running():
                    return
        except KeyboardInterrupt:
            log.info("Shutting down...")
            cleanup_hooks()

    except Exception:
        log.exception("An exception occurred. dqxclarity will exit.")
        sys.exit(1)


if __name__ == "__main__":
    main()
