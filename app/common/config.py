from common.lib import get_project_root
from loguru import logger as log

import configparser
import os


class UserConfig:
    def __init__(self, filepath: str = None, warnings: bool = False) -> dict:
        if not filepath:
            settings_file = get_project_root("user_settings.ini")
        else:
            settings_file = f"{filepath}/user_settings.ini"

        self.filepath = filepath
        self.file = settings_file
        self.warnings = warnings
        self.config = self.read()
        self.service = self.eval_translation_service()

        if self.service:
            self.key = self.eval_translation_key()

        self.game_path = self.config['config'].get('installdirectory')


    def read(self) -> dict:
        base_config = configparser.ConfigParser()
        base_config["translation"] = {
            "enabledeepltranslate": False,
            "deepltranslatekey": "",
            "enablegoogletranslate": False,
            "googletranslatekey": "",
            "enablegoogletranslatefree": False,
        }
        base_config["config"] = {
            "installdirectory": ""
        }

        # Create the config if it doesn't exist.
        if not os.path.exists(self.file):
            with open(self.file, "w+") as configfile:
                base_config.write(configfile)

            if self.warnings:
                log.warning(
                    "user_settings.ini was not found, so one was created for you. "
                    "You will need to fill in the appropriate values and restart this program "
                    "to pick up your changes."
                )

        # Compare user's config with base config to ensure all sections and keys exist.
        user_config = configparser.ConfigParser()
        user_config.read(self.file)

        for section in base_config.sections():
            if section not in user_config.sections():
                log.exception(f"{section} section missing from user_settings.ini.")
            for key, _ in base_config.items(section):
                if key not in user_config[section]:
                    log.exception(f"{key} missing from {section} in user_settings.ini.")

        return user_config


    def reinit(self) -> dict:
        # update class instance with new values read from file written by this method.
        return self.__init__(self.filepath)


    def update(self, section: str, key: str, value: str) -> None:
        config = configparser.ConfigParser()
        config.read(self.file)
        config.set(section, key, value)
        with open(self.file, "w+") as configfile:
            config.write(configfile)


    def eval_translation_service(self) -> str:
        if self.config['translation'].getboolean('enabledeepltranslate'):
            return "deepl"
        if self.config['translation'].getboolean('enablegoogletranslate'):
            return "google"
        if self.config['translation'].getboolean('enablegoogletranslatefree'):
            return "googlefree"

        if self.warnings:
            log.warning("You did not enable a translation service, so no live translation will be performed.")

        return ""


    def eval_translation_key(self) -> str:
        service = self.eval_translation_service()
        if service == "deepl":
            if key := self.config['translation'].get('deepltranslatekey'):
                return key
        if service == "google":
            if key := self.config['translation'].get('googletranslatekey'):
                return key
        if service == "googlefree":
            return ""

        if self.warnings:
            log.exception(f"You enabled {service}, but did not specify a key.")

        return ""
