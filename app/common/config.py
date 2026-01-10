import configparser
import os
from common.lib import get_project_root


class UserConfig:
    """
    Defines the user's user_settings.ini file, which contains things like the game path,
    enabled translation services and associated api keys.
    """

    def __init__(self, filepath: str = None):
        self.file = get_project_root("user_settings.ini") if not filepath else f"{filepath}/user_settings.ini"
        self.config = self._read_config()

    def _get_default_config(self) -> configparser.ConfigParser:
        config = configparser.ConfigParser()
        config["translation"] = {
            "enabledeepltranslate": "False",
            "deepltranslatekey": "",
            "enablegoogletranslate": "False",
            "googletranslatekey": "",
            "enablegoogletranslatefree": "False",
            "communityapikey": "",
            "enablecommunityapi": "False",
        }
        config["config"] = {"installdirectory": "C:/Program Files (x86)/SquareEnix/DRAGON QUEST X"}
        return config

    def _read_config(self) -> configparser.ConfigParser:
        defaults = self._get_default_config()

        user_config = configparser.ConfigParser()
        user_config.read(self.file)

        needs_write = False

        # add missing sections and keys from defaults
        for section in defaults.sections():
            if section not in user_config.sections():
                user_config.add_section(section)
                needs_write = True

            for key, value in defaults.items(section):
                if not user_config.has_option(section, key):
                    user_config.set(section, key, value)
                    needs_write = True

        # remove keys that aren't in defaults (only within sections we manage)
        for section in defaults.sections():
            if section in user_config.sections():
                for key in list(user_config.options(section)):
                    if not defaults.has_option(section, key):
                        user_config.remove_option(section, key)
                        needs_write = True

        # write back if there were changes or file didn't exist
        if needs_write or not os.path.exists(self.file):
            with open(self.file, "w") as f:
                user_config.write(f)

        return user_config

    def update(self, section: str, key: str, value: str) -> None:
        """Update a config value and write it to disk."""
        self.config.set(section, key, value)
        with open(self.file, "w") as f:
            self.config.write(f)

    @property
    def translation_section(self):
        return self.config["translation"]

    @property
    def deepl_enabled(self) -> bool:
        return self.translation_section.getboolean("enabledeepltranslate", False)

    @property
    def deepl_key(self) -> str:
        return self.translation_section.get("deepltranslatekey", "")

    @property
    def google_enabled(self) -> bool:
        return self.translation_section.getboolean("enablegoogletranslate", False)

    @property
    def google_key(self) -> str:
        return self.translation_section.get("googletranslatekey", "")

    @property
    def google_free_enabled(self) -> bool:
        return self.translation_section.getboolean("enablegoogletranslatefree", False)

    @property
    def community_enabled(self) -> bool:
        return self.translation_section.getboolean("enablecommunityapi", False)

    @property
    def community_key(self) -> str:
        return self.translation_section.get("communityapikey", "")

    @property
    def config_section(self):
        return self.config["config"]

    @property
    def game_directory(self):
        value = self.config_section.get("installdirectory", "")
        return value if value else "C:/Program Files (x86)/SquareEnix/DRAGON QUEST X"

    @property
    def translate_key(self) -> str:
        if self.deepl_enabled:
            return self.deepl_key
        if self.google_enabled:
            return self.google_key
        if self.google_free_enabled:
            return ""
        return ""

    @property
    def translate_service(self) -> str:
        if self.deepl_enabled:
            return "deepl"
        if self.google_enabled:
            return "google"
        if self.google_free_enabled:
            return "googlefree"
        return ""
