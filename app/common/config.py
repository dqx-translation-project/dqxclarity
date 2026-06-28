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
            "translate_service": "googlefree",
            "translate_key": "",
            "chatgpt_model": "gpt-4o-mini",
            "ollama_url": "http://localhost:11434",
            "ollama_model": "llama3",
            "libretranslate_url": "https://libretranslate.com",
            # Runtime translation target, written by the launcher from the highest-priority
            # active language pack. Code (e.g. "en") drives API targets; name (e.g. "English")
            # is injected into LLM prompts.
            "target_language": "en",
            "target_language_name": "English",
        }
        config["config"] = {"installdirectory": "C:/Program Files (x86)/SquareEnix/DRAGON QUEST X"}
        return config

    def _read_config(self) -> configparser.ConfigParser:
        defaults = self._get_default_config()

        user_config = configparser.ConfigParser()
        user_config.read(self.file)

        # migrate from old per-service boolean flags to a single translate_service string
        if user_config.has_section("translation") and not user_config.has_option("translation", "translate_service"):
            t = user_config["translation"]
            if t.get("enabledeepltranslate", "False").lower() == "true":
                user_config.set("translation", "translate_service", "deepl")
                user_config.set("translation", "translate_key", t.get("deepltranslatekey", ""))
            elif t.get("enablegoogletranslate", "False").lower() == "true":
                user_config.set("translation", "translate_service", "google")
                user_config.set("translation", "translate_key", t.get("googletranslatekey", ""))
            elif t.get("enablegoogletranslatefree", "False").lower() == "true":
                user_config.set("translation", "translate_service", "googlefree")

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
    def translate_service(self) -> str:
        return self.translation_section.get("translate_service", "")

    @property
    def translate_key(self) -> str:
        return self.translation_section.get("translate_key", "")

    @property
    def chatgpt_model(self) -> str:
        return self.translation_section.get("chatgpt_model", "gpt-4o-mini")

    @property
    def ollama_url(self) -> str:
        return self.translation_section.get("ollama_url", "http://localhost:11434")

    @property
    def ollama_model(self) -> str:
        return self.translation_section.get("ollama_model", "llama3")

    @property
    def libretranslate_url(self) -> str:
        return self.translation_section.get("libretranslate_url", "https://libretranslate.com")

    @property
    def target_language(self) -> str:
        """Target language code for runtime translation (e.g. "en"). Defaults to English."""
        return self.translation_section.get("target_language", "en") or "en"

    @property
    def target_language_name(self) -> str:
        """Human-readable target language name (e.g. "English"), used in LLM prompts."""
        return self.translation_section.get("target_language_name", "English") or "English"

    @property
    def config_section(self):
        return self.config["config"]

    @property
    def game_directory(self):
        value = self.config_section.get("installdirectory", "")
        return value if value else "C:/Program Files (x86)/SquareEnix/DRAGON QUEST X"
