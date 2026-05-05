import os
import unittest
from common.config import UserConfig


class TestConfig(unittest.TestCase):
    @classmethod
    def tearDownClass(cls) -> None:
        if os.path.exists("user_settings.ini"):
            os.remove("user_settings.ini")

    def test_init_user_config(self) -> None:
        _ = UserConfig(".")
        self.assertTrue(os.path.exists("user_settings.ini"))

    def test_default_translate_service(self) -> None:
        config = UserConfig(".")
        self.assertEqual(config.translate_service, "googlefree")

    def test_update_translate_service(self) -> None:
        config = UserConfig(".")
        config.update(section="translation", key="translate_service", value="deepl")
        config = UserConfig(".")
        self.assertEqual(config.translate_service, "deepl")

    def test_update_translate_key(self) -> None:
        config = UserConfig(".")
        config.update(section="translation", key="translate_service", value="deepl")
        config.update(section="translation", key="translate_key", value="abcd1234")
        config = UserConfig(".")
        self.assertEqual(config.translate_service, "deepl")
        self.assertEqual(config.translate_key, "abcd1234")

    def test_chatgpt_model_default(self) -> None:
        config = UserConfig(".")
        self.assertEqual(config.chatgpt_model, "gpt-4o-mini")

    def test_chatgpt_model_update(self) -> None:
        config = UserConfig(".")
        config.update(section="translation", key="chatgpt_model", value="gpt-4o")
        config = UserConfig(".")
        self.assertEqual(config.chatgpt_model, "gpt-4o")

    def test_ollama_defaults(self) -> None:
        config = UserConfig(".")
        self.assertEqual(config.ollama_url, "http://localhost:11434")
        self.assertEqual(config.ollama_model, "llama3")

    def test_ollama_update(self) -> None:
        config = UserConfig(".")
        config.update(section="translation", key="ollama_url", value="http://192.168.1.10:11434")
        config.update(section="translation", key="ollama_model", value="mistral")
        config = UserConfig(".")
        self.assertEqual(config.ollama_url, "http://192.168.1.10:11434")
        self.assertEqual(config.ollama_model, "mistral")

    def test_libretranslate_default(self) -> None:
        config = UserConfig(".")
        self.assertEqual(config.libretranslate_url, "https://libretranslate.com")

    def test_libretranslate_update(self) -> None:
        config = UserConfig(".")
        config.update(section="translation", key="libretranslate_url", value="http://localhost:5000")
        config = UserConfig(".")
        self.assertEqual(config.libretranslate_url, "http://localhost:5000")

    def test_community_api_properties(self) -> None:
        config = UserConfig(".")
        config.update(section="translation", key="enablecommunityapi", value="True")
        config.update(section="translation", key="communityapikey", value="community_key_789")
        config = UserConfig(".")
        self.assertTrue(config.community_enabled)
        self.assertEqual(config.community_key, "community_key_789")

    def test_game_directory_property(self) -> None:
        config = UserConfig(".")
        config.update(section="config", key="installdirectory", value="D:/Games/DQX")
        config = UserConfig(".")
        self.assertEqual(config.game_directory, "D:/Games/DQX")

    def test_game_directory_default(self) -> None:
        config = UserConfig(".")
        self.assertEqual(config.game_directory, "C:/Program Files (x86)/SquareEnix/DRAGON QUEST X")

    def test_migration_from_old_deepl_flags(self) -> None:
        """Old boolean flags in user_settings.ini should migrate to translate_service."""
        import configparser

        # Write an old-format INI manually
        cfg = configparser.ConfigParser()
        cfg["translation"] = {
            "enabledeepltranslate": "True",
            "deepltranslatekey": "migrated_key",
            "enablegoogletranslate": "False",
            "googletranslatekey": "",
            "enablegoogletranslatefree": "False",
            "communityapikey": "",
            "enablecommunityapi": "False",
        }
        cfg["config"] = {"installdirectory": "C:/Program Files (x86)/SquareEnix/DRAGON QUEST X"}
        with open("user_settings.ini", "w") as f:
            cfg.write(f)

        config = UserConfig(".")
        self.assertEqual(config.translate_service, "deepl")
        self.assertEqual(config.translate_key, "migrated_key")

    def test_migration_from_old_google_flags(self) -> None:
        import configparser

        cfg = configparser.ConfigParser()
        cfg["translation"] = {
            "enabledeepltranslate": "False",
            "deepltranslatekey": "",
            "enablegoogletranslate": "True",
            "googletranslatekey": "gkey",
            "enablegoogletranslatefree": "False",
            "communityapikey": "",
            "enablecommunityapi": "False",
        }
        cfg["config"] = {"installdirectory": "C:/Program Files (x86)/SquareEnix/DRAGON QUEST X"}
        with open("user_settings.ini", "w") as f:
            cfg.write(f)

        config = UserConfig(".")
        self.assertEqual(config.translate_service, "google")
        self.assertEqual(config.translate_key, "gkey")

    def test_migration_from_old_googlefree_flag(self) -> None:
        import configparser

        cfg = configparser.ConfigParser()
        cfg["translation"] = {
            "enabledeepltranslate": "False",
            "deepltranslatekey": "",
            "enablegoogletranslate": "False",
            "googletranslatekey": "",
            "enablegoogletranslatefree": "True",
            "communityapikey": "",
            "enablecommunityapi": "False",
        }
        cfg["config"] = {"installdirectory": "C:/Program Files (x86)/SquareEnix/DRAGON QUEST X"}
        with open("user_settings.ini", "w") as f:
            cfg.write(f)

        config = UserConfig(".")
        self.assertEqual(config.translate_service, "googlefree")

    def test_config_auto_cleanup(self) -> None:
        config = UserConfig(".")
        config.config.set("translation", "unknownkey", "value")
        with open(config.file, "w") as f:
            config.config.write(f)
        config = UserConfig(".")
        self.assertFalse(config.config.has_option("translation", "unknownkey"))

    def test_config_auto_add_missing_keys(self) -> None:
        config = UserConfig(".")
        config.config.remove_option("translation", "enablecommunityapi")
        with open(config.file, "w") as f:
            config.config.write(f)
        config = UserConfig(".")
        self.assertTrue(config.config.has_option("translation", "enablecommunityapi"))

    def test_translation_section_property(self) -> None:
        config = UserConfig(".")
        section = config.translation_section
        self.assertIsNotNone(section)
        self.assertIn("translate_service", section)
        self.assertIn("translate_key", section)

    def test_config_section_property(self) -> None:
        config = UserConfig(".")
        section = config.config_section
        self.assertIsNotNone(section)
        self.assertIn("installdirectory", section)


if __name__ == "__main__":
    unittest.main()
