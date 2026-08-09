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

    def test_update_user_config(self) -> None:
        config = UserConfig(".")
        config.update(section="translation", key="deepltranslatekey", value="abcd1234")
        config.update(section="translation", key="enabledeepltranslate", value="True")

        # Reinitialize to read updated values
        config = UserConfig(".")

        self.assertEqual(config.deepl_key, "abcd1234")
        self.assertTrue(config.deepl_enabled)

    def test_eval_translation_service(self) -> None:
        config = UserConfig(".")
        config.update(section="translation", key="enabledeepltranslate", value="True")

        # Reinitialize to read updated values
        config = UserConfig(".")

        self.assertEqual(config.translate_service, "deepl")

    def test_eval_translation_key(self) -> None:
        config = UserConfig(".")
        config.update(section="translation", key="enabledeepltranslate", value="True")
        config.update(section="translation", key="deepltranslatekey", value="abcd1234")

        # Reinitialize to read updated values
        config = UserConfig(".")

        self.assertEqual(config.translate_key, "abcd1234")

    def test_deepl_properties(self) -> None:
        config = UserConfig(".")
        config.update(section="translation", key="enabledeepltranslate", value="True")
        config.update(section="translation", key="deepltranslatekey", value="test_key_123")

        # Reinitialize to read updated values
        config = UserConfig(".")

        self.assertTrue(config.deepl_enabled)
        self.assertEqual(config.deepl_key, "test_key_123")

    def test_google_properties(self) -> None:
        config = UserConfig(".")
        config.update(section="translation", key="enablegoogletranslate", value="True")
        config.update(section="translation", key="googletranslatekey", value="google_key_456")

        # Reinitialize to read updated values
        config = UserConfig(".")

        self.assertTrue(config.google_enabled)
        self.assertEqual(config.google_key, "google_key_456")

    def test_google_free_properties(self) -> None:
        config = UserConfig(".")
        config.update(section="translation", key="enablegoogletranslatefree", value="True")

        # Reinitialize to read updated values
        config = UserConfig(".")

        self.assertTrue(config.google_free_enabled)

    def test_community_api_properties(self) -> None:
        config = UserConfig(".")
        config.update(section="translation", key="enablecommunityapi", value="True")
        config.update(section="translation", key="communityapikey", value="community_key_789")

        # Reinitialize to read updated values
        config = UserConfig(".")

        self.assertTrue(config.community_enabled)
        self.assertEqual(config.community_key, "community_key_789")

    def test_game_directory_property(self) -> None:
        config = UserConfig(".")
        config.update(section="config", key="installdirectory", value="D:/Games/DQX")

        # Reinitialize to read updated values
        config = UserConfig(".")

        self.assertEqual(config.game_directory, "D:/Games/DQX")

    def test_game_directory_default(self) -> None:
        config = UserConfig(".")

        # Should return default if not set
        self.assertEqual(config.game_directory, "C:/Program Files (x86)/SquareEnix/DRAGON QUEST X")

    def test_translate_service_priority(self) -> None:
        """Test that translate_service returns services in priority order: deepl > google > googlefree"""
        config = UserConfig(".")

        # Test deepl priority
        config.update(section="translation", key="enabledeepltranslate", value="True")
        config.update(section="translation", key="enablegoogletranslate", value="True")
        config.update(section="translation", key="enablegoogletranslatefree", value="True")
        config = UserConfig(".")
        self.assertEqual(config.translate_service, "deepl")

        # Test google priority (deepl disabled)
        config.update(section="translation", key="enabledeepltranslate", value="False")
        config = UserConfig(".")
        self.assertEqual(config.translate_service, "google")

        # Test googlefree (deepl and google disabled)
        config.update(section="translation", key="enablegoogletranslate", value="False")
        config = UserConfig(".")
        self.assertEqual(config.translate_service, "googlefree")

        # Test empty string when all disabled
        config.update(section="translation", key="enablegoogletranslatefree", value="False")
        config = UserConfig(".")
        self.assertEqual(config.translate_service, "")

    def test_translate_key_priority(self) -> None:
        """Test that translate_key returns the correct key based on enabled service"""
        config = UserConfig(".")

        # Test deepl key
        config.update(section="translation", key="enabledeepltranslate", value="True")
        config.update(section="translation", key="deepltranslatekey", value="deepl_key")
        config = UserConfig(".")
        self.assertEqual(config.translate_key, "deepl_key")

        # Test google key
        config.update(section="translation", key="enabledeepltranslate", value="False")
        config.update(section="translation", key="enablegoogletranslate", value="True")
        config.update(section="translation", key="googletranslatekey", value="google_key")
        config = UserConfig(".")
        self.assertEqual(config.translate_key, "google_key")

        # Test empty string for google free
        config.update(section="translation", key="enablegoogletranslate", value="False")
        config.update(section="translation", key="enablegoogletranslatefree", value="True")
        config = UserConfig(".")
        self.assertEqual(config.translate_key, "")

    def test_translation_section_property(self) -> None:
        config = UserConfig(".")

        # Test that translation_section returns the correct section
        section = config.translation_section
        self.assertIsNotNone(section)
        self.assertIn("enabledeepltranslate", section)
        self.assertIn("deepltranslatekey", section)

    def test_config_section_property(self) -> None:
        config = UserConfig(".")

        # Test that config_section returns the correct section
        section = config.config_section
        self.assertIsNotNone(section)
        self.assertIn("installdirectory", section)

    def test_config_auto_cleanup(self) -> None:
        """Test that unknown keys are automatically removed from managed sections"""
        config = UserConfig(".")

        # Manually add an unknown key
        config.config.set("translation", "unknownkey", "value")
        with open(config.file, "w") as f:
            config.config.write(f)

        # Reinitialize - should remove unknown key
        config = UserConfig(".")

        self.assertFalse(config.config.has_option("translation", "unknownkey"))

    def test_config_auto_add_missing_keys(self) -> None:
        """Test that missing default keys are automatically added"""
        config = UserConfig(".")

        # Remove a default key
        config.config.remove_option("translation", "enablecommunityapi")
        with open(config.file, "w") as f:
            config.config.write(f)

        # Reinitialize - should add missing key
        config = UserConfig(".")

        self.assertTrue(config.config.has_option("translation", "enablecommunityapi"))


if __name__ == "__main__":
    unittest.main()
