# ruff: noqa: F403, F405
import os
import sys


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import unittest
from common.translate import *


class TestTranslate(unittest.TestCase):
    def test_transliterate_player_name(self):
        name = "セラニー"
        result = transliterate_player_name(name)
        self.assertTrue(result == "Seranii")

        name = "エりん"
        result = transliterate_player_name(name)
        self.assertTrue(result == "Erin")

        name = "ファンシー"
        result = transliterate_player_name(name)
        self.assertTrue(result == "Fuanshii")

    def test_clean_up_and_return_items(self):
        pass  # tbd


if __name__ == "__main__":
    unittest.main()
