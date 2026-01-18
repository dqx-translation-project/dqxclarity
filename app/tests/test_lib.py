# ruff: noqa: F403, F405
import os
import sys


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import unittest
from common.lib import *


class TestLib(unittest.TestCase):
    def test_get_project_root(self):
        root = get_project_root()
        self.assertTrue(root.endswith("dqxclarity/app"))


if __name__ == "__main__":
    unittest.main()
