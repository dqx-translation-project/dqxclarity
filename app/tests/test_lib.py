import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.lib import *

import unittest


class TestLib(unittest.TestCase):
    def test_get_project_root(self):
        root = get_project_root()
        self.assertTrue(root.endswith('dqxclarity/app'))


if __name__ == '__main__':
    unittest.main()
