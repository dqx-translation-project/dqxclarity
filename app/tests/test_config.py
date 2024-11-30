import os
import shutil
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.config import *

import unittest


class TestConfig(unittest.TestCase):
    @classmethod
    def tearDownClass(cls) -> None:
        if os.path.exists('user_settings.ini'):
            os.remove('user_settings.ini')


    def test_init_user_config(self) -> None:
        _ = UserConfig('.')
        self.assertTrue(os.path.exists('user_settings.ini'))


    def test_update_user_config(self) -> None:
        config = UserConfig('.')
        config.update(section='translation', key='deepltranslatekey', value='abcd1234')
        config.update(section='translation', key='enabledeepltranslate', value='True')

        config.reinit()

        self.assertTrue(config.config._sections['translation']['enabledeepltranslate'] == 'True')
        self.assertTrue(config.config._sections['translation']['deepltranslatekey'] == 'abcd1234')


    def test_eval_translation_service(self) -> None:
        config = UserConfig('.')
        config.update(section='translation', key='enabledeepltranslate', value='True')

        config.reinit()

        self.assertTrue(config.service == 'deepl')


    def test_eval_translation_key(self) -> None:
        config = UserConfig('.')
        config.update(section='translation', key='enabledeepltranslate', value='True')
        config.update(section='translation', key='deepltranslatekey', value='abcd1234')

        config.reinit()

        self.assertTrue(config.key == 'abcd1234')


if __name__ == '__main__':
    unittest.main()
