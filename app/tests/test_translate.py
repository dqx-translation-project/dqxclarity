import os
import shutil
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.translate import *

import unittest


class TestTranslate(unittest.TestCase):
    @classmethod
    def tearDownClass(cls) -> None:
        if os.path.exists('user_settings.ini'):
            os.remove('user_settings.ini')


    def test_detect_lang(self):
        ja_str = '<speed=0><se_nots Joutyu_SE 61>ショウブは　近くのものを指差した！'
        result = detect_lang(ja_str)
        self.assertTrue(result)

        en_str = 'This is a test.'
        result = detect_lang(en_str)
        self.assertFalse(result)


    def test_transliterate_player_name(self):
        name = 'セラニー'
        result = transliterate_player_name(name)
        self.assertTrue(result == 'Seranii')

        name = 'エりん'
        result = transliterate_player_name(name)
        self.assertTrue(result == 'Erin')

        name = 'ファンシー'
        result = transliterate_player_name(name)
        self.assertTrue(result == 'Fuanshii')


    def test_load_user_config(self):
        config = load_user_config('.')

        # test that a new file was created
        self.assertTrue(os.path.exists('user_settings.ini'))

        # test that keys were created
        self.assertTrue(config['translation'])
        self.assertTrue(config['config'])


    def test_load_update_user_config(self):
        shutil.copy('../../user_settings.ini', '.')
        update_user_config(section='translation', key='deepltranslatekey', value='abcd1234')
        config = load_user_config('.')
        self.assertTrue(config['translation']['deepltranslatekey'] == 'abcd1234')


    def test_determine_translation_service(self):
        pass # tbd


    def test_clean_up_and_return_items(self):
        pass # tbd


if __name__ == '__main__':
    unittest.main()
