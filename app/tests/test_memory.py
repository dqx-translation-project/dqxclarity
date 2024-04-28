import os
import subprocess
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.memory import *

import unittest


class TestMemory(unittest.TestCase):

    process = None
    python = None

    @classmethod
    def setUpClass(cls):
        def start_testing_process():
            info = subprocess.STARTUPINFO()
            info.dwFlags = subprocess.STARTF_USESHOWWINDOW
            info.wShowWindow = subprocess.SW_HIDE
            python = subprocess.Popen("python.exe", startupinfo=info)
            return python

        cls.python = start_testing_process()
        cls.process = MemWriter(cls.python.pid)


    @classmethod
    def tearDownClass(cls):
        cls.process.close()
        cls.python.kill()


    def test_attach(self):
        self.process.attach("python.exe")


    def test_allocate_memory(self):
        address = self.process.allocate_memory(4)

        self.assertTrue(address)


    def test_allocate_read_and_write_bytes(self):
        address = self.process.allocate_memory(4)
        self.process.write_bytes(address=address, value=b"\x00\x01\x02\x03")
        value = self.process.read_bytes(address=address, size=4)

        self.assertTrue(value == b"\x00\x01\x02\x03")


    def test_allocate_read_and_write_string(self):
        address = self.process.allocate_memory(4)
        self.process.write_string(address=address, text="this is a test")
        value = self.process.read_string(address=address)

        self.assertTrue(value == "this is a test")


    def test_pattern_scan_all(self):
        address = self.process.allocate_memory(4)

        to_write = b"This is a test of the emergency broadcasting system."
        self.process.write_bytes(address=address, value=to_write)

        # all_protections is required as allocate_memory adds RWE to the address
        result = self.process.pattern_scan(pattern=to_write, all_protections=True)

        self.assertTrue(result == address)


    def test_pattern_scan_module(self):
        # first few bytes of Py_InitializeEx
        to_search = b"\x55\x8B\xEC\x83\xE4\xF0\x81\xEC\x30\x01\x00\x00"
        result = self.process.pattern_scan(pattern=to_search, all_protections=True, module="python311.dll")

        self.assertTrue(result)


    def test_get_ptr_address(self):
        address = self.process.allocate_memory(4)
        fake_address = b"\x01\x23\x45\x67"

        self.process.write_bytes(address, fake_address)
        pointer = self.process.get_ptr_address(address, offsets=[0x0, 0x0, 0x0])

        self.assertTrue(hex(pointer) == "0x67452301")


    def test_get_base_address(self):
        address = self.process.get_base_address("python311.dll")

        self.assertTrue(address)


    def test_pack_to_int(self):
        address = 0x01234567
        result = self.process.pack_to_int(address)

        self.assertTrue(result.hex(" ") == "67 45 23 01")


    def test_unpack_to_int(self):
        address = self.process.allocate_memory(4)
        self.process.write_bytes(address, b"\x01\x23\x45\x67")
        result = self.process.unpack_to_int(address)

        self.assertTrue(hex(result) == "0x67452301")


    def test_allocate_memory(self):
        address = self.process.allocate_memory(4)

        self.assertTrue(address)


    def test_calc_rel_addr_forwards(self):
        offset = self.process.calc_rel_addr(origin_address=0x10000000, destination_address=0x20000000)

        self.assertTrue(offset == b"\xfb\xff\xff\x0f")


    def test_calc_rel_addr_backwards(self):
        offset = self.process.calc_rel_addr(origin_address=0x20000000, destination_address=0x10000000)

        self.assertTrue(offset == b"\x00\x00\x00\xf0")


    def test_get_hook_bytecode(self):
        jump_bytes = self.process.get_hook_bytecode(0x01234567)

        self.assertTrue(jump_bytes.hex(" ") == "e9 67 45 23 01")


if __name__ == '__main__':
    unittest.main()
