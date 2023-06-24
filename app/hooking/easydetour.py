import sys
from common.memory import pattern_scan, allocate_memory, pack_to_int, write_bytes, calc_rel_addr, read_bytes, dqx_mem
from loguru import logger


class EasyDetour:
    """
    Creates a detour object that allows you to redirect code execution to your own via Python

    :param hook_name: Name of your hook
    :param signature: Bytes used to find the function you want to redirect
    :param num_bytes_to_steal: Number of bytes to steal from the original func to be executed after your detour
    :param simple_str_addr: Address of where Py_SimpleString is
    :returns: Initiated EasyDetour object. Use enable() to turn on your detour and disable() to turn off
    """

    def __init__(self, hook_name: str, signature: bytes, num_bytes_to_steal: int, simple_str_addr: int, debug=False):
        self.hook_name = hook_name
        self.signature = signature
        self.num_bytes_to_steal = num_bytes_to_steal
        self.simple_str_addr = simple_str_addr
        self.debug = debug
        self.address_dict = self.write_detour()

    def get_signature_address(self):
        return pattern_scan(pattern=self.signature, module="DQXGame.exe")

    def get_stolen_bytes(self):
        return read_bytes(self.get_signature_address(), self.num_bytes_to_steal)

    def write_detour(self):
        mov_insts_addr = allocate_memory(150)  # allocate memory for our bytecode
        backup_values_addr = allocate_memory(50)  # allocate memory to back up existing register values
        shellcode_addr = allocate_memory(2048)  # where our shellcode will be
        pyrun_func_addr = self.simple_str_addr

        # fmt: off
        # bytecode to back up the existing memory registers by mov'ing to remote address
        bytecode = b"\xA3" + pack_to_int(backup_values_addr) + b"\x90" # mov [reg_values], eax then nop
        bytecode += b"\x89\x1D" + pack_to_int(backup_values_addr + 4)  # mov [reg_values+6], ebx
        bytecode += b"\x89\x0D" + pack_to_int(backup_values_addr + 8)  # mov [reg_values+12], ecx
        bytecode += b"\x89\x15" + pack_to_int(backup_values_addr + 12) # mov [reg_values+18], edx
        bytecode += b"\x89\x35" + pack_to_int(backup_values_addr + 16) # mov [reg_values+24], esi
        bytecode += b"\x89\x3D" + pack_to_int(backup_values_addr + 20) # mov [reg_values+30], edi
        bytecode += b"\x89\x2D" + pack_to_int(backup_values_addr + 24) # mov [reg_values+36], ebp
        bytecode += b"\x89\x25" + pack_to_int(backup_values_addr + 28) # mov [reg_values+42], esp

        # capture what we have so far
        address_dict = {
            "name": f"{self.hook_name}",
            "attrs": {
                "begin": mov_insts_addr,  # address where our memory was allocated
                "run_our_code": mov_insts_addr + len(bytecode),  # address where our code starts to get executed
                "restore_orig": backup_values_addr,  # address where we restore the memory registers
                "eax": backup_values_addr,  # value of eax when func hits
                "ebx": backup_values_addr + 4,  # value of ebx when func hits
                "ecx": backup_values_addr + 8,  # value of ecx when func hits
                "edx": backup_values_addr + 12,  # value of edx when func hits
                "esi": backup_values_addr + 16,  # value of esi when func hits
                "edi": backup_values_addr + 20,  # value of edi when func hits
                "ebp": backup_values_addr + 24,  # value of ebp when func hits
                "esp": backup_values_addr + 28,  # value of esp when func hits
                "game_func": self.get_signature_address(),  # address of original game func
                "shellcode": shellcode_addr  # address where our shellcode lives
            }
        }

        # push our shellcode to py_run_simplestring
        bytecode += b"\x68" + bytes(pack_to_int(shellcode_addr))  # push shellcode_addr
        bytecode += b"\xE8" + calc_rel_addr(address_dict["attrs"]["run_our_code"] + 5, pyrun_func_addr)  # push py_run_simple_string_addr

        address_dict["attrs"]["after_our_code"] = mov_insts_addr + len(bytecode)  # address after our code gets executed

        # fmt: off
        # bytecode to restore the registers back to before our code was run
        bytecode += b"\xA1" + pack_to_int(backup_values_addr) + b"\x90"  # mov eax, [backup_values_addr] then nop
        bytecode += b"\x8B\x1D" + pack_to_int(backup_values_addr + 4)    # mov ebx, [backup_values_addr+6]
        bytecode += b"\x8B\x0D" + pack_to_int(backup_values_addr + 8)    # mov ecx, [backup_values_addr+12]
        bytecode += b"\x8B\x15" + pack_to_int(backup_values_addr + 12)   # mov edx, [backup_values_addr+18]
        bytecode += b"\x8B\x35" + pack_to_int(backup_values_addr + 16)   # mov esi, [backup_values_addr+24]
        bytecode += b"\x8B\x3D" + pack_to_int(backup_values_addr + 20)   # mov edi, [backup_values_addr+30]
        bytecode += b"\x8B\x2D" + pack_to_int(backup_values_addr + 24)   # mov ebp, [backup_values_addr+36]
        bytecode += b"\x8B\x25" + pack_to_int(backup_values_addr + 28)   # mov esp, [backup_values_addr+42]

        address_dict["attrs"]["after_restore"] = mov_insts_addr + len(bytecode)  # address after we restore the memory registers
        # fmt: on

        # make sure we run the game's bytes before jumping back
        address_dict["attrs"]["game_bytes"] = self.get_stolen_bytes()  # orig game bytes
        bytecode += address_dict["attrs"]["game_bytes"]

        # jump back to original function, just after stolen bytes
        if self.num_bytes_to_steal > 5:
            count = self.num_bytes_to_steal - 5
        else:
            count = 0
        bytecode += b"\xE9" + calc_rel_addr(
            address_dict["attrs"]["after_restore"] + self.num_bytes_to_steal, address_dict["attrs"]["game_func"] + count
        )

        # write our new function to memory
        write_bytes(mov_insts_addr, bytecode)

        logger.remove()
        if self.debug:
            logger.add(sys.stderr, level="DEBUG")
        else:
            logger.add(sys.stderr, level="INFO")
        logger.debug(
            f"{self.hook_name} :: hook ({hex(address_dict['attrs']['begin'])}) :: shellcode ({hex(address_dict['attrs']['shellcode'])}) :: detour ({hex(address_dict['attrs']['game_func'])})"
        )

        return address_dict

    def enable(self):
        addresses = self.address_dict["attrs"]
        bytecode = b"\xE9" + calc_rel_addr(addresses["game_func"], addresses["begin"])
        if self.num_bytes_to_steal > 5:
            count = self.num_bytes_to_steal - 5
            for i in range(count):
                bytecode += b"\x90"
        write_bytes(addresses["game_func"], bytecode)

    def disable(self):
        addresses = self.address_dict["attrs"]
        write_bytes(addresses["game_func"], addresses["game_bytes"])
