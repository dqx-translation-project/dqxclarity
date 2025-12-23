from common.memory import MemWriter
from loguru import logger as log


class Trampoline:
    """Creates a trampoline that allows you to redirect code execution to your
    own.

    :param hook_name: Name of your hook.
    :param signature: Bytes used to find the function you want to
        redirect.
    :param num_bytes_to_steal: Number of bytes to steal from the
        original func to be executed after your hook.
    :param offset: Offset from the signature to write your trampoline.
    :returns: Initialized Trampoline object.
    """

    writer = None
    py_simple_str_addr = None
    thread_state_addr = None

    def __init__(
        self,
        name: str,
        signature: bytes,
        num_bytes_to_steal: int,
        offset: int = 0x0,
    ):
        # only initialize this once and make it global for any additional class creations.
        if not Trampoline.writer:
            Trampoline.writer = MemWriter()
        if not Trampoline.py_simple_str_addr:
            Trampoline.py_simple_str_addr = Trampoline.writer.inject_python()
        if not Trampoline.thread_state_addr:
            thread_state_addr = Trampoline.writer.allocate_memory(1)
            Trampoline.thread_state_addr = bytes(
                Trampoline.writer.pack_to_int(thread_state_addr)
            )

        self.name = name
        self.signature = signature
        self.offset = offset
        self.num_bytes_to_steal = num_bytes_to_steal
        self.signature_address = self.__get_signature_address(signature)
        self.initialized = False

        if self.signature_address == 0:
            log.error(f"Did not find address for hook {self.name}.")
            return

        self.orig_game_bytes = self.__get_stolen_bytes()

        # initialized on __install().
        self.start = None      # address to the bytecode that our trampoline will execute
        self.restore = None    # address where we restore the memory registers
        self.shellcode = None  # address where the actual python shellcode lives that will be executed

        # addresses of where to find registers when trampoline has been taken.
        self.eax = None
        self.ebx = None
        self.ecx = None
        self.edx = None
        self.esi = None
        self.edi = None
        self.ebp = None
        self.esp = None

        self.is_enabled = False

        self.__install()

    def __get_signature_address(self, signature: bytes) -> int:
        """Scans for the address associated with the requested signature.

        :param signature: Signature to search for in memory.
        :returns: Address of the found signature.
        """
        addr = Trampoline.writer.pattern_scan(pattern=signature, module="DQXGame.exe")

        if not addr:
            return 0

        return addr + self.offset

    def __get_stolen_bytes(self) -> bytes:
        """Gets the original bytes prior to us writing our trampoline."""
        return Trampoline.writer.read_bytes(
            self.signature_address, self.num_bytes_to_steal
        )

    def __install(self) -> None:
        """Allocates memory and sets the trampoline code up without enabling
        it."""
        # allocate memory for our bytecode
        mov_insts_addr = Trampoline.writer.allocate_memory(150)

        # allocate memory to back up existing register values. this ensures that we put everything
        # back once our trampoline has run to not corrupt the stack.
        backup_values_addr = Trampoline.writer.allocate_memory(50)

        # where our shellcode will be written.
        shellcode_addr = Trampoline.writer.allocate_memory(2048)

        # fmt: off
        # bytecode to back up existing register values to a remote location, which we can use to read
        # registers as they were prior to the trampoline.
        bytecode = b"\xA3" + Trampoline.writer.pack_to_int(backup_values_addr) + b"\x90" # mov [reg_values], eax then nop
        bytecode += b"\x89\x1D" + Trampoline.writer.pack_to_int(backup_values_addr + 4)  # mov [reg_values+6], ebx
        bytecode += b"\x89\x0D" + Trampoline.writer.pack_to_int(backup_values_addr + 8)  # mov [reg_values+12], ecx
        bytecode += b"\x89\x15" + Trampoline.writer.pack_to_int(backup_values_addr + 12) # mov [reg_values+18], edx
        bytecode += b"\x89\x35" + Trampoline.writer.pack_to_int(backup_values_addr + 16) # mov [reg_values+24], esi
        bytecode += b"\x89\x3D" + Trampoline.writer.pack_to_int(backup_values_addr + 20) # mov [reg_values+30], edi
        bytecode += b"\x89\x2D" + Trampoline.writer.pack_to_int(backup_values_addr + 24) # mov [reg_values+36], ebp
        bytecode += b"\x89\x25" + Trampoline.writer.pack_to_int(backup_values_addr + 28) # mov [reg_values+42], esp

        # back up registers and flags.
        bytecode += b"\x9c\x90" # pushfd; nop
        bytecode += b"\xfc\x90" # cld; nop
        bytecode += b"\x60\x90" # pushad; nop
        # fmt on

        # capture what we have so far
        self.start = mov_insts_addr
        self.restore = backup_values_addr
        self.shellcode = shellcode_addr
        self.eax = backup_values_addr
        self.ebx = backup_values_addr + 4
        self.ecx = backup_values_addr + 8
        self.edx = backup_values_addr + 12
        self.esi = backup_values_addr + 16
        self.edi = backup_values_addr + 20
        self.ebp = backup_values_addr + 24
        self.esp = backup_values_addr + 28

        # spinlock to make sure no other python code is being executed from another thread.
        bytecode += b"\xB0\x01"                                 # mov al, 01                ; prepare to acquire
        bytecode += b"\x86\x05" + Trampoline.thread_state_addr  # xchg byte ptr [addr], al  ; atomic test and set
        bytecode += b"\x84\xC0"                                 # test al, al               ; test for lock
        bytecode += b"\x75\xF4"                                 # jnz                       ; spin back if locked

        # address where our code will start to get executed.
        code_start_addr = mov_insts_addr + len(bytecode)

        # push our shellcode to py_run_simplestring to have it execute.
        bytecode += b"\x68" + bytes(Trampoline.writer.pack_to_int(shellcode_addr))                         # push shellcode_addr
        bytecode += b"\xE8" + Trampoline.writer.calc_rel_addr(code_start_addr + 5, Trampoline.py_simple_str_addr)  # push py_run_simple_string_addr

        # restore the registers back to before our code was run
        # since PyRun_SimpleString is __cdecl, need to clean up
        bytecode += b"\x83\xc4\x04\x90"  # add esp,04; nop

        # restore registers and flags
        bytecode += b"\x61\x90"  # popad; nop
        bytecode += b"\x9d\x90"  # popfd; nop

        # release the spinlock
        bytecode += b"\xC6\x05" + Trampoline.thread_state_addr + b"\x00"

        # address after we restore the memory registers
        after_restore = mov_insts_addr + len(bytecode)

        # make sure we run the game's bytes before jumping back
        bytecode += self.orig_game_bytes

        # jump back to original function, just after stolen bytes
        if self.num_bytes_to_steal > 5:
            count = self.num_bytes_to_steal - 5
        else:
            count = 0

        # calculate relative address to properly trampoline back to the original function.
        bytecode += b"\xe9" + Trampoline.writer.calc_rel_addr(
            after_restore + self.num_bytes_to_steal,
            self.signature_address + count,
        )

        # write our new function to memory
        Trampoline.writer.write_bytes(mov_insts_addr, bytecode)

        log.debug(
            f"{self.name} "
            f":: hook ({hex(self.start)}) "
            f":: shellcode ({hex(self.shellcode)}) "
            f":: trampoline ({hex(self.signature_address)})"
        )

        self.initialized = True

        return None

    def enable(self) -> None:
        """Writes over the original function to enable the trampoline."""
        bytecode = b"\xe9" + Trampoline.writer.calc_rel_addr(
            self.signature_address, self.start
        )

        if self.num_bytes_to_steal > 5:
            count = self.num_bytes_to_steal - 5
            for i in range(count):
                bytecode += b"\x90"

        self.is_enabled = True

        old_protection = Trampoline.writer.get_protection(self.signature_address)
        Trampoline.writer.set_protection(self.signature_address)
        Trampoline.writer.write_bytes(self.signature_address, bytecode)
        Trampoline.writer.set_protection(
            self.signature_address, new_protection=old_protection
        )

        return True

    def disable(self) -> None:
        """Writes over the original function to disable the trampoline."""
        self.is_enabled = False

        old_protection = Trampoline.writer.get_protection(self.signature_address)
        Trampoline.writer.set_protection(self.signature_address)
        Trampoline.writer.write_bytes(self.signature_address, self.orig_game_bytes)
        Trampoline.writer.set_protection(
            self.signature_address, new_protection=old_protection
        )

        return True
