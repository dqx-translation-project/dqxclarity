import ctypes
import sys


def message_box(title: str, message: str, exit_prog: bool = False):
    """Generate a topmost message box."""
    ctypes.windll.user32.MessageBoxW(0, message, f"[dqxclarity] {title}", 0x1000)  # 0x1000 ensures a topmost window
    if exit_prog:
        sys.exit()


class ClarityError(Exception):
    """Base class for exceptions."""


class AddressOutOfRange(ClarityError):
    """Throw exception when address out of range."""

    def __init__(self, address):
        super().__init__(f"Address {address} out of bounds!")


class MemoryReadError(ClarityError):
    """Raised when we couldn't read memory."""

    def __init__(self, address_or_message: int | str):
        if isinstance(address_or_message, int):
            super().__init__(f"Unable to read memory at address {address_or_message}.")
        else:
            super().__init__(address_or_message)


class MemoryWriteError(ClarityError):
    """Raised when we couldn't write to some memory."""

    def __init__(self, address: int):
        super().__init__(f"Unable to write memory at address {address}.")


class PatternFailed(ClarityError):
    """Raised when the pattern scan fails."""

    def __init__(self, pattern):
        super().__init__(f"Pattern {pattern} failed. Restart DQX and try again.")


class FailedToReadAddress(ClarityError):
    """Raised when unable to read bytes at address."""

    def __init__(self, address: int):
        super().__init__(f"Unable to read address at {address}. Restart DQX and try again.")


class PatternMultipleResults(ClarityError):
    """Raised when a pattern has more than one result."""
