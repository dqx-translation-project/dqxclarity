import contextlib
import ctypes
import ctypes.wintypes
import frida
import time
from hooking.hook import HOOKS, HookScript
from loguru import logger as log


PROCESS_NAME = "DQXGame.exe"

active_scripts: list[HookScript] = []


def get_process_memory_mb(process_name: str) -> float:
    """Get the memory usage of a process by name from outside the process.

    :param process_name: Name of the process (e.g., "DQXGame.exe")
    :return: Memory usage in MB, or 0 if process not found or error
    """
    # Windows API definitions
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010

    kernel32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi

    try:
        # Find the process by name
        device = frida.get_local_device()
        processes = [p for p in device.enumerate_processes() if p.name == process_name]

        if not processes:
            log.debug(f"Process {process_name} not found")
            return 0.0

        pid = processes[0].pid

        # Open process handle
        h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h_process:
            error_code = kernel32.GetLastError()
            log.debug(f"Failed to open process handle, error code: {error_code}")
            return 0.0

        try:
            # PROCESS_MEMORY_COUNTERS structure - must define all fields
            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.wintypes.DWORD),
                    ("PageFaultCount", ctypes.wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            pmc = PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)

            if psapi.GetProcessMemoryInfo(h_process, ctypes.byref(pmc), pmc.cb):
                memory_mb = pmc.WorkingSetSize / (1024 * 1024)
                log.debug(f"Read memory successfully: {memory_mb:.1f}MB")
                return memory_mb
            else:
                error_code = kernel32.GetLastError()
                log.debug(f"GetProcessMemoryInfo failed, error code: {error_code}")
                return 0.0
        finally:
            kernel32.CloseHandle(h_process)
    except Exception as e:
        log.exception(f"Exception in get_process_memory_mb: {e}")
        return 0.0


def wait_for_memory_threshold(process_name: str, threshold_mb: int = 200):
    """Wait for process memory to exceed a threshold from outside the process.

    :param process_name: Name of the process to monitor
    :param threshold_mb: Minimum memory in MB before continuing
    """
    log.debug("Waiting for game to load...")

    count = 0
    while True:
        memory_mb = get_process_memory_mb(process_name)

        if memory_mb >= threshold_mb:
            log.debug(f"Memory threshold reached: {memory_mb:.1f}MB")
            time.sleep(1)  # Wait 1 second before continuing
            return

        if memory_mb > 0:
            log.debug(f"Current memory: {memory_mb:.1f}MB")

        if count == 10:
            log.warning("Waited 10 seconds, attempting to hook anyways...")
            return

        time.sleep(1)
        count += 1


def activate_hooks(communication_window: bool, nameplates: bool, community_logging: bool):
    global active_scripts

    try:
        enabled_hooks = HOOKS["default"].copy()

        category_flags = {
            "communication_window": communication_window,
            "nameplates": nameplates,
            "community_logging": community_logging,
        }

        # enable hooks based on args passed to activate_hooks
        for category, is_enabled in category_flags.items():
            if is_enabled:
                enabled_hooks.extend(HOOKS[category])

        log.info(f"Enabled hooks ({len(enabled_hooks)}):")
        for hook in enabled_hooks:
            log.info(f"  {hook.name}")

        # wait for binary to be fully loaded into memory before attaching
        wait_for_memory_threshold(PROCESS_NAME)

        log.info(f"Attaching to {PROCESS_NAME}...")
        session = frida.attach(PROCESS_NAME)

        # load each hook as a separate script
        log.info("Loading hook scripts...")
        for i, hook in enumerate(enabled_hooks):
            try:
                hook_script = HookScript(hook, i, session)
                hook_script.load()
                active_scripts.append(hook_script)
            except Exception as e:
                log.exception(f"Failed to load {hook.name}: {e}")

        if not active_scripts:
            log.info("No hooks were loaded. Exiting.")
            time.sleep(3)
            return

        log.success(f"Successfully loaded {len(active_scripts)} hook(s)!")

        # hooks will remain active as long as the session is alive.
        # main process will handle blocking and ctrl+c

    except Exception as e:
        log.exception(e)


def cleanup_hooks():
    """Clean up all active hooks."""
    global active_scripts
    log.info("Cleaning up hooks...")
    for hook_script in active_scripts:
        with contextlib.suppress(Exception):
            hook_script.unload()
    active_scripts.clear()
