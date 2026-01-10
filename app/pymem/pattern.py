import sys
import pymem.memory
import pymem.ressources.kernel32
import pymem.ressources.structure


def scan_pattern_page(
    handle, address, pattern, *, all_protections=True, use_regex=False, return_multiple=False, data_only=False
):
    """Search a byte pattern given a memory location.
    Will query memory location information and search over until it reaches the
    length of the memory page. If nothing is found the function returns the
    next page location.
    Parameters
    ----------
    handle: HANDLE
        Handle to an open object
    address: int
        An address to search from
    pattern: bytes
        A regex byte pattern to search for
    all_protections: list(string)
        A list of MEMORY_PROTECTION(s) the page must match to be considered
    return_multiple: bool
        If multiple results should be returned instead of stopping on the first
    data_only: bool
        Only scan for memory regions that are considered data and read/writable
    Returns
    -------
    tuple
        next_region, found address
        found address may be None if one was not found or we didn't have permission to scan
        the region
        if return_multiple is True found address will instead be a list of found addresses
        or an empty list if no results
    """
    if use_regex:
        import regex as re
    else:
        import re

    mbi = pymem.memory.virtual_query(handle, address)
    next_region = mbi.BaseAddress + mbi.RegionSize

    if all_protections:
        allowed_protections = [
            pymem.ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_READ,
            pymem.ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE,
            pymem.ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_WRITECOPY,  # steamos opens wine processes with this
            pymem.ressources.structure.MEMORY_PROTECTION.PAGE_READWRITE,
            pymem.ressources.structure.MEMORY_PROTECTION.PAGE_READONLY,
        ]
    else:
        allowed_protections = [
            pymem.ressources.structure.MEMORY_PROTECTION.PAGE_READWRITE,
            pymem.ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_WRITECOPY,  # steamos opens wine processes with this
        ]

    if mbi.state != pymem.ressources.structure.MEMORY_STATE.MEM_COMMIT or mbi.protect not in allowed_protections:
        return next_region, None

    # clarity_custom: Only scan for data regions.
    if data_only and mbi.type not in [
        pymem.ressources.structure.MEMORY_TYPES.MEM_PRIVATE,
        pymem.ressources.structure.MEMORY_TYPES.MEM_MAPPED,
    ]:
        return next_region, None

    try:
        page_bytes = pymem.memory.read_bytes(handle, address, mbi.RegionSize)
    except pymem.exception.WinAPIError as e:
        if e.error_code == 299:  # hiding an issue where memory changes between query and read
            return next_region, None
        raise pymem.exception.MemoryReadError(address, mbi.RegionSize, e.error_code)
    except MemoryError:  # we somehow read more bytes than we should have
        return next_region, None

    if not return_multiple:
        found = None
        match = re.search(pattern, page_bytes, re.DOTALL)

        if match:
            found = address + match.span()[0]

    else:
        found = []

        for match in re.finditer(pattern, page_bytes, re.DOTALL):
            found_address = address + match.span()[0]
            found.append(found_address)

    return next_region, found


def pattern_scan_module(handle, module, pattern, *, all_protections=True, use_regex=False, return_multiple=False):
    """Given a handle over an opened process and a module will scan memory after
    a byte pattern and return its corresponding memory address.
    Parameters
    ----------
    handle: int
        Handle to an open object
    module: MODULEINFO
        An instance of a given module
    pattern: bytes
        A regex byte pattern to search for
    return_multiple: bool
        If multiple results should be returned instead of stopping on the first
    Returns
    -------
    int, list, optional
        Memory address of given pattern, or None if one was not found
        or a list of found addresses in return_multiple is True
    Examples
    --------
    >>> pm = pymem.Pymem("Notepad.exe")
    # Here the "." means that the byte can be any byte; a "wildcard"
    # also note that this pattern may be outdated
    >>> bytes_pattern = b".\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00" \\
    ...                 b"\\x00\\x00\\x00\\x00\\x00\\x00..\\x00\\x00..\\x00\\x00\\x64\\x04"
    >>> module_notepad = pymem.process.module_from_name(pm.process_handle, "Notepad.exe")
    >>> character_count_address = pymem.pattern.pattern_scan_module(pm.process_handle, module_notepad, bytes_pattern)
    """
    base_address = module.lpBaseOfDll
    max_address = module.lpBaseOfDll + module.SizeOfImage
    page_address = base_address

    if not return_multiple:
        found = None
        while page_address < max_address:
            page_address, found = scan_pattern_page(
                handle, page_address, pattern, all_protections=all_protections, use_regex=use_regex
            )

            if found:
                break

    else:
        found = []
        while page_address < max_address:
            page_address, new_found = scan_pattern_page(
                handle, page_address, pattern, all_protections=all_protections, use_regex=use_regex, return_multiple=True
            )

            if new_found:
                found += new_found

    return found


def pattern_scan_all(handle, pattern, *, all_protections=True, use_regex=False, return_multiple=False, data_only=False):
    """Scan the entire address space for a given regex pattern
    Parameters
    ----------
    handle: int
        Handle to an open process
    pattern: bytes
        A regex bytes pattern to search for
    return_multiple: bool
        If multiple results should be returned
    Returns
    -------
    int, list, optional
        Memory address of given pattern, or None if one was not found
        or a list of found addresses in return_multiple is True
    """
    next_region = 0

    found = []
    user_space_limit = 0x7FFFFFFF0000 if sys.maxsize > 2**32 else 0x7FFF0000
    while next_region < user_space_limit:
        next_region, page_found = scan_pattern_page(
            handle,
            next_region,
            pattern,
            all_protections=all_protections,
            use_regex=use_regex,
            return_multiple=return_multiple,
            data_only=data_only,
        )

        if not return_multiple and page_found:
            return page_found

        if page_found:
            found += page_found

    if not return_multiple:
        return None

    return found
