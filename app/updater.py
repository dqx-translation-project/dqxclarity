import argparse
import contextlib
import ctypes
import ctypes.wintypes
import os
import re
import shutil
import ssl
import sys
import tempfile
from io import BytesIO
from urllib.request import Request, urlopen
from zipfile import ZipFile


def is_dqx_process_running():
    """Return True if DQX is currently running.

    Uses the Windows API directly with Unicode functions (Process32FirstW,
    Process32NextW) to avoid locale/code page issues that occur when decoding
    process names from subprocess output.
    """

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.wintypes.DWORD),
            ("cntUsage", ctypes.wintypes.DWORD),
            ("th32ProcessID", ctypes.wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", ctypes.wintypes.DWORD),
            ("cntThreads", ctypes.wintypes.DWORD),
            ("th32ParentProcessID", ctypes.wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),  # MAX_PATH, Unicode
        ]

    TH32CS_SNAPPROCESS = 0x00000002
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    kernel32 = ctypes.windll.kernel32

    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        return False

    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return False

        while True:
            if entry.szExeFile.lower() == "dqxgame.exe":
                return True
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break

        return False
    finally:
        kernel32.CloseHandle(snapshot)


def is_steam_deck() -> bool:
    """Check if user is on a Steam Deck."""
    return os.environ.get("SteamDeck") == "1"  # noqa: SIM112


def kill_exe(name: str) -> None:
    """Use taskkill to kill a running executable."""
    os.system(f"taskkill /f /im {name} >nul 2>&1")


def download_zip(url: str) -> ZipFile:
    print("Downloading update...")
    req = Request(url)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    data = urlopen(req, timeout=60, context=ctx)
    if data.status != 200:
        raise RuntimeError(f"HTTP {data.status}")
    return ZipFile(BytesIO(data.read()))


def strip_markdown(text: str) -> str:
    # Remove heading markers, keep text
    text = re.sub(r"^#{1,6}\s+", "", text, flags=re.MULTILINE)
    # Remove bold/italic markers
    text = re.sub(r"\*{1,3}(.+?)\*{1,3}", r"\1", text)
    # Remove inline code markers
    text = re.sub(r"`(.+?)`", r"\1", text)
    # Remove links, keep display text
    text = re.sub(r"\[(.+?)\]\(.+?\)", r"\1", text)
    # Remove horizontal rules
    text = re.sub(r"^[-*]{3,}\s*$", "", text, flags=re.MULTILINE)
    # Collapse excessive blank lines
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def main():
    parser = argparse.ArgumentParser(description="dqxclarity updater")
    parser.add_argument("--zip-url", help="URL to download the release zip from")
    parser.add_argument("--local-zip", help="Path to a local zip file (for testing)")
    parser.add_argument("--work-dir", help="Directory to update (defaults to directory of this script)")
    parser.add_argument("--cur-version", help="Current installed version")
    parser.add_argument("--new-version", help="New version being installed")
    parser.add_argument("--release-notes-file", help="Path to a temp file containing release notes")
    args = parser.parse_args()

    if not args.zip_url and not args.local_zip:
        print("Error: must provide --zip-url or --local-zip.")
        sys.exit(1)

    work_dir = os.path.abspath(args.work_dir or os.path.split(os.path.abspath(__file__))[0])

    if is_dqx_process_running():
        input(
            "Please close DQX before updating. Re-launch dqxclarity once the game has been closed.\n\n"
            "Press ENTER to close this window."
        )
        sys.exit()

    print("dqxclarity is updating. Please wait...")

    if is_steam_deck():
        kill_exe("DQXBoot.exe")
        kill_exe("DQXLauncher.exe")

    kill_exe("DQXClarity.exe")

    try:
        if args.local_zip:
            print(f"Using local zip: {args.local_zip}")
            z_data = ZipFile(args.local_zip)
        else:
            z_data = download_zip(args.zip_url)
    except Exception as e:
        input(
            "Failed to download the latest update. Your existing install is unchanged.\n"
            "Please try again or download the update manually from GitHub.\n"
            "Documentation: https://dqx-translation-project.github.io/dqxclarity\n\n"
            f"Error: {e}\n\nPress ENTER to close this window."
        )
        sys.exit(1)

    print("Applying update...")
    temp_dir = tempfile.mkdtemp(prefix="dqxclarity_update_")

    ignored_files = ["user_settings.ini"]
    ignored_directories = ["misc_files", "logs", "venv"]

    try:
        new_file_set = set()

        for obj in z_data.infolist():
            normalized = obj.filename.replace("dqxclarity/", "")
            basename = os.path.basename(normalized)
            is_dir = normalized.endswith("/") or not basename

            if not normalized:
                continue
            if any(x in normalized for x in ignored_directories):
                continue
            if basename in ignored_files:
                continue

            if not is_dir:
                new_file_set.add(normalized.replace("/", os.sep))

            obj.filename = normalized
            if not is_dir:
                z_data.extract(obj, temp_dir)

        # Copy extracted files from temp into work_dir
        for root, _dirs, files in os.walk(temp_dir):
            rel_root = os.path.relpath(root, temp_dir)
            dest_root = os.path.join(work_dir, rel_root) if rel_root != "." else work_dir
            os.makedirs(dest_root, exist_ok=True)
            for file in files:
                shutil.copy2(os.path.join(root, file), os.path.join(dest_root, file))

        # Remove stale files in work_dir that aren't in the new release
        for root, _dirs, files in os.walk(work_dir):
            for file in files:
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, work_dir)
                basename = os.path.basename(abs_path)

                if any(x in rel_path for x in ignored_directories):
                    continue
                if basename in ignored_files:
                    continue
                if rel_path not in new_file_set:
                    with contextlib.suppress(OSError):
                        os.remove(abs_path)

    except Exception as e:
        input(
            "Failed to apply the update. Your existing install may be in a mixed state.\n"
            "Please download the update manually from GitHub.\n"
            "Documentation: https://dqx-translation-project.github.io/dqxclarity\n\n"
            f"Error: {e}\n\nPress ENTER to close this window."
        )
        sys.exit(1)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    # Wipe venv so any new or removed dependencies are resolved on next launch
    venv_path = os.path.join(work_dir, "venv")
    if os.path.exists(venv_path):
        shutil.rmtree(venv_path, ignore_errors=True)

    # Read and display release notes, then clean up the temp file
    release_notes = ""
    if args.release_notes_file and os.path.exists(args.release_notes_file):
        try:
            with open(args.release_notes_file, encoding="utf-8") as f:
                release_notes = strip_markdown(f.read())
        except Exception:
            pass
        finally:
            with contextlib.suppress(OSError):
                os.remove(args.release_notes_file)

    if args.cur_version and args.new_version:
        version_str = f"({args.cur_version} -> {args.new_version})"
    elif args.new_version:
        version_str = f"(v{args.new_version})"
    else:
        version_str = ""

    print()
    if release_notes and args.new_version:
        header = f"=== What's new in v{args.new_version} ==="
        print(header)
        print()
        print(release_notes)
        print()
        print("=" * len(header))
        print()

    input(f"Update complete! {version_str} Please re-launch dqxclarity.\nPress ENTER to close this window.")


if __name__ == "__main__":
    main()
