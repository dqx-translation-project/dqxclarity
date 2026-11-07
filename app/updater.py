"""
Migration updater. As Python isn't being used anymore, any Python installs
will grab this updater for a final update, then the update will be handled
by the new launcher moving forward. This script is fetched on 5.x versions
to transition them to 6.x, in which this file will no longer be used.
This script should live in the repo for a period of time before being removed.
"""

import json
import os
import shutil
import ssl
import sys
import tempfile
import time
import zipfile
from urllib.request import Request, urlopen

REPO = "dqx-translation-project/dqxclarity"
PRESERVED_DIRS = {"misc_files", "logs", "language-packs"}
PRESERVED_FILES = {"user_settings.ini"}

# Leftovers of the old Python-based install that the C# build doesn't use. Only these exact
# names are removed (after a successful update); anything else in the folder is left alone.
OLD_PYTHON_DIRS = ["venv", "common", "hooking", "scans", "pymem", "__pycache__"]
OLD_PYTHON_FILES = ["main.py", "__init__.py", "pyproject.toml"]


def remove_old_python_files(install_dir):
    print("Removing old Python files (this can take a moment)...")
    for name in OLD_PYTHON_DIRS:
        path = os.path.join(install_dir, name)
        try:
            if os.path.islink(path):
                os.unlink(path)
            elif os.path.isdir(path):
                # rmtree does not follow links/junctions, so the venv's pointer to the
                # system Python install is removed without touching that install.
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            pass
    for name in OLD_PYTHON_FILES:
        try:
            os.remove(os.path.join(install_dir, name))
        except OSError:
            pass


def _http(url):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urlopen(
        Request(url, headers={"User-Agent": "dqxclarity-updater"}),
        timeout=60,
        context=ctx,
    )


def main():
    # WorkingDirectory is set to the install dir by the old launcher
    install_dir = os.getcwd()
    exe_path = os.path.join(install_dir, "dqxclarity.exe")

    print("Fetching latest release...")
    with _http(f"https://api.github.com/repos/{REPO}/releases/latest") as resp:
        release = json.loads(resp.read())

    tag = release["tag_name"]
    zip_url = f"https://github.com/{REPO}/releases/download/{tag}/dqxclarity.zip"

    tmp = tempfile.mktemp(suffix=".zip")
    try:
        print(f"Downloading {tag}...")
        with _http(zip_url) as resp, open(tmp, "wb") as f:
            f.write(resp.read())

        print("Applying update...")
        with zipfile.ZipFile(tmp) as zf:
            for entry in zf.namelist():
                rel = (
                    entry[len("dqxclarity/") :]
                    if entry.startswith("dqxclarity/")
                    else entry
                )

                if not rel or rel.endswith("/"):
                    continue

                # Skip preserved paths
                top = rel.split("/")[0]
                if top in PRESERVED_DIRS or rel in PRESERVED_FILES:
                    continue

                dest = os.path.join(install_dir, rel)
                os.makedirs(os.path.dirname(dest) or install_dir, exist_ok=True)

                for attempt in range(5):
                    try:
                        with zf.open(entry) as src, open(dest, "wb") as out:
                            out.write(src.read())
                        break
                    except PermissionError:
                        if attempt == 4:
                            raise
                        time.sleep(0.5)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

    try:
        remove_old_python_files(install_dir)
    except Exception:
        pass  # cleanup is optional; never block the launch

    print("Launching dqxclarity...")
    try:
        os.startfile(exe_path)
    except Exception:
        pass


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\nUpdate failed: {e}")
        print(
            f"Download the latest release manually: https://github.com/{REPO}/releases/latest"
        )
        input("\nPress Enter to close...")
        sys.exit(1)
