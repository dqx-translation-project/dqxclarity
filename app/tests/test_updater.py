import os
import shutil
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from updater import main, strip_markdown


def make_zip(zip_path: str, files: dict) -> None:
    """Create a zip at zip_path with files dict of {relative_path: content}. Paths
    are prefixed with 'dqxclarity/' to mirror the real release zip layout."""
    with zipfile.ZipFile(zip_path, "w") as zf:
        for path, content in files.items():
            zf.writestr(f"dqxclarity/{path}", content)


class TestStripMarkdown(unittest.TestCase):
    # strip_markdown is a pure function — no setup needed, called directly.

    def test_removes_headers(self):
        self.assertEqual(strip_markdown("## What's Changed"), "What's Changed")

    def test_removes_all_header_levels(self):
        for level in range(1, 7):
            self.assertEqual(strip_markdown(f"{'#' * level} Title"), "Title")

    def test_removes_bold(self):
        self.assertEqual(strip_markdown("**bold**"), "bold")

    def test_removes_italic(self):
        self.assertEqual(strip_markdown("*italic*"), "italic")

    def test_removes_inline_code(self):
        self.assertEqual(strip_markdown("`code`"), "code")

    def test_removes_link_keeps_text(self):
        self.assertEqual(strip_markdown("[display](https://example.com)"), "display")

    def test_removes_horizontal_rules(self):
        result = strip_markdown("above\n---\nbelow")
        self.assertNotIn("---", result)

    def test_collapses_excessive_blank_lines(self):
        result = strip_markdown("a\n\n\n\nb")
        self.assertNotIn("\n\n\n", result)

    def test_preserves_bullet_points(self):
        text = "- item one\n- item two"
        self.assertEqual(strip_markdown(text), text)

    def test_mixed_content(self):
        # Verify a realistic GitHub release notes block strips cleanly
        text = "## Changes\n\n- Fix **bug** in `module`\n- Update [dep](https://example.com)"
        result = strip_markdown(text)
        self.assertIn("Changes", result)
        self.assertIn("Fix bug in module", result)
        self.assertIn("Update dep", result)
        self.assertNotIn("##", result)
        self.assertNotIn("**", result)
        self.assertNotIn("`", result)


class TestUpdaterMain(unittest.TestCase):
    # Each test calls _run_main(), which patches out everything that would block
    # or touch the live system: DQX process check, exe kills, and the input()
    # prompt at the end. Tests use a real temp work_dir and a real local zip so
    # the actual file extraction and copy logic runs unpatched.

    def setUp(self):
        # Fresh temp work dir and zip file for each test
        self.work_dir = tempfile.mkdtemp(prefix="dqxclarity_test_work_")
        self.zip_fd, self.zip_path = tempfile.mkstemp(suffix=".zip")
        os.close(self.zip_fd)

    def tearDown(self):
        shutil.rmtree(self.work_dir, ignore_errors=True)
        if os.path.exists(self.zip_path):
            os.remove(self.zip_path)

    def _run_main(self, extra_args=None):
        """Invoke main() with --local-zip and --work-dir pointing at test fixtures.
        Patches sys.argv so argparse reads our test args, and patches everything
        that would block (input) or touch the live OS (process checks, kill_exe)."""
        argv = [
            "updater.py",
            "--local-zip",
            self.zip_path,
            "--work-dir",
            self.work_dir,
            "--cur-version",
            "1.0.0",
            "--new-version",
            "1.1.0",
        ]
        if extra_args:
            argv += extra_args

        with (
            patch("sys.argv", argv),
            patch("updater.is_dqx_process_running", return_value=False),
            patch("updater.is_steam_deck", return_value=False),
            patch("updater.kill_exe"),
            patch("builtins.input"),
        ):
            main()

    def test_files_copied_to_work_dir(self):
        # Verify new files from the zip land in work_dir at the right paths
        make_zip(self.zip_path, {"app/main.py": "print('hello')", "version.update": "1.1.0"})
        self._run_main()

        self.assertTrue(os.path.exists(os.path.join(self.work_dir, "app", "main.py")))
        self.assertTrue(os.path.exists(os.path.join(self.work_dir, "version.update")))

    def test_file_contents_updated(self):
        # Verify a pre-existing file gets overwritten with the version from the zip
        app_dir = os.path.join(self.work_dir, "app")
        os.makedirs(app_dir)
        with open(os.path.join(app_dir, "main.py"), "w") as f:
            f.write("old content")

        make_zip(self.zip_path, {"app/main.py": "new content"})
        self._run_main()

        with open(os.path.join(self.work_dir, "app", "main.py")) as f:
            self.assertEqual(f.read(), "new content")

    def test_stale_files_removed(self):
        # A file present in work_dir but absent from the zip should be deleted
        stale = os.path.join(self.work_dir, "old_file.py")
        open(stale, "w").close()

        make_zip(self.zip_path, {"app/main.py": "x"})
        self._run_main()

        self.assertFalse(os.path.exists(stale))

    def test_user_settings_preserved(self):
        # user_settings.ini is in ignored_files and must never be touched
        settings = os.path.join(self.work_dir, "user_settings.ini")
        with open(settings, "w") as f:
            f.write("[config]\nkey=value\n")

        make_zip(self.zip_path, {"app/main.py": "x"})
        self._run_main()

        self.assertTrue(os.path.exists(settings))
        with open(settings) as f:
            self.assertIn("key=value", f.read())

    def test_ignored_directories_preserved(self):
        # misc_files and logs are in ignored_directories — contents must survive
        for dirname in ["misc_files", "logs"]:
            dirpath = os.path.join(self.work_dir, dirname)
            os.makedirs(dirpath)
            with open(os.path.join(dirpath, "keep_me.txt"), "w") as f:
                f.write("keep")

        make_zip(self.zip_path, {"app/main.py": "x"})
        self._run_main()

        for dirname in ["misc_files", "logs"]:
            self.assertTrue(os.path.exists(os.path.join(self.work_dir, dirname, "keep_me.txt")))

    def test_venv_removed(self):
        # venv is wiped after a successful update so dependencies get rebuilt
        venv_path = os.path.join(self.work_dir, "venv")
        os.makedirs(os.path.join(venv_path, "Lib", "site-packages"))

        make_zip(self.zip_path, {"app/main.py": "x"})
        self._run_main()

        self.assertFalse(os.path.exists(venv_path))

    def test_release_notes_displayed(self):
        # Release notes are written to a temp file by check_for_updates and passed
        # via --release-notes-file. Verify the stripped content appears in output.
        fd, notes_file = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        with open(notes_file, "w") as f:
            f.write("## What's new\n\n- Fixed a bug")

        make_zip(self.zip_path, {"app/main.py": "x"})

        with patch("builtins.print") as mock_print:
            self._run_main(extra_args=["--release-notes-file", notes_file])

        printed = " ".join(str(c) for call in mock_print.call_args_list for c in call[0])
        self.assertIn("What's new", printed)
        self.assertIn("Fixed a bug", printed)

    def test_release_notes_file_cleaned_up(self):
        # The temp notes file should be deleted after being read
        fd, notes_file = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        with open(notes_file, "w") as f:
            f.write("some notes")

        make_zip(self.zip_path, {"app/main.py": "x"})
        self._run_main(extra_args=["--release-notes-file", notes_file])

        self.assertFalse(os.path.exists(notes_file))

    def test_version_string_in_success_message(self):
        # Both old and new versions should appear in the final input() prompt
        make_zip(self.zip_path, {"app/main.py": "x"})

        with (
            patch("builtins.input") as mock_input,
            patch(
                "sys.argv",
                [
                    "updater.py",
                    "--local-zip",
                    self.zip_path,
                    "--work-dir",
                    self.work_dir,
                    "--cur-version",
                    "1.0.0",
                    "--new-version",
                    "1.1.0",
                ],
            ),
            patch("updater.is_dqx_process_running", return_value=False),
            patch("updater.is_steam_deck", return_value=False),
            patch("updater.kill_exe"),
        ):
            main()

        call_arg = mock_input.call_args[0][0]
        self.assertIn("1.0.0", call_arg)
        self.assertIn("1.1.0", call_arg)

    def test_invalid_zip_exits(self):
        # A corrupt zip should fail gracefully and call sys.exit(1)
        with open(self.zip_path, "w") as f:
            f.write("not a zip")

        with self.assertRaises(SystemExit):
            self._run_main()

    def test_missing_zip_exits(self):
        # A path that doesn't exist should fail gracefully and call sys.exit(1)
        with (
            self.assertRaises(SystemExit),
            patch("sys.argv", ["updater.py", "--local-zip", "/nonexistent.zip", "--work-dir", self.work_dir]),
            patch("updater.is_dqx_process_running", return_value=False),
            patch("updater.is_steam_deck", return_value=False),
            patch("updater.kill_exe"),
            patch("builtins.input"),
        ):
            main()

    def test_no_source_arg_exits(self):
        # Calling the updater without --zip-url or --local-zip should exit immediately
        with self.assertRaises(SystemExit), patch("sys.argv", ["updater.py", "--work-dir", self.work_dir]):
            main()


if __name__ == "__main__":
    unittest.main()
