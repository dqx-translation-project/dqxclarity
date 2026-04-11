import os
import shutil
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import MagicMock, patch


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
    # Each test calls _run_main(), which patches out everything that touches the
    # network or blocks: fetch_release_info, download_zip, process checks, exe
    # kills, and the input() prompt at the end. Tests use a real temp work_dir
    # and a real local zip so the actual file extraction and copy logic runs
    # unpatched.

    def setUp(self):
        # Fresh temp work dir and zip file for each test
        self.work_dir = tempfile.mkdtemp(prefix="dqxclarity_test_work_")
        self.zip_fd, self.zip_path = tempfile.mkstemp(suffix=".zip")
        os.close(self.zip_fd)
        # Write version.update so cur_ver can be read
        with open(os.path.join(self.work_dir, "version.update"), "w") as f:
            f.write("1.0.0")

    def tearDown(self):
        shutil.rmtree(self.work_dir, ignore_errors=True)
        if os.path.exists(self.zip_path):
            os.remove(self.zip_path)

    def _run_main(self, extra_args=None, release_notes="", fetch_side_effect=None, download_side_effect=None):
        """Invoke main() with all network I/O patched and work-dir pointed at
        the test fixture. Returns the mock_input so callers can inspect the
        final prompt if needed."""
        fake_release = {"tag_name": "v1.1.0", "body": release_notes}
        mock_input = MagicMock()

        argv = ["updater.py", "--work-dir", self.work_dir]
        if extra_args:
            argv += extra_args

        if fetch_side_effect:
            fetch_patch = patch("updater.fetch_release_info", side_effect=fetch_side_effect)
        else:
            fetch_patch = patch("updater.fetch_release_info", return_value=fake_release)

        zip_obj = None
        if download_side_effect:
            download_patch = patch("updater.download_zip", side_effect=download_side_effect)
        else:
            zip_obj = zipfile.ZipFile(self.zip_path)
            download_patch = patch("updater.download_zip", return_value=zip_obj)

        try:
            with (
                patch("sys.argv", argv),
                patch("updater.is_dqx_process_running", return_value=False),
                patch("updater.is_steam_deck", return_value=False),
                patch("updater.kill_exe"),
                fetch_patch,
                download_patch,
                patch("builtins.input", mock_input),
            ):
                main()
        finally:
            if zip_obj is not None:
                zip_obj.close()

        return mock_input

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
        # Release notes come from the fetch_release_info response body.
        # Verify the stripped content appears in output.
        make_zip(self.zip_path, {"app/main.py": "x"})

        with patch("builtins.print") as mock_print:
            self._run_main(release_notes="## What's new\n\n- Fixed a bug")

        printed = " ".join(str(c) for call in mock_print.call_args_list for c in call[0])
        self.assertIn("What's new", printed)
        self.assertIn("Fixed a bug", printed)

    def test_version_string_in_success_message(self):
        # cur_ver comes from version.update (written in setUp as "1.0.0").
        # new_ver comes from the fake release tag "v1.1.0".
        make_zip(self.zip_path, {"app/main.py": "x"})

        mock_input = self._run_main()

        call_arg = mock_input.call_args[0][0]
        self.assertIn("1.0.0", call_arg)
        self.assertIn("1.1.0", call_arg)

    def test_specific_release_arg_passed_to_fetch(self):
        # When --release is supplied, fetch_release_info should receive that tag.
        make_zip(self.zip_path, {"app/main.py": "x"})
        zip_obj = zipfile.ZipFile(self.zip_path)

        try:
            with (
                patch("updater.fetch_release_info", return_value={"tag_name": "v1.0.5", "body": ""}) as mock_fetch,
                patch("updater.download_zip", return_value=zip_obj),
                patch("updater.is_dqx_process_running", return_value=False),
                patch("updater.is_steam_deck", return_value=False),
                patch("updater.kill_exe"),
                patch("builtins.input"),
                patch("sys.argv", ["updater.py", "--work-dir", self.work_dir, "--release", "v1.0.5"]),
            ):
                main()
        finally:
            zip_obj.close()

        mock_fetch.assert_called_once_with("v1.0.5")

    def test_fetch_failure_exits(self):
        # A failure fetching release info should exit gracefully
        make_zip(self.zip_path, {"app/main.py": "x"})
        with self.assertRaises(SystemExit):
            self._run_main(fetch_side_effect=RuntimeError("HTTP 404"))

    def test_zip_download_failure_exits(self):
        # A failure downloading the zip should exit gracefully
        make_zip(self.zip_path, {"app/main.py": "x"})
        with self.assertRaises(SystemExit):
            self._run_main(download_side_effect=RuntimeError("connection error"))


if __name__ == "__main__":
    unittest.main()
