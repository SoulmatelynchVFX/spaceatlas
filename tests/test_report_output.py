from contextlib import redirect_stdout, redirect_stderr
import csv
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from storage_inspector.__main__ import main
from storage_inspector.domain import InstalledApp
from storage_inspector.report_output import ReportOutput, ReportOutputError
from storage_inspector.windows_inventory import InventoryResult


class ReportOutputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / "input"
        self.source.mkdir()
        self.sample = self.source / "中文.txt"
        self.sample.write_bytes(b"abc")
        self.target = self.base / "report.json"

    def run_cli(self, *extra, source=None):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = main(["--path", str(source or self.source), "--output", str(self.target), *extra])
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(list(self.base.glob(".spaceatlas-*.tmp")), [])
        return code, errors.getvalue()

    def test_all_formats_save_utf8_without_stdout(self):
        for fmt in ("json", "csv", "ndjson"):
            self.target = self.base / ("报告." + fmt)
            code, errors = self.run_cli("--format", fmt)
            self.assertEqual(code, 0, errors)
            raw = self.target.read_bytes()
            self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
            text = raw.decode("utf-8")
            if fmt == "json":
                report = json.loads(text)
            elif fmt == "csv":
                rows = list(csv.reader(io.StringIO(text)))
                self.assertEqual(rows[1][0], str(self.sample))
                self.assertNotIn(b"\r\r\n", raw)
                report = json.loads(errors)
            else:
                events = [json.loads(line) for line in text.splitlines()]
                self.assertEqual(events[0]["path"], str(self.sample))
                self.assertEqual(events[-1]["event"], "summary")
                report = events[-1]["report"]
            self.assertEqual((report["file_count"], report["logical_bytes"]), (1, 3))
            self.assertFalse(report["partial"])

    def test_existing_without_force_preserves_contents_before_scan(self):
        self.target.write_bytes(b"old")
        with patch("storage_inspector.__main__.directory_stats") as scan:
            code, errors = self.run_cli()
        scan.assert_not_called()
        self.assertEqual(code, 1)
        self.assertIn("--force", errors)
        self.assertEqual(self.target.read_bytes(), b"old")

    def test_force_replaces_regular_file(self):
        self.target.write_bytes(b"old")
        code, errors = self.run_cli("--force")
        self.assertEqual(code, 0, errors)
        self.assertEqual(json.loads(self.target.read_text())["logical_bytes"], 3)

    def test_force_allows_new_file(self):
        self.assertEqual(self.run_cli("--force")[0], 0)

    def test_force_requires_output_before_scanning(self):
        with redirect_stderr(io.StringIO()), patch("storage_inspector.__main__.directory_stats") as scan:
            with self.assertRaises(SystemExit) as raised:
                main(["--path", str(self.source), "--force"])
        self.assertEqual(raised.exception.code, 2)
        scan.assert_not_called()

    def test_source_file_cannot_be_overwritten(self):
        self.target = self.sample
        self.assertEqual(self.run_cli("--force", source=self.sample)[0], 1)
        self.assertEqual(self.sample.read_bytes(), b"abc")

    def test_new_or_existing_output_inside_scan_root_is_rejected(self):
        for exists in (False, True):
            self.target = self.source / "report.json"
            if exists:
                self.target.write_bytes(b"keep")
            with self.subTest(exists=exists):
                self.assertEqual(self.run_cli("--force")[0], 1)
                if exists:
                    self.assertEqual(self.target.read_bytes(), b"keep")
                else:
                    self.assertFalse(self.target.exists())
                self.assertEqual(list(self.source.glob(".spaceatlas-*.tmp")), [])

    def test_directory_and_missing_parent_rejected(self):
        for target in (self.source, self.base / "missing" / "out.json"):
            self.target = target
            self.assertEqual(self.run_cli("--force")[0], 1)
        self.assertFalse((self.base / "missing").exists())

    def test_hardlinked_destination_rejected(self):
        os.link(self.sample, self.target)
        self.assertEqual(self.run_cli("--force")[0], 1)
        self.assertEqual(self.sample.read_bytes(), b"abc")
        self.assertEqual(self.target.read_bytes(), b"abc")

    def test_symbolic_target_and_parent_rejected(self):
        try:
            self.target.symlink_to(self.sample)
        except OSError as error:
            self.skipTest(f"Symlink creation unavailable: {error}")
        self.assertEqual(self.run_cli("--force")[0], 1)
        self.assertTrue(self.target.is_symlink())
        alias = self.base / "alias"
        alias.symlink_to(self.source, target_is_directory=True)
        self.target = alias / "new.json"
        self.assertEqual(self.run_cli()[0], 1)
        self.assertFalse((self.source / "new.json").exists())

    def test_reparse_target_and_parent_rejected_by_metadata(self):
        self.target.write_bytes(b"old")
        original = Path.lstat
        for marked in (self.target, self.base):
            def fake(path):
                if path == marked:
                    return SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x400)
                return original(path)
            with self.subTest(path=marked), patch.object(Path, "lstat", fake):
                self.assertEqual(self.run_cli("--force")[0], 1)
        self.assertEqual(self.target.read_bytes(), b"old")

    def test_parent_traversal_rejected(self):
        self.target = self.base / "input" / ".." / "out.json"
        self.assertEqual(self.run_cli()[0], 1)

    def test_unresolvable_output_fails_without_traceback_or_temp_file(self):
        original = Path.resolve
        def resolve(path, *args, **kwargs):
            if path == self.target:
                raise RuntimeError("Symlink loop")
            return original(path, *args, **kwargs)
        with patch.object(Path, "resolve", resolve):
            code, errors = self.run_cli()
        self.assertEqual(code, 1)
        self.assertIn("无法确认输出路径", errors)
        self.assertFalse(self.target.exists())

    @unittest.skipUnless(os.name == "nt", "Windows path semantics")
    def test_windows_devices_ads_and_ambiguous_names_rejected(self):
        for name in ("NUL", "out.json:stream", "out.json.", "out.json "):
            self.target = self.base / name
            with self.subTest(name=name):
                self.assertEqual(self.run_cli("--force")[0], 1)

    def test_temp_creation_permission_failure_preserves_old(self):
        self.target.write_bytes(b"old")
        with patch("storage_inspector.report_output.tempfile.mkstemp", side_effect=PermissionError("read-only")):
            code, errors = self.run_cli("--force")
        self.assertEqual(code, 1)
        self.assertIn("read-only", errors)
        self.assertEqual(self.target.read_bytes(), b"old")

    def test_write_fsync_and_replace_failures_preserve_old(self):
        for operation in ("write", "fsync", "replace"):
            self.target.write_bytes(b"old")
            target = {"write": "storage_inspector.__main__.json.dumps",
                      "fsync": "storage_inspector.report_output.os.fsync",
                      "replace": "storage_inspector.report_output.os.replace"}[operation]
            with self.subTest(operation=operation), patch(target, side_effect=OSError("destination full")):
                code, errors = self.run_cli("--force")
            self.assertEqual(code, 1)
            self.assertIn("destination full", errors)
            self.assertEqual(self.target.read_bytes(), b"old")

    def test_stream_failure_in_csv_and_ndjson_preserves_old(self):
        for fmt, writer in (("csv", "CsvFileWriter"), ("ndjson", "NdjsonFileWriter")):
            self.target.write_bytes(b"old")
            with patch(f"storage_inspector.__main__.{writer}.write_file", side_effect=OSError("write failed")):
                self.assertEqual(self.run_cli("--force", "--format", fmt)[0], 1)
            self.assertEqual(self.target.read_bytes(), b"old")

    def test_new_destination_appearing_during_write_is_not_overwritten(self):
        with self.assertRaises(ReportOutputError):
            with ReportOutput(self.target, [self.source], force=True) as destination:
                destination.stream.write("new report")
                self.target.write_bytes(b"other writer")
                destination.commit()
        self.assertEqual(self.target.read_bytes(), b"other writer")
        self.assertEqual(list(self.base.glob(".spaceatlas-*.tmp")), [])

    def test_existing_destination_changed_during_write_is_preserved(self):
        self.target.write_bytes(b"old")
        with self.assertRaises(ReportOutputError):
            with ReportOutput(self.target, [self.source], force=True) as destination:
                destination.stream.write("new report")
                self.target.write_bytes(b"changed by another writer")
                destination.commit()
        self.assertEqual(self.target.read_bytes(), b"changed by another writer")

    def test_partial_scan_is_saved_and_keeps_nonzero_exit(self):
        for fmt in ("json", "csv", "ndjson"):
            self.target = self.base / ("partial." + fmt)
            code, errors = self.run_cli("--format", fmt, "--max-files", "1")
            self.assertEqual(code, 2)
            text = self.target.read_text(encoding="utf-8")
            report = (json.loads(errors) if fmt == "csv" else
                      json.loads(text.splitlines()[-1])["report"] if fmt == "ndjson" else json.loads(text))
            self.assertTrue(report["partial"])
            self.assertEqual(report["stop_reason"], "max_files")

    def test_early_interrupt_preserves_old_file(self):
        self.target.write_bytes(b"old")
        with patch("storage_inspector.__main__.directory_stats", side_effect=KeyboardInterrupt):
            self.assertEqual(self.run_cli("--force")[0], 130)
        self.assertEqual(self.target.read_bytes(), b"old")

    def test_reportable_traversal_interrupt_saves_partial(self):
        original = os.scandir
        def interrupted(path):
            if Path(path) == self.source:
                raise KeyboardInterrupt
            return original(path)
        with patch("storage_inspector.scanner.os.scandir", side_effect=interrupted):
            self.assertEqual(self.run_cli()[0], 130)
        report = json.loads(self.target.read_text())
        self.assertTrue(report["partial"])
        self.assertEqual(report["stop_reason"], "interrupted")

    def test_app_output_respects_installation_scope(self):
        inventory = InventoryResult(applications=[InstalledApp("sample", "Example", install_location=str(self.source))])
        for target, expected in ((self.target, 0), (self.source / "report.json", 1)):
            with patch("storage_inspector.__main__.discover_inventory", return_value=inventory), \
                    patch("storage_inspector.__main__.os", SimpleNamespace(name="nt")), \
                    patch("storage_inspector.app_scan.valid_install_location", return_value=True), \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(main(["--app", "sample", "--output", str(target)]), expected)

    def test_inventory_json_export_without_real_registry_read(self):
        with patch("storage_inspector.__main__.discover_inventory", return_value=InventoryResult()), \
                patch("storage_inspector.__main__.os", SimpleNamespace(name="nt")), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--list-apps", "--output", str(self.target)]), 0)
        self.assertEqual(json.loads(self.target.read_text())["report_type"], "application_inventory")

    def test_cli_process_export(self):
        result = subprocess.run([sys.executable, "-m", "storage_inspector", "--path", str(self.source),
                                 "--output", str(self.target), "--format", "ndjson"],
                                cwd=Path(__file__).resolve().parents[1], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(json.loads(self.target.read_text().splitlines()[-1])["exit_code"], 0)


if __name__ == "__main__":
    unittest.main()
