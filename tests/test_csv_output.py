from contextlib import redirect_stderr, redirect_stdout
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
from storage_inspector.csv_output import CsvFileWriter, CsvOutputError
from storage_inspector.domain import InstalledApp
from storage_inspector.windows_inventory import InventoryResult


class CsvOutputTests(unittest.TestCase):
    def run_csv(self, args):
        output, errors = io.StringIO(newline=""), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            status = main([*args, "--format", "csv"])
        return status, list(csv.reader(io.StringIO(output.getvalue(), newline=""))), json.loads(errors.getvalue())

    def test_empty_directory_has_only_header_and_complete_status(self):
        with tempfile.TemporaryDirectory() as directory:
            status, rows, report = self.run_csv(["--path", directory])
        self.assertEqual(status, 0)
        self.assertEqual(rows, [["path", "size", "modified"]])
        self.assertEqual(report["csv"], {"rows_written": 0, "missing_modified": 0})
        self.assertFalse(report["partial"])
        self.assertEqual(report["schema_version"], 1)

    def test_metadata_rows_have_absolute_paths_sizes_and_utc_without_reading_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "nested").mkdir()
            files = [root / "中文,文件.txt", root / "nested" / "=SUM.txt"]
            for file in files:
                file.write_bytes(b"abc")
                os.utime(file, (1704067200, 1704067200))
            with patch.object(Path, "open", side_effect=AssertionError("no content reads")):
                status, rows, report = self.run_csv(["--path", directory])
        self.assertEqual(status, 0)
        self.assertEqual({tuple(row) for row in rows[1:]},
                         {(str(file), "3", "2024-01-01T00:00:00.000000Z") for file in files})
        self.assertEqual(report["file_count"], report["csv"]["rows_written"])
        self.assertEqual(report["logical_bytes"], 6)

    def test_csv_quoting_round_trips_synthetic_quotes_commas_and_newlines(self):
        output = io.StringIO(newline="")
        writer = CsvFileWriter(output)
        path = 'C:/example/中文,"quoted"\r\nname.txt'
        writer.write_file(path, SimpleNamespace(st_size=7, st_mtime=1704067200))
        rows = list(csv.reader(io.StringIO(output.getvalue(), newline="")))
        self.assertEqual(rows[1][0], path)
        self.assertIn('""quoted""', output.getvalue())

    def test_missing_or_unrepresentable_mtime_is_empty_and_reported(self):
        for timestamp in (None, float("inf"), float("nan"), 1e100):
            info = SimpleNamespace(st_mode=stat.S_IFREG, st_dev=1, st_ino=1,
                                   st_size=3, st_mtime=timestamp)
            with self.subTest(timestamp=timestamp), patch.object(Path, "lstat", return_value=info):
                status, rows, report = self.run_csv(["--path", "sample.txt"])
            self.assertEqual(status, 2)
            self.assertEqual(rows[1][2], "")
            self.assertTrue(report["partial"])
            self.assertEqual(report["csv"]["missing_modified"], 1)

    def test_pre_epoch_mtime_is_exported_as_utc(self):
        info = SimpleNamespace(st_mode=stat.S_IFREG, st_dev=1, st_ino=1,
                               st_size=3, st_mtime=-0.5)
        with patch.object(Path, "lstat", return_value=info):
            status, rows, report = self.run_csv(["--path", "sample.txt"])
        self.assertEqual(status, 0)
        self.assertEqual(rows[1][2], "1969-12-31T23:59:59.500000Z")
        self.assertFalse(report["partial"])
        self.assertEqual(report["csv"]["missing_modified"], 0)

    def test_incompatible_options_fail_before_scan_or_header(self):
        cases = [["--list-apps"], ["--path", ".", "--by-extension"],
                 ["--path", ".", "--by-directory"], ["--path", ".", "--top-files", "2"]]
        for args in cases:
            output, errors = io.StringIO(), io.StringIO()
            with self.subTest(args=args), redirect_stdout(output), redirect_stderr(errors), \
                    patch("storage_inspector.__main__.discover_inventory") as discover, \
                    patch("storage_inspector.__main__.directory_stats") as scan:
                with self.assertRaises(SystemExit) as raised:
                    main([*args, "--format", "csv"])
                self.assertEqual(raised.exception.code, 2)
                discover.assert_not_called()
                scan.assert_not_called()
            self.assertEqual(output.getvalue(), "")
            self.assertIn("--format csv", errors.getvalue())

    def test_file_limit_keeps_partial_status_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ("a", "b"):
                (Path(directory) / name).write_bytes(b"abc")
            status, rows, report = self.run_csv(["--path", directory, "--max-files", "1"])
        self.assertEqual(status, 2)
        self.assertEqual(len(rows), 2)
        self.assertEqual(report["stop_reason"], "max_files")
        self.assertEqual(report["csv"]["rows_written"], 1)

    def test_time_limit_keeps_header_and_partial_status(self):
        with patch("storage_inspector.scanner.time.monotonic", side_effect=[0, 2]):
            status, rows, report = self.run_csv(["--path", ".", "--max-seconds", "1"])
        self.assertEqual(status, 2)
        self.assertEqual(len(rows), 1)
        self.assertEqual(report["stop_reason"], "max_seconds")

    def test_excluded_directory_is_not_exported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "skip").mkdir()
            (root / "skip" / "hidden.txt").write_bytes(b"abc")
            (root / "visible.txt").write_bytes(b"x")
            status, rows, report = self.run_csv(["--path", directory, "--exclude-dir", "skip"])
        self.assertEqual(status, 2)
        self.assertEqual(len(rows), 2)
        self.assertTrue(rows[1][0].endswith("visible.txt"))
        self.assertEqual(report["excluded_directories"], 1)

    def test_hardlink_rows_are_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "first").write_bytes(b"abc")
            os.link(root / "first", root / "second")
            status, rows, report = self.run_csv(["--path", directory])
        self.assertEqual(status, 0)
        self.assertEqual(len(rows), 2)
        self.assertEqual(report["duplicates"], 1)
        self.assertEqual(report["logical_bytes"], 3)

    def test_missing_and_skipped_targets_do_not_look_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            status, rows, report = self.run_csv(["--path", str(Path(directory) / "missing")])
        self.assertEqual(status, 2)
        self.assertEqual(len(rows), 1)
        self.assertEqual(report["error_count"], 1)
        with patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFLNK)):
            status, rows, report = self.run_csv(["--path", "link"])
        self.assertEqual(status, 2)
        self.assertEqual(len(rows), 1)
        self.assertEqual(report["skip_reason_counts"], {"symbolic_link": 1})

    def test_interruption_preserves_rows_and_closes_iterator(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "sample"
            file.write_bytes(b"x")
            class Entries:
                closed = False
                count = 0
                def __next__(self):
                    self.count += 1
                    if self.count == 1:
                        return file
                    raise KeyboardInterrupt
                def close(self):
                    self.closed = True
            entries = Entries()
            with patch("storage_inspector.scanner.os.scandir", return_value=entries):
                status, rows, report = self.run_csv(["--path", directory])
        self.assertEqual(status, 130)
        self.assertEqual(len(rows), 2)
        self.assertEqual(report["stop_reason"], "interrupted")
        self.assertTrue(entries.closed)

    def test_app_csv_preserves_inventory_diagnostics_and_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "sample").write_bytes(b"abc")
            inventory = InventoryResult(applications=[InstalledApp("example", "Example", install_location=directory)])
            inventory.record_error("HKLM", "open_root", PermissionError("denied"))
            with patch("storage_inspector.__main__.os", SimpleNamespace(name="nt")), \
                    patch("storage_inspector.__main__.discover_inventory", return_value=inventory), \
                    patch("storage_inspector.app_scan.valid_install_location", return_value=True):
                status, rows, report = self.run_csv(["--app", "example"])
                missing_status, missing_rows, missing = self.run_csv(["--app", "unknown"])
        self.assertEqual(status, 2)
        self.assertEqual(len(rows), 2)
        self.assertEqual(report["report_type"], "application_scan")
        self.assertEqual(report["scope"], "install_location_only")
        self.assertEqual(report["inventory"]["error_count"], 1)
        self.assertFalse(report["scan"]["partial"])
        self.assertEqual(missing_status, 2)
        self.assertEqual(len(missing_rows), 1)
        self.assertIsNone(missing["scan"])

    def test_write_failure_stops_without_success_diagnostic(self):
        class FailingOutput(io.StringIO):
            def write(self, value):
                if self.tell():
                    raise OSError("destination full")
                return super().write(value)
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "sample").write_bytes(b"abc")
            output, errors = FailingOutput(), io.StringIO()
            with redirect_stdout(output), redirect_stderr(errors):
                status = main(["--path", directory, "--format", "csv"])
        self.assertEqual(status, 1)
        self.assertEqual(output.getvalue(), "path,size,modified\r\n")
        self.assertIn("destination full", errors.getvalue())
        self.assertNotIn('"schema_version"', errors.getvalue())

    def test_flush_failure_does_not_emit_success(self):
        output, diagnostics = io.StringIO(), io.StringIO()
        writer = CsvFileWriter(output)
        with patch.object(output, "flush", side_effect=OSError("full")), self.assertRaises(CsvOutputError):
            writer.finish({"partial": False}, diagnostics)
        self.assertEqual(diagnostics.getvalue(), "")

    def test_default_json_matches_explicit_json(self):
        with tempfile.TemporaryDirectory() as directory:
            outputs = []
            for args in ([], ["--format", "json"]):
                output, errors = io.StringIO(), io.StringIO()
                with redirect_stdout(output), redirect_stderr(errors):
                    self.assertEqual(main(["--path", directory, *args]), 0)
                self.assertEqual(errors.getvalue(), "")
                outputs.append(output.getvalue())
        self.assertEqual(*outputs)
        self.assertNotIn("csv", json.loads(outputs[0]))

    def test_process_output_is_utf8_without_doubled_carriage_returns(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "中文.txt").write_bytes(b"x")
            result = subprocess.run([sys.executable, "-m", "storage_inspector", "--path", directory,
                                     "--format", "csv"], cwd=Path(__file__).resolve().parents[1],
                                    capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("中文.txt", result.stdout.decode("utf-8"))
        self.assertNotIn(b"\r\r\n", result.stdout)
        self.assertEqual(json.loads(result.stderr)["csv"]["rows_written"], 1)


if __name__ == "__main__":
    unittest.main()
