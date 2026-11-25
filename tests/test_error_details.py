from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from storage_inspector.__main__ import main
from storage_inspector.app_scan import inspect_app
from storage_inspector.domain import InstalledApp
from storage_inspector.scanner import DirectoryStats, directory_stats
from storage_inspector.scan_report import scan_report
from storage_inspector.windows_inventory import InventoryResult


class ErrorDetailsTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        for name in ("bad1", "bad2", "bad3"):
            (self.root / name).touch()
        (self.root / "good").write_bytes(b"abc")
        original = Path.lstat
        def lstat(path, *args, **kwargs):
            if path.name.startswith("bad"):
                raise PermissionError("fixture denied")
            return original(path, *args, **kwargs)
        self.enterContext(patch.object(Path, "lstat", lstat))

    def cli(self, *args):
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = main(list(args))
        return status, out.getvalue(), err.getvalue()

    def assert_counts(self, report, total, retained):
        self.assertEqual(report["error_count"], total)
        self.assertEqual(len(report["errors"]), retained)
        self.assertEqual(report["error_details_omitted"], total - retained)
        self.assertEqual(report["partial"], total > 0)

    def test_default_and_configurable_boundaries_keep_uncapped_total(self):
        for limit in (0, 1, 100, 200):
            result = DirectoryStats("fixture", max_error_details=limit)
            for i in range(105):
                result.record_error(str(i), OSError("denied"))
            report = scan_report(result)
            self.assert_counts(report, 105, min(105, limit))
            self.assertEqual(report["max_error_details"], limit)
            self.assertEqual([e["path"] for e in report["errors"]],
                             [str(i) for i in range(min(105, limit))])
        self.assertEqual(DirectoryStats("fixture").max_error_details, 100)

    def test_scan_continues_after_errors_for_zero_small_and_large_limits(self):
        for limit in (0, 1, 3, 10):
            stats = directory_stats(self.root, max_error_details=limit)
            self.assert_counts(scan_report(stats), 3, min(3, limit))
            self.assertEqual((stats.file_count, stats.logical_bytes), (1, 3))
            self.assertIsNone(stats.stop_reason)

    def test_successful_scan_has_zero_omitted_and_original_success_status(self):
        status, out, _ = self.cli("--path", str(self.root / "good"), "--max-error-details", "0")
        self.assertEqual(status, 0)
        self.assert_counts(json.loads(out), 0, 0)

    def test_default_cli_still_keeps_details_and_returns_partial(self):
        status, out, _ = self.cli("--path", str(self.root))
        self.assertEqual(status, 2)
        self.assert_counts(json.loads(out), 3, 3)
        self.assertEqual(json.loads(out)["max_error_details"], 100)

    def test_json_csv_and_ndjson_status_keep_the_same_counts(self):
        for fmt in ("json", "csv", "ndjson"):
            status, out, err = self.cli("--path", str(self.root), "--format", fmt,
                                        "--max-error-details", "1")
            self.assertEqual(status, 2)
            if fmt == "json":
                report = json.loads(out)
            elif fmt == "csv":
                self.assertEqual(out.splitlines()[0], "path,size,modified")
                report = json.loads(err)
            else:
                events = [json.loads(line) for line in out.splitlines()]
                self.assertEqual(events[-1]["event"], "summary")
                report = events[-1]["report"]
            self.assert_counts(report, 3, 1)

    def test_saved_report_preserves_error_total_with_no_details(self):
        with TemporaryDirectory() as destination:
            output = Path(destination) / "report.json"
            status, _, _ = self.cli("--path", str(self.root), "--max-error-details", "0",
                                   "--output", str(output))
            self.assertEqual(status, 2)
            self.assert_counts(json.loads(output.read_text()), 3, 0)

    def test_invalid_api_values_rejected_before_scanning(self):
        for value in (-1, True, False, 1.5, "2", None):
            with self.subTest(value=value), patch("os.scandir") as scan:
                with self.assertRaises(ValueError):
                    directory_stats(self.root, max_error_details=value)
                with self.assertRaises(ValueError):
                    DirectoryStats("fixture", max_error_details=value)
                with self.assertRaises(ValueError):
                    inspect_app(InventoryResult(), "fixture", max_error_details=value)
                scan.assert_not_called()

    def test_invalid_cli_value_precedes_inventory_and_output_creation(self):
        with patch("storage_inspector.__main__.discover_inventory") as discover:
            for value in ("-1", "1.5", "bad"):
                output = self.root / "report.json"
                with self.assertRaises(SystemExit) as error:
                    self.cli("--app", "fixture", "--max-error-details", value, "--output", str(output))
                self.assertEqual(error.exception.code, 2)
                self.assertFalse(output.exists())
        discover.assert_not_called()

    def test_inventory_option_rejected_including_explicit_default(self):
        with patch("storage_inspector.__main__.discover_inventory") as discover:
            for limit in ("0", "100"):
                with self.assertRaises(SystemExit):
                    self.cli("--list-apps", "--max-error-details", limit)
        discover.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows application paths")
    def test_application_scan_cap_does_not_change_inventory_errors(self):
        inv = InventoryResult([InstalledApp("fixture", "Fixture", install_location=str(self.root))],
                              error_count=1, errors=[{"location": "fixture", "message": "inventory denied"}])
        with patch("storage_inspector.__main__.discover_inventory", return_value=inv):
            status, out, _ = self.cli("--app", "fixture", "--max-error-details", "0")
        report = json.loads(out)
        self.assertEqual(status, 2)
        self.assert_counts(report["scan"], 3, 0)
        self.assertEqual(report["inventory"]["error_count"], 1)
        self.assertEqual(len(report["inventory"]["errors"]), 1)
