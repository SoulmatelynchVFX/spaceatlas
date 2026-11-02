from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict
import io
import json
from pathlib import Path
import re
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from storage_inspector.__main__ import main
from storage_inspector.domain import InstalledApp
from storage_inspector.scanner import DirectoryStats, directory_stats
from storage_inspector.windows_inventory import InventoryResult


DOC = Path(__file__).resolve().parents[1] / "docs/schema.md"


class ReportSchemaTests(unittest.TestCase):
    def documented_fields(self, heading):
        text = DOC.read_text(encoding="utf-8")
        section = text.split(f"## {heading}\n", 1)[1].split("\n## ", 1)[0]
        return set(re.findall(r"^\| `([^`]+)` \|", section, re.MULTILINE))

    def run_cli(self, argv, inventory=None):
        output, errors = io.StringIO(), io.StringIO()
        with patch("storage_inspector.__main__.os", SimpleNamespace(name="nt")), \
                patch("storage_inspector.__main__.discover_inventory", return_value=inventory), \
                redirect_stdout(output), redirect_stderr(errors):
            status = main(argv)
        self.assertEqual(errors.getvalue(), "")
        return status, json.loads(output.getvalue())

    def assert_metadata(self, report, kind):
        self.assertIs(type(report["schema_version"]), int)
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["report_type"], kind)

    def test_path_reports_cover_complete_and_missing_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sample.txt").write_bytes(b"abc")
            for target, expected_status in [(root, 0), (root / "missing", 2)]:
                with self.subTest(status=expected_status):
                    status, report = self.run_cli(["--path", str(target)])
                    self.assertEqual(status, expected_status)
                    self.assert_metadata(report, "path_scan")
                    self.assertEqual(report["partial"], expected_status == 2)
                    self.assertEqual(set(report), self.documented_fields("公共顶层字段")
                                     | self.documented_fields("扫描对象"))
                    self.assertEqual(report["logical_bytes"], 3 if status == 0 else 0)
                    self.assertEqual(report["file_count"], 1 if status == 0 else 0)

    def test_limited_and_interrupted_path_reports_keep_version_and_status(self):
        for reason, expected in [("max_files", 2), ("max_seconds", 2), ("interrupted", 130)]:
            stats = DirectoryStats("C:\\Example", logical_bytes=9, file_count=2, stop_reason=reason)
            with self.subTest(reason=reason), \
                    patch("storage_inspector.__main__.directory_stats", return_value=stats):
                status, report = self.run_cli(["--path", "C:\\Example"])
            self.assertEqual(status, expected)
            self.assert_metadata(report, "path_scan")
            self.assertTrue(report["partial"])
            # Every pre-version scan field retains its value and position at the root.
            self.assertEqual({key: report[key] for key in asdict(stats)}, asdict(stats))

    def test_inventory_reports_preserve_applications_and_diagnostics(self):
        app = InstalledApp("sample", "示例", install_location="C:\\Example")
        for failed in (False, True):
            inventory = InventoryResult(applications=[app], missing_locations=["HKCU\\Missing"])
            if failed:
                inventory.record_error("HKLM", "open_root", PermissionError("denied"))
            with self.subTest(failed=failed):
                status, report = self.run_cli(["--list-apps"], inventory)
                self.assertEqual(status, 2 if failed else 0)
                self.assert_metadata(report, "application_inventory")
                self.assertEqual(report["partial"], failed)
                self.assertEqual(report["applications"], [asdict(app)])
                self.assertEqual(report["errors"], inventory.errors)
                self.assertEqual(report["missing_locations"], inventory.missing_locations)
                self.assertEqual(set(report), self.documented_fields("公共顶层字段")
                                 | self.documented_fields("应用清单字段"))

    def test_application_reports_cover_success_partial_and_interruption(self):
        app = InstalledApp("sample", "Example", install_location="C:\\Example")
        for reason, expected in [(None, 0), ("max_files", 2), ("interrupted", 130)]:
            stats = DirectoryStats(app.install_location, logical_bytes=12, file_count=1, stop_reason=reason)
            with self.subTest(reason=reason), \
                    patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFDIR)), \
                    patch("storage_inspector.app_scan.directory_stats", return_value=stats):
                status, report = self.run_cli(["--app", "sample"], InventoryResult(applications=[app]))
            self.assertEqual(status, expected)
            self.assert_metadata(report, "application_scan")
            self.assertEqual(report["application"], asdict(app))
            self.assertEqual(report["scan"], {**asdict(stats), "partial": stats.partial,
                                             "logical_mib": "0.000"})
            self.assertEqual(report["partial"], reason is not None)
            self.assertEqual(report["scope"], "install_location_only")
            self.assertEqual(set(report), (self.documented_fields("公共顶层字段")
                             | self.documented_fields("单应用字段")) - {"error"})
            self.assertEqual(set(report["inventory"]), self.documented_fields("内层清单诊断"))

    def test_refused_app_scan_is_versioned_without_a_fake_scan(self):
        for applications in ([], [InstalledApp("sample", "Example")]):
            with self.subTest(applications=applications):
                status, report = self.run_cli(["--app", "sample"], InventoryResult(applications=applications))
                self.assertEqual(status, 2)
                self.assert_metadata(report, "application_scan")
                self.assertIsNone(report["scan"])
                self.assertEqual(report["application"], asdict(applications[0]) if applications else None)
                self.assertTrue(report["partial"])
                self.assertTrue(report["error"])
                self.assertEqual(set(report), self.documented_fields("公共顶层字段")
                                 | self.documented_fields("单应用字段"))

    def test_parameter_error_and_early_interrupt_do_not_emit_a_report(self):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors), self.assertRaises(SystemExit) as raised:
            main(["--path", ".", "--max-files", "0"])
        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertTrue(errors.getvalue())
        output, errors = io.StringIO(), io.StringIO()
        with patch("storage_inspector.__main__.os", SimpleNamespace(name="nt")), \
                patch("storage_inspector.__main__.discover_inventory", side_effect=KeyboardInterrupt), \
                redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(main(["--list-apps"]), 130)
        self.assertEqual(output.getvalue(), "")
        self.assertTrue(errors.getvalue())

    def test_documented_fields_match_dataclass_serialization(self):
        self.assertEqual(self.documented_fields("扫描对象"),
                         set(asdict(DirectoryStats("sample"))) | {"partial", "logical_mib"})
        self.assertEqual(self.documented_fields("应用条目"), set(asdict(InstalledApp("sample", "Example"))))
        self.assertEqual(self.documented_fields("应用清单字段"), set(asdict(InventoryResult())) | {"source"})

    def test_documented_nested_fields_match_populated_scan_and_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sample.txt").write_bytes(b"abc")
            stats = directory_stats(root, top_files=1, by_extension=True, by_directory=True)
        stats.record_error("C:\\Denied", PermissionError("denied"))
        stats.record_skip("C:\\Link", "symbolic_link")
        for heading, entries in [("大文件条目", stats.largest_files),
                                 ("扩展名分组", stats.extension_summary),
                                 ("目录分组", stats.directory_summary),
                                 ("扫描错误", stats.errors), ("跳过明细", stats.skip_details)]:
            with self.subTest(heading=heading):
                self.assertTrue(entries)
                for entry in entries:
                    self.assertEqual(set(entry), self.documented_fields(heading))
        inventory = InventoryResult()
        inventory.record_error("HKLM", "open_root", PermissionError("denied"))
        self.assertEqual(set(inventory.errors[0]), self.documented_fields("注册表错误"))


if __name__ == "__main__":
    unittest.main()
