from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict
import csv
import io
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from storage_inspector.__main__ import main
from storage_inspector.domain import InstalledApp
from storage_inspector.scan_report import format_logical_mib, scan_report
from storage_inspector.scanner import DirectoryStats
from storage_inspector.windows_inventory import InventoryResult


class ScanReportTests(unittest.TestCase):
    def run_cli(self, argv):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            status = main(argv)
        return status, output.getvalue(), errors.getvalue()

    def decode_report(self, kind, output, errors):
        if kind == "csv":
            self.assertEqual(output.splitlines()[0], "path,size,modified")
            return json.loads(errors)
        self.assertEqual(errors, "")
        if kind == "ndjson":
            return json.loads(output.splitlines()[-1])["report"]
        return json.loads(output)

    def test_conversion_boundaries_and_half_up(self):
        for size, expected in [(0, "0.000"), (1, "0.000"), (524, "0.000"),
                               (525, "0.001"), (65535, "0.062"), (65536, "0.063"),
                               (65537, "0.063"), (1048575, "1.000"),
                               (1048576, "1.000"), (1572864, "1.500")]:
            with self.subTest(size=size):
                self.assertEqual(format_logical_mib(size), expected)

    def test_large_integer_does_not_pass_through_float(self):
        whole = 10**100
        size = whole * 1048576 + 65536
        report = scan_report(DirectoryStats("synthetic", logical_bytes=size))
        self.assertEqual(report["logical_mib"], f"{whole}.063")
        self.assertEqual(json.loads(json.dumps(report))["logical_bytes"], size)

    def test_invalid_sizes_rejected(self):
        for value in (-1, True, 1.5, "12", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                format_logical_mib(value)

    def test_serialization_preserves_stats_and_does_not_mutate(self):
        stats = DirectoryStats("synthetic", logical_bytes=1572864,
                               directory_summary=[{"logical_bytes": 1572864}],
                               stop_reason="max_files")
        original = asdict(stats)
        report = scan_report(stats)
        self.assertEqual({key: report[key] for key in original}, original)
        self.assertTrue(report["partial"])
        self.assertEqual(report["logical_mib"], "1.500")
        report["directory_summary"][0]["logical_bytes"] = 0
        self.assertEqual(asdict(stats), original)

    def test_real_fixture_all_formats_keep_file_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sample.bin").write_bytes(b"x" * 65536)
            for kind in ("json", "csv", "ndjson"):
                with self.subTest(kind=kind):
                    status, output, errors = self.run_cli(["--path", str(root), "--format", kind])
                    self.assertEqual(status, 0)
                    report = self.decode_report(kind, output, errors)
                    self.assertEqual(report["logical_bytes"], 65536)
                    self.assertEqual(report["logical_mib"], "0.063")
                    self.assertEqual(report["schema_version"], 1)
                    self.assertIn("不是磁盘实际分配量或可清理容量", report["note"])
                    if kind == "csv":
                        rows = list(csv.reader(io.StringIO(output)))
                        self.assertEqual(len(rows), 2)
                        self.assertEqual(len(rows[1]), 3)
                        self.assertEqual(rows[1][1], "65536")
                    if kind == "ndjson":
                        event = json.loads(output.splitlines()[0])
                        self.assertEqual(set(event), {"schema_version", "event", "path", "size", "modified"})
                        self.assertEqual(event["size"], 65536)

    def test_empty_and_missing_paths_have_zero_but_distinct_status(self):
        with tempfile.TemporaryDirectory() as directory:
            for target, expected in [(Path(directory), 0), (Path(directory) / "missing", 2)]:
                for kind in ("json", "csv", "ndjson"):
                    with self.subTest(target=target, kind=kind):
                        status, output, errors = self.run_cli(["--path", str(target), "--format", kind])
                        report = self.decode_report(kind, output, errors)
                        self.assertEqual(status, expected)
                        self.assertEqual(report["logical_mib"], "0.000")
                        self.assertEqual(report["partial"], expected == 2)

    def test_partial_and_interrupted_totals_all_formats(self):
        for reason, expected in [("max_files", 2), ("max_seconds", 2), ("interrupted", 130)]:
            for kind in ("json", "csv", "ndjson"):
                stats = DirectoryStats("synthetic", logical_bytes=1572864, stop_reason=reason)
                with self.subTest(reason=reason, kind=kind), \
                        patch("storage_inspector.__main__.directory_stats", return_value=stats):
                    status, output, errors = self.run_cli(["--path", "synthetic", "--format", kind])
                report = self.decode_report(kind, output, errors)
                self.assertEqual(status, expected)
                self.assertTrue(report["partial"])
                self.assertEqual(report["logical_mib"], "1.500")
                self.assertEqual(report["stop_reason"], reason)

    def test_application_totals_all_formats(self):
        inventory = InventoryResult(applications=[InstalledApp("sample", "Example", install_location="C:\\Example")])
        for reason, expected in [(None, 0), ("max_files", 2), ("interrupted", 130)]:
            for kind in ("json", "csv", "ndjson"):
                stats = DirectoryStats("C:\\Example", logical_bytes=1048576, stop_reason=reason)
                with self.subTest(reason=reason, kind=kind), \
                        patch("storage_inspector.__main__.os", SimpleNamespace(name="nt")), \
                        patch("storage_inspector.__main__.discover_inventory", return_value=inventory), \
                        patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFDIR)), \
                        patch("storage_inspector.app_scan.directory_stats", return_value=stats):
                    status, output, errors = self.run_cli(["--app", "sample", "--format", kind])
                report = self.decode_report(kind, output, errors)
                self.assertEqual(status, expected)
                self.assertNotIn("logical_mib", report)
                self.assertEqual(report["scan"]["logical_mib"], "1.000")
                self.assertEqual(report["scan"]["logical_bytes"], 1048576)

    def test_inventory_and_refused_app_do_not_invent_totals(self):
        for argv in (["--list-apps"], ["--app", "missing"],
                     ["--app", "missing", "--format", "csv"],
                     ["--app", "missing", "--format", "ndjson"]):
            with self.subTest(argv=argv), \
                    patch("storage_inspector.__main__.os", SimpleNamespace(name="nt")), \
                    patch("storage_inspector.__main__.discover_inventory", return_value=InventoryResult()):
                status, output, errors = self.run_cli(argv)
            kind = argv[-1] if "--format" in argv else "json"
            report = self.decode_report(kind, output, errors)
            self.assertNotIn("logical_mib", report)
            if "--app" in argv:
                self.assertEqual(status, 2)
                self.assertIsNone(report["scan"])
            else:
                self.assertEqual(status, 0)

    def test_explicit_saved_reports_use_same_units(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "file").write_bytes(b"x" * 65536)
            for kind in ("json", "csv", "ndjson"):
                destination = root / f"report.{kind}"
                status, output, errors = self.run_cli(["--path", str(source), "--format", kind,
                                                     "--output", str(destination)])
                self.assertEqual(status, 0)
                self.assertEqual(output, "")
                report = self.decode_report(kind, destination.read_text(encoding="utf-8"), errors)
                self.assertEqual(report["logical_mib"], "0.063")


if __name__ == "__main__":
    unittest.main()
