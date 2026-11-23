from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from storage_inspector.locations import LocationClassifier
from storage_inspector.scanner import directory_stats
from storage_inspector.__main__ import main
from storage_inspector.domain import InstalledApp
from storage_inspector.windows_inventory import InventoryResult


class ClassifierTests(unittest.TestCase):
    def classifier(self, **extra):
        return LocationClassifier({"ProgramFiles": r"C:\Programs", "ProgramData": r"C:\Shared",
                                   "APPDATA": r"C:\Users\Fixture\Roaming", **extra}, windows=True)

    def test_windows_paths_case_separators_and_component_boundary(self):
        c = self.classifier(**{"ProgramFiles(x86)": r"D:\Programs32", "LOCALAPPDATA": r"C:\Users\Fixture\Local"})
        for path, category in (("c:/PROGRAMS/app/a", "program_files"),
                               (r"D:\Programs32\a", "program_files"),
                               (r"C:\Shared\a", "program_data"),
                               (r"C:\Users\Fixture\Local\a", "app_data"),
                               (r"C:\Users\Fixture\Roaming\a", "app_data"),
                               (r"C:\ProgramsExtra\a", "other"),
                               (r"C:\Programs\..\else\a", "other"),
                               (r"E:\a", "other"), (r"C:\Users\Other\a", "other")):
            with self.subTest(path=path):
                self.assertEqual(c.classify(path), category)

    def test_missing_invalid_environment_and_non_windows_are_unknown(self):
        for env in ({}, {"ProgramFiles": "relative"}, {"ProgramFiles": "C:relative"}, {"ProgramFiles": "C:/bad*"},
                    {"APPDATA": r"%USERPROFILE%\AppData"}, {"ProgramData": "C:\\"}):
            c = LocationClassifier(env, windows=True)
            self.assertEqual(c.classify(r"C:\a"), "unknown")
        self.assertEqual(LocationClassifier({}, windows=False).classify(r"C:\a"), "unknown")
        self.assertEqual(self.classifier().classify("relative"), "unknown")
        self.assertEqual(self.classifier().classify(r"\\server\share\a"), "unknown")

    def test_nested_roots_choose_specific_and_ambiguous_roots_stay_unknown(self):
        c = self.classifier(APPDATA=r"C:\Programs\Profile")
        self.assertEqual(c.classify(r"C:\Programs\Profile\a"), "app_data")
        self.assertEqual(self.classifier(APPDATA=r"C:\Programs").classify(r"C:\Programs\a"), "unknown")

    def test_partial_environment_keeps_known_matches(self):
        c = LocationClassifier({"ProgramFiles": r"C:\Programs"}, windows=True)
        self.assertEqual(c.classify(r"C:\Programs\a"), "program_files")
        self.assertEqual(c.classify(r"C:\Else\a"), "unknown")


class LocationScanTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.env = {"ProgramFiles": str(self.root / "Programs"),
                    "ProgramData": str(self.root / "Shared"),
                    "APPDATA": str(self.root / "Profile")}
        self.enterContext(patch.dict(os.environ, self.env, clear=True))

    def file(self, name, size):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * size)
        return path

    def assert_totals(self, stats):
        self.assertEqual(sum(g["file_count"] for g in stats.location_summary), stats.file_count)
        self.assertEqual(sum(g["logical_bytes"] for g in stats.location_summary), stats.logical_bytes)

    def cli(self, *args):
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = main(list(args))
        return status, out.getvalue(), err.getvalue()

    def test_classifies_counted_files_without_reading_roots_or_contents(self):
        for name, size in (("Programs/a", 2), ("Shared/b", 3), ("Profile/c", 4), ("Else/d", 0)):
            self.file(name, size)
        with patch.object(Path, "open", side_effect=AssertionError("no content read")):
            stats = directory_stats(self.root, by_location=True)
        self.assert_totals(stats)
        self.assertEqual((stats.file_count, stats.logical_bytes), (4, 9))
        if os.name == "nt":
            self.assertEqual({g["category"] for g in stats.location_summary},
                             {"program_files", "program_data", "app_data", "other"})
        else:
            self.assertEqual(stats.location_summary[0]["category"], "unknown")
        self.assertFalse(stats.partial)

    def test_disabled_option_does_not_construct_classifier(self):
        with patch("storage_inspector.scanner.LocationClassifier") as classifier:
            self.assertEqual(directory_stats(self.root).location_summary, [])
        classifier.assert_not_called()

    def test_filtering_deduplication_and_limit_preserve_totals(self):
        source = self.file("Programs/a.txt", 5)
        os.link(source, self.root / "alias.txt")
        self.file("Shared/small.txt", 1)
        self.file("Profile/skip.bin", 7)
        self.file("omit/big.txt", 9)
        stats = directory_stats(self.root, by_location=True, include_ext=["txt"],
                                min_size=2, exclude_dirs=["omit"])
        self.assertEqual((stats.file_count, stats.logical_bytes, stats.duplicates), (1, 5, 1))
        self.assert_totals(stats)
        limited = directory_stats(self.root, by_location=True, max_files=1)
        self.assertEqual(limited.stop_reason, "max_files")
        self.assert_totals(limited)

    def test_empty_zero_missing_and_depth_boundary(self):
        self.assertEqual(directory_stats(self.root, by_location=True).location_summary, [])
        zero = self.file("Programs/zero", 0)
        stats = directory_stats(zero, by_location=True)
        self.assertEqual(stats.location_summary[0]["file_count"], 1)
        self.assert_totals(stats)
        missing = directory_stats(self.root / "missing", by_location=True)
        self.assertEqual((missing.error_count, missing.location_summary), (1, []))
        self.assert_totals(directory_stats(self.root, by_location=True, max_depth=0))

    def test_interruption_preserves_classification(self):
        self.file("Programs/a", 3)
        def interrupt(*args):
            raise KeyboardInterrupt
        stats = directory_stats(self.root, by_location=True, on_file=interrupt)
        self.assertEqual(stats.stop_reason, "interrupted")
        self.assertEqual(stats.file_count, 1)
        self.assert_totals(stats)

    def test_json_csv_ndjson_and_saved_output(self):
        self.file("Programs/a", 3)
        args = ("--path", str(self.root), "--by-location")
        status, out, err = self.cli(*args)
        self.assertEqual(status, 0)
        expected = json.loads(out)["location_summary"]
        for fmt in ("csv", "ndjson"):
            status, out, err = self.cli(*args, "--format", fmt)
            self.assertEqual(status, 0)
            report = json.loads(err) if fmt == "csv" else json.loads(out.splitlines()[-1])["report"]
            self.assertEqual(report["location_summary"], expected)
        with TemporaryDirectory() as dest:
            target = Path(dest) / "report.json"
            status, _, _ = self.cli(*args, "--output", str(target))
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(target.read_text())["location_summary"], expected)

    def test_inventory_rejected_before_reading_registry(self):
        with patch("storage_inspector.__main__.discover_inventory") as discover:
            with self.assertRaises(SystemExit) as error:
                self.cli("--list-apps", "--by-location")
            self.assertEqual(error.exception.code, 2)
        discover.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows installation paths")
    def test_application_scan_keeps_installation_scope(self):
        path = self.file("Programs/App/a", 4).parent
        self.file("Profile/unrelated", 100)
        inv = InventoryResult([InstalledApp("fixture", "Fixture", install_location=str(path))])
        with patch("storage_inspector.__main__.discover_inventory", return_value=inv):
            status, out, _ = self.cli("--app", "fixture", "--by-location")
        report = json.loads(out)
        self.assertEqual(status, 0)
        self.assertEqual(report["scan"]["logical_bytes"], 4)
        self.assertEqual(report["scan"]["location_summary"],
                         [{"category": "program_files", "logical_bytes": 4, "file_count": 1}])
