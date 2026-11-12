import csv
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import PropertyMock, patch

from storage_inspector.__main__ import main
from storage_inspector.domain import InstalledApp
from storage_inspector.mtime import DAY_NS, MTIME_BUCKETS, modification_bucket
from storage_inspector.scanner import directory_stats
from storage_inspector.windows_inventory import InventoryResult


REFERENCE_NS = 1_700_000_000_123_456_789
REFERENCE_UTC = "2023-11-14T22:13:20.123456789Z"


class MtimeBucketTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.clock = self.enterContext(patch("storage_inspector.scanner.time.time_ns",
                                            return_value=REFERENCE_NS))

    def file(self, name, *, days, size):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * size)
        modified = REFERENCE_NS - days * DAY_NS
        os.utime(path, ns=(modified, modified))
        return path

    def cli(self, *args):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main(list(args))
        return status, stdout.getvalue(), stderr.getvalue()

    def assert_bucket_totals(self, stats):
        self.assertEqual(set(stats.mtime_buckets), set(MTIME_BUCKETS))
        for key in ("file_count", "logical_bytes"):
            self.assertEqual(sum(bucket[key] for bucket in stats.mtime_buckets.values()),
                             getattr(stats, key))

    def test_bucket_boundaries(self):
        cases = (
            (-1, "future"), (0, "lt_30d"), (30 * DAY_NS - 1, "lt_30d"),
            (30 * DAY_NS, "30_to_lt_180d"), (180 * DAY_NS - 1, "30_to_lt_180d"),
            (180 * DAY_NS, "180_to_365d"), (365 * DAY_NS, "180_to_365d"),
            (365 * DAY_NS + 1, "gt_365d"),
        )
        for age_ns, expected in cases:
            with self.subTest(age_ns=age_ns):
                info = SimpleNamespace(st_mtime_ns=REFERENCE_NS - age_ns)
                self.assertEqual(modification_bucket(info, REFERENCE_NS), expected)

    def test_unusable_times(self):
        class Unreadable:
            st_mtime_ns = PropertyMock(side_effect=OSError("mtime unavailable"))

        cases = (SimpleNamespace(), Unreadable(), SimpleNamespace(st_mtime=float("nan")),
                 SimpleNamespace(st_mtime=float("inf")), SimpleNamespace(st_mtime_ns=10**24),
                 SimpleNamespace(st_mtime_ns=-(10**24)), SimpleNamespace(st_mtime_ns=True),
                 SimpleNamespace(st_mtime_ns="invalid"))
        for info in cases:
            with self.subTest(info=info):
                self.assertEqual(modification_bucket(info, REFERENCE_NS), "unknown")
        self.assertEqual(modification_bucket(SimpleNamespace(st_mtime=1_700_000_000.125),
                                             REFERENCE_NS), "future")

    def test_single_reference_and_future_do_not_make_scan_partial(self):
        self.file("new", days=1, size=2)
        self.file("old", days=400, size=3)
        self.file("future", days=-1, size=5)
        stats = directory_stats(self.root, by_mtime=True)
        self.clock.assert_called_once_with()
        self.assertEqual(stats.mtime_reference_utc, REFERENCE_UTC)
        self.assertFalse(stats.partial)
        self.assertEqual(stats.mtime_buckets["lt_30d"], {"file_count": 1, "logical_bytes": 2})
        self.assertEqual(stats.mtime_buckets["gt_365d"], {"file_count": 1, "logical_bytes": 3})
        self.assertEqual(stats.mtime_buckets["future"], {"file_count": 1, "logical_bytes": 5})
        self.assert_bucket_totals(stats)

    def test_only_included_files_count_and_hard_links_count_once(self):
        included = self.file("included.txt", days=60, size=5)
        os.link(included, self.root / "alias.txt")
        self.file("omit.txt", days=200, size=9)
        self.file("other.bin", days=200, size=7)
        self.file("small.txt", days=400, size=1)
        self.file("nested/deep.txt", days=400, size=6)
        stats = directory_stats(self.root, by_mtime=True, exclude_patterns=["omit.txt"],
                                include_ext=["txt"], min_size=2, max_depth=1)
        self.assertEqual((stats.file_count, stats.logical_bytes, stats.duplicates), (1, 5, 1))
        self.assertEqual(stats.mtime_buckets["30_to_lt_180d"], {"file_count": 1, "logical_bytes": 5})
        self.assert_bucket_totals(stats)

    def test_empty_and_limited_scans(self):
        empty = directory_stats(self.root, by_mtime=True)
        self.assertFalse(empty.partial)
        self.assert_bucket_totals(empty)
        self.file("one", days=1, size=5)
        self.file("two", days=200, size=7)
        limited = directory_stats(self.root, by_mtime=True, max_files=1)
        self.assertEqual((limited.file_count, limited.stop_reason), (1, "max_files"))
        self.assert_bucket_totals(limited)

    def test_unknown_mtime_keeps_file_size_and_marks_partial(self):
        info = SimpleNamespace(st_mode=stat.S_IFREG, st_dev=1, st_ino=1, st_size=7)
        with patch.object(Path, "lstat", return_value=info):
            status, output, _ = self.cli("--path", str(self.root / "sample"), "--by-mtime")
        report = json.loads(output)
        self.assertEqual(status, 2)
        self.assertTrue(report["partial"])
        self.assertEqual((report["file_count"], report["logical_bytes"], report["error_count"]), (1, 7, 0))
        self.assertEqual(report["mtime_buckets"]["unknown"], {"file_count": 1, "logical_bytes": 7})

    def test_failed_lstat_is_a_scan_error(self):
        stats = directory_stats(self.root / "missing", by_mtime=True)
        self.assertEqual((stats.file_count, stats.error_count), (0, 1))
        self.assert_bucket_totals(stats)

    def test_default_does_not_use_clock_or_mtime(self):
        info = SimpleNamespace(st_mode=stat.S_IFREG, st_dev=1, st_ino=1, st_size=7)
        with patch.object(Path, "lstat", return_value=info):
            stats = directory_stats(self.root / "sample")
        self.clock.assert_not_called()
        self.assertFalse(stats.partial)
        self.assertIsNone(stats.mtime_reference_utc)
        self.assertEqual(stats.mtime_buckets, {})

    def test_cli_reports_same_buckets_in_all_formats(self):
        self.file("sample", days=200, size=7)
        args = ("--path", str(self.root), "--by-mtime")
        status, stdout, _ = self.cli(*args)
        expected = json.loads(stdout)
        self.assertEqual(status, 0)
        self.assertEqual(expected["mtime_buckets"]["180_to_365d"], {"file_count": 1, "logical_bytes": 7})
        for output_format in ("csv", "ndjson"):
            with self.subTest(output_format=output_format):
                status, stdout, stderr = self.cli(*args, "--format", output_format)
                self.assertEqual(status, 0)
                if output_format == "csv":
                    rows = list(csv.reader(StringIO(stdout)))
                    self.assertEqual(rows[0], ["path", "size", "modified"])
                    self.assertEqual(len(rows), 2)
                    report = json.loads(stderr)
                else:
                    file_event, summary = (json.loads(line) for line in stdout.splitlines())
                    self.assertEqual(file_event["event"], "file")
                    self.assertEqual(summary["event"], "summary")
                    report = summary["report"]
                for key in ("schema_version", "mtime_reference_utc", "mtime_buckets"):
                    self.assertEqual(report[key], expected[key])

    @unittest.skipUnless(os.name == "nt", "Windows app scan")
    def test_cli_app_report_has_nested_buckets(self):
        self.file("sample", days=1, size=7)
        app = InstalledApp("sample", "示例", install_location=str(self.root))
        with patch("storage_inspector.__main__.discover_inventory",
                   return_value=InventoryResult(applications=[app])):
            status, stdout, _ = self.cli("--app", "sample", "--by-mtime")
        self.assertEqual(status, 0)
        scan = json.loads(stdout)["scan"]
        self.assertEqual(scan["mtime_reference_utc"], REFERENCE_UTC)
        self.assertEqual(scan["mtime_buckets"]["lt_30d"], {"file_count": 1, "logical_bytes": 7})

    def test_cli_rejects_list_apps_before_discovering_inventory(self):
        with patch("storage_inspector.__main__.discover_inventory") as discover:
            with self.assertRaises(SystemExit) as error:
                self.cli("--list-apps", "--by-mtime")
        self.assertEqual(error.exception.code, 2)
        discover.assert_not_called()
