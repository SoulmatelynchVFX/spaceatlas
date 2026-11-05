from contextlib import redirect_stdout, redirect_stderr
import csv
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from storage_inspector.__main__ import main
from storage_inspector.app_scan import inspect_app
from storage_inspector.domain import InstalledApp
from storage_inspector.scanner import directory_stats, parse_min_size
from storage_inspector.windows_inventory import InventoryResult
from test_scan_limits import TrackedEntries


class MinSizeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "source"
        (self.root / "child").mkdir(parents=True)
        for name, size in (("zero.bin", 0), ("small.bin", 2047),
                           ("equal.bin", 2048), ("child/large.dat", 4096)):
            (self.root / name).write_bytes(b"x" * size)

    def cli(self, args):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = main(args)
        return code, output.getvalue(), errors.getvalue()

    def test_units_integer_precision_and_case(self):
        for text, expected in (("0", 0), ("0002", 2), ("500K", 512000),
                               ("10M", 10485760), ("1g", 1073741824),
                               ("2k", 2048), ("2m", 2097152),
                               (str(2**60 + 1), 2**60 + 1)):
            self.assertEqual(parse_min_size(text), expected)

    def test_invalid_units(self):
        for text in ("", "-1", "+1", "1.5M", "1MB", "1KiB", "1T", "1e3",
                     "1 M", " 1", "1\n", "１", "1_000", None, True):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_min_size(text)

    def test_boundary_aggregation_and_events(self):
        events = []
        result = directory_stats(self.root, min_size=2048, by_extension=True,
                                 by_directory=True, top_files=10,
                                 on_file=lambda path, info: events.append((path, info.st_size)))
        self.assertEqual((result.file_count, result.logical_bytes), (2, 6144))
        self.assertEqual((result.min_size, result.size_filtered_files, result.size_filtered_bytes),
                         (2048, 2, 2047))
        self.assertTrue(result.partial)
        self.assertIsNone(result.stop_reason)
        self.assertEqual({p.name for p, _ in events}, {"equal.bin", "large.dat"})
        self.assertEqual(sum(size for _, size in events), result.logical_bytes)
        for groups in (result.extension_summary, result.directory_summary, result.largest_files):
            self.assertEqual(sum(g["logical_bytes"] for g in groups), 6144)

    def test_default_zero_and_no_matching_filter(self):
        for threshold in (None, 0):
            result = directory_stats(self.root, min_size=threshold)
            self.assertEqual((result.file_count, result.logical_bytes), (4, 8191))
            self.assertFalse(result.partial)
            self.assertEqual(result.size_filtered_files, 0)
            self.assertEqual(result.min_size, threshold)
        self.assertFalse(directory_stats(self.root / "equal.bin", min_size=2048).partial)

    def test_all_filtered_and_zero_byte_filter_are_partial(self):
        result = directory_stats(self.root, min_size=8192)
        self.assertEqual((result.file_count, result.logical_bytes), (0, 0))
        self.assertEqual((result.size_filtered_files, result.size_filtered_bytes), (4, 8191))
        self.assertTrue(result.partial)
        zero = directory_stats(self.root / "zero.bin", min_size=1)
        self.assertEqual((zero.size_filtered_files, zero.size_filtered_bytes), (1, 0))
        self.assertTrue(zero.partial)

    def test_hard_links_deduplicated_before_filter(self):
        # Deterministic metadata seam: all regular paths have the same identity.
        real_stat = Path.lstat
        def metadata(path, *args, **kwargs):
            info = real_stat(path, *args, **kwargs)
            if stat.S_ISREG(info.st_mode):
                return SimpleNamespace(st_mode=stat.S_IFREG, st_dev=1, st_ino=77, st_size=3)
            return info
        for threshold, included, filtered in ((3, 1, 0), (4, 0, 1)):
            with patch.object(Path, "lstat", metadata):
                result = directory_stats(self.root, min_size=threshold)
            self.assertEqual((result.file_count, result.size_filtered_files, result.duplicates),
                             (included, filtered, 3))
            self.assertEqual(result.size_filtered_bytes, filtered * 3)

    def test_no_inode_does_not_deduplicate_distinct_paths(self):
        real_stat = Path.lstat
        def metadata(path, *args, **kwargs):
            info = real_stat(path, *args, **kwargs)
            if stat.S_ISREG(info.st_mode):
                return SimpleNamespace(st_mode=stat.S_IFREG, st_dev=0, st_ino=0, st_size=3)
            return info
        with patch.object(Path, "lstat", metadata):
            result = directory_stats(self.root, min_size=4)
        self.assertEqual((result.size_filtered_files, result.duplicates), (4, 0))

    def test_depth_and_exclusion_keep_own_boundaries(self):
        for options in ({"max_depth": 1}, {"exclude_dirs": ["child"]}):
            result = directory_stats(self.root, min_size=2048, **options)
            self.assertEqual((result.file_count, result.logical_bytes), (1, 2048))
            self.assertEqual(result.size_filtered_files, 2)
            self.assertTrue(result.partial)
        result = directory_stats(self.root, min_size=1, max_depth=0)
        self.assertEqual((result.size_filtered_files, result.depth_limited_directories), (0, 1))

    def test_count_limit_only_counts_included_files(self):
        result = directory_stats(self.root, min_size=8192, max_files=1)
        self.assertEqual(result.size_filtered_files, 4)
        self.assertIsNone(result.stop_reason)
        result = directory_stats(self.root, min_size=2048, max_files=1)
        self.assertEqual(result.file_count, 1)
        self.assertEqual(result.stop_reason, "max_files")

    def test_time_limit_and_interrupt_close_iterators(self):
        with patch("storage_inspector.scanner.time.monotonic", side_effect=[0, 2]):
            result = directory_stats(self.root, min_size=2048, max_seconds=1)
        self.assertEqual(result.stop_reason, "max_seconds")
        real_scandir, opened = os.scandir, []
        def track(path):
            entries = TrackedEntries(real_scandir(path))
            opened.append(entries)
            return entries
        def interrupt(path, info):
            raise KeyboardInterrupt
        with patch("storage_inspector.scanner.os.scandir", side_effect=track):
            result = directory_stats(self.root, min_size=2048, on_file=interrupt)
        self.assertEqual(result.stop_reason, "interrupted")
        self.assertEqual(result.file_count, 1)
        self.assertTrue(all(entries.closed for entries in opened))

    def test_invalid_api_before_metadata_access(self):
        for value in (-1, True, 1.5, "1K"):
            with self.subTest(value=value), patch.object(Path, "lstat") as probe:
                with self.assertRaises(ValueError):
                    directory_stats(self.root, min_size=value)
                with self.assertRaises(ValueError):
                    inspect_app(InventoryResult(), "missing", min_size=value)
                probe.assert_not_called()

    def test_cli_invalid_before_inventory_scan_or_output(self):
        for args in (["--list-apps", "--min-size", "0"],
                     ["--path", str(self.root), "--min-size", "1MB"],
                     ["--path", str(self.root), "--min-size=-1"]):
            with self.subTest(args=args), patch("storage_inspector.__main__.discover_inventory") as inv, \
                    patch("storage_inspector.__main__.directory_stats") as scan, \
                    patch("storage_inspector.__main__.ReportOutput") as output, \
                    self.assertRaises(SystemExit) as error:
                self.cli(args + ["--output", str(self.base / "report.json")])
            self.assertEqual(error.exception.code, 2)
            inv.assert_not_called()
            scan.assert_not_called()
            output.assert_not_called()

    def test_all_formats_stdout_and_saved(self):
        for kind in ("json", "csv", "ndjson"):
            for saved in (False, True):
                with self.subTest(kind=kind, saved=saved):
                    args = ["--path", str(self.root), "--min-size", "2K", "--format", kind]
                    dest = self.base / f"report.{kind}"
                    if saved:
                        args += ["--output", str(dest)]
                    code, output, errors = self.cli(args)
                    if saved:
                        self.assertEqual(output, "")
                        output = dest.read_text(encoding="utf-8")
                    if kind == "csv":
                        report = json.loads(errors)
                        rows = list(csv.DictReader(io.StringIO(output)))
                        self.assertEqual(sorted(int(r["size"]) for r in rows), [2048, 4096])
                    elif kind == "ndjson":
                        events = [json.loads(line) for line in output.splitlines()]
                        report = events[-1]["report"]
                        self.assertEqual(sorted(e["size"] for e in events[:-1]), [2048, 4096])
                        self.assertEqual(events[-1]["exit_code"], 2)
                    else:
                        report = json.loads(output)
                    self.assertEqual(code, 2)
                    self.assertEqual(report["logical_bytes"], 6144)
                    self.assertEqual(report["min_size"], 2048)
                    self.assertEqual(report["size_filtered_files"], 2)
                    self.assertEqual(report["size_filtered_bytes"], 2047)
                    self.assertTrue(report["partial"])

    @unittest.skipUnless(os.name == "nt", "Windows installation path")
    def test_application_all_formats(self):
        inventory = InventoryResult(applications=[InstalledApp("sample", "Sample", install_location=str(self.root))])
        for kind in ("json", "csv", "ndjson"):
            with patch("storage_inspector.__main__.discover_inventory", return_value=inventory):
                code, output, errors = self.cli(["--app", "sample", "--min-size", "2K", "--format", kind])
            report = (json.loads(errors) if kind == "csv" else
                      json.loads(output.splitlines()[-1])["report"] if kind == "ndjson" else json.loads(output))
            self.assertEqual(code, 2)
            self.assertEqual(report["scan"]["logical_bytes"], 6144)
            self.assertEqual(report["scan"]["size_filtered_files"], 2)

    def test_safety_skips_not_classified_as_size_filters(self):
        for info in (SimpleNamespace(st_mode=stat.S_IFLNK),
                     SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x1000)):
            with patch.object(Path, "lstat", return_value=info):
                result = directory_stats(self.root, min_size=2048)
            self.assertEqual((result.skipped, result.size_filtered_files), (1, 0))


if __name__ == "__main__":
    unittest.main()
