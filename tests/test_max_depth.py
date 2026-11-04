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
from storage_inspector.scanner import directory_stats
from storage_inspector.windows_inventory import InventoryResult
from test_scan_limits import TrackedEntries


class MaxDepthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "source"
        (self.root / "child/deep").mkdir(parents=True)
        (self.root / "a.bin").write_bytes(b"abc")
        (self.root / "child/b.bin").write_bytes(b"12345")
        (self.root / "child/deep/c.bin").write_bytes(b"1234567")

    def cli(self, args):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = main(args)
        return code, output.getvalue(), errors.getvalue()

    def decode(self, kind, output, errors):
        if kind == "csv":
            return json.loads(errors)
        self.assertEqual(errors, "")
        if kind == "ndjson":
            return json.loads(output.splitlines()[-1])["report"]
        return json.loads(output)

    def test_depth_zero_never_opens_root(self):
        with patch("storage_inspector.scanner.os.scandir") as open_dir:
            result = directory_stats(self.root, max_depth=0)
        open_dir.assert_not_called()
        self.assertEqual((result.file_count, result.logical_bytes), (0, 0))
        self.assertEqual(result.depth_limited_directories, 1)
        self.assertTrue(result.partial)

    def test_depth_levels_and_unlimited(self):
        for depth, size, count, cut in [(0, 0, 0, 1), (1, 3, 1, 1),
                                      (2, 8, 2, 1), (3, 15, 3, 0), (None, 15, 3, 0)]:
            with self.subTest(depth=depth):
                result = directory_stats(self.root, max_depth=depth)
                self.assertEqual((result.logical_bytes, result.file_count), (size, count))
                self.assertEqual(result.max_depth, depth)
                self.assertEqual(result.depth_limited_directories, cut)
                self.assertEqual(result.partial, bool(cut))
                self.assertIsNone(result.stop_reason)

    def test_no_metadata_or_enumeration_below_boundary(self):
        real_stat, real_scandir = Path.lstat, os.scandir
        visited, opened = [], []
        def probe(path, *args, **kwargs):
            visited.append(path)
            return real_stat(path, *args, **kwargs)
        def track(path):
            entries = TrackedEntries(real_scandir(path))
            opened.append((path, entries))
            return entries
        with patch.object(Path, "lstat", probe), patch("storage_inspector.scanner.os.scandir", side_effect=track):
            directory_stats(self.root, max_depth=1)
        self.assertEqual(set(visited), {self.root, self.root / "a.bin", self.root / "child"})
        self.assertEqual([p for p, _ in opened], [self.root])
        self.assertTrue(all(e.closed for _, e in opened))

    def test_grouping_and_events_do_not_expand_depth(self):
        events = []
        result = directory_stats(self.root, max_depth=2, by_directory=True, by_extension=True,
                                 top_files=10, on_file=lambda p, info: events.append(p))
        self.assertEqual(set(events), {self.root / "a.bin", self.root / "child/b.bin"})
        self.assertEqual(sum(g["logical_bytes"] for g in result.directory_summary), 8)
        self.assertEqual(sum(g["logical_bytes"] for g in result.extension_summary), 8)
        self.assertEqual(sum(g["logical_bytes"] for g in result.largest_files), 8)

    def test_empty_boundary_directory_is_unknown(self):
        empty = self.base / "empty"
        empty.mkdir()
        self.assertTrue(directory_stats(empty, max_depth=0).partial)
        self.assertFalse(directory_stats(empty, max_depth=1).partial)

    def test_single_file_at_zero_is_counted(self):
        result = directory_stats(self.root / "a.bin", max_depth=0)
        self.assertEqual(result.logical_bytes, 3)
        self.assertEqual(result.depth_limited_directories, 0)
        self.assertFalse(result.partial)

    def test_exclusion_precedes_depth_without_double_count(self):
        result = directory_stats(self.root, max_depth=1, exclude_dirs=["child"])
        self.assertEqual(result.excluded_directories, 1)
        self.assertEqual(result.depth_limited_directories, 0)
        self.assertTrue(result.partial)

    def test_link_and_offline_roots_stay_skipped(self):
        for info in (SimpleNamespace(st_mode=stat.S_IFLNK),
                     SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400),
                     SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x1000)):
            with self.subTest(info=info), patch.object(Path, "lstat", return_value=info), \
                    patch("storage_inspector.scanner.os.scandir") as opened:
                result = directory_stats(self.root, max_depth=0)
            opened.assert_not_called()
            self.assertEqual((result.skipped, result.depth_limited_directories), (1, 0))

    def test_invalid_depth_rejected_before_access(self):
        for value in (-1, True, 1.5, "1"):
            with self.subTest(value=value), patch.object(Path, "lstat") as probe:
                with self.assertRaises(ValueError):
                    directory_stats(self.root, max_depth=value)
                with self.assertRaises(ValueError):
                    inspect_app(InventoryResult(), "missing", max_depth=value)
                probe.assert_not_called()

    def test_cli_invalid_or_inventory_combination_before_scan(self):
        for args in (["--path", str(self.root), "--max-depth", "-1"],
                     ["--path", str(self.root), "--max-depth", "1.5"],
                     ["--list-apps", "--max-depth", "0"]):
            with self.subTest(args=args), patch("storage_inspector.__main__.discover_inventory") as inventory, \
                    patch("storage_inspector.__main__.directory_stats") as scan, \
                    self.assertRaises(SystemExit) as error:
                self.cli(args)
            self.assertEqual(error.exception.code, 2)
            inventory.assert_not_called()
            scan.assert_not_called()

    def test_all_formats_and_saved_reports(self):
        for kind in ("json", "csv", "ndjson"):
            for saved in (False, True):
                with self.subTest(kind=kind, saved=saved):
                    args = ["--path", str(self.root), "--max-depth", "1", "--format", kind]
                    destination = self.base / f"report.{kind}"
                    if saved:
                        args += ["--output", str(destination)]
                    code, output, errors = self.cli(args)
                    if saved:
                        self.assertEqual(output, "")
                        output = destination.read_text(encoding="utf-8")
                    report = self.decode(kind, output, errors)
                    self.assertEqual(code, 2)
                    self.assertEqual(report["logical_bytes"], 3)
                    self.assertEqual(report["max_depth"], 1)
                    self.assertEqual(report["depth_limited_directories"], 1)
                    self.assertTrue(report["partial"])
                    if kind == "csv":
                        self.assertEqual(len(list(csv.reader(io.StringIO(output)))), 2)
                    if kind == "ndjson":
                        self.assertEqual(len(output.splitlines()), 2)
                        self.assertEqual(json.loads(output.splitlines()[-1])["exit_code"], 2)

    @unittest.skipUnless(os.name == "nt", "Windows installation paths")
    def test_application_uses_selected_root_all_formats(self):
        inventory = InventoryResult(applications=[InstalledApp("sample", "Sample", install_location=str(self.root))])
        for kind in ("json", "csv", "ndjson"):
            with self.subTest(kind=kind), patch("storage_inspector.__main__.discover_inventory", return_value=inventory):
                code, output, errors = self.cli(["--app", "sample", "--max-depth", "1", "--format", kind])
            report = self.decode(kind, output, errors)
            self.assertEqual(code, 2)
            self.assertTrue(report["partial"])
            self.assertEqual(report["scan"]["max_depth"], 1)
            self.assertEqual(report["scan"]["logical_bytes"], 3)

    def test_global_limits_and_interrupt_still_close_iterators(self):
        real_scandir = os.scandir
        for limits, reason in [({"max_files": 1}, "max_files"), ({}, "interrupted")]:
            opened = []
            def track(path):
                entries = TrackedEntries(real_scandir(path))
                opened.append(entries)
                return entries
            def on_file(path, info):
                if not limits:
                    raise KeyboardInterrupt
            with self.subTest(reason=reason), patch("storage_inspector.scanner.os.scandir", side_effect=track):
                result = directory_stats(self.root, max_depth=1, on_file=on_file, **limits)
            self.assertEqual(result.stop_reason, reason)
            self.assertTrue(result.partial)
            self.assertTrue(all(e.closed for e in opened))

    def test_time_limit_remains_global(self):
        with patch("storage_inspector.scanner.time.monotonic", side_effect=[0, 2]):
            result = directory_stats(self.root, max_depth=1, max_seconds=1)
        self.assertEqual(result.stop_reason, "max_seconds")
        self.assertTrue(result.partial)


if __name__ == "__main__":
    unittest.main()
