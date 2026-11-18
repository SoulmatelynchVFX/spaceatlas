from contextlib import redirect_stderr, redirect_stdout
import heapq
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
from storage_inspector.scanner import directory_stats
from storage_inspector.windows_inventory import InventoryResult


class RankingTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))

    def file(self, name, size):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * size)
        return path

    def cli(self, *args):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main(list(args))
        return status, stdout.getvalue(), stderr.getvalue()

    def assert_totals(self, stats):
        ranking = stats.ranking
        self.assertEqual(stats.file_count,
                         sum(item["file_count"] for item in ranking["entries"]) + ranking["omitted_file_count"])
        self.assertEqual(stats.logical_bytes,
                         sum(item["logical_bytes"] for item in ranking["entries"]) + ranking["omitted_logical_bytes"])

    def test_legacy_and_new_file_size_ranking_share_ties_and_values(self):
        for name, size in (("a", 1), ("b", 4), ("c", 4)):
            self.file(name, size)
        legacy = directory_stats(self.root, top_files=2)
        ranked = directory_stats(self.root, sort="size", limit=2, top_files=2)
        self.assertEqual(ranked.largest_files, legacy.largest_files)
        self.assertEqual([Path(item["path"]).name for item in ranked.ranking["entries"]], ["c", "b"])
        self.assertEqual((ranked.ranking["omitted_count"], ranked.ranking["omitted_logical_bytes"]), (1, 1))
        self.assertFalse(ranked.partial)
        self.assertIsNone(legacy.ranking)
        self.assert_totals(ranked)

    def test_name_order_and_bounded_heap(self):
        for name in ("d", "b", "c", "a"):
            self.file(name, 1)
        push, pushpop = heapq.heappush, heapq.heappushpop
        def bounded_push(heap, item):
            self.assertLess(len(heap), 2)
            return push(heap, item)
        def bounded_pushpop(heap, item):
            self.assertEqual(len(heap), 2)
            return pushpop(heap, item)
        with patch("storage_inspector.scanner.heapq.heappush", side_effect=bounded_push), \
                patch("storage_inspector.scanner.heapq.heappushpop", side_effect=bounded_pushpop):
            stats = directory_stats(self.root, sort="name", limit=2)
        self.assertEqual([Path(item["path"]).name for item in stats.ranking["entries"]], ["a", "b"])
        self.assertEqual(stats.largest_files, [])
        self.assert_totals(stats)

    def test_groups_sort_by_count_name_and_size_without_losing_full_summary(self):
        self.file("many/a.txt", 1)
        self.file("many/b.txt", 1)
        self.file("large/a.bin", 8)
        for order, expected in (("count", "many"), ("size", "large"), ("name", "large")):
            stats = directory_stats(self.root, by_directory=True, sort=order, limit=1)
            self.assertEqual(Path(stats.ranking["entries"][0]["path"]).name, expected)
            self.assertEqual(len(stats.directory_summary), 2)
            self.assertEqual(stats.ranking["omitted_count"], 1)
            self.assert_totals(stats)
        stats = directory_stats(self.root, by_extension=True, sort="count")
        self.assertEqual([item["extension"] for item in stats.ranking["entries"]], [".txt", ".bin"])
        self.assertIsNone(stats.ranking["limit"])
        self.assert_totals(stats)

    def test_default_file_limit_and_oversized_limit(self):
        for index in range(12):
            self.file(str(index), index)
        stats = directory_stats(self.root, sort="size")
        self.assertEqual((len(stats.ranking["entries"]), stats.ranking["limit"]), (10, 10))
        unlimited = directory_stats(self.root, limit=20)
        self.assertEqual((len(unlimited.ranking["entries"]), unlimited.ranking["omitted_count"]), (12, 0))
        self.assert_totals(stats)
        self.assert_totals(unlimited)

    def test_partial_filters_and_hardlink_deduplication(self):
        source = self.file("a.txt", 5)
        os.link(source, self.root / "alias.txt")
        self.file("omit.bin", 3)
        stats = directory_stats(self.root, sort="size", limit=1, include_ext=["txt"])
        self.assertEqual((stats.file_count, stats.duplicates, stats.extension_filtered_files), (1, 1, 1))
        self.assertTrue(stats.partial)
        self.assert_totals(stats)
        limited = directory_stats(self.root, sort="name", limit=4, max_files=1)
        self.assertEqual((limited.file_count, limited.stop_reason), (1, "max_files"))
        self.assert_totals(limited)

    def test_empty_missing_and_single_file(self):
        stats = directory_stats(self.root, sort="name")
        self.assertEqual(stats.ranking["entries"], [])
        self.assert_totals(stats)
        stats = directory_stats(self.root / "missing", limit=1)
        self.assertEqual(stats.error_count, 1)
        self.assert_totals(stats)
        target = self.file("zero", 0)
        stats = directory_stats(target, limit=1)
        self.assertEqual(stats.ranking["entries"], [{"path": str(target), "logical_bytes": 0, "file_count": 1}])

    def test_all_output_formats_and_saved_report(self):
        self.file("a", 2)
        self.file("b", 1)
        args = ("--path", str(self.root), "--sort", "name", "--limit", "1")
        status, output, _ = self.cli(*args)
        self.assertEqual(status, 0)
        expected = json.loads(output)["ranking"]
        for format in ("csv", "ndjson"):
            status, output, errors = self.cli(*args, "--format", format)
            self.assertEqual(status, 0)
            if format == "csv":
                self.assertEqual(len(output.splitlines()), 3)
                report = json.loads(errors)
            else:
                events = [json.loads(line) for line in output.splitlines()]
                self.assertEqual([event["event"] for event in events], ["file", "file", "summary"])
                report = events[-1]["report"]
            self.assertEqual(report["ranking"], expected)
        with TemporaryDirectory() as destination:
            target = Path(destination) / "report.json"
            status, output, _ = self.cli(*args, "--output", str(target))
            self.assertEqual((status, output), (0, ""))
            self.assertEqual(json.loads(target.read_text(encoding="utf-8"))["ranking"], expected)

    @unittest.skipUnless(os.name == "nt", "Windows application paths")
    def test_application_entry(self):
        self.file("file", 1)
        inventory = InventoryResult([InstalledApp("fixture", "Fixture", install_location=str(self.root))])
        with patch("storage_inspector.__main__.discover_inventory", return_value=inventory):
            status, output, _ = self.cli("--app", "fixture", "--limit", "1")
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output)["scan"]["ranking"]["source"], "files")

    def test_invalid_combinations_rejected_before_io(self):
        invalid = (
            {"limit": 0}, {"limit": True}, {"sort": "invalid"}, {"sort": "count"},
            {"limit": 1, "top_files": 2}, {"sort": "name", "top_files": 2},
            {"sort": "size", "by_extension": True, "top_files": 2},
            {"sort": "count", "by_extension": True, "by_directory": True},
        )
        with patch.object(Path, "lstat") as stat:
            for options in invalid:
                with self.subTest(options=options):
                    with self.assertRaises(ValueError):
                        directory_stats(self.root, **options)
                    with self.assertRaises(ValueError):
                        inspect_app(InventoryResult(), "fixture", **options)
            stat.assert_not_called()
        with patch("storage_inspector.__main__.discover_inventory") as discover, \
                patch("storage_inspector.__main__.directory_stats") as scan:
            for arguments in (("--list-apps", "--limit", "2"),
                              ("--app", "fixture", "--sort", "count"),
                              ("--path", str(self.root), "--limit", "0")):
                with self.assertRaises(SystemExit) as error:
                    self.cli(*arguments)
                self.assertEqual(error.exception.code, 2)
        discover.assert_not_called()
        scan.assert_not_called()
