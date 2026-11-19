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
from storage_inspector.file_types import CATEGORIES, MAPPING_PATH, load_file_types
from storage_inspector.scanner import directory_stats
from storage_inspector.windows_inventory import InventoryResult


class FileTypeTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))

    def file(self, name, size):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"x" * size)
        return target

    def cli(self, *args):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main(list(args))
        return status, stdout.getvalue(), stderr.getvalue()

    def test_seven_categories_and_last_suffix_casefolding(self):
        for name, size in (("图.JPG", 2), ("clip.MP4", 3), ("song.FLAC", 4), ("read.PDF", 5),
                           ("source.TSX", 6), ("backup.tar.GZ", 7), ("unknown.zzz", 1),
                           ("README", 0), (".config", 0)):
            self.file(name, size)
        stats = directory_stats(self.root, by_type=True)
        groups = {item["category"]: item for item in stats.type_summary}
        self.assertEqual(set(groups), CATEGORIES)
        self.assertEqual(groups["image"]["logical_bytes"], 2)
        self.assertEqual(groups["archive"]["logical_bytes"], 7)
        self.assertEqual(groups["other"]["file_count"], 3)
        self.assertEqual(sum(item["file_count"] for item in groups.values()), stats.file_count)
        self.assertEqual(sum(item["logical_bytes"] for item in groups.values()), stats.logical_bytes)
        self.assertFalse(stats.partial)

    def test_hard_links_filters_and_limits_use_the_same_counted_files(self):
        original = self.file("first.JPG", 5)
        os.link(original, self.root / "alias.JPG")
        self.file("small.png", 1)
        self.file("omit/video.mp4", 9)
        self.file("filtered.txt", 4)
        stats = directory_stats(self.root, by_type=True, exclude_dirs=["omit"],
                                include_ext=["jpg", "png"], min_size=2)
        self.assertEqual((stats.file_count, stats.logical_bytes, stats.duplicates), (1, 5, 1))
        self.assertEqual(stats.type_summary, [{"category": "image", "logical_bytes": 5, "file_count": 1}])
        self.assertTrue(stats.partial)
        limited = directory_stats(self.root, by_type=True, max_files=1)
        self.assertEqual(limited.stop_reason, "max_files")
        self.assertEqual(sum(item["file_count"] for item in limited.type_summary), 1)

    def test_empty_single_zero_file_and_missing_target(self):
        self.assertEqual(directory_stats(self.root, by_type=True).type_summary, [])
        file = self.file("zero.py", 0)
        self.assertEqual(directory_stats(file, by_type=True).type_summary,
                         [{"category": "code", "logical_bytes": 0, "file_count": 1}])
        missing = directory_stats(self.root / "missing", by_type=True)
        self.assertEqual((missing.type_summary, missing.error_count), ([], 1))

    def test_disabled_does_not_load_the_mapping(self):
        self.file("sample.txt", 2)
        with patch("storage_inspector.scanner.load_file_types") as loader:
            self.assertEqual(directory_stats(self.root).type_summary, [])
        loader.assert_not_called()

    def test_type_ranking_uses_full_summary_and_reports_omissions(self):
        self.file("one.jpg", 1)
        self.file("two.png", 1)
        self.file("film.mp4", 8)
        stats = directory_stats(self.root, by_type=True, sort="count", limit=1)
        self.assertEqual(stats.ranking["source"], "type_summary")
        self.assertEqual(stats.ranking["entries"][0]["category"], "image")
        self.assertEqual((stats.ranking["omitted_file_count"], stats.ranking["omitted_logical_bytes"]), (1, 8))
        self.assertEqual(len(stats.type_summary), 2)
        for sort in ("size", "name"):
            ranked = directory_stats(self.root, by_type=True, sort=sort)
            self.assertEqual(len(ranked.ranking["entries"]), 2)

    def test_bundled_mapping_and_invalid_contents_fail_explicitly(self):
        valid = MAPPING_PATH.read_text(encoding="utf-8")
        contents = (
            "{", "[]", "{}", valid.replace('".jpg"', '".JPG"'),
            valid.replace('".mp4"', '".jpg"'),
            valid.replace('"other": []', '"other": [".odd"]'),
            valid.replace('"other": []', '"other": [], "other": []'),
        )
        mapping = self.root / "mapping.json"
        with patch("storage_inspector.file_types.MAPPING_PATH", mapping):
            for text in contents:
                mapping.write_text(text, encoding="utf-8")
                with self.subTest(text=text[:50]), self.assertRaises(ValueError):
                    load_file_types()
            mapping.write_text(valid, encoding="utf-8")
            self.assertEqual(load_file_types()[".jpg"], "image")
            mapping.unlink()
            with self.assertRaises(ValueError):
                load_file_types()

    def test_invalid_mapping_prevents_scan_inventory_and_output_creation(self):
        mapping = self.root / "broken.json"
        mapping.write_text("{", encoding="utf-8")
        output = self.root / "report.json"
        with patch("storage_inspector.file_types.MAPPING_PATH", mapping), \
                patch.object(Path, "lstat") as stat, \
                patch("storage_inspector.__main__.discover_inventory") as discover:
            with self.assertRaises(ValueError):
                directory_stats(self.root, by_type=True)
            with self.assertRaises(ValueError):
                inspect_app(InventoryResult(), "fixture", by_type=True)
            with self.assertRaises(SystemExit) as error:
                self.cli("--app", "fixture", "--by-type", "--output", str(output))
            self.assertEqual(error.exception.code, 2)
        stat.assert_not_called()
        discover.assert_not_called()
        self.assertFalse(output.exists())

    def test_three_formats_and_safe_saved_report(self):
        self.file("sample.mp4", 3)
        args = ("--path", str(self.root), "--by-type")
        status, output, _ = self.cli(*args)
        self.assertEqual(status, 0)
        expected = json.loads(output)["type_summary"]
        for format in ("csv", "ndjson"):
            status, output, errors = self.cli(*args, "--format", format)
            self.assertEqual(status, 0)
            if format == "csv":
                self.assertEqual(output.splitlines()[0], "path,size,modified")
                report = json.loads(errors)
            else:
                events = [json.loads(line) for line in output.splitlines()]
                self.assertEqual([item["event"] for item in events], ["file", "summary"])
                report = events[-1]["report"]
            self.assertEqual(report["type_summary"], expected)
        with TemporaryDirectory() as destination:
            path = Path(destination) / "report.json"
            status, _, _ = self.cli(*args, "--output", str(path))
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["type_summary"], expected)

    @unittest.skipUnless(os.name == "nt", "Windows application paths")
    def test_application_entry(self):
        self.file("file.txt", 2)
        inventory = InventoryResult([InstalledApp("fixture", "Fixture", install_location=str(self.root))])
        with patch("storage_inspector.__main__.discover_inventory", return_value=inventory):
            status, output, _ = self.cli("--app", "fixture", "--by-type")
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output)["scan"]["type_summary"][0]["category"], "document")

    def test_inventory_and_ambiguous_ranking_rejected_before_io(self):
        with patch("storage_inspector.__main__.discover_inventory") as discover, \
                patch("storage_inspector.__main__.directory_stats") as scan:
            for args in (("--list-apps", "--by-type"),
                         ("--path", str(self.root), "--by-type", "--by-extension", "--sort", "size")):
                with self.assertRaises(SystemExit) as error:
                    self.cli(*args)
                self.assertEqual(error.exception.code, 2)
        discover.assert_not_called()
        scan.assert_not_called()
